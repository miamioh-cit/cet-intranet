'use strict';
const http = require('node:http');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { createKubernetesAccountStore } = require('./account-store.cjs');

const COOKIE = '__Host-cet_staff';
const TTL = 8 * 60 * 60 * 1000;
const IDLE = 30 * 60 * 1000;
const WINDOW = 15 * 60 * 1000;
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

function createAuthServer({ passwordFile = process.env.AUTH_PASSWORD_FILE || '/etc/nginx/auth/htpasswd', clock = Date.now, allowHttp = process.env.AUTH_ALLOW_HTTP === 'true', accountStore } = {}) {
  const store = accountStore || (process.env.AUTH_ACCOUNT_STORAGE === 'kubernetes' ? createKubernetesAccountStore() : { read: () => fs.readFile(passwordFile, 'utf8') });
  const sessions = new Map();
  const attempts = new Map();
  const dummyHash = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 10);
  let verifying = 0;

  function prune() {
    const now = clock();
    for (const [id, session] of sessions) if (session.expires <= now || session.lastSeen + IDLE <= now) sessions.delete(id);
    for (const [id, attempt] of attempts) if (attempt.until <= now) attempts.delete(id);
  }
  function reply(res, status, message, headers = {}) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
    res.end(JSON.stringify({ message }));
  }
  function token(req) {
    const name = cookieName(req);
    const values = (req.headers.cookie || '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '='));
    if (values.length !== 1) return '';
    const value = values[0].slice(name.length + 1);
    return /^[a-f0-9]{64}$/.test(value) ? value : '';
  }
  function secure(req) { return req.headers['x-forwarded-proto'] === 'https'; }
  function cookieName(req) { return secure(req) ? COOKIE : 'cet_staff_http'; }
  function cookie(req, value, age) {
    return `${cookieName(req)}=${value}; Path=/; Max-Age=${age}; ${secure(req) ? 'Secure; ' : ''}HttpOnly; SameSite=Strict`;
  }
  async function accounts() {
    const content = await store.read();
    const users = new Map();
    for (const line of content.split(/\r?\n/)) {
      if (!line || line.startsWith('#')) continue;
      const at = line.indexOf(':');
      const name = line.slice(0, at), hash = line.slice(at + 1);
      if (at > 0 && /^[A-Za-z0-9_.@-]{1,64}$/.test(name) && /^\$2[aby]\$(?:0[8-9]|1[0-4])\$[./A-Za-z0-9]{53}$/.test(hash)) users.set(name, hash);
    }
    if (!users.size) throw new Error('Staff accounts are not configured');
    return users;
  }
  async function sessionFor(req) {
    const id = token(req);
    if (!id) return null;
    const session = sessions.get(digest(id));
    if (!session) return null;
    // Revoking an account or changing its hash also revokes its active sessions.
    const users = await accounts();
    if (digest(users.get(session.username) || '') !== session.accountHash) {
      sessions.delete(digest(id));
      return null;
    }
    session.lastSeen = clock();
    return session;
  }
  function originMatches(req) {
    const protocol = req.headers['x-forwarded-proto'];
    return (protocol === 'https' || (allowHttp && protocol === 'http')) && req.headers.origin === `${protocol}://${req.headers.host}`;
  }
  function throttle(key, limit) {
    let value = attempts.get(key);
    if (!value) {
      if (attempts.size >= 4000) return false;
      value = { count: 0, until: clock() + WINDOW }; attempts.set(key, value);
    }
    value.count++;
    return value.count <= limit;
  }
  async function body(req) {
    let size = 0; const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 4096) throw new Error('Invalid request');
      chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }

  return http.createServer({ requestTimeout: 10000, headersTimeout: 10000 }, async (req, res) => {
    prune();
    try {
      if (req.method === 'GET' && req.url === '/health') return reply(res, 200, 'Ready');
      if (req.method === 'GET' && req.url === '/options') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ allowHttp }));
      }
      if (req.method === 'GET' && req.url === '/check') {
        if (!secure(req) && !(allowHttp && req.headers['x-forwarded-proto'] === 'http')) return reply(res, 401, 'Sign in required');
        return reply(res, await sessionFor(req) ? 200 : 401, 'Session check');
      }
      if (!['/login', '/logout', '/change-password'].includes(req.url)) return reply(res, 404, 'Not found');
      if (req.method !== 'POST') return reply(res, 405, 'POST required', { Allow: 'POST' });
      if (!originMatches(req)) return reply(res, 403, 'Use the secure HTTPS intranet address to sign in.');
      if (req.url === '/logout') {
        const id = token(req); if (id) sessions.delete(digest(id));
        return reply(res, 200, 'Signed out', { 'Set-Cookie': cookie(req, '', 0) });
      }
      if ((req.headers['content-type'] || '').split(';')[0] !== 'application/json') return reply(res, 415, 'JSON required');
      const ip = req.headers['x-real-ip'] || req.socket.remoteAddress;
      if (!throttle('ip:' + ip, 60)) return reply(res, 429, 'Too many attempts. Try again in 15 minutes.', { 'Retry-After': '900' });
      let input;
      try { input = await body(req); } catch { return reply(res, 400, 'Enter a valid username and password.'); }
      const { username, password } = input || {};
      if (req.url === '/change-password') {
        const session = await sessionFor(req);
        if (!session) return reply(res, 401, 'Your session expired. Please sign in again.');
        if (!throttle('change:' + digest(session.username), 10)) return reply(res, 429, 'Too many attempts. Try again in 15 minutes.', { 'Retry-After': '900' });
        const { currentPassword, newPassword, confirmPassword } = input || {};
        if (typeof currentPassword !== 'string' || !currentPassword || Buffer.byteLength(currentPassword, 'utf8') > 72 || typeof newPassword !== 'string' || newPassword.length < 12 || Buffer.byteLength(newPassword, 'utf8') > 72 || newPassword !== confirmPassword) return reply(res, 400, 'Use a new password of at least 12 characters (up to 72 bytes) and enter it twice.');
        if (newPassword === currentPassword) return reply(res, 400, 'Choose a different password.');
        if (!store.change) return reply(res, 503, 'Password changes are not configured yet. Contact your administrator.');
        if (verifying >= 4) return reply(res, 503, 'Sign-in is busy. Please try again shortly.');
        verifying++;
        try {
          const users = await accounts();
          const oldHash = users.get(session.username);
          if (!oldHash || digest(oldHash) !== session.accountHash || !await bcrypt.compare(currentPassword, oldHash)) return reply(res, 401, 'Current password is incorrect.');
          const newHash = await bcrypt.hash(newPassword, 12);
          try { await store.change(session.username, oldHash, newHash); }
          catch (error) {
            return reply(res, error.code === 'ACCOUNT_CHANGED' ? 409 : 503, error.code === 'ACCOUNT_CHANGED' ? 'Your account changed. Sign in again before retrying.' : 'Unable to save your password. Please try again or contact your administrator.');
          }
          for (const [id, active] of sessions) if (active.username === session.username) sessions.delete(id);
          return reply(res, 200, 'Password changed. Sign in with your new password.', { 'Set-Cookie': cookie(req, '', 0) });
        } finally { verifying--; }
      }
      if (typeof username !== 'string' || !/^[A-Za-z0-9_.@-]{1,64}$/.test(username) || typeof password !== 'string' || !password || Buffer.byteLength(password, 'utf8') > 72) return reply(res, 400, 'Enter a valid username and password.');
      if (!throttle('user:' + digest(username), 10)) return reply(res, 429, 'Too many attempts. Try again in 15 minutes.', { 'Retry-After': '900' });
      let users;
      try { users = await accounts(); } catch { return reply(res, 503, 'Staff sign-in is not configured yet. Contact your administrator.'); }
      if (verifying >= 4) return reply(res, 503, 'Sign-in is busy. Please try again shortly.');
      verifying++;
      let valid;
      try { valid = await bcrypt.compare(password, users.get(username) || dummyHash); } finally { verifying--; }
      if (!valid || !users.has(username)) return reply(res, 401, 'Incorrect username or password.');
      if (sessions.size >= 1000) return reply(res, 503, 'Sign-in is busy. Please try again shortly.');
      const id = crypto.randomBytes(32).toString('hex');
      const previous = token(req); if (previous) sessions.delete(digest(previous));
      sessions.set(digest(id), { username, accountHash: digest(users.get(username)), expires: clock() + TTL, lastSeen: clock() });
      attempts.delete('user:' + digest(username));
      return reply(res, 200, 'Signed in', { 'Set-Cookie': cookie(req, id, TTL / 1000) });
    } catch {
      // Do not log passwords, cookies, hashes, or request bodies.
      return reply(res, 503, 'Staff sign-in is temporarily unavailable.');
    }
  });
}

if (require.main === module) {
  const server = createAuthServer();
  server.listen(Number(process.env.AUTH_PORT || 3001), '127.0.0.1', () => console.log('Staff authentication listening on loopback'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
}
module.exports = { createAuthServer, COOKIE, TTL, IDLE };
