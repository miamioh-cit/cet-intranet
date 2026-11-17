const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { createAuthServer, COOKIE, IDLE, TTL } = require('./server.cjs');

async function fixture(t, options = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cet-auth-test-'));
  const file = path.join(dir, 'htpasswd');
  const password = 'temporary-test-password';
  const hash = await bcrypt.hash(password, 8);
  await fs.writeFile(file, 'staff:' + hash + '\n');
  let now = Date.now();
  const server = createAuthServer({ passwordFile: file, clock: () => now, ...options });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); });
  const call = (route, { protocol = 'https', cookie, origin, ...init } = {}) => fetch(base + route, {
    ...init, headers: { 'X-Forwarded-Proto': protocol, Origin: origin || `${protocol}://${new URL(base).host}`, 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}), ...init.headers },
  });
  const login = (credentials = {}, extra = {}) => call('/login', { method: 'POST', body: JSON.stringify({ username: 'staff', password, ...credentials }), ...extra });
  return { file, call, login, advance: ms => { now += ms; } };
}

test('HTTPS sign-in issues secure cookie and logout invalidates it', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('/check')).status, 401);
  const response = await f.login(); assert.equal(response.status, 200);
  const set = response.headers.get('set-cookie');
  assert(set.startsWith(COOKIE + '=')); assert.match(set, /Secure; HttpOnly; SameSite=Strict/);
  const cookie = set.split(';')[0];
  assert.equal((await f.call('/check', { cookie })).status, 200);
  assert.equal((await f.call('/logout', { method: 'POST', cookie })).status, 200);
  assert.equal((await f.call('/check', { cookie })).status, 401);
});
test('temporary HTTP sign-in is opt-in and works when explicitly enabled', async t => {
  const f = await fixture(t);
  assert.equal((await f.login({}, { protocol: 'http' })).status, 403);
  const enabled = await fixture(t, { allowHttp: true });
  assert.equal((await (await enabled.call('/options')).json()).allowHttp, true);
  const response = await enabled.login({}, { protocol: 'http' });
  assert.equal(response.status, 200);
  const cookie = response.headers.get('set-cookie');
  assert(cookie.startsWith('cet_staff_http=')); assert(!cookie.includes('Secure'));
  assert.match(cookie, /HttpOnly; SameSite=Strict/);
  assert.equal((await enabled.call('/check', { protocol: 'http', cookie: cookie.split(';')[0] })).status, 200);
});
test('wrong, nonexistent, and forged credentials are rejected', async t => {
  const f = await fixture(t);
  const wrong = await f.login({ password: 'wrong' });
  const unknown = await f.login({ username: 'not-a-staff-member' });
  assert.equal(wrong.status, 401); assert.equal(unknown.status, 401);
  assert.deepEqual(await wrong.json(), await unknown.json());
  assert.equal((await f.call('/check', { cookie: COOKIE + '=' + 'a'.repeat(64) })).status, 401);
});
test('cross-site login and logout are rejected', async t => {
  const f = await fixture(t);
  assert.equal((await f.login({}, { origin: 'https://other.test' })).status, 403);
  assert.equal((await f.call('/logout', { method: 'POST', origin: 'https://other.test' })).status, 403);
});
test('idle sessions expire', async t => {
  const f = await fixture(t); const cookie = (await f.login()).headers.get('set-cookie').split(';')[0];
  f.advance(IDLE + 1); assert.equal((await f.call('/check', { cookie })).status, 401);
});
test('absolute session expiry applies despite activity', async t => {
  const f = await fixture(t); const cookie = (await f.login()).headers.get('set-cookie').split(';')[0];
  for (let elapsed = 0; elapsed < TTL - IDLE; elapsed += IDLE / 2) {
    f.advance(IDLE / 2); assert.equal((await f.call('/check', { cookie })).status, 200);
  }
  f.advance(IDLE); assert.equal((await f.call('/check', { cookie })).status, 401);
});
test('password change revokes existing sessions', async t => {
  const f = await fixture(t); const cookie = (await f.login()).headers.get('set-cookie').split(';')[0];
  await fs.writeFile(f.file, 'staff:' + await bcrypt.hash('replacement-password', 8) + '\n');
  assert.equal((await f.call('/check', { cookie })).status, 401);
});
test('missing account file blocks sign-in without exposing file details', async t => {
  const f = await fixture(t); await fs.unlink(f.file);
  const response = await f.login(); assert.equal(response.status, 503);
  assert(!JSON.stringify(await response.json()).includes(f.file));
});
test('malformed requests and oversized passwords are rejected', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('/login', { method: 'GET' })).status, 405);
  assert.equal((await f.call('/login', { method: 'POST', body: 'not json' })).status, 400);
  assert.equal((await f.login({ password: 'a'.repeat(73) })).status, 400);
  assert.equal((await f.login({ username: ['staff'] })).status, 400);
});
test('repeated failed logins are limited', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 10; i++) assert.equal((await f.login({ password: 'wrong' })).status, 401);
  assert.equal((await f.login()).status, 429);
});
