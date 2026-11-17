'use strict';
const fs = require('node:fs/promises');
const https = require('node:https');

function replaceAccount(content, username, expectedHash, newHash) {
  const lines = content.split(/\r?\n/);
  const matches = lines.map((line, index) => line.startsWith(username + ':') ? index : -1).filter(index => index >= 0);
  if (matches.length !== 1 || lines[matches[0]] !== username + ':' + expectedHash) {
    const error = new Error('Account changed; sign in again'); error.code = 'ACCOUNT_CHANGED'; throw error;
  }
  lines[matches[0]] = username + ':' + newHash;
  return lines.join('\n');
}

function createKubernetesAccountStore({ credentialsDir = '/var/run/secrets/staff-api', host = process.env.KUBERNETES_SERVICE_HOST, port = process.env.KUBERNETES_SERVICE_PORT_HTTPS || '443' } = {}) {
  async function request(method, patch) {
    const [token, ca, namespace] = await Promise.all(['token', 'ca.crt', 'namespace'].map(name => fs.readFile(credentialsDir + '/' + name)));
    const payload = patch ? JSON.stringify(patch) : null;
    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: host, port, method, ca,
        path: '/api/v1/namespaces/' + encodeURIComponent(namespace.toString().trim()) + '/secrets/intranet-admin-auth',
        headers: { Authorization: 'Bearer ' + token.toString().trim(), Accept: 'application/json', ...(payload ? { 'Content-Type': 'application/json-patch+json', 'Content-Length': Buffer.byteLength(payload) } : {}) },
      }, res => {
        const chunks = []; let bytes = 0;
        res.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) req.destroy(new Error('Account response too large')); else chunks.push(chunk); });
        res.on('error', reject);
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            const error = new Error('Account storage is unavailable'); error.code = [409, 422].includes(res.statusCode) ? 'ACCOUNT_CHANGED' : 'STORE_UNAVAILABLE'; return reject(error);
          }
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('Invalid account storage response')); }
        });
      });
      req.setTimeout(5000, () => req.destroy(new Error('Account storage timed out')));
      req.on('error', reject);
      req.end(payload);
    });
  }
  function decode(secret) {
    if (typeof secret.data?.htpasswd !== 'string') throw new Error('Staff accounts are not configured');
    return Buffer.from(secret.data.htpasswd, 'base64').toString('utf8');
  }
  return {
    async read() { return decode(await request('GET')); },
    async change(username, expectedHash, newHash) {
      const secret = await request('GET');
      const updated = replaceAccount(decode(secret), username, expectedHash, newHash);
      // Optimistic concurrency: never overwrite another user's simultaneous edit.
      await request('PATCH', [
        { op: 'test', path: '/metadata/resourceVersion', value: secret.metadata.resourceVersion },
        { op: 'replace', path: '/data/htpasswd', value: Buffer.from(updated).toString('base64') },
      ]);
    },
  };
}
module.exports = { createKubernetesAccountStore, replaceAccount };
