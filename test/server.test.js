import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const PORT = 4900 + Math.floor(Math.random() * 500);
const URL_ = `http://localhost:${PORT}/api/vault`;
const vault = (rev) => ({ v: 1, rev, kdf: { salt: 'AA==', iterations: 1 }, key: { iv: 'AA==', ct: 'AA==' }, data: null });
const put = (body, headers = { 'x-pwdkeepr': '1', 'content-type': 'application/json' }) =>
  fetch(URL_, { method: 'PUT', headers, body: JSON.stringify(body) });
let srv, dir;

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pwdkeepr-'));
  srv = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT, VAULT_FILE: path.join(dir, 'v.json') } });
  await once(srv.stdout, 'data');
});
after(async () => {
  srv.kill();
  await fs.rm(dir, { recursive: true });
});

test('vault API lifecycle and guards', async () => {
  assert.equal((await fetch(URL_)).status, 404);
  assert.equal((await put(vault(0), { 'content-type': 'application/json' })).status, 403, 'missing csrf header');
  assert.equal((await put({ v: 1 })).status, 400, 'invalid shape');
  assert.deepEqual(await (await put(vault(0))).json(), { rev: 1 });
  assert.equal((await put(vault(0))).status, 409, 'stale rev');
  assert.equal((await fetch(URL_).then((r) => r.json())).rev, 1);
  assert.ok(await fs.stat(path.join(dir, 'v.json')));
  await put(vault(1));
  assert.equal(JSON.parse(await fs.readFile(path.join(dir, 'v.json.bak'), 'utf8')).rev, 1, 'backup of previous version');
});

test('rejects foreign Host header (DNS rebinding)', async () => {
  const { request } = await import('node:http');
  const status = await new Promise((resolve) =>
    request({ port: PORT, path: '/api/vault', headers: { host: `evil.example:${PORT}` } }, (r) => resolve(r.statusCode)).end());
  assert.equal(status, 403);
});

test('serves app and blocks path traversal', async () => {
  assert.equal((await fetch(`http://localhost:${PORT}/`)).status, 200);
  assert.equal((await fetch(`http://localhost:${PORT}/vault-crypto.js`)).headers.get('content-type'), 'text/javascript');
  assert.equal((await fetch(`http://localhost:${PORT}/%2e%2e/server.js`)).status, 404);
});
