import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { matchesPage } from '../extension/match.js';

test('extension vault-crypto.js is in sync with public/ (run: npm run sync-ext)', async () => {
  const read = (p) => fs.readFile(new URL(p, import.meta.url), 'utf8');
  assert.equal(await read('../extension/vault-crypto.js'), await read('../public/vault-crypto.js'));
});

test('matchesPage only offers logins for the same host', () => {
  const item = { type: 'login', url: 'https://github.com/login' };
  assert.ok(matchesPage(item, 'https://github.com/session'));
  assert.ok(matchesPage(item, 'https://www.github.com/'));
  assert.ok(!matchesPage(item, 'https://github.com.evil.io/'), 'lookalike host');
  assert.ok(!matchesPage(item, 'https://gist.github.com/'), 'no subdomain matching');
  assert.ok(!matchesPage(item, 'http://github.com/'), 'no https to http downgrade');
  assert.ok(matchesPage({ type: 'login', url: 'http://router.local' }, 'http://router.local/admin'));
  assert.ok(!matchesPage({ type: 'note', url: 'https://github.com' }, 'https://github.com/'), 'only logins');
  assert.ok(!matchesPage({ type: 'login', url: '' }, 'https://github.com/'));
  assert.ok(!matchesPage(item, 'not a url'));
});
