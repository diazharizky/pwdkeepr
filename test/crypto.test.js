import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as vc from '../public/vault-crypto.js';

const ITER = 1000; // fast for tests; the app uses vc.ITERATIONS

test('round-trips items and rejects wrong password', async () => {
  const { file, vk } = await vc.createVault('correct horse', ITER);
  const saved = await vc.saveItems(file, vk, [{ id: '1', title: 'GitHub', password: 's3cret' }]);
  assert.ok(!JSON.stringify(saved).includes('s3cret'));
  assert.deepEqual((await vc.unlock(saved, 'correct horse')).items[0].password, 's3cret');
  await assert.rejects(vc.unlock(saved, 'wrong'));
});

test('new vault unlocks to empty list', async () => {
  const { file } = await vc.createVault('pw', ITER);
  assert.deepEqual((await vc.unlock(file, 'pw')).items, []);
});

test('change password keeps items, old password stops working', async () => {
  const { file, vk } = await vc.createVault('old', ITER);
  const saved = await vc.saveItems(file, vk, [{ id: '1', title: 'x' }]);
  const changed = await vc.changePassword(saved, vk, 'new', ITER);
  assert.equal((await vc.unlock(changed, 'new')).items[0].title, 'x');
  await assert.rejects(vc.unlock(changed, 'old'));
});

test('tampered ciphertext is rejected', async () => {
  const { file, vk } = await vc.createVault('pw', ITER);
  const saved = await vc.saveItems(file, vk, [{ id: '1' }]);
  const bytes = Uint8Array.fromBase64(saved.data.ct);
  bytes[0] ^= 1;
  await assert.rejects(vc.unlock({ ...saved, data: { ...saved.data, ct: bytes.toBase64() } }, 'pw'));
});

test('exported vault key decrypts items after re-import (extension session storage)', async () => {
  const { file, vk } = await vc.createVault('pw', ITER);
  const saved = await vc.saveItems(file, vk, [{ id: '1', title: 'x' }]);
  const vk2 = await vc.importVaultKey(await vc.exportVaultKey(vk));
  assert.equal((await vc.decryptItems(saved, vk2))[0].title, 'x');
});

test('generatePassword respects length and charset', () => {
  const p = vc.generatePassword(32, false);
  assert.equal(p.length, 32);
  assert.match(p, /^[A-Za-z0-9]+$/);
  assert.notEqual(vc.generatePassword(), vc.generatePassword());
});
