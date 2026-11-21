// Zero-knowledge vault crypto, shared by the browser app and the Node tests.
// Key hierarchy (same idea as Proton Pass / LastPass):
//   master password --PBKDF2-SHA256--> master key --AES-GCM wraps--> random vault key
//   vault key --AES-GCM--> item list
// Changing the master password only re-wraps the vault key; items are not re-encrypted.

export const ITERATIONS = 600_000; // OWASP 2023 recommendation for PBKDF2-SHA256, also LastPass's default

const enc = new TextEncoder();
const dec = new TextDecoder();
const AES = { name: 'AES-GCM', length: 256 };

async function deriveMasterKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, AES, false, ['encrypt', 'decrypt']);
}

async function seal(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: iv.toBase64(), ct: new Uint8Array(ct).toBase64() };
}

function open(key, box) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.fromBase64(box.iv) }, key, Uint8Array.fromBase64(box.ct));
}

async function wrapVaultKey(vk, password, iterations) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const mk = await deriveMasterKey(password, salt, iterations);
  const raw = await crypto.subtle.exportKey('raw', vk);
  return { kdf: { salt: salt.toBase64(), iterations }, key: await seal(mk, raw) };
}

export async function createVault(password, iterations = ITERATIONS) {
  const vk = await crypto.subtle.generateKey(AES, true, ['encrypt', 'decrypt']);
  const file = { v: 1, rev: 0, ...(await wrapVaultKey(vk, password, iterations)), data: null };
  return { file, vk };
}

// Throws (OperationError) when the password is wrong or the file was tampered with.
export async function unlock(file, password) {
  const mk = await deriveMasterKey(password, Uint8Array.fromBase64(file.kdf.salt), file.kdf.iterations);
  const vk = await importVaultKey(new Uint8Array(await open(mk, file.key)).toBase64());
  return { vk, items: await decryptItems(file, vk) };
}

export async function decryptItems(file, vk) {
  return file.data ? JSON.parse(dec.decode(await open(vk, file.data))) : [];
}

// Lets the browser extension keep an unlocked vault key in memory-only session storage.
export async function exportVaultKey(vk) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', vk)).toBase64();
}

export function importVaultKey(b64) {
  return crypto.subtle.importKey('raw', Uint8Array.fromBase64(b64), AES, true, ['encrypt', 'decrypt']);
}

export async function saveItems(file, vk, items) {
  return { ...file, data: await seal(vk, enc.encode(JSON.stringify(items))) };
}

export async function changePassword(file, vk, newPassword, iterations = ITERATIONS) {
  return { ...file, ...(await wrapVaultKey(vk, newPassword, iterations)) };
}

// Unbiased random password: rejection sampling avoids modulo bias.
export function generatePassword(length = 20, symbols = true) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789' + (symbols ? '!@#$%^&*-_=+?' : '');
  const limit = 256 - (256 % chars.length);
  let out = '';
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(length))) {
      if (b < limit && out.length < length) out += chars[b % chars.length];
    }
  }
  return out;
}
