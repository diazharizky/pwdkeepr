# pwdkeepr

A local, zero-knowledge password manager modeled on Proton Pass / LastPass. No dependencies.

```
npm start        # http://localhost:4848  (PORT and VAULT_FILE env vars override)
npm test
```

Requires Node 25+ and a current browser (uses `Uint8Array.toBase64`).

## How it works

- Master password → PBKDF2-SHA256 (600k iterations) → master key. Runs in the browser only.
- Master key wraps a random AES-256 vault key; the vault key encrypts the item list (AES-GCM).
- The server stores only `data/vault.json` (ciphertext + salt). It never sees the password or keys.
- Changing the master password re-wraps the vault key; items are not re-encrypted.

Features: logins, secure notes, cards; search and type filter; password generator; copy with
30 s clipboard clear; auto-lock after 5 min idle; change master password.

Server hardening: binds `127.0.0.1` only, Host check (DNS rebinding), custom-header requirement on
writes (blocks cross-site writes), revision check (stale tabs get 409), atomic write + `vault.json.bak`.

## Chromium extension

1. `npm start` (the extension talks to `http://localhost:4848`).
2. Open `chrome://extensions`, enable Developer mode, click **Load unpacked**, pick `extension/`.
3. Click the toolbar icon and unlock with your master password.

What it does:
- Fill dropdown when you focus a login field on a site with a saved login (exact host match, `www.` ignored,
  https logins never filled into http pages). Works on username-only steps too.
- Popup: suggestions for the current site with **Fill**, search, copy username/password, password generator.
- After you log in, a banner offers to **save** the new login or **update** a changed password.
- Auto-locks after 15 min idle and on browser restart.

Security model: only the service worker holds the vault key, in `chrome.storage.session` (memory only,
not readable by content scripts). Content scripts get one password at a time, and only for logins whose
host matches the requesting frame's URL as reported by Chrome, not by the page.

`extension/vault-crypto.js` is a copy of `public/vault-crypto.js`. After editing the original, run
`npm run sync-ext`; a test fails if they drift.

**There is no recovery.** Forget the master password and the vault is lost. Back up `data/`.
