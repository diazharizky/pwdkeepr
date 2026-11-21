// Service worker: the only extension part that holds the vault key or talks to the server.
// Content scripts get passwords one at a time, and only for logins that match their own frame URL.
import * as vc from './vault-crypto.js';
import { hostOf, matchesPage } from './match.js';

// shortcut: server URL fixed to the default port; add an options page if PORT is changed
const SERVER = 'http://localhost:4848/api/vault';
const AUTO_LOCK_MIN = 15;
const PENDING_TTL_MS = 2 * 60 * 1000;

async function fetchVault() {
  const res = await fetch(SERVER, { cache: 'no-store' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Server error ${res.status}`);
  return res.json();
}

// The vault key lives in chrome.storage.session: memory only, cleared on browser restart,
// and not readable by content scripts (default TRUSTED_CONTEXTS access level).
async function getKey() {
  const { vk } = await chrome.storage.session.get('vk');
  if (!vk) return null;
  chrome.alarms.create('autolock', { delayInMinutes: AUTO_LOCK_MIN }); // any use resets the idle timer
  return vc.importVaultKey(vk);
}

async function loadItems() {
  const vk = await getKey();
  if (!vk) return null;
  const file = await fetchVault();
  if (!file) throw new Error('Vault not found on server');
  return { vk, file, items: await vc.decryptItems(file, vk) };
}

// Always re-reads the latest vault right before writing, so the revision check rarely conflicts.
async function writeItems(mutate) {
  const s = await loadItems();
  if (!s) throw new Error('Locked');
  const body = await vc.saveItems(s.file, s.vk, mutate(s.items));
  const res = await fetch(SERVER, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-pwdkeepr': '1' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Save failed (${res.status})`);
}

async function lock() {
  await chrome.storage.session.clear();
  await chrome.alarms.clear('autolock');
}
chrome.alarms.onAlarm.addListener((a) => a.name === 'autolock' && lock());
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`pending:${tabId}`));

const publicPending = (p) => ({ host: p.host, username: p.username, update: !!p.updateId }); // never the password

async function getPending(tabId) {
  const key = `pending:${tabId}`;
  const { [key]: p } = await chrome.storage.session.get(key);
  return p && Date.now() - p.ts < PENDING_TTL_MS ? p : null;
}

const handlers = {
  // ---- popup only ----
  async status() {
    const file = await fetchVault().catch(() => undefined);
    const { vk } = await chrome.storage.session.get('vk');
    return { server: file !== undefined, hasVault: !!file, locked: !vk };
  },
  async unlock({ password }) {
    const file = await fetchVault();
    if (!file) throw new Error('No vault yet. Create one at http://localhost:4848');
    let r;
    try {
      r = await vc.unlock(file, password);
    } catch {
      throw new Error('Wrong master password.');
    }
    await chrome.storage.session.set({ vk: await vc.exportVaultKey(r.vk) });
    chrome.alarms.create('autolock', { delayInMinutes: AUTO_LOCK_MIN });
    return true;
  },
  lock,
  async list({ url }) {
    const s = await loadItems();
    if (!s) throw new Error('Locked');
    return { items: s.items, matchIds: s.items.filter((i) => matchesPage(i, url)).map((i) => i.id) };
  },
  async fillTab({ tabId, id }) {
    // The top frame's content script asks back for credentials, so the frame-URL check still applies.
    await chrome.tabs.sendMessage(tabId, { type: 'doFill', id }, { frameId: 0 });
  },

  // ---- content scripts ----
  async matches(_, sender) {
    const s = await loadItems();
    if (!s) return { locked: true, items: [] };
    return { items: s.items.filter((i) => matchesPage(i, sender.url)).map(({ id, title, username }) => ({ id, title, username })) };
  },
  async credentials({ id }, sender) {
    const s = await loadItems();
    const item = s?.items.find((i) => i.id === id);
    if (!item || !matchesPage(item, sender.url)) throw new Error('No matching login');
    return { username: item.username, password: item.password };
  },
  async capture({ username, password }, sender) {
    if (typeof password !== 'string' || !password || typeof username !== 'string') return null;
    const s = await loadItems().catch(() => null);
    if (!s) return null; // locked: nothing to compare against, skip
    const existing = s.items.find((i) => matchesPage(i, sender.url) && (i.username || '') === username);
    if (existing?.password === password) return null;
    const p = { url: new URL(sender.url).origin, host: hostOf(sender.url), username, password, updateId: existing?.id ?? null, ts: Date.now() };
    await chrome.storage.session.set({ [`pending:${sender.tab.id}`]: p });
    chrome.tabs.sendMessage(sender.tab.id, { type: 'showPending' }, { frameId: 0 }).catch(() => {});
    return null;
  },
  async pending(_, sender) {
    if (sender.frameId !== 0) return null;
    const p = await getPending(sender.tab.id);
    return p && publicPending(p);
  },
  async resolvePending({ save }, sender) {
    const p = await getPending(sender.tab.id);
    await chrome.storage.session.remove(`pending:${sender.tab.id}`);
    if (!save || !p) return null;
    const now = Date.now();
    await writeItems((items) =>
      p.updateId
        ? items.map((i) => (i.id === p.updateId ? { ...i, password: p.password, updated: now } : i))
        : [...items, { id: crypto.randomUUID(), type: 'login', title: p.host, username: p.username, password: p.password, url: p.url, notes: '', created: now, updated: now }],
    );
    return true;
  },
};

const POPUP_ONLY = new Set(['status', 'unlock', 'lock', 'list', 'fillTab']);
const CONTENT_ONLY = new Set(['matches', 'credentials', 'capture', 'pending', 'resolvePending']);

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const fn = Object.hasOwn(handlers, msg?.type) && handlers[msg.type];
  const fromPage = !!sender.tab; // content scripts have a tab; the popup does not
  if (!fn || (POPUP_ONLY.has(msg.type) && fromPage) || (CONTENT_ONLY.has(msg.type) && !fromPage)) {
    reply({ error: 'forbidden' });
    return false;
  }
  fn(msg, sender).then(
    (data) => reply({ data }),
    (e) => reply({ error: e.message }),
  );
  return true; // async reply
});
