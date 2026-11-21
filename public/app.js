import * as vc from './vault-crypto.js';

const AUTO_LOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const TYPES = {
  login: { label: 'Login', fields: [['username', 'Username'], ['password', 'Password', 'secret'], ['url', 'Website', 'url'], ['notes', 'Notes', 'long']] },
  note: { label: 'Note', fields: [['notes', 'Note', 'long']] },
  card: { label: 'Card', fields: [['cardholder', 'Cardholder'], ['number', 'Card number', 'secret'], ['expiry', 'Expiry (MM/YY)'], ['cvv', 'CVV', 'secret'], ['notes', 'Notes', 'long']] },
};

const app = document.getElementById('app');
let file = null; // encrypted vault exactly as stored on the server
let vk = null; // vault key: only in memory while unlocked
let items = [];
let selectedId = null;
let query = '';
let filter = 'all';
let lockTimer = null;
let listEl, mainEl;

// Builds DOM with textContent only, so vault contents can never inject HTML.
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else if (v != null && v !== false) el.setAttribute(k, v);
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false));
  return el;
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 2500);
}

async function api(method, body) {
  const res = await fetch('/api/vault', {
    method,
    headers: body ? { 'content-type': 'application/json', 'x-pwdkeepr': '1' } : {},
    body: body && JSON.stringify(body),
  });
  if (method === 'GET' && res.status === 404) return null;
  if (res.status === 409) throw new Error('Vault was changed in another tab. Reload the page.');
  if (!res.ok) throw new Error(`Server error ${res.status}`);
  return res.json();
}

async function persist(next) {
  const { rev } = await api('PUT', next);
  file = { ...next, rev };
}

async function saveItems(next) {
  await persist(await vc.saveItems(file, vk, next));
  items = next; // only after the server accepted it
}

// ---------- auth screens ----------

function authScreen({ title, subtitle, confirm, button, onSubmit }) {
  const pw = h('input', { type: 'password', 'aria-label': 'Master password', placeholder: 'Master password', autocomplete: confirm ? 'new-password' : 'current-password', minlength: confirm ? 10 : null, required: true });
  const pw2 = confirm && h('input', { type: 'password', 'aria-label': 'Confirm master password', placeholder: 'Confirm master password', autocomplete: 'new-password', required: true });
  const err = h('p', { class: 'error', role: 'alert' });
  const btn = h('button', { class: 'primary', type: 'submit' }, button);
  const form = h('form', {
    class: 'auth card',
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = '';
      if (confirm && pw.value !== pw2.value) return (err.textContent = 'Passwords do not match.');
      btn.disabled = true;
      btn.textContent = 'Deriving key…';
      try {
        await onSubmit(pw.value);
      } catch (x) {
        err.textContent = x.message;
        btn.disabled = false;
        btn.textContent = button;
      }
    },
  }, h('div', { class: 'logo' }, '🔐'), h('h1', {}, title), h('p', { class: 'muted' }, subtitle), pw, pw2, err, btn);
  app.replaceChildren(h('div', { class: 'center' }, form));
  pw.focus();
}

function renderSetup() {
  authScreen({
    title: 'Create your vault',
    subtitle: 'Your master password encrypts everything in this browser. It cannot be recovered: forget it and the vault is lost.',
    confirm: true,
    button: 'Create vault',
    onSubmit: async (pw) => {
      const r = await vc.createVault(pw);
      await persist(r.file);
      vk = r.vk;
      items = [];
      renderVault();
    },
  });
}

function renderLocked() {
  authScreen({
    title: 'Vault locked',
    subtitle: 'Enter your master password to unlock.',
    button: 'Unlock',
    onSubmit: async (pw) => {
      let r;
      try {
        r = await vc.unlock(file, pw);
      } catch {
        throw new Error('Wrong master password.');
      }
      vk = r.vk;
      items = r.items;
      renderVault();
    },
  });
}

function lock() {
  clearTimeout(lockTimer);
  vk = null;
  items = [];
  selectedId = null;
  query = '';
  renderLocked();
}

function armAutoLock() {
  clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}
for (const ev of ['pointerdown', 'keydown']) addEventListener(ev, () => vk && armAutoLock(), { passive: true });

// ---------- vault ----------

function renderVault() {
  armAutoLock();
  const search = h('input', { type: 'search', placeholder: 'Search vault', 'aria-label': 'Search vault', value: query, oninput: (e) => { query = e.target.value; renderList(); } });
  const newMenu = h('select', { 'aria-label': 'New item', onchange: (e) => { const t = e.target.value; e.target.value = ''; if (t) renderEditor({ type: t }); } },
    h('option', { value: '' }, '+ New item'),
    Object.entries(TYPES).map(([k, t]) => h('option', { value: k }, t.label)));
  const tabs = h('nav', { class: 'tabs' },
    ['all', ...Object.keys(TYPES)].map((f) => h('button', { class: f === filter ? 'active' : null, onclick: () => { filter = f; renderVault(); } }, f === 'all' ? 'All' : `${TYPES[f].label}s`)));
  listEl = h('ul', { class: 'list' });
  mainEl = h('section', { class: 'main' });
  app.replaceChildren(h('div', { class: 'shell' },
    h('header', { class: 'top' }, h('strong', { class: 'brand' }, '🔐 pwdkeepr'), search, newMenu,
      h('button', { onclick: renderSettings }, 'Settings'), h('button', { onclick: lock }, 'Lock')),
    h('aside', { class: 'side' }, tabs, listEl),
    mainEl));
  renderList();
  const sel = items.find((i) => i.id === selectedId);
  sel ? renderDetail(sel) : renderEmpty();
}

function renderList() {
  const q = query.trim().toLowerCase();
  const shown = items
    .filter((i) => (filter === 'all' || i.type === filter) && (!q || [i.title, i.username, i.url].some((v) => v?.toLowerCase().includes(q))))
    .sort((a, b) => a.title.localeCompare(b.title));
  listEl.replaceChildren(...shown.map((i) => h('li', {},
    h('button', { class: i.id === selectedId ? 'item active' : 'item', onclick: () => { selectedId = i.id; renderList(); renderDetail(i); } },
      h('span', { class: `avatar ${i.type}` }, (i.title[0] || '?').toUpperCase()),
      h('span', { class: 'meta' }, h('span', { class: 'title' }, i.title), h('span', { class: 'sub' }, i.username || i.cardholder || TYPES[i.type].label))))));
  if (!shown.length) listEl.append(h('li', { class: 'muted empty' }, items.length ? 'No matches.' : 'Vault is empty.'));
}

function renderEmpty() {
  mainEl.replaceChildren(h('div', { class: 'placeholder muted' }, 'Select an item or create a new one.'));
}

async function copy(val, label) {
  try {
    await navigator.clipboard.writeText(val);
  } catch {
    return toast('Clipboard unavailable');
  }
  toast(`${label} copied, clears in 30s`);
  // shortcut: blind clear, may wipe something copied later; upgrade by comparing readText() when permitted
  setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIPBOARD_CLEAR_MS);
}

function renderDetail(item) {
  const mask = '•'.repeat(12);
  const rows = TYPES[item.type].fields.filter(([k]) => item[k]).map(([k, label, kind]) => {
    const val = item[k];
    const shown = h(kind === 'long' ? 'pre' : 'span', { class: 'value' }, kind === 'secret' ? mask : val);
    if (kind === 'url' && /^https?:\/\//i.test(val)) shown.replaceChildren(h('a', { href: val, target: '_blank', rel: 'noopener noreferrer' }, val));
    let open = false;
    const reveal = kind === 'secret' && h('button', { onclick: (e) => { open = !open; shown.textContent = open ? val : mask; e.target.textContent = open ? 'Hide' : 'Show'; } }, 'Show');
    return h('div', { class: 'field' }, h('div', { class: 'label' }, label),
      h('div', { class: 'row' }, shown, h('span', { class: 'actions' }, reveal, h('button', { onclick: () => copy(val, label) }, 'Copy'))));
  });
  mainEl.replaceChildren(h('article', { class: 'card detail' },
    h('div', { class: 'detail-head' },
      h('span', { class: `avatar big ${item.type}` }, (item.title[0] || '?').toUpperCase()),
      h('div', {}, h('h2', {}, item.title), h('p', { class: 'muted' }, `${TYPES[item.type].label} · updated ${new Date(item.updated).toLocaleString()}`))),
    rows,
    h('div', { class: 'buttons' },
      h('button', { class: 'primary', onclick: () => renderEditor(item) }, 'Edit'),
      h('button', { class: 'danger', onclick: () => remove(item) }, 'Delete'))));
}

function renderEditor(item) {
  const t = TYPES[item.type];
  const inputs = {};
  const field = (key, label, kind) => {
    const el = kind === 'long'
      ? h('textarea', { id: `f-${key}`, rows: 4 })
      : h('input', { id: `f-${key}`, type: kind === 'secret' ? 'password' : kind === 'url' ? 'url' : 'text', autocomplete: 'off', spellcheck: 'false', required: key === 'title' });
    el.value = item[key] || '';
    inputs[key] = el;
    return h('div', { class: 'field' }, h('label', { for: el.id }, label), h('div', { class: 'row' }, el,
      kind === 'secret' && h('button', { type: 'button', onclick: () => { el.type = el.type === 'password' ? 'text' : 'password'; } }, 'Show'),
      key === 'password' && h('button', { type: 'button', onclick: () => { el.value = vc.generatePassword(); el.type = 'text'; } }, 'Generate')));
  };
  const err = h('p', { class: 'error', role: 'alert' });
  const form = h('form', {
    class: 'card editor',
    onsubmit: async (e) => {
      e.preventDefault();
      const now = Date.now();
      const next = { ...item, id: item.id || crypto.randomUUID(), created: item.created || now, updated: now, title: inputs.title.value.trim() };
      for (const [k] of t.fields) next[k] = inputs[k].value;
      try {
        await saveItems(item.id ? items.map((i) => (i.id === item.id ? next : i)) : [...items, next]);
        selectedId = next.id;
        renderList();
        renderDetail(next);
        toast('Saved');
      } catch (x) {
        err.textContent = x.message;
      }
    },
  }, h('h2', {}, `${item.id ? 'Edit' : 'New'} ${t.label.toLowerCase()}`),
    field('title', 'Title'), t.fields.map((f) => field(...f)), err,
    h('div', { class: 'buttons' },
      h('button', { class: 'primary', type: 'submit' }, 'Save'),
      h('button', { type: 'button', onclick: () => { const cur = items.find((i) => i.id === item.id); cur ? renderDetail(cur) : renderEmpty(); } }, 'Cancel')));
  mainEl.replaceChildren(form);
  inputs.title.focus();
}

async function remove(item) {
  if (!confirm(`Delete "${item.title}"? This cannot be undone.`)) return;
  try {
    await saveItems(items.filter((i) => i.id !== item.id));
    selectedId = null;
    renderList();
    renderEmpty();
    toast('Deleted');
  } catch (x) {
    toast(x.message);
  }
}

function renderSettings() {
  const input = (id, label, ac, min) => h('div', { class: 'field' }, h('label', { for: id }, label),
    h('input', { id, type: 'password', autocomplete: ac, minlength: min, required: true }));
  const err = h('p', { class: 'error', role: 'alert' });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Change master password');
  mainEl.replaceChildren(h('form', {
    class: 'card editor',
    onsubmit: async (e) => {
      e.preventDefault();
      const [cur, nw, nw2] = ['s-cur', 's-new', 's-new2'].map((id) => document.getElementById(id).value);
      err.textContent = '';
      if (nw !== nw2) return (err.textContent = 'New passwords do not match.');
      btn.disabled = true;
      try {
        try {
          await vc.unlock(file, cur);
        } catch {
          throw new Error('Current password is wrong.');
        }
        await persist(await vc.changePassword(file, vk, nw));
        toast('Master password changed');
        renderEmpty();
      } catch (x) {
        err.textContent = x.message;
        btn.disabled = false;
      }
    },
  }, h('h2', {}, 'Change master password'),
    h('p', { class: 'muted' }, 'Re-wraps the vault key with a key derived from the new password. Items are not re-encrypted.'),
    input('s-cur', 'Current password', 'current-password'),
    input('s-new', 'New password', 'new-password', 10),
    input('s-new2', 'Confirm new password', 'new-password', 10),
    err, h('div', { class: 'buttons' }, btn)));
}

try {
  file = await api('GET');
  file ? renderLocked() : renderSetup();
} catch (x) {
  app.replaceChildren(h('p', { class: 'error center' }, `Cannot reach server: ${x.message}`));
}
