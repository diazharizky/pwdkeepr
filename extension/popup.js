import { generatePassword } from './vault-crypto.js';
import { hostOf } from './match.js';

const VAULT_URL = 'http://localhost:4848';
const app = document.getElementById('app');
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); // url visible via activeTab

const send = (msg) =>
  chrome.runtime.sendMessage(msg).then((r) => {
    if (r?.error) throw new Error(r.error);
    return r?.data;
  });

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
  toast.timer = setTimeout(() => t.classList.remove('show'), 2000);
}

// shortcut: no clipboard auto-clear here (popup closes, worker has no clipboard); add an offscreen document to clear it
const copy = (val, label) => navigator.clipboard.writeText(val).then(() => toast(`${label} copied`), () => toast('Copy failed'));

const message = (text, link) => app.replaceChildren(h('div', { class: 'msg' }, h('p', {}, text), link && h('a', { href: VAULT_URL, target: '_blank' }, 'Open pwdkeepr')));

async function render() {
  const s = await send({ type: 'status' });
  if (!s.server) return message('Cannot reach the pwdkeepr server at localhost:4848. Run `npm start` in the project.');
  if (!s.hasVault) return message('No vault yet. Create one in the web app first.', true);
  s.locked ? renderLocked() : renderVault();
}

function renderLocked() {
  const pw = h('input', { type: 'password', placeholder: 'Master password', 'aria-label': 'Master password', autocomplete: 'current-password', required: true });
  const err = h('p', { class: 'error', role: 'alert' });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Unlock');
  app.replaceChildren(h('form', {
    class: 'unlock',
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      btn.textContent = 'Deriving key…';
      try {
        await send({ type: 'unlock', password: pw.value });
        renderVault();
      } catch (x) {
        err.textContent = x.message;
        btn.disabled = false;
        btn.textContent = 'Unlock';
      }
    },
  }, h('h1', {}, '🔐 pwdkeepr'), pw, err, btn));
  pw.focus();
}

async function renderVault() {
  const { items, matchIds } = await send({ type: 'list', url: tab?.url || '' });
  const host = hostOf(tab?.url || '');
  const list = h('div', { class: 'list' });
  const search = h('input', { type: 'search', placeholder: 'Search vault', 'aria-label': 'Search vault', oninput: () => draw() });
  const gen = h('code', {}, generatePassword());

  const row = (i, canFill) => h('div', { class: 'row' },
    h('div', { class: 'meta' }, h('span', { class: 'title' }, i.title), h('span', { class: 'sub' }, i.username || i.cardholder || i.type)),
    h('div', { class: 'actions' },
      canFill && h('button', { class: 'primary', onclick: () => send({ type: 'fillTab', tabId: tab.id, id: i.id }).then(() => window.close(), (x) => toast(x.message)) }, 'Fill'),
      i.username && h('button', { title: 'Copy username', onclick: () => copy(i.username, 'Username') }, 'User'),
      (i.password || i.number) && h('button', { title: 'Copy password', onclick: () => copy(i.password || i.number, i.password ? 'Password' : 'Card number') }, 'Pass')));

  function draw() {
    const q = search.value.trim().toLowerCase();
    const hit = (i) => !q || [i.title, i.username, i.url].some((v) => v?.toLowerCase().includes(q));
    const matched = items.filter((i) => matchIds.includes(i.id) && hit(i));
    const rest = items.filter((i) => !matchIds.includes(i.id) && hit(i)).sort((a, b) => a.title.localeCompare(b.title));
    list.replaceChildren(
      matched.length > 0 && h('h2', {}, `Suggestions for ${host}`), matched.map((i) => row(i, true)),
      rest.length > 0 && h('h2', {}, 'All items'), rest.map((i) => row(i, false)),
      !matched.length && !rest.length && h('p', { class: 'muted' }, items.length ? 'No matches.' : 'Vault is empty.'));
  }
  draw();

  app.replaceChildren(
    h('header', {}, h('strong', {}, '🔐 pwdkeepr'),
      h('a', { href: VAULT_URL, target: '_blank' }, 'Open vault'),
      h('button', { onclick: () => send({ type: 'lock' }).then(renderLocked) }, 'Lock')),
    search, list,
    h('footer', {}, gen,
      h('button', { onclick: () => (gen.textContent = generatePassword()) }, 'New'),
      h('button', { onclick: () => copy(gen.textContent, 'Password') }, 'Copy')));
  search.focus();
}

render().catch((x) => message(x.message));
