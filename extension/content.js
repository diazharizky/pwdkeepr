// Runs in every page frame. Finds login fields, shows a fill dropdown, offers to save after login.
// UI lives in a closed shadow root so page CSS and scripts cannot style or read it.
(() => {
  const send = (msg) =>
    chrome.runtime.sendMessage(msg).then((r) => {
      if (r?.error) throw new Error(r.error);
      return r?.data;
    });

  const CSS = `
    :host { all: initial; }
    .box { position: fixed; z-index: 2147483647; font: 14px/1.4 system-ui, sans-serif; color: #1b1340;
      background: #fff; border: 1px solid #e4e1f0; border-radius: 10px; box-shadow: 0 8px 24px rgba(27,19,64,.18); }
    .dropdown { padding: 4px; min-width: 240px; }
    .dropdown button { display: grid; width: 100%; text-align: left; padding: 8px 10px; border: 0; border-radius: 6px; background: none; cursor: pointer; font: inherit; color: inherit; }
    .dropdown button:hover, .dropdown button:focus-visible { background: #efecfb; outline: none; }
    .sub, .hint { color: #6b6785; font-size: 12px; }
    .hint { padding: 8px 10px; }
    .banner { top: 16px; right: 16px; padding: 12px 14px; display: flex; gap: 10px; align-items: center; max-width: 420px; }
    .banner button { font: inherit; padding: 6px 12px; border-radius: 8px; border: 1px solid #e4e1f0; background: #fff; color: inherit; cursor: pointer; }
    .banner .primary { background: #6d4aff; border-color: #6d4aff; color: #fff; }
  `;

  let hostEl, shadow;
  function ui() {
    if (!hostEl?.isConnected) {
      hostEl = document.createElement('pwdkeepr-ui');
      shadow = hostEl.attachShadow({ mode: 'closed' });
      const sheet = new CSSStyleSheet(); // constructable sheet is not blocked by the page's CSP
      sheet.replaceSync(CSS);
      shadow.adoptedStyleSheets = [sheet];
      document.documentElement.append(hostEl);
    }
    return shadow;
  }

  function h(tag, props = {}, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) k.startsWith('on') ? el.addEventListener(k.slice(2), v) : el.setAttribute(k, v);
    el.append(...kids.filter((k) => k != null));
    return el;
  }

  // ---- field detection ----
  const visible = (el) => el.getClientRects().length > 0;
  const passwordFields = (root = document) => [...root.querySelectorAll('input[type=password]')].filter(visible);
  const textLike = (el) => el instanceof HTMLInputElement && ['text', 'email', 'tel'].includes(el.type) && visible(el);

  // Username = last visible text-like input before the password field, in the same form when there is one.
  function usernameFor(pw) {
    return [...(pw.form || document).querySelectorAll('input')]
      .filter((i) => textLike(i) && i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING)
      .pop();
  }

  const isLoginField = (el) =>
    el instanceof HTMLInputElement &&
    (el.type === 'password' ||
      (textLike(el) && (/username|email/.test(el.autocomplete) || /user|email|login|account/i.test(el.name + el.id) || passwordFields().some((pw) => usernameFor(pw) === el))));

  // Native setter + events so React/Vue-controlled inputs register the change.
  function setValue(el, value) {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  async function fill(id, anchor) {
    const { username, password } = await send({ type: 'credentials', id });
    const pw = anchor?.type === 'password' ? anchor : passwordFields(anchor?.form || document)[0] || passwordFields()[0];
    const user = pw ? usernameFor(pw) : anchor && textLike(anchor) ? anchor : null; // username-only step (e.g. Google)
    if (user && username) setValue(user, username);
    if (pw && password) setValue(pw, password);
  }

  // ---- dropdown ----
  const closeDropdown = () => shadow?.querySelector('.dropdown')?.remove();

  async function showDropdown(field) {
    let res;
    try {
      res = await send({ type: 'matches' });
    } catch {
      return;
    }
    if (!field.isConnected || document.activeElement !== field) return;
    if (!res.items.length && !(res.locked && field.type === 'password')) return;
    closeDropdown();
    const r = field.getBoundingClientRect();
    const box = h('div', { class: 'box dropdown', role: 'listbox' },
      ...(res.locked
        ? [h('div', { class: 'hint' }, 'pwdkeepr is locked. Click the toolbar icon to unlock.')]
        : res.items.map((i) =>
            h('button', {
              role: 'option',
              // mousedown + preventDefault keeps focus in the field so blur does not close us first
              onmousedown: (e) => {
                e.preventDefault();
                closeDropdown();
                fill(i.id, field).catch(() => {});
              },
            }, h('span', {}, i.title), h('span', { class: 'sub' }, i.username || '(no username)')),
          )));
    box.style.top = `${r.bottom + 4}px`;
    box.style.left = `${r.left}px`;
    box.style.width = `${Math.max(r.width, 240)}px`;
    ui().append(box);
  }

  document.addEventListener('focusin', (e) => isLoginField(e.target) && showDropdown(e.target), true);
  document.addEventListener('focusout', () => setTimeout(closeDropdown, 150), true);
  document.addEventListener('keydown', (e) => e.key === 'Escape' && closeDropdown(), true);
  addEventListener('scroll', closeDropdown, { passive: true, capture: true });

  // ---- capture on login ----
  function capture(scope) {
    const pw = passwordFields(scope).find((p) => p.value);
    if (pw) send({ type: 'capture', username: usernameFor(pw)?.value || '', password: pw.value }).catch(() => {});
  }
  document.addEventListener('submit', (e) => capture(e.target), true);
  document.addEventListener('click', (e) => {
    const b = e.target.closest?.('button, input[type=submit]');
    if (b?.type === 'submit') capture(b.form || document); // JS-driven logins often never fire 'submit'
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.type === 'password') capture(e.target.form || document);
  }, true);

  // ---- save banner (top frame only) ----
  async function showBanner() {
    if (window !== top) return;
    const p = await send({ type: 'pending' }).catch(() => null);
    if (!p) return;
    ui().querySelector('.banner')?.remove();
    const resolve = (save) => () => {
      bar.remove();
      send({ type: 'resolvePending', save }).catch(() => {});
    };
    const bar = h('div', { class: 'box banner', role: 'dialog', 'aria-label': 'pwdkeepr' },
      h('span', {}, `${p.update ? 'Update password' : 'Save login'} for ${p.username || 'this account'} on ${p.host}?`),
      h('button', { class: 'primary', onclick: resolve(true) }, p.update ? 'Update' : 'Save'),
      h('button', { onclick: resolve(false) }, 'Not now'));
    ui().append(bar);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'doFill') fill(msg.id, document.activeElement instanceof HTMLInputElement ? document.activeElement : null).catch(() => {});
    if (msg.type === 'showPending') showBanner();
  });
  showBanner(); // after a login navigates to a new page
})();
