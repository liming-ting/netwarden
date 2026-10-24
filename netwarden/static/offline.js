// netwarden - "not running" page (GET /offline, shown by the service worker when the
// local server does not answer). Picks the dashboard's last language, retries by itself
// every few seconds and reloads the dashboard as soon as the server is back. Talks to
// nothing but this origin; never shows user data.
'use strict';
(function () {
  // Stage H: the Home Assistant ingress prefix the server put on <html data-base>
  const BASE = (/^(\/[\w.~-]+)*$/.test(document.documentElement.dataset.base || '') && document.documentElement.dataset.base) || '';
  let texts = {};
  try { texts = JSON.parse(document.getElementById('off-texts').textContent) || {}; } catch (e) { texts = {}; }
  let lang = null;
  try { lang = localStorage.getItem('netwarden.lang'); } catch (e) { /* private mode */ }
  if (!texts[lang]) {
    const nav = (navigator.language || '').toLowerCase();
    lang = Object.keys(texts).find(c => c.toLowerCase() === nav) ||
           Object.keys(texts).find(c => nav.startsWith(c.toLowerCase().split('-')[0])) || null;
  }
  try {
    const theme = localStorage.getItem('netwarden.theme');
    if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  } catch (e) { /* private mode */ }
  const t = texts[lang];
  if (t) {
    document.documentElement.lang = lang;
    document.title = t.title;
    for (const k of ['title', 'lead', 'hint', 'retry', 'auto']) {
      const el = document.getElementById('off-' + k);
      if (el) el.textContent = t[k];
    }
  }
  const btn = document.getElementById('off-retry');
  async function check(manual) {
    if (btn) btn.disabled = true;
    try {
      const r = await fetch(BASE + '/api/meta', { cache: 'no-store', credentials: 'same-origin' });
      if (r.ok || r.status === 401) { location.replace(BASE + '/'); return; }
    } catch (e) { /* still down */ }
    if (btn) btn.disabled = false;
    if (manual && btn) btn.focus();
  }
  if (btn) btn.addEventListener('click', () => check(true));
  setInterval(() => check(false), 5000);
})();
