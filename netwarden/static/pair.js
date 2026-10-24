/* netwarden - pair.js: the pairing page (/pair, Stage M).
 *
 * A phone opens http://<lan-ip>:<port>/pair#<code> from the QR code on the computer.
 * The one-time code is in the URL FRAGMENT, which browsers never send to a server; this
 * script takes it out of the address bar at once (history.replaceState), POSTs it as JSON
 * to /api/pair and, once the server has set the HttpOnly session cookie, opens the
 * dashboard. Without a fragment the person types the code shown on the computer.
 * All messages come from data- attributes the server rendered (escaped) in the page's
 * language; nothing here builds markup.
 */
(function () {
  'use strict';
  try {   // the dashboard's saved theme, if this browser has one
    const t = localStorage.getItem('netwarden.theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* private mode */ }

  // Stage H: the Home Assistant ingress prefix the server put on <html data-base>
  const BASE = (/^(\/[\w.~-]+)*$/.test(document.documentElement.dataset.base || '') && document.documentElement.dataset.base) || '';
  const form = document.getElementById('pairform');
  const input = document.getElementById('paircode');
  const msg = document.getElementById('pairmsg');
  const btn = form.querySelector('button[type="submit"]');
  function say(text, kind) { msg.textContent = text || ''; msg.className = 'pair-msg' + (kind ? ' ' + kind : ''); }

  async function submit(code) {
    btn.disabled = true;
    say(form.dataset.working);
    try {
      const r = await fetch(BASE + '/api/pair', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: code, lang: document.documentElement.lang }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok) {
        say(form.dataset.done, 'ok');
        setTimeout(() => location.replace(BASE + '/'), 500);
        return;
      }
      say(j.error || (r.status === 429 ? form.dataset.locked : form.dataset.badCode), 'bad');
    } catch (e) {
      say(form.dataset.offline, 'bad');
    }
    btn.disabled = false;
    input.focus();
    input.select();
  }

  let code = '';
  try { code = decodeURIComponent(location.hash.slice(1)); } catch (e) { code = ''; }
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);

  form.addEventListener('submit', e => {
    e.preventDefault();
    const c = input.value.trim();
    if (!c) { say(form.dataset.needCode, 'bad'); input.focus(); return; }
    submit(c);
  });
  if (code) {
    const c = code.replace(/[\s-]/g, '').toUpperCase().slice(0, 20);
    input.value = c.length === 10 ? c.slice(0, 5) + '-' + c.slice(5) : c;
    submit(c);
  } else {
    input.focus();
  }
})();
