/* netwarden dashboard - vanilla JS, no framework, no build step, no external requests.
 *
 * How it fits together:
 *   - State lives in S. Views are pure functions state -> Html (the html`` tag escapes every
 *     interpolated value; only Html values pass through unescaped).
 *   - render() turns the current route into markup and morph()s it into the page: a small
 *     keyed DOM diff, so a refresh never loses scroll position, focus, open panels or text
 *     being typed (inputs are bound to state via data-draft / data-filter / #chatq).
 *   - Hash routes: one per page (#/overview #/inbox #/devices #/security ...; GROUPS puts
 *     them in seven places with sub-tabs, keys 1-7) and the
 *     slide-over #/device/<mac>, #/service/<id>, #/domain/<domain>.
 *   - Data comes from the local JSON API (?lang= on GETs, "lang" in POST bodies) and is
 *     refreshed every 30 s while the tab is visible. The AI is only ever called from an
 *     explicit click (Insight / Send) - never on load or refresh.
 *   - Every string comes from netwarden/locales/<code>.json via /api/locale.
 */
'use strict';
(function () {

// ---------------------------------------------------------------------------------------
// Safe HTML: html`...${value}...` escapes values; nested Html / arrays of Html pass through.
class Html { constructor(s) { this.s = s; } toString() { return this.s; } }
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(v) { return (v == null ? '' : String(v)).replace(/[&<>"']/g, c => ESC[c]); }
function part(v) {
  if (v instanceof Html) return v.s;
  if (Array.isArray(v)) return v.map(part).join('');
  if (v == null || v === false || v === true) return '';
  return esc(v);
}
function html(strs, ...vals) {
  let out = strs[0];
  for (let i = 0; i < vals.length; i++) out += part(vals[i]) + strs[i + 1];
  return new Html(out);
}
// Tiny markdown for AI answers, applied AFTER escaping (so it can only ever add these few
// tags): "# heading" lines -> bold, "- item" / "* item" -> "• item", **bold**, `code`,
// line breaks. Links and raw HTML stay plain text.
function md(t) {
  return new Html(esc(t)
    .replace(/^#{1,6}[ \t]+(.+)$/gm, '<strong>$1</strong>')
    .replace(/^([ \t]*)[-*][ \t]+/gm, '$1• ')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`\n]+?)`/g, '<code>$1</code>').replace(/\n/g, '<br>'));
}
const enc = encodeURIComponent;
const $ = (sel, root) => (root || document).querySelector(sel);

// ---------------------------------------------------------------------------------------
// Keyed DOM morph: patch `el` to match `content` in place. Children with data-key are
// matched by key, others by position + tag. A focused input/select/textarea keeps its
// value; elements marked data-keep are left alone entirely.
function morph(el, content) {
  const tpl = document.createElement('template');
  tpl.innerHTML = part(content);
  morphChildren(el, tpl.content);
}
function keyOf(n) { return n.nodeType === 1 ? (n.getAttribute('data-key') || null) : null; }
function morphChildren(from, to) {
  const keyed = new Map();
  for (const n of from.childNodes) { const k = keyOf(n); if (k) keyed.set(k, n); }
  const next = Array.from(to.childNodes);
  next.forEach((nn, i) => {
    const cur = from.childNodes[i] || null;
    const k = keyOf(nn);
    let match = null;
    if (k) { match = keyed.get(k) || null; if (match) keyed.delete(k); }
    else if (cur && !keyOf(cur) && cur.nodeType === nn.nodeType && cur.nodeName === nn.nodeName) match = cur;
    if (match) { if (match !== cur) from.insertBefore(match, cur); morphNode(match, nn); }
    else from.insertBefore(nn, cur);
  });
  while (from.childNodes.length > next.length) from.removeChild(from.lastChild);
}
function morphNode(a, b) {
  if (a.nodeType !== 1) { if (a.nodeValue !== b.nodeValue) a.nodeValue = b.nodeValue; return; }
  if (a.hasAttribute('data-keep') && b.hasAttribute('data-keep')) return;
  // a <details> the user opened or closed stays that way across refreshes (the template's
  // `open` only applies when it is first inserted)
  const own = at => a.nodeName === 'DETAILS' && at === 'open';
  for (const at of Array.from(a.attributes)) if (!b.hasAttribute(at.name) && !own(at.name)) a.removeAttribute(at.name);
  for (const at of Array.from(b.attributes)) if (a.getAttribute(at.name) !== at.value && !own(at.name)) a.setAttribute(at.name, at.value);
  const tag = a.nodeName, focused = a === document.activeElement;
  if (tag === 'TEXTAREA') { if (!focused && a.value !== b.textContent) a.value = b.textContent; return; }
  if (tag === 'INPUT') {
    if (!focused) {
      if (a.type === 'checkbox' || a.type === 'radio') a.checked = b.hasAttribute('checked');
      else if (a.value !== (b.getAttribute('value') || '')) a.value = b.getAttribute('value') || '';
    }
    return;
  }
  const want = tag === 'SELECT' ? ((b.querySelector('option[selected]') || {}).value) : null;
  morphChildren(a, b);
  if (tag === 'SELECT' && !focused) a.value = want != null ? want : (a.options[0] ? a.options[0].value : '');
}

// ---------------------------------------------------------------------------------------
// State
// Stage U: seven places to go - everyday use first, settings last. Every page belongs to
// one; pages that share a place show sub-tabs. The pages keep their own routes (#/security,
// #/system, #/people/<id>, ...), so every old link and bookmark still works; a place's
// nav link opens its first page. Keys 1-7 jump to the places; "g" + a letter to any page.
// #/welcome (the first-run wizard) is not in the navigation; it sits under Settings.
const GROUPS = [
  ['overview', ['overview', 'report']],
  ['inbox', ['inbox', 'suggestions']],
  ['devices', ['devices', 'map']],
  ['family', ['people', 'family']],
  ['network', ['security', 'health', 'privacy', 'activity']],
  ['ai', ['ai']],
  ['settings', ['settings', 'system']],
];
const GROUP_OF = Object.fromEntries(GROUPS.flatMap(([g, pages]) => pages.map(p => [p, g])).concat([['welcome', 'settings']]));
const groupPages = g => (GROUPS.find(x => x[0] === g) || [g, [g]])[1];
const groupLabel = g => T(['family', 'network'].includes(g) ? 'app.navg.' + g : 'app.nav.' + g);
const PAGES = GROUPS.flatMap(x => x[1]).concat(['welcome']);
const NAV_ORDER = GROUPS.flatMap(x => x[1]);           // every page, in navigation order (the palette)
const SEC_ICON = { overview: 'i-home', devices: 'i-devices', security: 'i-shield', health: 'i-wifi', suggestions: 'i-bulb',
                   privacy: 'i-eye-off', activity: 'i-pulse', family: 'i-family', ai: 'i-spark', system: 'i-sliders',
                   inbox: 'i-inbox', settings: 'i-gear', welcome: 'i-check', people: 'i-user', map: 'i-map', report: 'i-print' };
const GROUP_ICON = { overview: 'i-home', inbox: 'i-inbox', devices: 'i-devices', family: 'i-family', network: 'i-shield', ai: 'i-spark', settings: 'i-gear' };
const NAV_PRIMARY = ['overview', 'inbox', 'devices', 'family'];   // the phone's bottom bar; the rest: "More"
const TYPE_KEYS = ['phone', 'tablet', 'computer', 'tv', 'streaming', 'console', 'camera', 'speaker', 'network',
                   'printer', 'appliance', 'vacuum', 'wearable', 'iot', 'unknown'];
const THEMES = ['auto', 'light', 'dark'];
const THEME_ICON = { auto: 'i-auto', light: 'i-sun', dark: 'i-moon' };
const LANG_KEY = 'netwarden.lang', THEME_KEY = 'netwarden.theme';
const REFRESH_MS = 30000;

const S = {
  lang: '', L: {}, meta: null, theme: 'auto',
  route: { name: 'overview' }, base: 'overview',
  data: { inv: null, alerts: null, privacy: null, vis: null, status: null, homeAct: null, upnp: null,
          health: null, sug: null, score: null, inbox: null, pres: null, notify: null, hyg: null },
  share: { period: '7', privacy: 'shareable', names: 'type', people: 'roles', format: 'html' },   // the Report page
  more: false, sugTab: 'open', sugOpen: new Set(), sugPlat: {}, probe: null, probeSaving: false,
  showExtIp: false,   // the router's public IP stays masked until the user asks
  types: [], people: [], rooms: [],
  loading: true, offline: false, refreshing: false, updated: 0,
  // Stage G: the last refresh's error (the server's localized text), the Overview datasets
  // it could not compute, "still loading after a while", the server clock minus ours (ms)
  loadErr: null, partial: [], slow: false, skew: 0, skel: false,
  dev: { mac: null, d: null, act: null, tl: null, err: null },
  look: { kind: null, arg: null, r: null, err: null },
  f: { q: '', type: '', owner: '', room: '', show: 'all', group: '', sort: 'queries', dir: -1, since: '' },
  edit: null, draft: {}, hidden: new Set(),
  chat: { messages: [], busy: false, draft: '', ctx: null, open: false, ctrl: null, back: null, follow: false },
  check: { job: null, mac: null, done: 0, total: 0 },
  pal: { open: false, q: '', sel: 0, remote: null, items: [] },
  keys: { open: false }, notify: { on: false, primed: false }, gAt: 0,
  ai: { s: null, err: null, form: {}, saving: false, testing: false, test: null, prev: { open: false }, usage: null },
  pair: { s: null, err: null, code: null, busy: false, confirmAll: false },   // Stage M (this computer only)
  fam: { st: null, wk: null, bed: null, err: null, form: null, prev: {}, saving: false },
  // Stage X: inbox triage, settings page, first-run wizard, the confirm sheet
  inbox: { sel: 0, picked: new Set(), gone: new Set(), undo: [] },
  set: { form: {}, saving: null, errs: {}, tests: {}, testing: {}, bk: null },
  // round 10 N: notification channels (Settings): list, editor draft, preview, test results, logs
  push: { d: null, err: null, ed: null, pv: null, pvErr: null, busy: {}, res: {}, log: {}, logOpen: null },
  setup: { s: null, err: null, step: null, scan: null, test: null, tz: null },
  confirm: { open: false },
  // Stage P: people cards / one person, the person form, the device picker's query, and the
  // Devices table's selection for bulk assignment
  persons: [], ppl: { id: '', r: null, err: null, det: null, detErr: null, form: null, ferr: null, saving: false, q: '' },
  bulk: new Set(), bulkTo: '-',
  returnFocus: null,
  // Stage Q: open "Why this alert?" boxes and hygiene checks, the Tuning panel's data
  whyOpen: new Set(), hygOpen: new Set(), tune: null,
  // Stage T: the network map (grouping, list/map, filters, search, viewport, nodes already
  // shown), "Since your last visit", and what flashes after a live update
  map: { by: 'person', mode: null, q: '', person: '', type: '', status: '', view: { x: 0, y: 0, k: 1 }, seen: null },
  since: { t: null, r: null, off: false }, flash: {}, flashTimer: null,
  // Round 9 U: <details data-persist> open / closed, a scroll position still to restore
  openSec: {}, wantY: null,
};

// ---------------------------------------------------------------------------------------
// i18n + Intl formatting in the selected language
// a value that already ends in "." ("59 Min.") at the end of a sentence: no "Min.."
function tpl(s, o) { return s.replace(/[{](\w+)[}](\.?)/g, (m, k, dot) => (o && k in o ? String(o[k]) + (dot && String(o[k]).endsWith('.') ? '' : dot) : m)); }
function T(key, o) { return tpl(key in S.L ? S.L[key] : key, o); }
let F = null;
// Stage G: dates and times in netwarden's zone (the one its hour charts, nights and
// bedtimes use), so a browser in another zone never shows two different "23:00"s
function homeZone() {
  const z = S.meta && S.meta.tz;
  if (!z || !z.includes('/')) return undefined;   // a bare "UTC+08:00" label: the browser's own zone
  try { new Intl.DateTimeFormat('en', { timeZone: z }); return z; } catch (e) { return undefined; }
}
function fmtInit() {
  const l = S.lang || 'en', timeZone = homeZone();
  F = { l, n: new Intl.NumberFormat(l), p: new Intl.NumberFormat(l, { style: 'percent', maximumFractionDigits: 0 }),
        dt: new Intl.DateTimeFormat(l, { dateStyle: 'medium', timeStyle: 'short', timeZone }),
        day: new Intl.DateTimeFormat(l, { month: 'numeric', day: 'numeric' }),   // server-local dates, as they are
        rt: new Intl.RelativeTimeFormat(l, { numeric: 'auto' }), units: {} };
}
const fmt = {
  num: n => F.n.format(n || 0),
  pct: x => F.p.format(x || 0),
  bytes(n) {
    const u = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte'];
    let i = 0; n = n || 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    const k = u[i];
    F.units[k] = F.units[k] || new Intl.NumberFormat(F.l, { style: 'unit', unit: k, unitDisplay: 'short',
                                                             maximumFractionDigits: i ? 1 : 0 });
    return F.units[k].format(n);
  },
  date(iso) { const t = parseTs(iso); return t ? F.dt.format(new Date(t)) : '—'; },
  day(d) { return F.day.format(new Date(d + 'T12:00:00')); },
  rel(iso) {
    const t = typeof iso === 'number' ? iso : parseTs(iso);
    if (!t) return T('status.never');
    const s = Math.round((t - nowMs()) / 1000), a = Math.abs(s);
    if (a < 45) return F.rt.format(Math.round(s / 5) * 5 || 0, 'second');
    if (a < 2700) return F.rt.format(Math.round(s / 60), 'minute');
    if (a < 79200) return F.rt.format(Math.round(s / 3600), 'hour');
    return F.rt.format(Math.round(s / 86400), 'day');
  },
  dur(sec) {
    for (const [u, n] of [['d', 86400], ['h', 3600], ['min', 60]]) if (sec >= n && sec % n === 0) return T('time.' + u, { n: sec / n });
    return T('time.s', { n: sec });
  },
};
// netwarden timestamps carry microseconds; trim to milliseconds before Date.parse.
function parseTs(iso) { if (!iso) return 0; const t = Date.parse(String(iso).replace(/(\.\d{3})\d+/, '$1')); return isNaN(t) ? 0 : t; }
// Stage G: a browser whose clock is wrong (a phone with the time set by hand, a laptop
// back from sleep) would say "in 3 hours" about something that just happened. Every
// answer's Date header tells us netwarden's clock; beyond a minute apart, "now" is
// netwarden's now (relative times, "since your last visit") and the page says so.
const CLOCK_SLACK_MS = 60 * 1000, CLOCK_NOTICE_MS = 5 * 60 * 1000;
function clockFrom(r) {
  if (DEMO) return;   // the demo's "now" is when it was built (boot), whatever the host's Date says
  const d =Date.parse((r && r.headers && r.headers.get('date')) || '');
  if (!isNaN(d)) S.skew = d - Date.now();   // 1-s resolution + latency: noise far below the slack
}
const skewMs = () => (Math.abs(S.skew) > CLOCK_SLACK_MS ? S.skew : 0);
const nowMs = () => Date.now() + skewMs();
// "about 3 hours": the size of a clock difference in words
function approxDur(ms) {
  const m = Math.round(Math.abs(ms) / 60000);
  if (m < 90) return T('time.min', { n: fmt.num(m) });
  const h = Math.round(m / 60);
  return h < 36 ? T('time.h', { n: fmt.num(h) }) : T('time.d', { n: fmt.num(Math.round(h / 24)) });
}
// The quiet line under the header: this device's clock / time zone differ from netwarden's
function noticeBar() {
  const el = $('#notice'); if (!el || !S.meta || !F) return;
  const lines = [];
  if (DEMO) { el.hidden = true; return; }   // a made-up home: its clock and zone are part of the story
  if (Math.abs(S.skew) > CLOCK_NOTICE_MS) lines.push(T('app.clock.skew', { d: approxDur(S.skew) }));
  if (typeof S.meta.tz_offset_min === 'number' && S.meta.tz_offset_min !== -new Date().getTimezoneOffset())
    lines.push(T('app.clock.tz', { tz: S.meta.tz }));
  el.hidden = !lines.length;
  morph(el, lines.length ? html`${icon('i-globe')}<span>${lines.join(' ')}</span>` : '');
}

// ---------------------------------------------------------------------------------------
// HTTP
// Stage H: under Home Assistant ingress every URL of ours lives below a prefix
// (/api/hassio_ingress/<token>); the server puts it on <html data-base> ('' normally)
const BASE = (/^(\/[\w.~-]+)*$/.test(document.documentElement.dataset.base || '') && document.documentElement.dataset.base) || '';
// an env-set setting: in the Home Assistant add-on the env IS the add-on options
function envLocked(env) { return T(S.meta.addon ? 'app.ai.addon_locked' : 'app.ai.env_locked', { env }); }
// Round 9 W: the static live demo (scripts/build_static_demo.py: plain files on GitHub Pages,
// under any sub-path). ONLY its index.html sets data-static-demo and loads static/demo.js
// (NWDemo); the real app has neither, so DEMO is false there and nothing changes. In the
// demo every GET is a file saved at build time by the real server (NWDemo.file), every
// other URL is relative to the page, nothing is ever written (postJSON refuses, see
// demoRefused) and there is no live stream.
const DEMO = document.documentElement.dataset.staticDemo === '1' && typeof window.NWDemo === 'object';
function url(path) {
  if (path.charAt(0) !== '/') return path;
  if (DEMO) return /^\/(api|report)\//.test(path) ? window.NWDemo.file(path, S.lang) : path.slice(1);
  return BASE + path;
}
function api(path) { return url(path + (path.includes('?') ? '&' : '?') + 'lang=' + enc(S.lang)); }
// Stage M: a 401 means this browser's session is gone (revoked / expired) -> pair again.
// Stage G: the page was open, so this browser HAD access: /pair says the sign-in ended.
function needPair(r) { clockFrom(r); if (r.status === 401) { location.replace(url('/pair?expired=1')); return true; } return false; }
// A failed answer without a message of its own: a 404 is "not found" (in the static demo:
// "not part of the demo" - there is no server to have an error), anything else the status.
function httpMsg(j, status) {
  if (j && typeof j.error === 'string' && j.error) return j.error;
  if (status === 404) return T(DEMO ? 'app.demo.not_found' : 'err.not_found');
  return T('app.err.http', { status });
}
async function getJSON(path) {
  const r = await fetch(api(path), { cache: 'no-store' });
  needPair(r);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(httpMsg(j, r.status)); e.status = r.status; throw e; }
  return j;
}
async function postJSON(path, body) {
  if (DEMO) throw demoRefused();   // the static demo never sends a write (its host has nowhere to send it)
  const r = await fetch(url(path), { method: 'POST', headers: { 'content-type': 'application/json' },
                                body: JSON.stringify(Object.assign({}, body, { lang: S.lang })) });
  needPair(r);
  const j = await r.json().catch(() => ({}));
  // e.body: the server's answer (a settings error names its "key", a backup error its "section")
  if (!r.ok) { const e = new Error(httpMsg(j, r.status)); e.status = r.status; e.body = j; throw e; }
  return j;
}
const isNetErr = e => e instanceof TypeError;   // fetch() rejects with TypeError when unreachable
// Stage G: what the person reads about a failure - "can't reach netwarden", the server's
// own (localized) answer, or one calm sentence. Never a JS exception text or a stack.
function uiError(msg) { const e = new Error(msg); e.ui = true; return e; }
// Round 9 W: what a write in the static demo answers - fail() turns it into a calm note
function demoRefused(key) { const e = uiError(T(key || 'app.demo.readonly')); e.demo = true; return e; }
function errText(e) {
  if (isNetErr(e)) return T('app.offline');
  return e && (e.status || e.ui) && e.message ? e.message : T('err.internal');
}

// ---------------------------------------------------------------------------------------
// Small view helpers
const icon = (id, cls) => html`<svg class="ic ${cls || ''}" aria-hidden="true"><use href="#${id}"/></svg>`;
const typeKey = t => (TYPE_KEYS.includes(t) ? t : 'unknown');
const typeIcon = t => icon('t-' + typeKey(t));
const grade = (g, big) => (g ? html`<span class="grade g-${g}${big ? ' big' : ''}">${g}</span>` : '');
const devHref = mac => '#/device/' + enc(mac);
function dname(d) {
  // label > hostname > what it announced on the LAN (mDNS / SSDP) > vendor, like the
  // server's store.device_names
  if (d && d.name) return d.name;
  if (d && d.ident && d.ident.name) return d.ident.name;
  if (d && d.vendor) return d.vendor;
  // two nameless private-address phones must not read the same: "Phone · Mom"
  const tn = d && d.type_info && d.type && d.type !== 'unknown' ? d.type_info.type_name : '';
  if (tn && d.owner) return tn + ' · ' + d.owner;
  return T(d && d.randomized ? 'app.d.private_device' : 'ui.unknown_device');
}
function devices() { return (S.data.inv && S.data.inv.devices) || []; }
function findDev(mac) { return devices().find(d => d.mac === mac) || null; }
function devName(mac, fallback) { const d = findDev(mac); return d ? dname(d) : (fallback || mac); }
// Server rows name a device by its label/hostname or, failing that, its MAC; prefer the
// page's own name so a nameless private-address phone reads the same in every card.
const rowName = (o, n) => (o.mac ? devName(o.mac, n || o.name) : (n || o.name));
// Older locale strings start with an emoji ("⚠️ ..."); next to an SVG icon it would be doubled.
// Some are sentence prefixes ending in ":" ("Looked up by:"), which a heading does not need.
const bare = s => (typeof s === 'string' ? s.replace(/^[\p{Extended_Pictographic}\u{FE0F}\u{200D}\s]+/u, '').replace(/\s*[:：]\s*$/u, '') : s);
// "summary." + " · " + "night share" without a doubled stop ("。 · ").
const joinHint = (a, b) => (b ? String(a || '').replace(/[\s.。．]+$/u, '') + ' · ' + b : a);
function card(o) {
  return html`<section class="card ${o.cls || ''}"${o.key ? html` data-key="${o.key}"` : ''}>
    ${o.title != null ? html`<div class="card-h"><h2>${o.icon ? icon(o.icon) : ''}${o.icon ? bare(o.title) : o.title}</h2><div class="card-a">${o.actions || ''}</div></div>` : ''}
    ${o.body}</section>`;
}
function empty(ic, title, text, ok) {
  return html`<div class="empty${ok ? ' ok' : ''}"><div class="ei">${icon(ic)}</div>
    <div class="et">${title}</div>${text ? html`<div>${text}</div>` : ''}</div>`;
}
// A page whose data is not here yet. Stage G: says "loading" to screen readers, "this is
// slow" after a while, and - when the server cannot be reached or answered with an error -
// becomes a calm error state with Retry instead of shimmering forever.
function skeleton(n) {
  if (S.offline || S.loadErr) return loadFailed();
  S.skel = true;
  const one = html`<section class="card" aria-hidden="true"><div class="skel h"></div><div class="skel w8"></div><div class="skel w6"></div><div class="skel"></div></section>`;
  return html`<div class="phead" aria-hidden="true"><div><div class="skel h" style="width:200px"></div></div></div>
    <p class="${S.slow ? 'load-slow' : 'sr'}" data-key="loading" role="status">${S.slow ? html`${icon('i-pulse')}<span>${T('app.load.slow')}</span>` : T('ui.loading')}</p>
    <div class="grid">${Array(n || 4).fill(one)}</div>`;
}
function loadFailed() {
  const off = S.offline;
  return card({ key: 'load-failed', cls: 'load-failed', body: html`<div class="empty" role="alert">
    <div class="ei">${icon(off ? 'i-wifi' : 'i-alert')}</div>
    <div class="et">${T(off ? 'app.load.offline_title' : 'app.load.error_title')}</div>
    <div>${off ? T('app.load.offline_text') : S.loadErr}</div>
    <p class="hint">${T('app.load.auto')}</p>
    <button type="button" class="btn" data-act="retry"${S.refreshing ? ' disabled' : ''}>${icon('i-refresh', S.refreshing ? 'spin' : '')}${S.refreshing ? T('ui.loading') : T('app.retry')}</button>
  </div>` });
}
function phead(title, sub, acts) {
  return html`<div class="phead"><div><h1>${bare(title)}</h1>${sub ? html`<div class="sub">${sub}</div>` : ''}</div>
    ${acts ? html`<div class="acts">${acts}</div>` : ''}</div>`;
}
const demoPill = () => (S.meta && S.meta.demo ? html`<span class="demo-pill">${T('ui.demo_badge')}</span>` : '');
function copyBtn(text, label) {
  return html`<button type="button" class="btn sm ghost" data-act="copy" data-text="${text}">${icon('i-copy')}${label || T('ui.copy')}</button>`;
}
function rulesBox(rules) {
  if (!rules || !rules.adguard) return html`<div class="hint">${T('ui.rules_none')}</div>`;
  const box = (title, text) => html`<div><div class="rh"><span>${title}</span>${copyBtn(text)}</div>
    <textarea class="rule" name="rule" readonly aria-label="${title}">${text}</textarea></div>`;
  return html`<div class="rules">${box(T('ui.rules_adguard'), rules.adguard)}${box(T('ui.rules_pihole'), rules.pihole)}</div>`;
}

// Heatmap: 7 days x 24 local hours (weekday names come localized from the server).
function heatmap(a) {
  if (!a || !a.grid) return '';
  const max = Math.max(1, ...a.grid.map(r => Math.max(...r)));
  const hours = []; for (let h = 0; h < 24; h++) hours.push(html`<span class="hh">${h % 6 === 0 ? h : ''}</span>`);
  const rows = a.grid.map((row, wd) => [html`<span class="hl">${a.weekdays[wd]}</span>`, row.map((n, h) => {
    const title = T('ui.heat_cell', { day: a.weekdays[wd], hour: String(h).padStart(2, '0'), n: fmt.num(n) });
    return n ? html`<span class="hc" style="--v:${(n / max).toFixed(3)}" title="${title}"></span>`
             : html`<span class="hc" title="${title}"></span>`;
  })]);
  return html`<div class="heat" role="img" aria-label="${a.summary || ''}"><span></span>${hours}${rows}</div>`;
}
function queryBars(trend) {
  if (!trend || !trend.length) return '';
  const max = Math.max(1, ...trend.map(x => x.queries));
  return html`<div class="bars">${trend.map(x => html`<div class="b" title="${T('ui.trend_bar', { day: fmt.day(x.day), queries: fmt.num(x.queries), blocked: fmt.num(x.blocked) })}">
    <div class="col"><i style="--h:${Math.round(100 * x.queries / max)}%"></i></div><span>${fmt.day(x.day)}</span></div>`)}</div>`;
}
function bwBars(trend) {
  const max = Math.max(1, ...trend.map(x => x.rx_bytes + x.tx_bytes));
  return html`<div class="bars">${trend.map(x => html`<div class="b" title="${T('bw.bar_title', { day: fmt.day(x.day), rx: fmt.bytes(x.rx_bytes), tx: fmt.bytes(x.tx_bytes) })}">
    <div class="col"><i class="tx" style="--h:${(100 * x.tx_bytes / max).toFixed(1)}%"></i><i class="rx" style="--h:${(100 * x.rx_bytes / max).toFixed(1)}%"></i></div>
    <span>${fmt.day(x.day)}</span></div>`)}</div>
    <div class="legend"><span><i></i>↓ ${T('app.download')}</span><span><i class="tx"></i>↑ ${T('app.upload')}</span></div>`;
}
function topBandwidth(limit) {
  const list = devices().filter(d => d.bandwidth).sort((a, b) => bwTotal(b) - bwTotal(a)).slice(0, limit || 5);
  if (!list.length) return html`<div class="hint">${T('bw.no_sensor')}</div>`;
  const max = Math.max(1, ...list.map(bwTotal));
  return html`<ul class="hbars">${list.map(d => html`<li class="hbar" data-key="${d.mac}">
    <div class="hrow"><a href="${devHref(d.mac)}">${dname(d)}</a><span class="muted num">↓ ${fmt.bytes(d.bandwidth.rx_bytes)} · ↑ ${fmt.bytes(d.bandwidth.tx_bytes)}</span></div>
    <div class="track"><i style="--w:${(100 * d.bandwidth.rx_bytes / max).toFixed(1)}%"></i><i class="tx" style="--w:${(100 * d.bandwidth.tx_bytes / max).toFixed(1)}%"></i></div></li>`)}</ul>`;
}
const bwTotal = d => (d.bandwidth ? d.bandwidth.rx_bytes + d.bandwidth.tx_bytes : 0);

// ---------------------------------------------------------------------------------------
// "Needs attention": every alert kind, worst first, minus what the user just muted.
function hiddenKey(mac, key) { return (mac || '') + '|' + (key || ''); }
function isHidden(mac, key) { return S.hidden.has(hiddenKey(mac, '')) || S.hidden.has(hiddenKey(mac, key)); }
function attention() {
  const a = S.data.alerts; if (!a) return [];
  const out = [];
  // plain = the same finding as one line of text (desktop notifications)
  (a.threats || []).forEach(t => out.push({ k: 't|' + t.mac + '|' + t.domain, kind: 'threat', sev: t.severity === 'malicious' ? 0 : 1,
    ic: 'i-alert', tag: T(t.severity === 'malicious' ? 'sev.malicious' : 'sev.high_risk'), mac: t.mac, ack: t.domain, what: t.domain,
    title: html`${rowName(t, t.device)} → <a href="#/domain/${enc(t.domain)}"><code>${t.domain}</code></a>`,
    text: html`<strong>${t.label}</strong> · ${t.why}`, mute: true, trust: true, why: t.explain, plain: `${rowName(t, t.device)} → ${t.domain}: ${t.label}` }));
  (a.exposure || []).forEach(x => out.push({ k: 'x|' + x.mac + '|' + x.port, kind: 'exposure', sev: x.risk === 'high' ? 1 : 2,
    ic: 'i-port', tag: T('ui.tag_exposure'), mac: x.mac, ack: x.ack, what: x.port + ' ' + x.service,
    title: html`${rowName(x)} · <span class="risk-${x.risk}">${x.port} ${x.service}</span>`,
    text: html`${x.risk_name}${x.new ? html` · <strong>${T('ui.port_new')}</strong>` : ''} — ${x.note}`, mute: true, why: x.explain,
    plain: `${rowName(x)}: ${x.port} ${x.service} (${x.risk_name})` }));
  (a.upnp || []).forEach(m => out.push({ k: 'u|' + m.protocol + '|' + m.external_port, kind: 'upnp', sev: m.risky ? 1 : 2,
    ic: 'i-port', tag: T('app.tag_upnp'), mac: m.mac, ack: m.ack, what: m.protocol + ' ' + m.external_port,
    title: html`${m.mac ? rowName(m) : m.internal_client} · <span class="risk-${m.risky ? 'high' : 'low'}">${m.protocol} ${m.external_port}</span>`,
    text: html`${m.new ? html`<strong>${T('ui.port_new')}</strong> · ` : ''}${m.text}`, mute: !!m.mac, why: m.explain,
    plain: m.text }));
  // Stage H: the internet / router was down (whole network: "Got it" mutes on the pseudo device "network")
  (a.outage || []).forEach(o => out.push({ k: 'o|' + o.id, kind: 'outage', sev: o.ongoing ? 0 : 2, ic: 'i-wifi', tag: T('app.tag_outage'),
    mac: 'network', href: '#/health', ack: o.ack, what: o.when, title: o.cause_name, text: o.text, mute: true, why: o.explain, plain: o.text }));
  (a.visibility || []).forEach(v => out.push({ k: 'v|' + v.mac + '|' + v.kind, kind: 'visibility', sev: 2, ic: 'i-eye-off',
    tag: T('ui.tag_visibility'), mac: v.mac, ack: v.ack, what: T('tl.what.visibility'), title: rowName(v), text: v.text, mute: true, why: v.explain, plain: v.text }));
  (a.unusual_hours || []).forEach(n => out.push({ k: 'n|' + n.mac, kind: 'night', sev: 2, ic: 'i-moon', tag: T('ui.tag_night'),
    mac: n.mac, ack: n.ack, what: T('tl.what.night'), title: rowName(n), text: n.text, mute: true, why: n.explain, plain: n.text }));
  // Stage F: a bedtime rule reached (one per device and night; "Got it" mutes that night)
  (a.bedtime || []).forEach(n => out.push({ k: 'z|' + n.mac + '|' + n.ack, kind: 'bedtime', sev: 2, ic: 'i-bed', tag: T('app.tag_bedtime'),
    mac: n.mac, ack: n.ack, what: T('app.tag_bedtime') + ' ' + n.night_label, title: rowName(n), text: n.text, mute: true, why: n.explain, plain: n.text }));
  (a.bandwidth_spikes || []).forEach(b => out.push({ k: 'b|' + b.mac, kind: 'spike', sev: 2, ic: 'i-download',
    tag: T('ui.tag_spike'), mac: b.mac, ack: b.ack, what: T('ui.tag_spike'), title: rowName(b), text: b.text, mute: true, why: b.explain, plain: b.text }));
  (a.new_devices || []).forEach(d => out.push({ k: 'd|' + d.mac, kind: 'new', sev: 3, ic: 'i-plus', tag: T('ui.tag_new'), mac: d.mac,
    title: rowName(d), text: [d.vendor, d.ip, fmt.rel(d.first_seen)].filter(Boolean).join(' · '), trust: true, why: d.explain,
    plain: [rowName(d), d.vendor, d.ip].filter(Boolean).join(' · ') }));
  (a.behavior_changes || []).forEach(c => out.push({ k: 'c|' + c.mac, kind: 'change', sev: 3, ic: 'i-swap', tag: T('ui.tag_changed'),
    mac: c.mac, title: rowName(c), text: T('ui.started_using') + ' ' + (c.new_services || []).join(T('list_sep')), trust: true, why: c.explain,
    plain: rowName(c) + ': ' + T('ui.started_using') + ' ' + (c.new_services || []).join(T('list_sep')) }));
  return out.filter(it => !isHidden(it.mac, it.ack || '')).sort((x, y) => x.sev - y.sev);
}
function attItem(it) {
  // a plain string for the data-name attribute (titles may be Html with links in them)
  const name = devName(it.mac, typeof it.title === 'string' ? it.title : it.mac);
  return html`<li class="att sev-${it.sev} k-${it.kind}" data-key="${it.k}">
    <span class="att-ic">${icon(it.ic)}</span>
    <div class="att-b"><div class="att-t"><span class="tag tag-${it.kind}">${it.tag}</span><span>${it.title}</span></div>
      <div class="att-x">${it.text}</div>
      ${it.why ? whyPart('a|' + it.k, it.why, typeof it.plain === 'string' ? it.plain : name, name) : ''}</div>
    <div class="att-a">
      ${it.mac ? html`<a class="btn sm ghost" href="${it.href || devHref(it.mac)}">${T('app.act.open')}</a>` : ''}
      ${it.mute ? html`<button type="button" class="btn sm ghost" data-act="mute" data-mac="${it.mac}" data-ack="${it.ack}" data-what="${it.what}">${T('ui.btn_ack')}</button>` : ''}
      ${it.trust ? html`<button type="button" class="btn sm ghost" data-act="trust" data-mac="${it.mac}" data-name="${name}">${T('ui.btn_trust')}</button>` : ''}
      ${it.why ? tuneBtn(it.why.tune, name) : ''}
    </div></li>`;
}

// ---------------------------------------------------------------------------------------
// Stage Q - "Why this alert?" (explain.py: rule, data points, threshold) under an alert row,
// in the inbox and the device drawer; "Tune" opens one sheet for every alert kind
// (normal / less sensitive / off, snooze 1 h / 1 day / 1 week / until I change it) - the
// user's own notes (POST /api/tuning), each change undoable from its toast.
function whyPart(k, why, title, name) {
  const open = S.whyOpen.has(k), id = 'why-' + k.replace(/[^\w-]/g, '_');
  return html`<button type="button" class="why-btn" data-act="why" data-k="${k}" aria-expanded="${String(open)}" aria-controls="${id}">${icon('i-chev', 'chev')}${T('app.why.show')}</button>
    ${open ? html`<div class="why-box" id="${id}">
      <p><b>${T('app.why.rule')}</b> ${why.rule}</p>
      ${(why.facts || []).length ? html`<div><b>${T('app.why.data')}</b><ul class="why-facts">${why.facts.map(f => html`<li>${f}</li>`)}</ul></div>` : ''}
      ${why.threshold ? html`<p><b>${T('app.why.threshold')}</b> ${why.threshold}</p>` : ''}
      ${why.level_text ? html`<p class="muted">${why.level_text}</p>` : ''}
      <div class="why-acts">${tuneBtn(why.tune, name, T('app.why.tune'))}
        ${why.ref ? html`<button type="button" class="btn sm ghost" data-act="why-ask" data-kind="${why.ref.kind}" data-mac="${why.ref.mac || ''}" data-key="${why.ref.key}" data-name="${name || ''}" data-title="${title}">${icon('i-spark')}${T('app.why.ask')}</button>` : ''}</div>
    </div>` : ''}`;
}
function tuneBtn(t, name, label) {
  if (!t) return '';
  return html`<button type="button" class="btn sm ghost" data-act="tune" data-kind="${t.kind}" data-mac="${t.mac || ''}" data-name="${name || ''}" aria-haspopup="dialog">${label ? html`${icon('i-sliders')}${label}` : T('app.tune.btn')}</button>`;
}
const tuneKind = k => T('app.tune.kind.' + k);
// What is set now for the sheet's kind + scope: the open drawer's device levels, or the
// Tuning panel's "all devices" rows (when loaded); unknown = normal.
function tuneCurrent(t) {
  if (t.scope === 'device') {
    const d = S.dev.d, lv = d && d.mac === t.mac && d.tuning ? d.tuning[t.kind] : null;
    return lv && lv.scope === 'device' ? lv : { level: 'normal' };
  }
  const e = ((S.tune && S.tune.entries) || []).find(x => x.kind === t.kind && x.mac === 'all' && x.source === 'tuning');
  return e ? { level: e.level, until: e.until } : { level: 'normal' };
}
// the sheet: S.confirm.tune = {kind, mac, name, scope: 'device' | 'all'}
function tuneSheet() {
  const t = S.confirm.tune, dev = !!t.mac, lv = tuneCurrent(t);
  // the level in force is the filled button ("off" for good = the "Off" button)
  const on = (v, f) => lv.level === v && (v !== 'off' || (f === 'forever') === !lv.until);
  const btn = (v, f, label) => html`<button type="button" class="btn${on(v, f) ? '' : ' ghost'}" aria-pressed="${String(on(v, f))}" data-act="tune-set" data-v="${v}" data-for="${f || ''}">${label}</button>`;
  morph($('#confirmbody'), html`<header class="sheet-h"><h2 id="confirm-title">${icon('i-sliders')}${T('app.tune.heading', { kind: tuneKind(t.kind) })}</h2></header>
    <p id="confirm-text" class="confirm-text">${T('app.tune.sheet_help')}</p>
    ${dev ? html`<div class="seg tune-scope" role="group" aria-label="${T('app.tune.title')}">
      <button type="button" data-act="tune-scope" data-v="device" aria-pressed="${String(t.scope === 'device')}">${T('app.tune.scope_device', { name: t.name || t.mac })}</button>
      <button type="button" data-act="tune-scope" data-v="all" aria-pressed="${String(t.scope === 'all')}">${T('app.tune.scope_all')}</button></div>` : ''}
    <div class="tune-row">${btn('normal', '', T('app.tune.level.normal'))}${btn('less', '', T('app.tune.level.less'))}${btn('off', 'forever', T('app.tune.level.off'))}</div>
    <h3 class="hint">${T('app.tune.snooze')}</h3>
    <div class="tune-row">${['1h', '1d', '1w'].map(f => btn('off', f, T('app.tune.for.' + f)))}</div>
    <div class="ai-acts confirm-acts"><a class="btn quiet" href="#/settings" data-act="tune-all">${T('app.tune.title')}</a>
      <button type="button" class="btn ghost" data-act="confirm-no">${T('app.cancel')}</button></div>`);
}
function openTune(kind, mac, name) {
  closePalette(true);
  S.confirm = { open: true, back: document.activeElement, tune: { kind, mac: mac || null, name, scope: mac ? 'device' : 'all' } };
  tuneSheet();
  $('#confirmsheet').hidden = false;
  const f = $('#confirmsheet .seg button, #confirmsheet .tune-row button'); if (f) f.focus();
}
const TUNE_CRITICAL = ['threat', 'exposure', 'upnp'];
async function setTune(kind, mac, level, forv, confirmed) {
  try {
    const body = { kind, mac: mac || null, level, for: forv || null };
    if (confirmed) body.confirm = true;
    const r = await postJSON('/api/tuning', body);
    const what = tuneKind(kind) + (r.mac && r.mac !== 'all' ? ' · ' + devName(r.mac, r.mac) : ' ' + T('app.tune.whole'));
    const msg = level === 'off' && r.until ? T('app.tune.snoozed', { kind: what, until: T('app.tune.until', { when: fmt.date(r.until) }) })
                                            : T('app.tune.set', { kind: what, level: T('app.tune.level.' + level) });
    toast(msg, { undo: async () => {
      try { await postJSON('/api/tuning/undo', { kind, mac: r.mac, before: r.before }); toast(T('app.toast.undone')); } catch (e) { fail(e); }
      afterTune();
    } });
  } catch (e) { fail(e); }
  afterTune();
}
function afterTune() {
  if (S.base === 'settings') loadTuning();
  if (S.route.name === 'device') loadDevice();
  refresh();
}
async function loadTuning() {
  try { S.tune = await getJSON('/api/tuning'); } catch (e) { if (!S.tune) S.tune = { err: errText(e) }; }
  render();
}
function tuneLevelName(e) {
  if (e.source === 'setting') return T('app.tune.src.setting');
  if (e.level === 'snoozed') return T('app.tune.src.snooze');
  if (e.level === 'off' && e.until) return T('app.tune.snooze');
  return T('app.tune.level.' + e.level);
}
function tuningCard() {
  const tu = S.tune, remote = S.meta && S.meta.remote;
  const body = !tu ? html`<div class="skel box"></div>` : (tu.err ? empty('i-alert', tu.err) : (!(tu.entries || []).length ? empty('i-check', T('app.tune.empty'), '', true)
    : html`<ul class="rows tune-list">${tu.entries.map(e => html`<li data-key="${e.id}">
        <span class="grow"><b>${e.kind_name}</b> · ${e.target} <span class="tag${e.level === 'less' ? ' tag-acc' : ' tag-warn'}">${tuneLevelName(e)}</span>
          <div class="muted" style="font-size:var(--fs-xs)">${e.until ? T('app.tune.until', { when: fmt.date(e.until) }) : T('app.tune.no_end')}</div></span>
        <button type="button" class="btn sm ghost" data-act="tune-restore" data-id="${e.id}" data-kind="${e.kind_name}"${e.admin && remote ? html` disabled title="${T('app.tune.local_only')}"` : ''}>${T('app.tune.restore')}</button></li>`)}</ul>`));
  return card({ key: 'tuning', cls: 'span2', icon: 'i-bell', title: T('app.tune.title'), body: html`
    <p class="muted" style="margin:0 0 var(--s2)">${T('app.tune.help')}</p>${body}` });
}
async function restoreTune(id, kindName) {
  try {
    const r = await postJSON('/api/tuning/restore', { id });
    toast(T('app.tune.restored', { kind: kindName }), { undo: async () => {
      try { await postJSON('/api/tuning/restore_undo', { undo: r.undo }); toast(T('app.toast.undone')); } catch (e) { fail(e); }
      if (r.undo && r.undo.setting) loadAI();
      afterTune();
    } });
    if (r.undo && r.undo.setting) loadAI();
  } catch (e) { fail(e); }
  afterTune();
}
// Overview / badge view of attention(): one row per device for its threat domains (a
// camera calling 3 bad hosts is ONE thing to look at). Every count on the page uses this.
function attentionGrouped() {
  const out = [], byMac = {};
  attention().forEach(it => {
    if (it.kind !== 'threat' || !it.mac) { out.push(it); return; }
    const g = byMac[it.mac];
    if (!g) { byMac[it.mac] = Object.assign({}, it, { doms: [it.what] }); out.push(byMac[it.mac]); return; }
    g.doms.push(it.what); g.sev = Math.min(g.sev, it.sev);
    const dev = devName(it.mac, it.mac);
    g.title = html`${dev} → ${g.doms.map((d, i) => html`${i ? ', ' : ''}<a href="#/domain/${enc(d)}"><code>${d}</code></a>`)}`;
    g.text = T('app.ov.threat_domains', { n: fmt.num(g.doms.length) });
    g.mute = false;            // mute each domain on its own (Security page)
  });
  return out.sort((x, y) => x.sev - y.sev);
}
function securityCount() {
  return attentionGrouped().length;
}
const OV_MAX = 8;   // attention rows on the Overview; the rest is one link away

// ---------------------------------------------------------------------------------------
// Onboarding: driven by /api/status. Shown on Overview while there is (almost) no data.
// netwarden never installs a DNS filter: the user adds these to its settings file.
const DNS_ENV_LINES = 'ADGUARD_URL=\nADGUARD_USER=\nADGUARD_PASS=';
function setupSteps() {
  const st = S.data.status; if (!st) return [];
  const src = st.sources || {}, ok = n => !!(src[n] && src[n].configured && src[n].last_ok_ts);
  const dnsConf = ['adguard', 'pihole'].some(n => src[n] && src[n].configured);
  return [
    { k: 'dns', done: ok('adguard') || ok('pihole'), part: dnsConf, cmd: DNS_ENV_LINES },
    { k: 'scan', done: ok('discovery'), cmd: 'python3 -m netwarden scan' },
    { k: 'run', done: Object.keys(st.loops || {}).length > 0, cmd: 'python3 -m netwarden run' },
    { k: 'ntopng', done: ok('ntopng'), optional: true, cmd: 'NTOPNG_URL=\nNTOPNG_USER=\nNTOPNG_PASS=' },
    { k: 'ai', done: st.ai && st.ai.mode !== 'offline', optional: true, cmd: 'ANTHROPIC_API_KEY=' },
  ].filter(s => !(st.demo && s.k === 'run'));   // the demo runs without loops by design
}
function needsOnboarding() {
  const st = S.data.status;
  return !!st && !st.demo && (!st.db.devices || !st.db.dns_events);
}
function setupCard() {
  const steps = setupSteps();
  return card({ key: 'setup', icon: 'i-check', title: T('app.ob.title'), body: html`
    <p class="muted" style="margin:0 0 var(--s2)">${T('app.ob.intro')}</p>
    <ol class="steps">${steps.map((s, i) => html`<li class="step${s.done ? ' done' : ''}" data-key="${s.k}">
      <span class="mark">${s.done ? icon('i-check') : i + 1}</span>
      <div class="sb"><div class="st">${T('app.ob.' + s.k)}
        <span class="tag ${s.done ? 'tag-ok' : (s.optional ? '' : 'tag-warn')}">${T(s.done ? 'app.ob.done' : (s.optional ? 'app.ob.optional' : 'app.ob.todo'))}</span></div>
        ${s.done ? '' : html`<div class="sx">${T('app.ob.' + s.k + '_body')}</div>
        <div class="cmd"><code>${s.cmd}</code>${copyBtn(s.cmd)}</div>`}</div></li>`)}</ol>` });
}

// ---------------------------------------------------------------------------------------
// Overview
function viewOverview() {
  const inv = S.data.inv, st = S.data.status;
  if (!inv) return skeleton(4);
  const items = attentionGrouped(), serious = items.filter(i => i.sev <= 1).length;
  const more = Math.max(0, items.length - OV_MAX);
  const idle = !items.length && needsOnboarding();   // an empty home is not "all good"
  const level = serious ? 'bad' : (items.length ? 'warn' : (idle ? 'idle' : 'ok'));
  const online = devices().filter(d => d.online).length;
  const blocked = devices().reduce((n, d) => n + (d.blocked || 0), 0);
  const src = st ? Object.values(st.sources).filter(s => s.configured) : [];
  const srcOk = src.filter(s => s.last_ok_ts && !s.stale && !(s.last_error_ts && s.last_error_ts > (s.last_ok_ts || ''))).length;
  const homeGrade = inv.privacy && inv.privacy.grade;
  const tile = (href, k, v, d) => tileA(href, k, v, d);
  // the headline counts what the Inbox (and its badge) counts, split into alerts and
  // suggestions right below it: one number for "to do" on the whole page
  const todo = S.data.inbox ? inboxCount() : items.length;
  const sugs = inboxItems().filter(it => it.kind === 'suggestion').length;
  return html`
    ${demoWelcome()}
    ${setupNeeded() ? resumeCard() : (needsOnboarding() ? setupCard() : '')}
    ${sinceBanner()}
    ${quietCards()}
    <section class="card hero ${level}" data-key="hero">
      <div class="big">${icon(level === 'ok' ? 'i-check' : (idle ? 'i-pulse' : 'i-alert'))}</div>
      <div><h1>${items.length ? T('app.ov.attention_n', { n: fmt.num(todo) }) : (idle ? T('app.ov.no_data_yet') : T('app.ov.all_good'))}</h1>
        <p>${T('ui.meta_line', { devices: fmt.num(inv.known_devices), dns: fmt.num(inv.clients_with_dns), queries: fmt.num(inv.total_queries), h: inv.window_hours })} ${demoPill()}</p>
        ${inboxCount() ? html`<p class="hero-go"><a class="btn sm" href="#/inbox">${icon('i-inbox')}${T('app.ov.open_inbox')}</a>
          <span class="muted">${T('app.ov.todo_split', { alerts: fmt.num(inboxCount() - sugs), sugs: fmt.num(sugs) })}</span></p>` : ''}</div>
    </section>
    ${homeStrip()}
    <div class="tiles">
      ${tile('#/devices', T('app.nav.devices'), fmt.num(devices().length), T('app.stat.online', { n: fmt.num(online) }))}
      ${tile('#/privacy', T('app.stat.lookups', { h: inv.window_hours }), fmt.num(inv.total_queries), T('app.stat.blocked', { pct: fmt.pct(inv.total_queries ? blocked / inv.total_queries : 0) }))}
      ${tile('#/privacy', T('app.stat.privacy'), homeGrade || '—', inv.privacy ? T('app.stat.trackers', { pct: fmt.pct(inv.privacy.tracker_share) }) : '')}
      ${S.data.inbox ? tile('#/inbox', T('app.stat.alerts'), fmt.num(todo - sugs), T('app.stat.alerts_sub'))
                     : tile('#/security', T('app.stat.alerts'), fmt.num(items.length), T('app.stat.alerts_sub'))}
      ${healthTile()}
      ${st && !['adguard', 'pihole'].some(n => st.sources[n] && st.sources[n].configured)
        // "6/6" would read as all good while the main source (DNS) is missing
        ? tileA('#/welcome', T('app.stat.sources'), srcOk + '/' + src.length, T('app.stat.no_dns'), 'lvl-warn')
        : tile('#/system', T('app.stat.sources'), st ? srcOk + '/' + src.length : '—', T('app.stat.sources_sub'))}
    </div>
    <div class="grid">
      ${scoreCard()}
      ${nextStepsCard()}
      ${mapCard()}
      ${card({ key: 'priv', icon: 'i-eye-off', title: T('app.nav.privacy'), actions: html`<a class="btn sm quiet" href="#/privacy">${T('app.ov.see_all')}</a>`,
        body: privacySummary(3) })}
      ${card({ key: 'att', cls: 'span2', icon: 'i-alert', title: T('app.ov.attention'), actions: html`<a class="btn sm quiet" href="#/inbox">${T('app.inbox.open')}</a>`,
        body: items.length ? html`<ul class="att-list">${items.slice(0, OV_MAX).map(attItem)}</ul>
                             ${more ? html`<a class="more-link" data-key="att-more" href="#/inbox">${T('app.ov.more_n', { n: fmt.num(more) })}</a>` : ''}`
                           : empty('i-check', T('app.ov.nothing'), '', true) })}
      ${card({ key: 'heat', icon: 'i-pulse', title: T('app.ov.activity'), actions: html`<a class="btn sm quiet" href="#/activity">${T('app.ov.see_all')}</a>`,
        body: S.data.homeAct ? html`${heatmap(S.data.homeAct)}<div class="hint">${S.data.homeAct.summary}</div>` : html`<div class="skel box"></div>` })}
      ${inv.has_bandwidth ? card({ key: 'bw', icon: 'i-download', title: T('app.ov.bandwidth', { h: inv.window_hours }),
        actions: html`<a class="btn sm quiet" href="#/activity">${T('app.ov.see_all')}</a>`, body: topBandwidth(5) }) : ''}
    </div>`;
}
function healthTile() {
  const h = S.data.health;
  if (!h) return tileA('#/health', T('app.h.tile'), '—', '');
  const lvl = h.verdict.level;
  return tileA('#/health', T('app.h.tile'), T('app.h.state.' + lvl), T('app.h.outages_n', { n: fmt.num(h.outages_7d) }), 'lvl-' + lvl);
}
function privacySummary(n) {
  const p = S.data.privacy;
  if (!p) return html`<div class="skel box"></div>`;
  if (!p.home || !p.home.tracker_queries) return empty('i-eye-off', T('app.priv.none'), '', true);
  return html`<div style="display:flex;gap:var(--s3);align-items:center">${grade(p.home.grade, true)}<div>${p.home.line}</div></div>
    ${(p.worst || []).length ? html`<div class="hint">${T('ui.privacy_worst')}</div><ul class="rows">${p.worst.slice(0, n).map(w => html`
      <li data-key="${w.mac}">${grade(w.grade)}<span class="grow">${w.mac ? html`<a href="${devHref(w.mac)}">${rowName(w)}</a>` : w.name}
        <div class="muted" style="font-size:var(--fs-xs)">${w.reason}</div></span></li>`)}</ul>` : ''}`;
}

// ---------------------------------------------------------------------------------------
// Devices: filter, sort, group; inline edit
const GRADE_RANK = { A: 1, B: 2, C: 3, D: 4, F: 5 };
function isRisky(d) {
  return d.threat_count > 0 || d.risky_ports > 0 || d.upnp_risky > 0 || !!d.dns_visibility || !!d.unusual_hours ||
         !!d.bandwidth_spike || (d.privacy && GRADE_RANK[d.privacy.grade] >= 4);
}
function ipKey(ip) { return (ip || '').split('.').map(x => x.padStart(3, '0')).join('.'); }
const SORTS = {
  name: d => dname(d).toLowerCase(), type: d => (d.type_info && d.type_info.type_name) || '',
  owner: d => d.owner || '￿', room: d => d.room || '￿', ip: d => ipKey((d.ips || [])[0]),
  last: d => (d.online ? '~' : '') + (d.last_active || ''), queries: d => d.queries || 0,
  privacy: d => (d.privacy ? GRADE_RANK[d.privacy.grade] : 0), traffic: bwTotal,
};
function filtered() {
  const f = S.f, q = f.q.trim();
  const list = devices().filter(d => {
    // round 9: case / accent / width / 繁简 insensitive, every word somewhere (fold())
    if (q && !matches(q, devHay(d) + ' ' + ((d.type_info && d.type_info.type_name) || '') + ' ' + (d.services || []).join(' '))) return false;
    if (f.type && typeKey(d.type) !== f.type) return false;
    if (f.owner && (d.owner || '') !== f.owner) return false;
    if (f.room && (d.room || '') !== f.room) return false;
    if (f.show === 'online' && !d.online) return false;
    if (f.show === 'risky' && !isRisky(d)) return false;
    if (f.show === 'new' && !d.new) return false;
    if (f.since && !((d.first_seen || '') > f.since)) return false;   // Stage T: "since your last visit"
    return true;
  });
  const key = SORTS[f.sort] || SORTS.queries, coll = new Intl.Collator(S.lang, { numeric: true });
  list.sort((a, b) => {
    const x = key(a), y = key(b);
    const c = typeof x === 'number' ? x - y : coll.compare(x, y);
    return c * f.dir || coll.compare(dname(a), dname(b));
  });
  return list;
}
function groups(list) {
  const g = S.f.group; if (!g) return [[null, list]];
  const m = new Map();
  list.forEach(d => {
    const k = g === 'type' ? ((d.type_info && d.type_info.type_name) || T('devtype.unknown')) : (d[g] || '');
    if (!m.has(k)) m.set(k, []); m.get(k).push(d);
  });
  const coll = new Intl.Collator(S.lang);
  return Array.from(m.entries()).sort((a, b) => (!a[0]) - (!b[0]) || coll.compare(a[0], b[0]));
}
function devCols() {
  const cols = [['name', T('ui.th_device')], ['type', T('ui.type')], ['owner', T('app.owner')], ['room', T('app.room')],
                ['ip', T('ui.th_ip')], ['last', T('app.last_seen')], ['queries', T('ui.th_queries'), 1], ['privacy', T('ui.th_privacy')]];
  if (S.data.inv && S.data.inv.has_bandwidth) cols.push(['traffic', T('bw.col'), 1]);
  return cols;
}
function badges(d) {
  const b = [];
  if (d.threat_count) b.push(html`<span class="tag tag-threat">${icon('i-alert')}${fmt.num(d.threat_count)}</span>`);
  if (d.risky_ports) b.push(html`<span class="tag tag-exposure">${T('ui.tag_exposure')}</span>`);
  if (d.upnp_risky) b.push(html`<span class="tag tag-upnp">${T('app.tag_upnp')}</span>`);
  if (d.dns_visibility) b.push(html`<span class="tag tag-visibility">${T('ui.tag_visibility')}</span>`);
  if (d.unusual_hours) b.push(html`<span class="tag tag-night">${T('ui.tag_night')}</span>`);
  if (d.bandwidth_spike) b.push(html`<span class="tag tag-spike">${T('ui.tag_spike')}</span>`);
  if (d.new) b.push(html`<span class="tag tag-new">${T('app.badge.new')}</span>`);
  if (d.trusted) b.push(html`<span class="tag tag-ok">${T('app.badge.trusted')}</span>`);
  return b.length ? html`<span class="badges">${b}</span>` : '';
}
function lastSeen(d) {
  return d.online ? html`<span class="nowrap"><span class="dot on"></span> ${T('app.online')}</span>`
                  : html`<time datetime="${d.last_active || ''}" title="${fmt.date(d.last_active)}">${fmt.rel(d.last_active)}</time>`;
}
function devRow(d, cols) {
  if (S.edit === d.mac) return editRow(d, cols.length + 1);
  const ti = d.type_info || {}, sub = [d.vendor !== dname(d) ? d.vendor : '', (d.services || []).slice(0, 3).join(T('list_sep'))].filter(Boolean).join(' · ');
  const bw = S.data.inv.has_bandwidth;
  return html`<tr data-key="${d.mac || dname(d)}" class="${d.online ? '' : 'off'}${d.mac && isFlash('dev:' + d.mac) ? ' flash' : ''}">
    <td class="c-dev"><div class="dev-pick">${d.mac ? html`<input type="checkbox" class="pick" name="pick" data-bulk="${d.mac}"${S.bulk.has(d.mac) ? ' checked' : ''} aria-label="${T('app.bulk.pick', { name: dname(d) })}">` : ''}<a class="dev" href="${d.mac ? devHref(d.mac) : '#/devices'}"><span class="ticon">${typeIcon(d.type)}<i class="dot${d.online ? ' on' : ''}"></i></span>
      <span class="dn"><span class="n">${dname(d)}</span><span class="sub">${sub}</span></span></a></div>${badges(d)}</td>
    <td class="c-type" data-label="${T('ui.type')}" title="${ti.reason ? T('ui.type_reason', { reason: ti.reason, pct: Math.round((ti.confidence || 0) * 100) }) : ''}">${ti.type_name || '—'}${ti.source !== 'user' && (ti.confidence || 0) < 0.5 ? html` <span class="faint">?</span>` : ''}</td>
    <td class="c-clip" data-label="${T('app.owner')}" title="${d.owner || ''}">${d.owner || html`<span class="faint">—</span>`}</td>
    <td class="c-clip" data-label="${T('app.room')}" title="${d.room || ''}">${d.room || html`<span class="faint">—</span>`}</td>
    <td class="mono" data-label="${T('ui.th_ip')}">${(d.ips || []).join(', ') || '—'}</td>
    <td class="c-seen" data-label="${T('app.last_seen')}">${lastSeen(d)}</td>
    <td class="num" data-label="${T('ui.th_queries')}">${fmt.num(d.queries)}${d.blocked ? html` <span class="faint" title="${T('ui.th_blocked')}">(${fmt.num(d.blocked)})</span>` : ''}</td>
    <td data-label="${T('ui.th_privacy')}">${d.privacy ? grade(d.privacy.grade) : html`<span class="faint">—</span>`}</td>
    ${bw ? html`<td class="num" data-label="${T('bw.col')}">${d.bandwidth ? html`↓ ${fmt.bytes(d.bandwidth.rx_bytes)}<br>↑ ${fmt.bytes(d.bandwidth.tx_bytes)}` : '—'}</td>` : ''}
    <td class="c-act">${d.mac ? html`<button type="button" class="btn icon sm quiet" data-act="edit" data-mac="${d.mac}" aria-label="${T('app.edit_device', { name: dname(d) })}" title="${T('app.edit')}">${icon('i-edit')}</button>` : ''}</td>
  </tr>`;
}
// The user's editable notes about a device, as currently shown (draft wins while editing).
function current(d, field) {
  if (field === 'label') return d.label || '';
  if (field === 'type') return d.type_info && d.type_info.source === 'user' ? d.type : '';
  return d[field] || '';
}
function draftVal(d, field) { const dr = S.draft[d.mac]; return dr && field in dr ? dr[field] : current(d, field); }
function typeOptions(d, val) {
  const auto = d.type_info && d.type_info.source !== 'user' ? d.type_info.type_name : '';
  return html`<option value=""${val ? '' : ' selected'}>${T('ui.type_auto')}${auto ? ' (' + auto + ')' : ''}</option>
    ${S.types.map(t => html`<option value="${t.key}"${t.key === val ? ' selected' : ''}>${t.name}</option>`)}`;
}
function editFields(d, cls, drawer) {
  const auto = d.hostname || d.vendor || T('ui.unknown_device');
  // the drawer picks a person (or Shared) from the list; the table row keeps the free-text owner
  // "Add a person…" is a button, not a list entry: arrowing through the list (which fires
  // change on every step in some browsers) must never leave the page (WCAG 3.2.2)
  const owner = drawer ? html`<div class="field owner-pick ${cls || ''}"><label class="field"><span>${T('app.ppl.person')}</span><select name="person" data-assign data-mac="${d.mac}">${personOptions(assignValue(d), false)}</select></label>
      ${S.meta.remote ? '' : html`<button type="button" class="btn sm ghost" data-act="add-person-for" data-mac="${d.mac}">${T('app.ppl.add_new_opt')}</button>`}</div>`
    : html`<label class="field ${cls || ''}"><span>${T('app.owner')}</span><input type="text" name="owner" maxlength="64" list="peopleList" data-draft="owner" data-mac="${d.mac}" value="${draftVal(d, 'owner')}" placeholder="${T('ui.owner')}"></label>`;
  return html`
    <label class="field ${cls || ''}"><span>${T('app.name')}</span><input type="text" name="label" maxlength="64" data-draft="label" data-mac="${d.mac}" value="${draftVal(d, 'label')}" placeholder="${auto}"></label>
    <label class="field ${cls || ''}"><span>${T('ui.type')}</span><select name="type" data-draft="type" data-mac="${d.mac}">${typeOptions(d, draftVal(d, 'type'))}</select></label>
    ${owner}
    <label class="field ${cls || ''}"><span>${T('app.room')}</span><input type="text" name="room" maxlength="64" list="roomList" data-draft="room" data-mac="${d.mac}" value="${draftVal(d, 'room')}" placeholder="${T('ui.room')}"></label>`;
}
function editRow(d, span) {
  return html`<tr data-key="${d.mac}" class="editing"><td colspan="${span}">
    <form class="rowedit" data-mac="${d.mac}" aria-label="${T('app.edit_device', { name: dname(d) })}">${editFields(d)}
      <div class="btns"><button type="submit" class="btn sm">${T('ui.save')}</button>
        <button type="button" class="btn sm ghost" data-act="edit-cancel" data-mac="${d.mac}">${T('ui.cancel')}</button></div>
    </form></td></tr>`;
}
function filterSelect(name, label, opts) {
  return html`<select name="${name}" data-filter="${name}" aria-label="${label}">${opts.map(([v, l]) => html`<option value="${v}"${S.f[name] === v ? ' selected' : ''}>${l}</option>`)}</select>`;
}
function viewDevices() {
  const inv = S.data.inv;
  if (!inv) return skeleton(1);
  const all = devices(), list = filtered(), cols = devCols(), f = S.f;
  // a remembered / linked owner or room that no device has (any more) stays a visible choice,
  // so the menu never says "All rooms" while the list is filtered by it
  const keepCur = (vals, v) => (v && !vals.includes(v) ? vals.concat([v]) : vals);
  const owners = keepCur(Array.from(new Set(all.map(d => d.owner).filter(Boolean))).sort(), f.owner);
  const rooms = keepCur(Array.from(new Set(all.map(d => d.room).filter(Boolean))).sort(), f.room);
  const shows = [['all', T('app.f.all')], ['online', T('app.online')], ['risky', T('app.badge.risky')], ['new', T('app.badge.new')]];
  const active = f.q || f.type || f.owner || f.room || f.show !== 'all' || f.since;
  const head = html`<tr>${cols.map(([k, label, num]) => html`<th class="${num ? 'num' : ''}" aria-sort="${f.sort === k ? (f.dir > 0 ? 'ascending' : 'descending') : 'none'}">
      <button type="button" class="sortbtn" data-act="sort" data-col="${k}">${label}<span class="arr" aria-hidden="true">${f.sort === k && f.dir > 0 ? '▲' : '▼'}</span></button></th>`)}
      <th class="c-act"><span class="sr">${T('app.edit')}</span></th></tr>`;
  const body = groups(list).map(([g, rows]) => html`<tbody data-key="g:${g == null ? '-' : g}">
      ${g != null ? html`<tr class="grp"><th colspan="${cols.length + 1}">${g || T('app.group.unset')} <span class="muted">· ${fmt.num(rows.length)}</span></th></tr>` : ''}
      ${rows.map(d => devRow(d, cols))}</tbody>`);
  return html`${phead(T('app.nav.devices'), T('ui.meta_line', { devices: fmt.num(inv.known_devices), dns: fmt.num(inv.clients_with_dns), queries: fmt.num(inv.total_queries), h: inv.window_hours }),
      html`${demoPill()}<a class="btn sm ghost" href="${api('/api/export/devices.csv')}" download>${T('ui.export_csv')}</a>`)}
    <section class="card" data-key="devlist">
      <div class="toolbar" role="search">
        <label class="q"><span class="sr">${T('app.dev.search')}</span>${icon('i-search')}<input type="search" name="q" data-filter="q" value="${f.q}" placeholder="${T('app.dev.search')}" autocomplete="off" maxlength="100"></label>
        ${filterSelect('type', T('ui.type'), [['', T('app.f.all_types')]].concat(S.types.map(t => [t.key, t.name])))}
        ${filterSelect('owner', T('app.owner'), [['', T('app.f.all_owners')]].concat(owners.map(o => [o, o])))}
        ${filterSelect('room', T('app.room'), [['', T('app.f.all_rooms')]].concat(rooms.map(o => [o, o])))}
        ${filterSelect('group', T('app.group'), [['', T('app.group.none')], ['owner', T('app.group.owner')], ['room', T('app.group.room')], ['type', T('app.group.type')]])}
      </div>
      <div class="toolbar">
        <div class="chips" role="group" aria-label="${T('app.f.show')}">${shows.map(([v, l]) => html`<button type="button" class="chip" data-act="show" data-v="${v}" aria-pressed="${String(f.show === v)}">${l}</button>`)}
          ${f.since ? html`<button type="button" class="chip" data-act="since-clear" aria-pressed="true">${T('app.since.filter')}${icon('i-x')}</button>` : ''}</div>
        ${active ? html`<button type="button" class="btn sm quiet" data-act="clear-filters">${icon('i-x')}${T('app.f.clear')}</button>` : ''}
        ${list.length ? html`<button type="button" class="btn sm quiet" data-act="bulk-all">${T('app.bulk.all')}</button>` : ''}
        <span class="meta" aria-live="polite">${T('app.dev.count', { n: fmt.num(list.length), total: fmt.num(all.length) })}</span>
      </div>
      ${bulkBar()}
      ${all.length ? (list.length ? html`<div class="tbl-wrap"><table class="tbl cards"><thead>${head}</thead>${body}</table></div>`
                                  : empty('i-search', T('app.dev.empty'), html`<button type="button" class="btn sm ghost" data-act="clear-filters">${T('app.f.clear')}</button>`))
                   : empty('i-devices', T('app.dev.empty_title'), html`${T('app.ob.scan_body')}
                       <div class="cmd"><code>python3 -m netwarden scan</code>${copyBtn('python3 -m netwarden scan')}</div>`)}
    </section>`;
}

// ---------------------------------------------------------------------------------------
// Security
function viewSecurity() {
  const a = S.data.alerts, v = S.data.vis;
  if (!a) return skeleton(3);
  const threats = (a.threats || []).filter(t => !isHidden(t.mac, t.domain));
  const items = attention(), exp = items.filter(i => i.kind === 'exposure'), vis = items.filter(i => i.kind === 'visibility');
  const changes = items.filter(i => i.kind === 'new' || i.kind === 'change');
  const demo = S.meta && S.meta.demo, running = S.check.job && !S.check.mac;
  const remote = S.meta && S.meta.remote;   // port checks: from the computer running netwarden only
  const checkBtn = html`<button type="button" class="btn sm" data-act="check-all"${demo || remote || S.check.job ? ' disabled' : ''} title="${demo ? T('exposure.demo_refused') : (remote ? T('app.pair.admin_only') : '')}">${icon('i-port')}${T('app.sec.check_all')}</button>`;
  return html`${phead(T('app.nav.security'), T('ui.threats_hint'))}
    <div class="stack">
    ${card({ key: 'threats', icon: 'i-alert', title: T('ui.threats_title'), body: threats.length ? html`<ul class="att-list">${threats.map(t => attItem({
        k: 't|' + t.mac + '|' + t.domain, kind: 'threat', sev: t.severity === 'malicious' ? 0 : 1, ic: 'i-alert',
        tag: T(t.severity === 'malicious' ? 'sev.malicious' : 'sev.high_risk'), mac: t.mac, ack: t.domain, what: t.domain,
        title: html`${rowName(t, t.device)} → <a href="#/domain/${enc(t.domain)}"><code>${t.domain}</code></a> · ${T('app.times', { n: fmt.num(t.count) })}`,
        text: html`<strong>${t.label}</strong> · ${t.why}`, mute: true, trust: true, why: t.explain,
        plain: `${rowName(t, t.device)} → ${t.domain}: ${t.label}` }))}</ul>` : empty('i-shield', T('app.sec.none'), '', true) })}
    ${hygieneCard()}
    ${card({ key: 'exposure', icon: 'i-port', title: T('ui.ports_title'), actions: checkBtn, body: html`
      ${running ? progress(S.check.done, S.check.total) : ''}
      ${exp.length ? html`<ul class="att-list">${exp.map(attItem)}</ul>` : empty('i-port', T('app.sec.exposure_none'), '', true)}
      <div class="hint">${demo ? T('exposure.demo_refused') : T('app.sec.check_note')}</div>` })}
    ${upnpCard()}
    ${card({ key: 'vis', icon: 'i-eye-off', title: T('ui.visibility_title'), body: html`
      ${v && v.summary ? html`<p style="margin-top:0">${v.summary}</p>` : ''}
      ${vis.length ? html`<ul class="att-list">${vis.map(attItem)}</ul>` : ''}
      ${v && (v.items || []).filter(i => i.kind === 'never').length ? html`<ul class="plain">${v.items.filter(i => i.kind === 'never').map(i => html`<li>${i.mac ? html`<a href="${devHref(i.mac)}">${i.text}</a>` : i.text}</li>`)}</ul>` : ''}
      ${v && (v.suggestions || []).length ? html`<h3 class="hint">${T('ui.suggestions')}</h3><ul class="plain">${v.suggestions.map(s => html`<li>${s}</li>`)}</ul>${v.rules && v.rules.adguard ? rulesBox(v.rules) : ''}` : ''}
      <div class="hint">${T('ui.visibility_hint')}</div>` })}
    ${card({ key: 'changes', icon: 'i-swap', title: T('ui.changes_title', { h: (a.window || {}).recent_hours }), body: html`
      ${changes.length ? html`<ul class="att-list">${changes.map(attItem)}</ul>` : empty('i-check', T('app.sec.no_changes'), '', true)}
      <div class="hint">${T('ui.changes_hint')}</div>` })}
    </div>`;
}
// Stage Q - router & network hygiene (GET /api/hygiene): read-only checks from data
// netwarden already has, each pass / warn / fail / unknown with the manual steps.
const HYG_TAG = { pass: 'tag-ok', warn: 'tag-warn', fail: 'tag-bad', unknown: '' };
const HYG_ICON = { pass: 'i-check', warn: 'i-alert', fail: 'i-alert', unknown: 'i-search' };
function hygieneCard() {
  const h = S.data.hyg;
  if (!h) return card({ key: 'hyg', icon: 'i-shield', title: T('app.hyg.title'), body: html`<div class="skel box"></div>` });
  const row = c => {
    const open = S.hygOpen.has(c.key), more = c.steps.length || c.suggestions.length;
    return html`<li class="sug hyg hyg-${c.status}" data-key="h-${c.key}">
      ${more ? html`<button type="button" class="sug-h" data-act="hyg-toggle" data-k="${c.key}" aria-expanded="${String(open)}">
        <span class="sug-ic">${icon(HYG_ICON[c.status])}</span>
        <span class="sug-t"><span class="sug-title">${c.title}</span><span class="sug-meta"><span class="tag ${HYG_TAG[c.status]}">${c.status_name}</span></span><span class="hyg-x">${c.text}</span></span>
        ${icon('i-chev', 'chev')}</button>`
      : html`<div class="sug-h"><span class="sug-ic">${icon(HYG_ICON[c.status])}</span>
        <span class="sug-t"><span class="sug-title">${c.title}</span><span class="sug-meta"><span class="tag ${HYG_TAG[c.status]}">${c.status_name}</span></span><span class="hyg-x">${c.text}</span></span></div>`}
      ${open && more ? html`<div class="sug-b">
        ${c.steps.length ? html`<h3 class="hint">${T('app.hyg.steps')}</h3><ol class="sug-steps">${c.steps.map(s => html`<li>${s}</li>`)}</ol>` : ''}
        ${c.suggestions.length ? html`<div class="chips">${c.suggestions.map(sid => html`<a class="chip" href="#/suggestions" data-act="sug-goto" data-id="${sid}">${icon('i-bulb')}${T('app.hyg.sug')}</a>`)}</div>` : ''}</div>` : ''}</li>`;
  };
  return card({ key: 'hyg', icon: 'i-shield', title: T('app.hyg.title'),
    actions: html`<span class="tag ${HYG_TAG[h.status]}">${h.summary}</span>`, body: html`
    <ul class="sug-list hyg-list">${h.checks.map(row)}</ul>
    <div class="hint">${h.note}</div>` });
}
async function loadHyg() {
  const lang = S.lang;
  try { const r = await getJSON('/api/hygiene'); if (lang === S.lang) { localData('hyg', r); render(); } } catch (e) { /* the card keeps its last state */ }
}
// "Ports your devices opened on the router" (UPnP). Read-only: netwarden never changes
// the router; the how-to says where the user can switch UPnP off.
function upnpCard() {
  const u = S.data.upnp;
  if (!u) return card({ key: 'upnp', icon: 'i-port', title: T('app.upnp.title'), body: html`<div class="skel box"></div>` });
  const maps = u.mappings || [];
  const row = m => {
    const muted = m.muted || isHidden(m.mac, m.ack);
    return html`<li data-key="${m.protocol}${m.external_port}">
      <strong class="risk-${m.risky ? 'high' : 'low'} nowrap">${m.protocol} ${m.external_port}</strong>
      <span class="grow">${m.mac ? html`<a href="${devHref(m.mac)}">${rowName(m)}</a>` : html`<span class="mono">${m.internal_client}</span>`}
        → <span class="mono">${m.internal_client}:${m.internal_port}</span>
        ${m.risky ? html` <span class="tag tag-bad">${m.risk_name}</span>` : ''}${m.new ? html` <span class="tag tag-new">${T('ui.port_new')}</span>` : ''}${muted ? html` <span class="tag">${T('app.upnp.muted')}</span>` : ''}
        <div class="muted" style="font-size:var(--fs-xs)">${m.text}</div></span>
      ${m.mac && !muted && (m.risky || m.new) ? html`<button type="button" class="btn sm ghost" data-act="mute" data-mac="${m.mac}" data-ack="${m.ack}" data-what="${m.protocol + ' ' + m.external_port}">${T('ui.btn_ack')}</button>` : ''}</li>`;
  };
  const ext = u.external_ip ? html`<div class="extip"><span class="muted">${T('app.upnp.external_ip')}</span>
      <span class="mono">${S.showExtIp ? u.external_ip : u.external_ip_masked}</span>
      <button type="button" class="btn sm quiet" data-act="extip" aria-pressed="${String(S.showExtIp)}">${T(S.showExtIp ? 'app.upnp.hide' : 'app.upnp.show')}</button></div>` : '';
  const gw = u.gateway && u.gateway.name ? html`<div class="muted" style="font-size:var(--fs-sm)">${T('app.upnp.gateway', { name: u.gateway.name, when: fmt.rel(u.checked_ts) })}</div>` : '';
  return card({ key: 'upnp', icon: 'i-port', title: T('app.upnp.title'), body: html`
    <p style="margin-top:0">${u.summary}</p>
    ${maps.length ? html`<ul class="rows">${maps.map(row)}</ul>` : ''}
    ${u.available ? html`${gw}${ext}` : ''}
    ${maps.length ? html`<div class="hint">${u.howto}</div>` : ''}` });
}
function progress(done, total) {
  const w = total ? Math.round(100 * done / total) : 5;
  return html`<div role="progressbar" aria-valuemin="0" aria-valuemax="${total || 0}" aria-valuenow="${done || 0}">
    <div class="muted" style="font-size:var(--fs-sm)">${T('ui.check_running', { done: fmt.num(done || 0), total: fmt.num(total || 0) })}</div>
    <div class="progress"><i style="--w:${w}%"></i></div></div>`;
}

// ---------------------------------------------------------------------------------------
// Privacy
function viewPrivacy() {
  const p = S.data.privacy;
  if (!p) return skeleton(3);
  if (!p.home || !p.home.tracker_queries) return html`${phead(T('app.nav.privacy'))}${card({ body: empty('i-eye-off', T('app.priv.none'), T('ui.privacy_hint'), true) })}`;
  const cats = Object.entries(p.home.by_category_names || {}).sort((a, b) => b[1] - a[1]);
  const cmax = Math.max(1, ...cats.map(c => c[1]));
  const devs = (p.devices || []).filter(d => d.tracker_queries).sort((a, b) => GRADE_RANK[b.grade] - GRADE_RANK[a.grade] || b.tracker_share - a.tracker_share);
  return html`${phead(T('ui.privacy_title', { h: p.window_hours }), T('ui.privacy_hint'))}
    <div class="grid">
      ${card({ key: 'home', icon: 'i-home', title: T('app.priv.home'), body: html`
        <div style="display:flex;gap:var(--s4);align-items:center">${grade(p.home.grade, true)}<div>${p.home.line}</div></div>
        <h3 class="hint">${T('app.priv.by_category')}</h3>
        <ul class="hbars">${cats.map(([name, n]) => html`<li class="hbar" data-key="${name}"><div class="hrow"><span>${name}</span><span class="muted num">${fmt.num(n)}</span></div>
          <div class="track"><i style="--w:${(100 * n / cmax).toFixed(1)}%"></i></div></li>`)}</ul>` })}
      ${card({ key: 'worst', icon: 'i-alert', title: T('ui.privacy_worst'), body: privacySummaryList(p.worst) })}
      ${card({ key: 'devs', cls: 'span2', icon: 'i-devices', title: T('app.priv.devices'), body: html`<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>${T('ui.th_device')}</th><th>${T('ui.th_privacy')}</th><th class="num">${T('app.priv.tracker_share')}</th><th class="num">${T('app.priv.blocked_share')}</th><th>${T('app.priv.why')}</th></tr></thead>
        <tbody>${devs.map(d => html`<tr data-key="${d.mac || d.name}"><td>${d.mac ? html`<a href="${devHref(d.mac)}">${rowName(d)}</a>` : d.name}</td><td>${grade(d.grade)}</td>
          <td class="num">${fmt.pct(d.tracker_share)}</td><td class="num">${fmt.pct(d.blocked_share)}</td><td class="muted">${d.reason}</td></tr>`)}</tbody></table></div>` })}
      ${card({ key: 'rules', cls: 'span2', icon: 'i-copy', title: T('ui.rules_title'), body: rulesBox(p.rules) })}
    </div>`;
}
function privacySummaryList(list) {
  if (!(list || []).length) return empty('i-check', T('ui.rules_none'), '', true);
  return html`<ul class="rows">${list.map(w => html`<li data-key="${w.mac}">${grade(w.grade)}<span class="grow">${w.mac ? html`<a href="${devHref(w.mac)}">${rowName(w)}</a>` : w.name}
    <div class="muted" style="font-size:var(--fs-xs)">${w.reason}</div></span></li>`)}</ul>`;
}

// ---------------------------------------------------------------------------------------
// Activity (home heatmap, unusual hours, people, per-device hours, bandwidth)
// A person's devices by the page's names; under the owner's own name "Phone · Mom" is just "Phone".
function ownerDevices(p) {
  const mine = devices().filter(d => d.owner === p.owner);
  if (!mine.length) return p.devices || [];
  return mine.map(d => (d.name || d.vendor ? dname(d) : (d.type_info && d.type_info.type_name) || dname(d)));
}
function viewActivity() {
  const inv = S.data.inv, a = S.data.homeAct;
  if (!inv) return skeleton(3);
  const night = attention().filter(i => i.kind === 'night');
  const people = inv.people || [];
  const active = devices().filter(d => d.active_hours || d.night_share_7d).sort((x, y) => (y.night_share_7d || 0) - (x.night_share_7d || 0));
  return html`${phead(T('app.nav.activity'), a ? T('app.act.tz', { tz: a.tz }) : '')}
    <div class="grid">
      ${card({ key: 'heat', cls: 'span2', icon: 'i-pulse', title: T('app.ov.activity'), body: a ? html`${heatmap(a)}
        <div class="hint">${joinHint(a.summary, a.night_share_text)}</div>` : html`<div class="skel box"></div>` })}
      ${card({ key: 'night', icon: 'i-moon', title: T('ui.tag_night'), body: night.length ? html`<ul class="att-list">${night.map(attItem)}</ul>` : empty('i-moon', T('app.act.no_unusual'), '', true) })}
      ${card({ key: 'people', icon: 'i-user', title: T('app.act.people'), body: people.length ? html`<ul class="rows">${people.map(p => html`<li data-key="${p.owner}">
          <span class="grow"><strong>${p.owner}</strong><div class="muted" style="font-size:var(--fs-xs)">${ownerDevices(p).join(T('list_sep'))}</div>
          <div class="muted" style="font-size:var(--fs-xs)">${T('app.act.person_line', { queries: fmt.num(p.queries), night: fmt.pct(p.queries_7d ? p.night_queries_7d / p.queries_7d : 0) })}</div></span>
          <button type="button" class="btn sm ghost" data-act="filter-owner" data-v="${p.owner}">${T('app.act.show_devices')}</button></li>`)}</ul>`
        : empty('i-user', T('app.act.no_people'), T('app.act.no_people_hint')) })}
      ${card({ key: 'hours', cls: 'span2', icon: 'i-devices', title: T('app.act.devices'), body: active.length ? html`<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>${T('ui.th_device')}</th><th>${T('app.owner')}</th><th>${T('app.act.usual')}</th><th class="num">${T('app.act.night')}</th></tr></thead>
        <tbody>${active.map(d => html`<tr data-key="${d.mac}"><td><a href="${devHref(d.mac)}">${dname(d)}</a> ${d.unusual_hours ? html`<span class="tag tag-night">${T('ui.tag_night')}</span>` : ''}</td>
          <td>${d.owner || html`<span class="faint">—</span>`}</td><td>${d.active_hours || '—'}</td><td class="num">${d.night_share_7d != null ? fmt.pct(d.night_share_7d) : '—'}</td></tr>`)}</tbody></table></div>`
        : empty('i-pulse', T('activity.no_data')) })}
      ${card({ key: 'bw', cls: 'span2', icon: 'i-download', title: T('app.ov.bandwidth', { h: inv.window_hours }), body: topBandwidth(10) })}
    </div>`;
}

// ---------------------------------------------------------------------------------------
// Family (Stage F): estimated screen time per person, "this week vs last week", bedtime
// rules (notify only). Everything here is an ESTIMATE for a family conversation, so the
// kind note always leads. Loaded only while the page is open (/api/screentime, /api/weekly,
// /api/bedtime); a rule's preview is POSTed (debounced) while it is edited.
function famDur(min) {
  min = Math.max(0, Math.round(min || 0));
  if (!min) return T('fam.dur_m', { m: 0 });
  const h = Math.floor(min / 60), m = min % 60;
  return h ? (m ? T('fam.dur_hm', { h, m }) : T('fam.dur_h', { h })) : T('fam.dur_m', { m });
}
let WD = null;   // weekday names Mon..Sun in the page's language (Mon=0, like the server)
function weekdays() {
  if (!WD || WD.l !== F.l) {
    const f = new Intl.DateTimeFormat(F.l, { weekday: 'short' });
    WD = { l: F.l, names: [0, 1, 2, 3, 4, 5, 6].map(i => f.format(new Date(2024, 0, 1 + i, 12))) };   // 2024-01-01 = Monday
  }
  return WD.names;
}
const BED_PRESETS = { school: [6, 0, 1, 2, 3], weekend: [4, 5], every: [0, 1, 2, 3, 4, 5, 6] };
const sameDays = (a, b) => a.length === b.length && a.every(x => b.includes(x));
function minuteBars(byDay, label) {
  if (!byDay || !byDay.length) return '';
  const max = Math.max(30, ...byDay.map(x => x.minutes));
  const wd = weekdays();
  return html`<div class="bars fam-bars" role="img" aria-label="${label || ''}">${byDay.map(x => {
    const day = wd[(new Date(x.date + 'T12:00:00').getDay() + 6) % 7];
    return html`<div class="b" title="${T('app.fam.bar', { day: day + ' ' + fmt.day(x.date), dur: famDur(x.minutes) })}">
      <div class="col"><i style="--h:${(100 * x.minutes / max).toFixed(1)}%"></i></div><span>${day}</span></div>`;
  })}</div>`;
}
function svcChips(list) {
  return (list || []).length ? html`<div class="svc-chips">${list.map(s => html`<a class="chip" href="#/service/${enc(s.id)}">${s.name} <span class="muted num">${famDur(s.minutes)}</span></a>`)}</div>` : '';
}
function weekMetric(label, m, fmtv, pts) {
  if (!m) return '';
  const delta = pts != null ? m.pts : m.pct;
  const dir = delta == null || delta === 0 ? '' : (delta > 0 ? 'up' : 'down');
  const d = delta == null ? '' : (pts != null ? T('app.fam.pts', { n: (delta > 0 ? '+' : '') + delta }) : (delta > 0 ? '+' : '') + fmt.num(delta) + '%');
  return html`<div class="tile wk"><div class="k">${label}</div><div class="v">${keepUnit(fmtv(m.this))}</div>
    <div class="d">${d ? html`<span class="delta ${dir}">${d}</span> · ` : ''}${T('app.fam.last_week', { v: keepUnit(fmtv(m.last)) })}</div></div>`;
}
function weekCard() {
  const w = S.fam.wk;
  if (!w) return card({ key: 'week', cls: 'span2', icon: 'i-swap', title: T('app.fam.week_title'), body: html`<div class="skel box"></div>` });
  const h = w.home || {};
  return card({ key: 'week', cls: 'span2', icon: 'i-swap', title: T('app.fam.week_title'), body: html`
    ${w.has_history ? html`<div class="tiles fam-tiles">
      ${weekMetric(T('app.fam.m.minutes'), h.minutes, famDur)}
      ${weekMetric(T('app.fam.m.queries'), h.queries, fmt.num)}
      ${weekMetric(T('app.fam.m.trackers'), h.trackers, fmt.num)}
      ${weekMetric(T('app.fam.m.blocked'), h.blocked_share, fmt.pct, true)}</div>` : ''}
    <ul class="fam-hl">${(w.highlights || []).map((t, i) => html`<li data-key="${i}">${t}</li>`)}</ul>` });
}
function memberCard(m) {
  const who = m.owner || T('rep.shared');
  const devs = (m.devices || []).map(d => devName(d.mac, d.name));
  return html`<li class="member" data-key="${m.owner || ''}">
    <div class="mh"><div><strong>${who}</strong><div class="muted fam-small">${devs.join(T('list_sep'))}</div></div>
      <div class="mt"><div class="v num">${famDur(m.minutes)}</div><div class="muted fam-small">${T('app.fam.per_day', { dur: famDur(m.avg_minutes) })} · ${T('app.fam.today', { dur: famDur(m.today_minutes) })}</div></div></div>
    ${minuteBars(m.by_day, who + ': ' + famDur(m.minutes))}
    ${svcChips(m.top_services)}</li>`;
}
function bedRuleLine(r) {
  const who = r.owner ? T('app.bed.person_all', { name: r.owner }) : devName(r.mac, r.target_name);
  return T('app.bed.line', { who, days: r.days_text, from: r.start, to: r.end, min: fmt.num(r.min_minutes) });
}
function bedEditor() {
  const f = S.fam.form, b = S.fam.bed || {}, p = S.fam.prev || {};
  const wd = weekdays(), people = b.people || [];
  const devs = devices().filter(d => d.mac && !d.is_self).sort((x, y) => dname(x).localeCompare(dname(y)));
  const overnight = f.end && f.start && f.end <= f.start;
  return html`<form class="bed-form" data-bed-form aria-labelledby="bed-form-h" data-key="form-${f.id || 'new'}">
    <h3 class="hint" id="bed-form-h" style="margin-top:0">${f.id ? T('app.edit') : T('app.bed.add')}</h3>
    <div class="edit-grid">
      <label class="field"><span>${T('app.bed.name')}</span><input type="text" name="bed-name" maxlength="40" data-bed="name" value="${f.name}" placeholder="${T('app.bed.name_ph')}"></label>
      <label class="field"><span>${T('app.bed.for')}</span><select name="bed-target" data-bed="target" required>
        <option value=""${f.target ? '' : ' selected'}>${T('app.bed.choose')}</option>
        ${people.length ? html`<optgroup label="${T('app.bed.people')}">${people.map(n => html`<option value="${'owner:' + n}"${f.target === 'owner:' + n ? ' selected' : ''}>${T('app.bed.person_all', { name: n })}</option>`)}</optgroup>` : ''}
        <optgroup label="${T('app.bed.devices')}">${devs.map(d => html`<option value="${'mac:' + d.mac}"${f.target === 'mac:' + d.mac ? ' selected' : ''}>${dname(d)}${d.owner && !dname(d).includes(d.owner) ? ' · ' + d.owner : ''}</option>`)}</optgroup>
      </select></label>
    </div>
    <div class="field"><span id="bed-nights">${T('app.bed.nights')}</span>
      <div class="chips" role="group" aria-labelledby="bed-nights">${wd.map((n, i) => html`<button type="button" class="chip" data-act="bed-day" data-v="${i}" aria-pressed="${String(f.days.includes(i))}">${n}</button>`)}</div>
      <div class="chips bed-presets">${Object.keys(BED_PRESETS).map(k => html`<button type="button" class="btn sm quiet" data-act="bed-preset" data-v="${k}" aria-pressed="${String(sameDays(f.days, BED_PRESETS[k]))}">${T('bed.days.' + k)}</button>`)}</div></div>
    <div class="edit-grid bed-times">
      <label class="field"><span>${T('app.bed.from')}</span><input type="time" name="bed-start" data-bed="start" value="${f.start}" required></label>
      <label class="field"><span>${T('app.bed.until')}${overnight ? html` <em class="faint">(${T('app.bed.next_morning')})</em>` : ''}</span><input type="time" name="bed-end" data-bed="end" value="${f.end}" required></label>
      <label class="field"><span>${T('app.bed.after')}</span><input type="number" name="bed-min" min="1" max="240" step="1" inputmode="numeric" data-bed="min" value="${String(f.min_minutes)}" required></label>
    </div>
    <div class="bed-prev" aria-live="polite" data-key="prev"><strong>${T('app.bed.preview')}:</strong>
      ${p.err ? html`<span class="hint warn">${p.err}</span>`
        : (!p.r ? html`<span class="muted">${f.target ? T('app.bed.checking') : T('err.bad_rule_target')}</span>` : html`<span>${p.r.summary}</span>
        ${(p.r.hits || []).length ? html`<ul class="rows">${p.r.hits.slice(0, 7).map(h => html`<li data-key="${h.mac + h.night}"><span class="tag tag-bedtime">${h.night_label}</span><span class="grow">${h.text}</span></li>`)}</ul>` : ''}`)}</div>
    <div class="form-acts"><button type="submit" class="btn"${S.fam.saving ? ' disabled' : ''}>${T('ui.save')}</button>
      <button type="button" class="btn ghost" data-act="bed-cancel">${T('ui.cancel')}</button></div>
  </form>`;
}
function bedCard() {
  const b = S.fam.bed;
  const add = html`<button type="button" class="btn sm" data-act="bed-new"${S.fam.form || (b && b.rules.length >= b.max_rules) ? ' disabled' : ''}>${icon('i-plus')}${T('app.bed.add')}</button>`;
  if (!b) return card({ key: 'bed', cls: 'span2', icon: 'i-bed', title: T('app.bed.title'), body: html`<div class="skel box"></div>` });
  const editing = S.fam.form && S.fam.form.id;
  return card({ key: 'bed', cls: 'span2', icon: 'i-bed', title: T('app.bed.title'), actions: add, body: html`
    ${S.fam.form && !editing ? bedEditor() : ''}
    ${b.rules.length ? html`<ul class="rows bed-rules">${b.rules.map(r => editing === r.id ? html`<li data-key="r${r.id}">${bedEditor()}</li>` : html`<li data-key="r${r.id}">
      <span class="grow"><strong>${r.name || r.target_name}</strong> <span class="tag${r.enabled ? ' tag-ok' : ''}">${T(r.enabled ? 'app.bed.active' : 'app.bed.paused')}</span>
        <div class="muted fam-small">${bedRuleLine(r)}</div>
        <div class="fam-small">${r.summary}</div></span>
      <span class="bed-acts">
        <button type="button" class="switch" role="switch" aria-checked="${String(r.enabled)}" aria-label="${T('app.bed.active') + ': ' + (r.name || r.target_name)}" data-act="bed-toggle" data-id="${r.id}"><i></i></button>
        <button type="button" class="btn icon sm quiet" data-act="bed-edit" data-id="${r.id}" aria-label="${T('app.edit') + ': ' + (r.name || r.target_name)}" title="${T('app.edit')}">${icon('i-edit')}</button>
        <button type="button" class="btn icon sm quiet" data-act="bed-delete" data-id="${r.id}" aria-label="${T('app.bed.delete') + ': ' + (r.name || r.target_name)}" title="${T('app.bed.delete')}">${icon('i-x')}</button></span></li>`)}</ul>`
      : (S.fam.form ? '' : empty('i-bed', T('app.bed.none'), T('app.bed.none_hint')))}
    <div class="hint">${b.note}</div>` });
}
function viewFamily() {
  const st = S.fam.st;
  if (!st && !S.fam.err) return skeleton(3);
  if (!st) return html`${phead(T('app.nav.family'))}${empty('i-alert', S.fam.err)}`;
  const members = st.members || [];
  const report = html`<a class="btn sm ghost" href="${api('/report/weekly')}" target="_blank" rel="noopener">${icon('i-print')}${T('app.fam.print')}</a>`;
  return html`${phead(T('app.nav.family'), T('app.fam.sub', { tz: st.tz }), report)}
    <div class="fam-note" data-key="note" role="note">${icon('i-user')}<span>${st.note}</span></div>
    <div class="grid">
      ${weekCard()}
      ${card({ key: 'members', cls: 'span2', icon: 'i-family', title: T('app.fam.members_title'), body: members.length
        ? html`<ul class="members">${members.map(memberCard)}</ul>`
        : empty('i-family', T('fam.none'), T('app.fam.empty_hint')) })}
      ${st.minutes ? card({ key: 'cats', icon: 'i-box', title: T('app.fam.categories'), body: html`<ul class="hbars">${st.categories.filter(c => c.minutes).map(c => html`<li class="hbar" data-key="${c.key}">
          <div class="hrow"><span>${c.name}</span><span class="muted num">${famDur(c.minutes)}</span></div>
          <div class="track"><i style="--w:${(100 * c.minutes / Math.max(1, st.minutes)).toFixed(1)}%"></i></div></li>`)}</ul>` }) : ''}
      ${st.minutes ? card({ key: 'apps', icon: 'i-globe', title: T('app.fam.top_apps'), body: html`${svcChips(st.services)}
          ${minuteBars(st.by_day, T('rep.by_day'))}` }) : ''}
      ${bedCard()}
      ${card({ key: 'how', cls: 'span2', icon: 'i-search', title: T('app.fam.how'), body: html`<p class="muted" style="margin:0">${st.method}</p>` })}
    </div>`;
}
async function loadFamily() {
  const lang = S.lang;
  const [st, wk, bed] = await Promise.allSettled([getJSON('/api/screentime?days=7'), getJSON('/api/weekly'), getJSON('/api/bedtime')]);
  if (lang !== S.lang) return;
  if (st.status === 'fulfilled') { S.fam.st = st.value; S.fam.err = null; }
  else if (!S.fam.st) S.fam.err = errText(st.reason);
  if (wk.status === 'fulfilled') S.fam.wk = wk.value;
  if (bed.status === 'fulfilled') S.fam.bed = bed.value;
  if (S.base !== 'family') return;
  if (S.fam.wantForm && S.fam.bed && !S.fam.form) { S.fam.wantForm = false; openBedForm(null); } else render();
}
// The rule editor: a draft in S.fam.form; every change re-asks the server for the preview
function bedRuleBody(f) {
  const [kind, ...rest] = (f.target || '').split(':'), val = rest.join(':');
  return { id: f.id || null, name: f.name, owner: kind === 'owner' ? val : null, mac: kind === 'mac' ? val : null,
           days: f.days, start: f.start, end: f.end, min_minutes: parseInt(f.min_minutes, 10), enabled: f.enabled };
}
function openBedForm(r) {
  const people = (S.fam.bed && S.fam.bed.people) || [];
  S.fam.form = r ? { id: r.id, name: r.name || '', target: r.owner ? 'owner:' + r.owner : 'mac:' + r.mac, days: r.days.slice(), start: r.start,
                     end: r.end, min_minutes: r.min_minutes, enabled: r.enabled }
                 : { id: null, name: '', target: people.length === 1 ? 'owner:' + people[0] : '', days: BED_PRESETS.school.slice(), start: '22:00',
                     end: '07:00', min_minutes: 15, enabled: true };
  S.fam.prev = {}; render(); bedPreview(true);
  const i = document.querySelector('form[data-bed-form] [data-bed="name"]'); if (i) i.focus();
}
function closeBedForm() {
  const id = S.fam.form && S.fam.form.id;
  S.fam.form = null; S.fam.prev = {}; clearTimeout(bedTimer); render();
  const b = document.querySelector(id ? `[data-act="bed-edit"][data-id="${id}"]` : '[data-act="bed-new"]'); if (b) b.focus();
}
let bedTimer = null;
function bedPreview(now) {
  clearTimeout(bedTimer);
  const f = S.fam.form; if (!f) return;
  if (!f.target) { S.fam.prev = {}; render(); return; }
  bedTimer = setTimeout(async () => {
    const body = bedRuleBody(f), key = JSON.stringify(body);
    S.fam.prev.key = key;
    try {
      const r = await postJSON('/api/bedtime/preview', { rule: body });
      if (S.fam.prev.key === key) S.fam.prev = { key, r, err: null };
    } catch (e) { if (S.fam.prev.key === key) S.fam.prev = { key, r: null, err: errText(e) }; }
    if (S.fam.form) render();
  }, now ? 0 : 350);
}
async function saveBedRule(rule, opts) {
  opts = opts || {};
  S.fam.saving = true; render();
  try {
    const j = await postJSON('/api/bedtime', { rule, restore: !!opts.restore });
    S.fam.bed = j; S.fam.saving = false;
    if (!opts.quiet) { S.fam.form = null; S.fam.prev = {}; }
    render();
    if (opts.toast !== false) toast(opts.undone ? T('app.toast.undone') : T('app.bed.saved'), opts.undo ? { undo: () => opts.undo(j.id) } : {});
    refresh();
    return j.id;
  } catch (e) { S.fam.saving = false; render(); fail(e); return null; }
}
async function deleteBedRule(id, undoing) {
  try {
    const j = await postJSON('/api/bedtime/delete', { id });
    S.fam.bed = j; if (S.fam.form && S.fam.form.id === id) { S.fam.form = null; S.fam.prev = {}; }
    render();
    const gone = j.deleted;
    toast(undoing ? T('app.toast.undone') : T('app.bed.deleted'), undoing ? {} : { undo: () => saveBedRule(gone, { restore: true, undone: true }) });
    refresh();
  } catch (e) { fail(e); }
}
function submitBedForm() {
  const f = S.fam.form; if (!f || S.fam.saving) return;
  const body = bedRuleBody(f);
  const before = f.id && S.fam.bed ? S.fam.bed.rules.find(r => r.id === f.id) : null;
  const prev = before ? { id: before.id, name: before.name, owner: before.owner, mac: before.mac, days: before.days, start: before.start,
                          end: before.end, min_minutes: before.min_minutes, enabled: before.enabled } : null;
  saveBedRule(body, { undo: id => (prev ? saveBedRule(prev, { restore: true, undone: true }) : deleteBedRule(id, true)) });
}
function toggleBedRule(id, undoing) {
  const r = S.fam.bed && S.fam.bed.rules.find(x => x.id === id); if (!r) return;
  const body = { id: r.id, name: r.name, owner: r.owner, mac: r.mac, days: r.days, start: r.start, end: r.end, min_minutes: r.min_minutes, enabled: !r.enabled };
  r.enabled = !r.enabled; render();
  saveBedRule(body, { quiet: true, toast: false }).then(rid => {
    if (rid == null) return;
    if (undoing) toast(T('app.toast.undone'));
    else toast(T(body.enabled ? 'app.bed.on_toast' : 'app.bed.off_toast', { name: r.name }), { undo: () => toggleBedRule(id, true) });
  });
}

// ---------------------------------------------------------------------------------------
// Stage P - People and presence ("who's home"). A person: name, avatar (an emoji or their
// initials), color, child flag, note; each device belongs to one person, to "Shared" or to
// nobody. Presence is opt-in per person (a privacy note + an explicit confirm, on this
// computer only). Everything here is the user's own notes, with Undo; #/people/<id> = one person.
const PPL_COLORS = ['blue', 'green', 'amber', 'rose', 'violet', 'teal', 'orange', 'slate'];
const PRES_TAG = { home: 'tag-ok', probably_home: 'tag-acc', away: '', unknown: 'tag-warn' };
function persons() { return (S.ppl.r && S.ppl.r.people) || S.persons || []; }
function personById(id) { return persons().find(p => p.id === id) || null; }
function personOf(d) { return d && d.owner ? persons().find(p => p.name === d.owner) || null : null; }
function initialsOf(name) {
  const w = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!w.length) return '?';
  // people.initials(): "Person 03" -> "P3" (a number whole, not "P0")
  const second = w.length < 2 ? '' : (/^[0-9]+$/.test(w[1]) ? String(parseInt(w[1], 10)).slice(0, 2) : Array.from(w[1])[0]);
  return (Array.from(w[0])[0] + second).toUpperCase();
}
function avatar(p, big) {
  const c = PPL_COLORS.includes(p.color) ? p.color : 'slate', txt = p.avatar || p.initials || initialsOf(p.name);
  // "P12": three characters still fit inside the circle
  return html`<span class="av c-${c}${big ? ' big' : ''}${!p.avatar && Array.from(txt).length > 2 ? ' long' : ''}" aria-hidden="true">${txt}</span>`;
}
const presTag = p => (p.state && p.state !== 'off' ? html`<span class="tag ${PRES_TAG[p.state] || ''}">${p.state_name}</span>` : '');
// The person a device belongs to, as a select value: '' nobody, 'shared', 'p:<id>'
function assignValue(d) {
  const p = personOf(d), inv = d && findDev(d.mac);
  return p ? 'p:' + p.id : (d && (d.shared || (inv && inv.shared)) ? 'shared' : '');
}
function personOptions(val, choose) {
  return html`${choose ? html`<option value="-"${val === '-' ? ' selected' : ''}>${T('app.bed.choose')}</option>` : ''}
    <option value=""${val === '' ? ' selected' : ''}>${T('app.ppl.nobody')}</option>
    <option value="shared"${val === 'shared' ? ' selected' : ''}>${T('app.ppl.shared')}</option>
    ${persons().map(p => html`<option value="${'p:' + p.id}"${val === 'p:' + p.id ? ' selected' : ''}>${p.name}</option>`)}`;
}
// Stage U: "Add a person…" in a device's owner list: the person form on People, and the
// device goes to the new person once it is saved (one undoable step each)
function addPersonFor(mac) {
  S.ppl.assignAfter = { mac, name: devName(mac) };
  S.ppl.wantForm = true;
  go('#/people');
}
function openPersonFormSoon() {
  if (!S.ppl.wantForm || S.base !== 'people' || S.ppl.id) return;
  S.ppl.wantForm = false;
  openPersonForm(null);
}
function homeStrip() {
  const pr = S.data.pres;
  if (!pr || !pr.enabled) return '';
  const on = pr.people.filter(p => p.state !== 'off'), links = (pr.links || []).length;
  return html`<section class="card home-strip" data-key="home-now" aria-labelledby="hs-t">
    <h2 id="hs-t">${icon('i-home')}${T('app.pres.home_now')}</h2>
    <ul class="hs-list">${on.map(p => html`<li data-key="${p.id}"><a href="#/people/${p.id}" title="${p.reason}">${avatar(p)}
      <span class="hs-n">${p.name}</span>${presTag(p)}</a></li>`)}</ul>
    ${links ? html`<a class="btn sm quiet" href="#/people">${icon('i-swap')}${T('app.pres.links_n', { n: fmt.num(links) })}</a>` : ''}</section>`;
}
function linkCard(pid) {
  const pr = S.data.pres, links = ((pr && pr.links) || []).filter(l => !pid || l.person_id === pid);
  if (!links.length) return '';
  return card({ key: 'links', cls: 'span2', icon: 'i-swap', title: T('app.pres.links_title'), body: html`<ul class="rows">${links.map(l => html`<li class="link-row" data-key="${l.mac}">
      <span class="grow">${l.text}<div class="muted fam-small"><a href="${devHref(l.mac)}">${rowName(l, l.name)}</a> · ${l.name === l.from_name ? T('app.d.randomized') : T('app.pres.link_was', { name: rowName({ mac: l.from_mac }, l.from_name) })}</div></span>
      <span class="bed-acts"><button type="button" class="btn sm wrap" data-act="ppl-link" data-mac="${l.mac}" data-id="${l.person_id}">${T('app.pres.link_yes', { person: l.person })}</button>
        <button type="button" class="btn sm ghost" data-act="ppl-link-no" data-mac="${l.mac}" data-id="${l.person_id}">${T('app.pres.link_no')}</button></span></li>`)}</ul>
    <div class="hint">${pr.private_mac}</div>` });
}
function personCard(p) {
  return html`<li class="member pcard" data-key="${p.id}">
    <div class="mh"><a class="pc-who" href="#/people/${p.id}">${avatar(p)}<span><strong>${p.name}</strong>${p.child ? html` <span class="tag">${T('app.ppl.child_tag')}</span>` : ''}
        <span class="muted fam-small pc-devs">${p.devices.length ? p.devices.map(d => devName(d.mac, d.name)).join(T('list_sep')) : T('app.ppl.no_devices')}</span></span></a>
      ${presTag(p)}</div>
    <dl class="pc-facts">
      <dt>${T('app.ppl.today')}</dt><dd>${famDur(p.today_minutes)} <span class="muted">· ${T('app.ppl.week', { dur: famDur(p.week_minutes) })}</span></dd>
      <dt>${T('app.bed.title')}</dt><dd>${p.bedtime.text}</dd>
      ${p.top_services.length ? html`<dt>${T('app.fam.top_apps')}</dt><dd>${p.top_services.join(T('list_sep'))}</dd>` : ''}
      ${p.state !== 'off' && p.state_reason ? html`<dt>${T('app.pres.title')}</dt><dd>${p.state_reason}</dd>` : ''}
      <dt>${T('app.d.alerts')}</dt><dd>${p.alert_count ? html`<span class="tag tag-warn">${fmt.num(p.alert_count)}</span> ${p.alerts[0].title}` : html`<span class="muted">${T('app.ppl.no_alerts')}</span>`}</dd>
    </dl>
    <a class="btn sm ghost wrap" href="#/people/${p.id}">${T('app.ppl.open', { name: p.name })}</a></li>`;
}
function devList(list, act, label) {
  return html`<ul class="rows">${list.map(d => html`<li data-key="${d.mac}">${typeIcon(d.type)}<span class="grow"><a href="${devHref(d.mac)}">${devName(d.mac, d.name)}</a>
      <div class="muted fam-small">${[d.type_name, d.randomized ? T('app.d.randomized') : ''].filter(Boolean).join(' · ')}</div></span>
      ${act ? html`<button type="button" class="btn sm quiet" data-act="${act}" data-mac="${d.mac}" aria-label="${label + ': ' + devName(d.mac, d.name)}">${label}</button>` : ''}</li>`)}</ul>`;
}
function viewPeople() {
  if (S.ppl.id) return viewPerson();
  const r = S.ppl.r;
  if (!r && !S.ppl.err) return skeleton(3);
  if (!r) return html`${phead(T('app.nav.people'))}${empty('i-alert', S.ppl.err)}`;
  const adding = S.ppl.form && !S.ppl.form.id;
  const add = html`<button type="button" class="btn sm" data-act="ppl-new"${adding ? ' disabled' : ''}>${icon('i-plus')}${T('app.ppl.add')}</button>`;
  return html`${phead(T('app.nav.people'), T('app.ppl.sub'), add)}
    ${adding ? card({ key: 'pform', body: personForm() }) : ''}
    ${homeStrip()}
    <div class="grid">
      ${linkCard()}
      ${r.people.length ? html`<ul class="members span2" data-key="cards">${r.people.map(personCard)}</ul>`
        : card({ key: 'none', cls: 'span2', body: empty('i-user', T('app.ppl.none'), T('app.ppl.none_hint')) })}
      ${card({ key: 'shared', icon: 'i-home', title: T('app.ppl.shared'), body: html`${r.shared.devices.length ? devList(r.shared.devices) : ''}
        <div class="hint">${T('app.ppl.shared_hint')}</div>` })}
      ${card({ key: 'unassigned', icon: 'i-devices', title: T('app.ppl.unassigned_title'), body: html`<p style="margin-top:0">${T('app.ppl.unassigned', { n: fmt.num(r.unassigned) })}</p>
        <a class="btn sm ghost" href="#/devices">${T('app.ppl.assign_in_devices')}</a>` })}
    </div>`;
}
function personForm() {
  const f = S.ppl.form;
  return html`<form class="person-form" data-person-form data-key="pform-${f.id || 'new'}" aria-labelledby="pf-h">
    <h3 class="hint" id="pf-h" style="margin-top:0">${f.id ? T('app.ppl.edit') : T('app.ppl.add')}</h3>
    ${!f.id && S.ppl.assignAfter ? html`<p class="muted" style="margin:0 0 var(--s2)">${T('app.ppl.assign_after', { device: S.ppl.assignAfter.name })}</p>` : ''}
    <div class="edit-grid">
      <label class="field"><span>${T('app.name')}</span><input type="text" name="pf-name" maxlength="40" data-pf="name" value="${f.name}" required autocomplete="off"></label>
      <label class="field"><span>${T('app.ppl.avatar')}</span><input type="text" name="pf-avatar" maxlength="8" data-pf="avatar" value="${f.avatar}" placeholder="${T('app.ppl.avatar_ph')}" autocomplete="off"></label>
      <label class="field"><span>${T('app.ppl.note')}</span><input type="text" name="pf-note" maxlength="200" data-pf="note" value="${f.note}" autocomplete="off"></label>
    </div>
    <div class="field"><span id="pf-colors">${T('app.ppl.color')}</span>
      <div class="chips" role="group" aria-labelledby="pf-colors">${PPL_COLORS.map(c => html`<button type="button" class="swatch c-${c}" data-act="pf-color" data-v="${c}" aria-pressed="${String(f.color === c)}" aria-label="${T('app.ppl.color_' + c)}" title="${T('app.ppl.color_' + c)}"></button>`)}</div></div>
    <div class="pf-row"><button type="button" class="switch" role="switch" aria-checked="${String(!!f.child)}" aria-labelledby="pf-child" data-act="pf-child"><i></i></button>
      <span id="pf-child">${T('app.ppl.child')}</span></div>
    ${S.ppl.ferr ? html`<div class="hint bad" role="alert">${S.ppl.ferr}</div>` : ''}
    <div class="form-acts"><button type="submit" class="btn"${S.ppl.saving ? ' disabled' : ''}>${T('ui.save')}</button>
      <button type="button" class="btn ghost" data-act="pf-cancel">${T('ui.cancel')}</button></div></form>`;
}
function presTimeline(p) {
  const wd = weekdays();
  return html`<ul class="ptl">${(p.days || []).map(d => {
    const day = wd[(new Date(d.date + 'T12:00:00').getDay() + 6) % 7] + ' ' + fmt.day(d.date);
    return html`<li data-key="${d.date}"><span class="ptl-d">${day}</span>
      <span class="ptl-t" role="img" aria-label="${T('app.pres.day_home', { day, dur: famDur(d.home_minutes) })}">${d.segments.map((s, i) => html`<i data-key="${i}" style="left:${(100 * s[0] / d.minutes).toFixed(2)}%;width:${Math.max(0.5, 100 * (s[1] - s[0]) / d.minutes).toFixed(2)}%"></i>`)}</span>
      <span class="ptl-v muted num">${famDur(d.home_minutes)}</span></li>`;
  })}</ul>
  <div class="ptl-axis" aria-hidden="true"><span>0</span><span>6</span><span>12</span><span>18</span><span>24</span></div>`;
}
function presEvents(p) {
  const ev = (p.events || []).slice(0, 24);
  return ev.length ? html`<ul class="tl pres-ev">${ev.map(e => html`<li class="k-${e.kind}" data-key="${e.kind + e.ts}">
      <time class="when" datetime="${e.ts}">${fmt.date(e.ts)}</time>${T('app.pres.ev_' + e.kind, { name: p.name })}${e.late ? html` <span class="tag tag-night">${T('app.pres.late')}</span>` : ''}</li>`)}</ul>`
    : empty('i-swap', T('app.pres.no_events'));
}
function presCard(p) {
  const pi = p.presence_info || { state: 'off' }, local = !S.meta.remote, pr = S.data.pres || {};
  if (!p.presence) {
    return card({ key: 'pres', cls: 'span2', icon: 'i-home', title: T('app.pres.title'), body: html`
      <p style="margin-top:0">${T('app.pres.off_text', { name: p.name })}</p>
      <div class="hint">${pr.privacy || ''}</div>
      <div class="form-acts">${local ? html`<button type="button" class="btn" data-act="pres-on" data-id="${p.id}">${T('app.pres.enable')}</button>`
        : html`<span class="hint">${T('app.pair.admin_only')}</span>`}</div>` });
  }
  const mine = p.devices, custom = !p.default_devices, chosen = new Set(p.presence_macs || []);
  return card({ key: 'pres', cls: 'span2', icon: 'i-home', title: T('app.pres.title'), actions: presTag(pi), body: html`
    <p class="pres-why" style="margin-top:0"><strong>${pi.state_name || ''}</strong> · ${pi.reason || ''}</p>
    ${pi.last_seen ? html`<div class="muted fam-small">${T('app.pres.last_seen', { when: fmt.date(pi.last_seen), ago: fmt.rel(pi.last_seen) })}</div>` : ''}
    <h3 class="hint">${T('app.pres.timeline')}</h3>${presTimeline(pi)}
    <h3 class="hint">${T('app.pres.events')}</h3>${presEvents(Object.assign({ name: p.name }, pi))}
    <h3 class="hint">${T('app.pres.devices')}</h3>
    <div class="pf-row"><button type="button" class="switch" role="switch" aria-checked="${String(!custom)}" aria-labelledby="pres-def" data-act="pres-default" data-id="${p.id}"${local ? '' : ' disabled'}><i></i></button>
      <span id="pres-def">${T('app.pres.default_devices')}</span></div>
    ${custom ? html`<div class="chips" role="group" aria-label="${T('app.pres.devices')}">${mine.map(d => html`<button type="button" class="chip" data-act="pres-dev" data-id="${p.id}" data-mac="${d.mac}" aria-pressed="${String(chosen.has(d.mac))}"${local ? '' : ' disabled'}>${devName(d.mac, d.name)}</button>`)}</div>` : ''}
    <div class="muted fam-small">${T('app.pres.using', { list: (pi.devices || []).map(d => devName(d.mac, d.name)).join(T('list_sep')) || '—' })}</div>
    ${(pi.devices || []).some(d => d.randomized) ? html`<div class="hint">${pr.private_mac || ''}</div>` : ''}
    <h3 class="hint">${T('app.pres.notify')}</h3>
    <div class="pf-row"><button type="button" class="switch" role="switch" aria-checked="${String(!!p.notify_arrive)}" aria-labelledby="pres-na" data-act="pres-notify" data-k="notify_arrive" data-id="${p.id}"><i></i></button><span id="pres-na">${T('app.pres.notify_arrive')}</span></div>
    <div class="pf-row"><button type="button" class="switch" role="switch" aria-checked="${String(!!p.notify_leave)}" aria-labelledby="pres-nl" data-act="pres-notify" data-k="notify_leave" data-id="${p.id}"><i></i></button><span id="pres-nl">${T('app.pres.notify_leave')}</span></div>
    <div class="hint">${T('app.pres.notify_hint')}</div>
    <div class="form-acts"><button type="button" class="btn ghost" data-act="pres-off" data-id="${p.id}">${T('app.pres.disable')}</button>
      <button type="button" class="btn ghost danger" data-act="pres-forget" data-id="${p.id}">${T('app.pres.forget')}</button></div>
    <div class="hint">${T('app.pres.how', { grace: fmt.num(pr.grace_minutes || 20), check: fmt.num(pr.check_minutes || 5) })}</div>` });
}
function devPicker(p) {
  const q = S.ppl.q.trim();
  const list = devices().filter(d => d.mac && !d.is_self && d.owner !== p.name)
    .filter(d => !q || matches(q, devHay(d)))
    .sort((x, y) => (!!x.owner - !!y.owner) || dname(x).localeCompare(dname(y))).slice(0, q ? 12 : 6);
  return html`<label class="q pick-q"><span class="sr">${T('app.ppl.pick_search')}</span>${icon('i-search')}<input type="search" name="ppl-q" data-ppl-q value="${S.ppl.q}" placeholder="${T('app.ppl.pick_search')}" autocomplete="off" maxlength="100"></label>
    ${list.length ? html`<ul class="rows">${list.map(d => html`<li data-key="${d.mac}">${typeIcon(d.type)}<span class="grow">${dname(d)}
        <div class="muted fam-small">${d.owner ? T('app.ppl.now_of', { name: d.owner }) : (d.shared ? T('app.ppl.shared') : T('app.ppl.nobody'))}</div></span>
        <button type="button" class="btn sm ghost" data-act="ppl-add-dev" data-mac="${d.mac}" data-id="${p.id}" aria-label="${T('app.ppl.add_to', { name: dname(d), person: p.name })}">${icon('i-plus')}${T('app.ppl.add_dev')}</button></li>`)}</ul>`
      : html`<div class="muted fam-small">${T('app.dev.empty')}</div>`}`;
}
function viewPerson() {
  const id = +S.ppl.id, p = S.ppl.det && S.ppl.det.id === id ? S.ppl.det : null;
  const back = html`<a class="btn sm quiet" href="#/people">${T('app.ppl.all')}</a>`;
  if (!p) return S.ppl.detErr ? html`${phead(T('app.nav.people'), '', back)}${empty('i-user', S.ppl.detErr)}` : skeleton(3);
  const editing = S.ppl.form && S.ppl.form.id === id;
  return html`<div class="phead"><div class="ph-person">${avatar(p, true)}<div><h1>${p.name}</h1>
      <div class="sub">${[p.child ? T('app.ppl.child_tag') : '', p.note].filter(Boolean).join(' · ')}</div></div></div>
    <div class="acts">${back}<button type="button" class="btn sm ghost" data-act="ppl-edit" data-id="${p.id}"${editing ? ' disabled' : ''}>${icon('i-edit')}${T('app.edit')}</button>
      <button type="button" class="btn sm ghost danger" data-act="ppl-delete" data-id="${p.id}">${icon('i-x')}${T('app.ppl.delete')}</button></div></div>
    ${editing ? card({ key: 'pform', body: personForm() }) : ''}
    <div class="grid">
      ${linkCard(p.id)}
      ${card({ key: 'devs', icon: 'i-devices', title: T('app.ppl.devices_title'), body: html`${p.devices.length ? devList(p.devices, 'ppl-rm-dev', T('app.ppl.remove'))
          : empty('i-devices', T('app.ppl.no_devices'))}
        <h3 class="hint">${T('app.ppl.add_devices')}</h3>${devPicker(p)}` })}
      ${card({ key: 'screen', icon: 'i-family', title: T('app.d.screen'), actions: html`<a class="btn sm quiet" href="#/family">${T('app.d.screen_more')}</a>`, body: html`
        <p style="margin:0"><strong>${T('app.fam.today', { dur: famDur(p.today_minutes) })}</strong></p>
        <div class="muted fam-small">${T('app.ppl.week', { dur: famDur(p.week_minutes) })} · ${T('app.fam.per_day', { dur: famDur(p.screen.avg_minutes) })}</div>
        ${minuteBars(p.screen.by_day, p.name + ': ' + famDur(p.week_minutes))}${svcChips(p.screen.top_services)}
        <div class="hint">${p.screen.note}</div>` })}
      ${card({ key: 'bed', icon: 'i-bed', title: T('app.bed.title'), actions: html`<a class="btn sm quiet" href="#/family">${T('app.ov.see_all')}</a>`, body: p.rules.length
        ? html`<ul class="rows">${p.rules.map(r => html`<li data-key="r${r.id}"><span class="grow"><strong>${r.name || r.target_name}</strong> <span class="tag${r.enabled ? ' tag-ok' : ''}">${T(r.enabled ? 'app.bed.active' : 'app.bed.paused')}</span>
            <div class="muted fam-small">${bedRuleLine(r)}</div><div class="fam-small">${r.summary}</div></span></li>`)}</ul>`
        : empty('i-bed', T('app.bed.none'), T('app.bed.none_hint')) })}
      ${card({ key: 'alerts', icon: 'i-alert', title: T('app.d.alerts'), body: p.alerts.length
        ? html`<ul class="rows">${p.alerts.map(a => html`<li data-key="${a.id}"><span class="grow"><a href="${a.href || '#/inbox'}">${a.title}</a><div class="muted fam-small">${a.text}</div></span></li>`)}</ul>`
        : empty('i-check', T('app.ppl.no_alerts'), '', true) })}
      ${presCard(p)}
    </div>`;
}
async function loadPeople() {
  const lang = S.lang, id = S.ppl.id ? +S.ppl.id : null;
  const [r, d] = await Promise.allSettled([getJSON('/api/people'), id ? getJSON('/api/person?id=' + id) : Promise.resolve(null)]);
  if (lang !== S.lang) return;
  if (r.status === 'fulfilled') { S.ppl.r = r.value; S.ppl.err = null; setPersons(r.value); }
  else if (!S.ppl.r) S.ppl.err = errText(r.reason);
  if (id && +S.ppl.id === id) {
    if (d.status === 'fulfilled') { S.ppl.det = d.value; S.ppl.detErr = null; }
    else if (!isNetErr(d.reason)) { S.ppl.det = null; S.ppl.detErr = errText(d.reason); }
  }
  if (S.base === 'people') render();
  openPersonFormSoon();
}
function setPersons(v) {
  S.persons = (v.people || []).map(p => ({ id: p.id, name: p.name, avatar: p.avatar, initials: p.initials, color: p.color, child: p.child }));
  S.people = v.items || [];
}
function afterPeopleChange() { loadChoices(); refresh(); if (S.base === 'people') loadPeople(); }
function openPersonForm(p) {
  S.ppl.ferr = null;
  S.ppl.form = p ? { id: p.id, name: p.name, avatar: p.avatar || '', color: p.color || '', child: !!p.child, note: p.note || '' }
                 : { id: null, name: '', avatar: '', color: PPL_COLORS[persons().length % PPL_COLORS.length], child: false, note: '' };
  render();
  const i = document.querySelector('form[data-person-form] [data-pf="name"]'); if (i) i.focus();
}
function closePersonForm() {
  const id = S.ppl.form && S.ppl.form.id, after = !id && S.ppl.assignAfter;
  S.ppl.form = null; S.ppl.ferr = null; S.ppl.assignAfter = null;
  if (after) {   // cancelled "Add a person…" from a device: back to that device's owner list
    S.drawerFocus = `[data-assign][data-mac="${CSS.escape(after.mac)}"]`;
    go(devHref(after.mac));
    return;
  }
  render();
  const b = document.querySelector(id ? '[data-act="ppl-edit"]' : '[data-act="ppl-new"]'); if (b) b.focus();
}
async function savePerson(person, undoing) {
  const f = person ? null : S.ppl.form;
  const body = person || { id: f.id || null, name: f.name, avatar: f.avatar, color: f.color, child: !!f.child, note: f.note };
  if (f) { if (S.ppl.saving) return; S.ppl.saving = true; S.ppl.ferr = null; render(); }
  try {
    const j = await postJSON('/api/people', { person: body });
    if (f) { S.ppl.saving = false; S.ppl.form = null; }
    const before = j.before;
    toast(undoing ? T('app.toast.undone') : T(body.id ? 'app.ppl.saved' : 'app.ppl.added', { name: body.name.trim() }),
          undoing ? {} : { undo: () => (before ? savePerson(before, true) : deletePerson(j.id, true)) });
    const after = f && !body.id && S.ppl.assignAfter;
    S.ppl.assignAfter = null;
    if (after && j.id) {   // the device that asked for this person goes to them
      await assignItems([{ mac: after.mac, person: j.id, shared: false }], T('app.ppl.assigned', { what: devName(after.mac, after.name), who: body.name.trim() }));
      return;
    }
    afterPeopleChange();
  } catch (e) {
    if (f) { S.ppl.saving = false; S.ppl.ferr = errText(e); render(); } else fail(e);
  }
}
async function deletePerson(id, undoing) {
  try {
    const j = await postJSON('/api/people/delete', { id });
    if (S.ppl.id && +S.ppl.id === id) go('#/people');
    toast(undoing ? T('app.toast.undone') : T('app.ppl.deleted', { name: j.deleted.name, n: fmt.num(j.deleted.devices) }),
          undoing ? {} : { undo: () => postJSON('/api/people/restore', { undo: j.undo }).then(() => { toast(T('app.toast.undone')); afterPeopleChange(); }).catch(fail) });
    afterPeopleChange();
  } catch (e) { fail(e); }
}
function assignWho(value) {
  if (value === 'shared') return T('app.ppl.shared');
  const p = value.startsWith('p:') ? personById(+value.slice(2)) : null;
  return p ? p.name : T('app.ppl.nobody');
}
async function assignDevices(macs, value) {
  if (!macs.length || value === '-') return;
  const pid = value.startsWith('p:') ? +value.slice(2) : null;
  const what = macs.length === 1 ? devName(macs[0]) : T('app.ppl.n_devices', { n: fmt.num(macs.length) });
  return assignItems(macs.map(mac => ({ mac, person: pid, shared: value === 'shared' })), T('app.ppl.assigned', { what, who: assignWho(value) }));
}
async function assignItems(items, msg, undoing) {
  try {
    const j = await postJSON('/api/people/assign', { items });
    toast(undoing ? T('app.toast.undone') : msg, undoing ? {} : { undo: () => assignItems(j.before, '', true) });
    afterPeopleChange();
    if (S.route.name === 'device') loadDevice();
    return true;
  } catch (e) { fail(e); refresh(); return false; }
}
async function presSet(id, body, msg, undo) {
  try {
    await postJSON('/api/presence/settings', Object.assign({ id }, body));
    if (msg) toast(msg, undo ? { undo } : {});
    afterPeopleChange();
  } catch (e) { fail(e); }
}
function presNotify(id, k, undoing) {
  const p = S.ppl.det; if (!p || p.id !== id) return;
  p[k] = !p[k]; render();
  presSet(p.id, { [k]: p[k] }, undoing ? T('app.toast.undone') : T('app.toast.saved', { name: p.name }),
          undoing ? null : () => presNotify(id, k, true));
}
function presEnable(id) {
  const p = personById(id); if (!p) return;
  if (S.meta.remote) { toast(T('app.pair.admin_only'), { kind: 'err' }); return; }
  openConfirm({ icon: 'i-home', title: T('app.pres.enable_title', { name: p.name }), text: (S.data.pres && S.data.pres.privacy) || '',
                ok: T('app.pres.enable_ok'), run: () => presSet(id, { enabled: true, confirm: true }, T('app.pres.enabled', { name: p.name })) });
}
function presDisable(id) {
  const p = personById(id); if (!p) return;
  openConfirm({ icon: 'i-home', title: T('app.pres.disable_title', { name: p.name }), text: T('app.pres.disable_text'),
                ok: T('app.pres.disable'), run: () => presSet(id, { enabled: false }, T('app.pres.disabled', { name: p.name })) });
}
function presForget(id) {
  const p = personById(id); if (!p) return;
  openConfirm({ icon: 'i-alert', title: T('app.pres.forget_title', { name: p.name }), text: T('app.pres.forget_text'), ok: T('app.pres.forget'), danger: true,
                run: () => postJSON('/api/presence/forget', { id }).then(j => { toast(T('app.pres.forgotten', { n: fmt.num(j.deleted) })); afterPeopleChange(); }).catch(fail) });
}
function presDevice(id, mac) {
  const p = S.ppl.det && S.ppl.det.id === id ? S.ppl.det : null; if (!p) return;
  const cur = new Set(p.presence_macs || []);
  if (cur.has(mac)) cur.delete(mac); else cur.add(mac);
  p.presence_macs = Array.from(cur); render();
  presSet(id, { devices: p.presence_macs });
}
async function presLink(mac, pid, dismiss) {
  const name = devName(mac), p = personById(pid);
  try {
    const j = await postJSON('/api/presence/link', { mac, person: pid, dismiss: !!dismiss });
    if (dismiss) toast(T('app.pres.link_dismissed', { name }), { undo: () => postJSON('/api/unack', { mac, domain: 'presence:link' }).then(() => { toast(T('app.toast.undone')); afterPeopleChange(); }).catch(fail) });
    else toast(T('app.pres.linked', { name, person: p ? p.name : '' }), { undo: () => postJSON('/api/presence/unlink', { undo: j.undo }).then(() => { toast(T('app.toast.undone')); afterPeopleChange(); }).catch(fail) });
    afterPeopleChange();
  } catch (e) { fail(e); }
}
// Devices table: pick rows, then give them all to one person / Shared / nobody
function bulkBar() {
  const n = S.bulk.size;
  if (!n) return '';
  return html`<div class="toolbar bulkbar" data-key="bulk" role="group" aria-label="${T('app.bulk.label')}">
    <strong>${T('app.bulk.n', { n: fmt.num(n) })}</strong>
    <label class="bulk-to"><span>${T('app.bulk.to')}</span><select name="bulk-to" data-bulk-to aria-label="${T('app.bulk.to')}">${personOptions(S.bulkTo, true)}</select></label>
    <button type="button" class="btn sm" data-act="bulk-assign"${S.bulkTo === '-' ? ' disabled' : ''}>${T('app.bulk.assign')}</button>
    <button type="button" class="btn sm quiet" data-act="bulk-none">${icon('i-x')}${T('app.bulk.clear')}</button></div>`;
}

// ---------------------------------------------------------------------------------------
// Stage H: Network health ("is it my router or the ISP?"), the suggestion center and the
// home network score. Read-only: the only things the page changes are the user's own
// notes (a suggestion's status, an outage "Got it", the optional internet probe setting).
const LEVEL_ICON = { ok: 'i-check', warn: 'i-alert', bad: 'i-alert', idle: 'i-pulse' };
const PILLAR_ICON = { security: 'i-shield', privacy: 'i-eye-off', health: 'i-wifi', tidiness: 'i-devices', family: 'i-family' };
const SEV_TAG = { high: 'tag-bad', medium: 'tag-warn', low: '' };
const SUG_TABS = ['open', 'done', 'snoozed', 'dismissed'];
const ms = v => (v == null ? '—' : T('app.h.ms', { n: v >= 10 ? fmt.num(Math.round(v)) : String(Math.round(v * 10) / 10) }));
// A number and its unit stay on one line in a narrow tile label ("(24 h)", "7 Tage").
const keepUnit = s => String(s).replace(/(\d) (?=\S)/g, '$1 ');
function tileA(href, k, v, d, cls) {
  return html`<a class="tile${cls ? ' ' + cls : ''}" href="${href}"><div class="k">${keepUnit(k)}</div><div class="v">${v}</div><div class="d">${d}</div></a>`;
}
// Router latency over the window: one line (gaps where nothing was measured), red ticks
// where the router did not answer. Plain SVG, values only - no text from the network.
function sparkline(series, label) {
  const W = 600, H = 84, n = series.length;
  const vals = series.map(p => p.ms).filter(v => v != null);
  if (!n || !vals.length) return html`<div class="hint">${T('app.h.no_samples')}</div>`;
  const max = Math.max(5, ...vals) * 1.15, x = i => (n > 1 ? (i * W) / (n - 1) : W / 2);
  const y = v => (H - 6 - (v / max) * (H - 14)).toFixed(1);
  const segs = []; let cur = [];
  series.forEach((p, i) => { if (p.ms == null) { if (cur.length) segs.push(cur); cur = []; } else cur.push(x(i).toFixed(1) + ',' + y(p.ms)); });
  if (cur.length) segs.push(cur);
  const down = series.map((p, i) => (p.down ? html`<rect class="down" x="${(x(i) - 2).toFixed(1)}" y="0" width="4" height="${H}"/>` : ''));
  return html`<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${label}">
    <line class="base" x1="0" y1="${H - 6}" x2="${W}" y2="${H - 6}"/>${down}
    ${segs.map(s => (s.length > 1 ? html`<polyline points="${s.join(' ')}"/>` : html`<circle r="2.5" cx="${s[0].split(',')[0]}" cy="${s[0].split(',')[1]}"/>`))}</svg>
    <div class="spark-x"><span>${fmt.date(series[0].t)}</span><span>${T('app.h.peak', { v: ms(Math.max(...vals)) })}</span><span>${T('app.h.now')}</span></div>`;
}
function dnsDays(days) {
  if (!days || !days.length) return html`<div class="hint">${T('app.h.no_dns')}</div>`;
  const maxMs = Math.max(1, ...days.map(d => d.avg_ms || 0)), maxF = Math.max(0.01, ...days.map(d => d.fail_rate || 0));
  const row = (cls, f) => html`<div class="bars h-bars ${cls}">${days.map(d => html`<div class="b" title="${T('app.h.dns_bar', { day: fmt.day(d.date), ms: ms(d.avg_ms), pct: fmt.pct(d.fail_rate || 0), n: fmt.num(d.queries) })}">
    <div class="col"><i style="--h:${f(d).toFixed(1)}%"></i></div><span>${fmt.day(d.date)}</span></div>`)}</div>`;
  return html`<div class="hint">${T('app.h.dns_speed')}</div>${row('speed', d => 100 * (d.avg_ms || 0) / maxMs)}
    <div class="hint">${T('app.h.dns_fail')}</div>${row('fail', d => 100 * (d.fail_rate || 0) / maxF)}`;
}
function outageRow(o) {
  return html`<li class="outage${o.ongoing ? ' ongoing' : ''}" data-key="o-${o.id}">
    <span class="att-ic">${icon(o.cause === 'router' ? 'i-wifi' : 'i-globe')}</span>
    <div class="grow"><div><strong>${o.when}</strong> · ${o.duration}${o.ongoing ? html` <span class="tag tag-bad">${T('app.h.ongoing')}</span>` : ''}</div>
      <div class="muted">${o.cause_name}</div></div></li>`;
}
function probeCard(h) {
  const inet = h.internet || {}, val = S.probe != null ? S.probe : (inet.target || '');
  const last = inet.latest;
  return card({ key: 'probe', icon: 'i-globe', title: T('app.h.probe'), body: html`
    <p class="hint" style="margin-top:0">${T('app.h.probe_body')}</p>
    ${S.meta.remote ? html`<dl class="facts"><dt>${T('settings.health.internet_probe')}</dt><dd class="mono">${inet.target || '—'}</dd></dl>
      <p class="hint">${T('app.pair.admin_only')}</p>` : html`<form class="probe-form" data-probe-form>
      <label class="field"><span>${T('settings.health.internet_probe')}</span>
        <input type="text" name="probe" data-probe value="${val}" placeholder="1.1.1.1:443" autocomplete="off" spellcheck="false" maxlength="262" inputmode="url"></label>
      <div class="form-acts"><button type="submit" class="btn sm"${S.probeSaving ? html` disabled` : ''}>${T('ui.save')}</button>
        ${inet.configured ? html`<button type="button" class="btn sm ghost" data-act="probe-off">${T('app.h.probe_off')}</button>` : ''}</div></form>`}
    <div class="hint">${inet.configured ? (last ? T(last.ok ? 'app.h.probe_ok' : 'app.h.probe_fail', { when: fmt.rel(last.ts), ms: ms(last.latency_ms) }) : T('app.h.probe_wait'))
                                        : T('app.h.probe_offline')}</div>` });
}
function serverCard(s) {
  if (!s) return '';
  return card({ key: 'server', icon: 'i-sliders', title: T('app.h.server', { name: s.server === 'pihole' ? 'Pi-hole' : 'AdGuard Home' }), body: html`
    <ul class="rows">
      ${s.queries != null ? html`<li><span class="grow">${T('app.h.server_queries')}</span><span class="num">${fmt.num(s.queries)}</span></li>` : ''}
      ${s.blocked != null ? html`<li><span class="grow">${T('app.h.server_blocked')}</span><span class="num">${fmt.num(s.blocked)}</span></li>` : ''}
      ${s.avg_ms != null ? html`<li><span class="grow">${T('app.h.server_avg')}</span><span class="num">${ms(s.avg_ms)}</span></li>` : ''}
      ${(s.upstreams || []).map(u => html`<li data-key="u-${u.name}"><code class="grow">${u.name}</code><span class="num">${ms(u.avg_ms)}</span></li>`)}</ul>
    <div class="hint">${T('app.h.server_when', { when: fmt.rel(s.ts) })}</div>` });
}
function viewHealth() {
  const h = S.data.health;
  if (!h) return skeleton(3);
  const v = h.verdict, gw = h.gateway, dns = h.dns, inet = h.internet || {};
  // the tile is "right now" (last hour); the verdict above speaks for the whole window
  const hour = gw.measured && gw.hour_ms != null;
  const gwMs = gw.measured ? (hour ? gw.hour_ms : gw.avg_ms) : null;
  const gwSub = !gw.measured ? T('app.h.not_measured')
    : (hour ? T('app.h.loss_hour', { pct: fmt.pct(gw.hour_loss || 0) }) : T('app.h.loss', { pct: fmt.pct(gw.loss || 0) }));
  return html`${phead(T('app.nav.health'), T('app.h.sub'), demoPill())}
    <section class="card hero ${v.level}" data-key="h-hero" aria-live="polite">
      <div class="big">${icon(LEVEL_ICON[v.level])}</div>
      <div><h2>${v.title}</h2><p>${v.text}</p></div></section>
    <div class="tiles">
      ${tileA('#/health', T('app.h.router'), gw.measured ? ms(gwMs) : '—', gwSub)}
      ${tileA('#/health', T('app.h.dns'), dns.measured ? ms(dns.avg_ms) : '—', dns.measured ? T('app.h.fails', { pct: fmt.pct(dns.fail_rate || 0) }) : T('app.h.not_measured'))}
      ${tileA('#/health', T('app.h.outages_7d'), fmt.num(h.outages_7d), T('app.h.outages_sub'))}
      ${tileA('#/health', T('app.h.internet'), inet.configured ? (inet.latest ? T(inet.latest.ok ? 'app.h.up' : 'app.h.down') : '…') : T('app.h.off'), inet.configured ? inet.target : T('app.h.probe_hint'))}
    </div>
    <div class="grid">
      ${card({ key: 'spark', cls: 'span2', icon: 'i-pulse', title: T('app.h.latency', { h: h.hours }), body: html`
        ${sparkline(gw.series || [], T('app.h.latency', { h: h.hours }))}
        <div class="hint">${gw.measured ? T('app.h.latency_hint', { ip: gw.ip || '—' }) : T('app.h.no_gateway_hint')}</div>` })}
      ${card({ key: 'out', cls: 'span2', icon: 'i-alert', title: T('app.h.outages'), body: (h.outages || []).length
        ? html`<ul class="rows outages">${h.outages.slice(0, 12).map(outageRow)}</ul><div class="hint">${T('app.h.cause_hint')}</div>`
        : empty('i-check', T('app.h.no_outages'), T('app.h.no_outages_sub'), true) })}
      ${card({ key: 'dns', icon: 'i-globe', title: T('app.h.dns_trend'), body: dnsDays(dns.days) })}
      ${probeCard(h)}
      ${serverCard(h.server)}
    </div>
    <p class="hint">${h.note}</p>`;
}
async function saveProbe(value) {
  S.probeSaving = true; render();
  try {
    await postJSON('/api/settings', { values: { 'health.internet_probe': value || null } });
    S.probe = null; toast(T(value ? 'app.h.probe_saved' : 'app.h.probe_removed'));
    refresh();
  } catch (e) { fail(e); }
  S.probeSaving = false; render();
}

// The suggestion center
function sugStatus(it) {
  if (it.status === 'done') {
    if (it.effect_ts) return html`<span class="tag tag-ok">${icon('i-check')}${T('app.sug.took_effect', { when: fmt.date(it.effect_ts) })}</span>`;
    return html`<span class="tag ${it.waiting ? 'tag-warn' : 'tag-ok'}">${T(it.waiting ? 'app.sug.waiting' : 'app.sug.resolved')}</span>`;
  }
  if (it.status === 'snoozed') return html`<span class="tag">${T('app.sug.snoozed_until', { when: fmt.date(it.until) })}</span>`;
  if (it.status === 'dismissed') return html`<span class="tag">${T('app.sug.dismissed_tag')}</span>`;
  return '';
}
function sugBody(it) {
  const plats = it.platforms || [], cur = S.sugPlat[it.id] && plats.some(p => p.key === S.sugPlat[it.id]) ? S.sugPlat[it.id] : (plats[0] || {}).key;
  const p = plats.find(x => x.key === cur) || { steps: [] };
  const btn = (v, label, cls) => html`<button type="button" class="btn sm ${cls || 'ghost'}" data-act="sug-set" data-id="${it.id}" data-v="${v}">${label}</button>`;
  return html`<div class="sug-b">
    <p>${it.why}</p>
    ${(it.devices || []).length ? html`<div class="chips">${it.devices.map(d => (d.mac ? html`<a class="chip" href="${devHref(d.mac)}" data-key="${d.mac}">${rowName(d)}</a>` : html`<span class="chip">${d.name}</span>`))}</div>` : ''}
    ${it.status === 'open' || (it.status === 'done' && it.waiting) || it.status === 'snoozed' ? html`
      ${plats.length > 1 ? html`<div class="seg" role="group" aria-label="${T('app.sug.platform')}">${plats.map(x => html`<button type="button" data-act="sug-plat" data-id="${it.id}" data-v="${x.key}" aria-pressed="${String(x.key === cur)}">${x.name}</button>`)}</div>`
                         : html`<div class="hint">${p.name}</div>`}
      <ol class="sug-steps">${p.steps.map(s => html`<li>${s}</li>`)}</ol>
      ${it.rules && it.rules.adguard && (cur === 'adguard' || cur === 'pihole') ? rulesBox(it.rules) : ''}
      ${it.copy ? html`<div class="rh"><span>${T('app.sug.log')}</span>${copyBtn(it.copy)}</div><textarea class="rule" name="sug-log" readonly aria-label="${T('app.sug.log')}">${it.copy}</textarea>` : ''}` : ''}
    <div class="form-acts">
      ${it.status === 'open' ? [btn('done', T('app.sug.mark_done'), 'primary'), btn('snoozed', T('app.sug.snooze')), btn('dismissed', T('app.sug.dismiss'))]
                             : btn('open', T('app.sug.reopen'))}
    </div>
    <div class="hint">${T('app.sug.never_auto')}</div></div>`;
}
function sugItem(it) {
  const open = S.sugOpen.has(it.id);
  return html`<li class="sug sev-${it.severity}" data-key="s-${it.id}">
    <button type="button" class="sug-h" data-act="sug-toggle" data-id="${it.id}" aria-expanded="${String(open)}" id="sh-${it.id}">
      <span class="sug-ic">${icon(PILLAR_ICON[it.pillar] || 'i-bulb')}</span>
      <span class="sug-t"><span class="sug-title">${it.status === 'done' && !it.waiting ? it.done_title : it.title}</span>
        <span class="sug-meta"><span class="tag ${SEV_TAG[it.severity]}">${it.severity_name}</span><span class="muted">${it.pillar_name}</span>
          ${it.points && it.status !== 'done' ? html`<span class="tag tag-ok">${T('app.sug.points', { n: it.points })}</span>` : ''}${sugStatus(it)}</span></span>
      ${icon('i-chev', 'chev')}</button>
    ${open ? sugBody(it) : ''}</li>`;
}
function viewSuggestions() {
  const g = S.data.sug;
  if (!g) return skeleton(3);
  const tab = SUG_TABS.includes(S.sugTab) ? S.sugTab : 'open', list = g[tab] || [];
  return html`${phead(T('app.nav.suggestions'), T('app.sug.sub'), demoPill())}
    <div class="chips sug-tabs" role="group" aria-label="${T('app.sug.filter')}">${SUG_TABS.map(t => html`
      <button type="button" class="chip" data-act="sug-tab" data-v="${t}" aria-pressed="${String(t === tab)}">${T('app.sug.tab.' + t)} <span class="muted">${fmt.num((g.counts || {})[t] || 0)}</span></button>`)}</div>
    ${card({ key: 'sug-' + tab, body: list.length ? html`<ul class="sug-list">${list.map(sugItem)}</ul>`
      : empty(tab === 'open' ? 'i-check' : 'i-bulb', T('app.sug.empty.' + tab), tab === 'open' ? T('app.sug.empty_sub') : '', tab === 'open') })}
    <p class="hint">${g.note}</p>`;
}
async function setSug(id, status, prev, undoing) {
  try {
    const r = await postJSON('/api/suggestions/' + enc(id), status === 'snoozed' ? { status, days: 7 } : { status });
    delete r.ok; localData('sug', r);
    if (!undoing) toast(T('app.sug.toast.' + status), { undo: prev && prev !== status ? () => setSug(id, prev, status, true) : null });
    else toast(T('app.toast.undone'));
    render(); refresh();
  } catch (e) { fail(e); }
}

// Overview: the home network score + "Next best steps"
function scoreCard() {
  const sc = S.data.score;
  if (!sc) return card({ key: 'score', icon: 'i-gauge', title: T('app.score.title'), body: html`<div class="skel box"></div>` });
  const trend = sc.trend || [], max = 100;
  const delta = sc.delta == null ? '' : html`<span class="delta ${sc.delta > 0 ? 'down' : sc.delta < 0 ? 'up' : ''}">${T(sc.delta > 0 ? 'app.score.up' : sc.delta < 0 ? 'app.score.down' : 'app.score.same', { n: Math.abs(sc.delta) })}</span>`;
  return card({ key: 'score', cls: 'span2', icon: 'i-gauge', title: T('app.score.title'),
    actions: html`<a class="btn sm quiet" href="#/suggestions">${T('app.score.raise')}</a>`, body: html`
    <div class="score">
      <div class="score-n lvl-${sc.level}" role="img" aria-label="${T('app.score.aria', { n: sc.score == null ? '—' : sc.score })}"><span class="v">${sc.score == null ? '—' : sc.score}</span><span class="of">/100</span></div>
      <div class="score-b"><div>${sc.summary} ${delta}</div>
        <ul class="hbars pillars">${sc.pillars.map(p => html`<li class="hbar" data-key="p-${p.key}"><div class="hrow"><span>${icon(PILLAR_ICON[p.key])} ${p.name}</span>
          <span class="muted num">${p.measured ? p.score + '/' + p.max : T('app.score.not_measured')}</span></div>
          <div class="track"><i class="${p.measured && p.score < p.max * 0.6 ? 'low' : ''}" style="--w:${p.measured ? (100 * p.score / p.max).toFixed(0) : 0}%"></i></div></li>`)}</ul></div>
      ${trend.length > 1 ? html`<div class="score-t"><div class="hint">${T('app.score.trend')}</div><div class="bars score-bars">${trend.map(t => html`<div class="b" title="${T('app.score.bar', { day: fmt.day(t.day), n: t.score })}">
        <div class="col"><i class="lvl-${t.level || 'ok'}" style="--h:${(100 * t.score / max).toFixed(0)}%"></i></div></div>`)}</div>
        <div class="spark-x"><span>${fmt.day(trend[0].day)}</span><span>${fmt.day(trend[trend.length - 1].day)}</span></div></div>` : ''}
    </div>
    ${(sc.raise || []).length ? html`<div class="hint">${T('app.score.how')}</div><ul class="rows">${sc.raise.map(r => html`<li data-key="r-${r.id}">
      <span class="grow"><a href="#/suggestions" data-act="sug-goto" data-id="${r.id}">${r.title}</a></span><span class="tag tag-ok">${T('app.sug.points', { n: r.gain })}</span></li>`)}</ul>` : ''}
    <details class="score-why" data-persist="score-why"${persistOpen('score-why')}><summary>${T('app.score.breakdown')}</summary>
      <ul class="rows">${(sc.deductions || []).map((d, i) => html`<li data-key="d-${i}"><span class="grow">${d.text}</span><span class="num muted">−${d.gain}</span></li>`)}</ul>
      <div class="hint">${sc.note}</div></details>` });
}
function nextStepsCard() {
  const g = S.data.sug;
  return card({ key: 'next', icon: 'i-bulb', title: T('app.sug.next'), actions: html`<a class="btn sm quiet" href="#/suggestions">${T('app.ov.see_all')}</a>`,
    body: !g ? html`<div class="skel box"></div>` : (g.top || []).length ? html`<ol class="next-steps">${g.top.map(it => html`<li data-key="n-${it.id}">
      <a href="#/suggestions" data-act="sug-goto" data-id="${it.id}"><strong>${it.title}</strong></a>
      <div class="muted">${it.why}</div></li>`)}</ol>` : empty('i-check', T('app.sug.empty.open'), '', true) });
}
function sugCount() { return (S.data.sug && S.data.sug.counts && S.data.sug.counts.open) || 0; }

// ---------------------------------------------------------------------------------------
// AI chat: one conversation, shown on the #/ai page or in the side panel (a bottom sheet on
// phones) from every other section. Replies stream in (POST /api/chat/stream, server-sent
// events) and can be stopped. The LLM is only ever called from chat() - an explicit Send /
// Insight / suggestion click - never on load or refresh. The conversation survives reloads
// in sessionStorage (this tab only).
const CHAT_KEY = 'netwarden.chat';
function aiBadge() {
  const m = S.meta || {};
  if (DEMO) return T('app.demo.ai_mode');   // the visitor chose no flag: saved answers, no AI is called
  const off = { forced: 'ui.ai_offline_forced', addon: 'ui.ai_offline_addon', chosen: 'ui.ai_offline_chosen' }[m.offline_reason] || 'ui.ai_offline';
  // These strings were written to be appended after a title ("· ..."): drop the lead-in.
  const s = m.ai_mode === 'offline' ? T(off) : (m.model ? T('ui.model', { model: m.model, provider: m.provider }) : '');
  return s.replace(/^[\s·・•|-]+/u, '');
}
// Where the AI's prompts go: this computer / the home network / the cloud (+ "names hidden").
const DEST_ICON = { local: 'i-home', lan: 'i-devices', cloud: 'i-globe', none: 'i-eye-off' };
const DEST_TAG = { local: 'tag-ok', lan: 'tag-ok', cloud: 'tag-warn', none: '' };
function destTag(dest, provider, redact, compact) {
  const d = DEST_ICON[dest] ? dest : 'none', hidden = T('ai.redact_on');
  return html`<span class="tag dest ${DEST_TAG[d]}">${icon(DEST_ICON[d])}${T('ai.dest.' + d, { provider: provider || '' })}</span>${!redact ? ''
    : (compact ? html` <span class="tag tag-acc dest" role="img" aria-label="${hidden}" title="${hidden}">${icon('i-eye-off')}</span>`
               : html` <span class="tag tag-acc dest">${icon('i-eye-off')}${hidden}</span>`)}`;
}
// The chat's subtitle: offline -> why; otherwise where it runs + which model (the side
// panel's narrow header: the model only on hover, "names hidden" as an icon).
function aiSub(compact) {
  const m = S.meta || {};
  if (m.ai_mode === 'offline' || !m.ai_mode) return aiBadge();
  if (compact) return html`<span title="${aiBadge()}">${destTag(m.ai_destination, m.provider, m.ai_redact, true)}</span>`;
  return html`${destTag(m.ai_destination, m.provider, m.ai_redact)} <span class="muted">${aiBadge()}</span>`;
}
function chatHere() { return S.base === 'ai' ? 'page' : (S.chat.open ? 'panel' : null); }
// Questions worth asking about THIS network right now (localized), most pressing first.
function suggestions() {
  if (DEMO) {   // the static demo: only questions it has an answer for
    const idx = demoChatIndex(), asked = new Set(S.chat.messages.filter(m => m.role === 'user').map(m => m.content.trim()));
    return idx ? idx.suggested.filter(q => !asked.has(q)).slice(0, 6) : [];
  }
  const out = [], seen = new Set(), add = (k, o) => { const t = T(k, o); if (!seen.has(t)) { seen.add(t); out.push(t); } };
  const a = S.data.alerts || {}, ctx = S.chat.ctx;
  if (ctx) add('app.ai.q.device', { name: ctx.name });
  const live = it => !isHidden(it.mac, it.ack || it.domain || '');
  const th = (a.threats || []).filter(t => live(Object.assign({ ack: t.domain }, t)))[0];
  if (th) add('app.ai.q.threat', { name: th.device });
  const ex = (a.exposure || []).filter(live)[0];
  if (ex) add('app.ai.q.exposure', { name: ex.name, port: ex.port });
  const night = (a.unusual_hours || []).filter(live)[0];
  if (night) add('app.ai.q.night', { time: String(night.window || '').split(/[–-]/)[0] || '00:00' });
  const p = S.data.privacy;
  if (p && p.home && p.home.tracker_queries && GRADE_RANK[p.home.grade] >= 3) add('app.ai.q.trackers');
  const vis = (a.visibility || []).filter(live)[0];
  if (vis) add('app.ai.q.visibility', { name: vis.name });
  const nd = (a.new_devices || []).filter(d => live(d) && !d.is_self)[0];
  if (nd) add('app.ai.q.new', { name: nd.name });
  const ch = (a.behavior_changes || []).filter(live)[0];
  if (ch) add('app.ai.q.change', { name: ch.name });
  if (S.data.inv && S.data.inv.has_bandwidth) add('app.ai.q.bandwidth');
  // Stage A: questions the server built from this home's data (the lookups can answer
  // them, offline too) lead; the alert-driven ones above fill up to 6
  const server = (questionsFor() || []).map(q => q.text).filter(t => t && !seen.has(t));
  ['app.ai.s1', 'app.ai.s2', 'app.ai.s3'].forEach(k => add(k));
  const merged = [];
  S.chat.messages.forEach(m => { if (m.role === 'user') merged.push(m.content); });   // already asked
  const asked = merged.length;
  if (ctx && out.length) merged.push(out.shift());
  server.forEach(t => { if (merged.length < asked + 3 && !merged.includes(t)) merged.push(t); });
  out.concat(server).forEach(t => { if (merged.length < asked + 6 && !merged.includes(t)) merged.push(t); });
  return merged.slice(asked);
}
// GET /api/ai/questions (no LLM): fetched when the chat shows, again after a reply, per
// language + focused device; a failed fetch just leaves the local questions.
const AIQ = { key: '', at: 0, list: null, busy: false };
function questionsFor() {
  const key = S.lang + '|' + (S.chat.ctx ? S.chat.ctx.mac : '');
  if (!AIQ.busy && (AIQ.key !== key || Date.now() - AIQ.at > 60000)) {
    AIQ.busy = true;
    const q = '/api/ai/questions?lang=' + encodeURIComponent(S.lang) + (S.chat.ctx ? '&mac=' + encodeURIComponent(S.chat.ctx.mac) : '');
    fetch(url(q)).then(r => r.ok ? r.json() : null).then(j => {
      const list = j && Array.isArray(j.questions) ? j.questions.filter(x => x && typeof x.text === 'string').slice(0, 6) : [];
      const changed = JSON.stringify(list) !== JSON.stringify(AIQ.list);
      Object.assign(AIQ, { key, at: Date.now(), list, busy: false });
      if (changed && chatHere()) render();
    }).catch(() => { Object.assign(AIQ, { key, at: Date.now(), busy: false }); });
  }
  return AIQ.key === key ? AIQ.list : null;
}
// "Looked up: Devices · Living-room TV · Domains (last 24 h)" - expandable to the exact
// JSON each lookup returned (what the AI received: the redacted text when names are hidden).
function toolText(x) { return x.label + (x.detail && x.detail.length ? ' (' + x.detail.join(', ') + ')' : ''); }
function toolChips(m, i) {
  const tools = m.tools || [];
  if (!tools.length) return '';
  return html`<details class="tools" data-key="tl${i}"><summary>${icon('i-search')}<span><b>${T('app.ai.looked_up')}:</b> ${tools.map(toolText).join(' · ')}</span></summary>
    ${tools.map((x, j) => html`<div class="toolres" data-key="t${j}">
      <div class="toolhead"><span class="tag">${x.label}</span>${x.detail && x.detail.length ? html` <span class="muted">${x.detail.join(' · ')}</span>` : ''}
        ${x.error ? html` <span class="tag tag-warn">${T('app.ai.tool_failed')}</span>` : ''}${x.truncated ? html` <span class="tag">${T('app.ai.tool_truncated')}</span>` : ''}</div>
      <div class="hint">${x.local ? T('app.ai.tool_local') : T(x.redacted ? 'app.ai.tool_sent' : 'app.ai.tool_sent_plain')}</div>
      <pre class="tooljson" tabindex="0">${x.sent}</pre></div>`)}
  </details>`;
}
// Round 7 C: what an answer used - "about 9,400 tokens · ~US$0.012", expandable to the
// parts (uncached input, read from / written to the prompt cache, output) and where the
// price comes from. Counted on this computer only (GET /api/ai/usage), never sent anywhere.
function usd(v) {
  if (v == null) return '';
  if (v > 0 && v < 0.001) return T('app.usage.usd_tiny');
  const d = v < 1 ? 3 : 2;
  return T('app.usage.usd', { v: new Intl.NumberFormat(F.l, { minimumFractionDigits: d, maximumFractionDigits: d }).format(v) });
}
const num0 = v => (typeof v === 'number' && isFinite(v) && v > 0 ? v : 0);
function cleanUsage(d) {
  if (!d || typeof d !== 'object') return undefined;
  const b = d.budget && typeof d.budget === 'object' ? d.budget : {};
  return { tokens: num0(d.tokens), requests: num0(d.requests), input_tokens: num0(d.input_tokens), output_tokens: num0(d.output_tokens),
           cache_read_tokens: num0(d.cache_read_tokens), cache_write_tokens: num0(d.cache_write_tokens), estimated: !!d.estimated,
           cost_usd: typeof d.cost_usd === 'number' && isFinite(d.cost_usd) ? d.cost_usd : null, local: !!d.local,
           provider: String(d.provider || '').slice(0, 60), model: String(d.model || '').slice(0, 120),
           prices_checked: String(d.prices_checked || '').slice(0, 10), price_source: d.price_source === 'settings' ? 'settings' : 'table',
           budget: { state: ['none', 'ok', 'near', 'over'].includes(b.state) ? b.state : 'none', share: num0(b.share), spent: num0(b.spent), limit: num0(b.limit) } };
}
function usageHead(u) {
  if (u.local) return T('app.usage.note_local', { n: fmt.num(u.tokens) });
  return u.cost_usd == null ? T('app.usage.note_tokens', { n: fmt.num(u.tokens) }) : T('app.usage.note', { n: fmt.num(u.tokens), cost: usd(u.cost_usd) });
}
function priceHint(u) {
  if (u.local) return T('app.usage.local_hint');
  if (u.cost_usd == null) return T('app.usage.no_price');
  return T(u.price_source === 'settings' ? 'app.usage.price_own' : 'app.usage.price_hint', { date: u.prices_checked });
}
function usageNote(m, i) {
  const u = m.usage;
  if (!u || !u.tokens) return '';
  const b = u.budget, row = (k, n) => (n ? html`<dt>${T('app.usage.' + k)}</dt><dd>${fmt.num(n)}</dd>` : '');
  return html`${b.state === 'near' || b.state === 'over' ? html`<div class="msg-note warn" role="status">${icon('i-gauge')}<span>${T('app.usage.budget_near', { pct: fmt.pct(b.share), spent: usd(b.spent), limit: usd(b.limit) })}</span></div>` : ''}
    <details class="usage" data-key="u${i}"><summary>${icon('i-gauge')}<span>${usageHead(u)}</span></summary>
    <dl class="facts">${row('input', u.input_tokens)}${row('cache_read', u.cache_read_tokens)}${row('cache_write', u.cache_write_tokens)}${row('output', u.output_tokens)}
      <dt>${T('app.usage.requests')}</dt><dd>${fmt.num(u.requests)}</dd><dt>${T('app.usage.model')}</dt><dd>${u.provider} · ${u.model}</dd></dl>
    ${u.estimated ? html`<p class="hint">${T('app.usage.estimated')}</p>` : ''}<p class="hint">${priceHint(u)}</p></details>`;
}
function chatMsg(m, i) {
  const ai = m.role !== 'user', last = i === S.chat.messages.length - 1;
  const body = m.content ? md(m.content) : '';
  return html`<div class="msg ${ai ? 'ai' : 'user'}${m.err ? ' failed' : ''}" data-key="m${i}">
    <div class="who"><span>${ai ? 'netwarden' : T('ui.you')}</span>
      ${ai && m.content && !m.pending ? html`<button type="button" class="btn icon xs quiet" data-act="copy-msg" data-i="${i}" aria-label="${T('app.chat.copy')}" title="${T('app.chat.copy')}">${icon('i-copy')}</button>` : ''}</div>
    ${ai ? toolChips(m, i) : ''}
    ${body}${m.pending && m.status ? html`<div class="lookup" role="status">${icon('i-search')}<span>${T('app.ai.looking_up', { what: toolText(m.status) })}</span></div>` : ''}
    ${m.pending && !m.content && !m.status ? html`<span class="typing-dots" aria-hidden="true"><i></i><i></i><i></i></span> <span class="muted">${T('ui.thinking')}</span>` : ''}
    ${m.pending && m.content && !m.status ? html`<span class="caret" aria-hidden="true"></span>` : ''}
    ${(m.notes || []).map(n => html`<div class="msg-note">${icon('i-bulb')}<span>${n}</span></div>`)}
    ${ai && !m.pending ? usageNote(m, i) : ''}
    ${m.suggest && m.suggest.length && !m.pending ? html`<div class="suggest inmsg" role="group" aria-label="${T('app.chat.suggested')}">${m.suggest.map(s => html`<button type="button" class="chip" data-act="suggest" data-text="${s}"${S.chat.busy ? ' disabled' : ''}>${s}</button>`)}</div>` : ''}
    ${m.stopped ? html`<div class="msg-note">${T('app.chat.stopped')}</div>` : ''}
    ${m.err ? html`<div class="msg-note err" role="alert">${icon('i-alert')}<span>${T('app.chat.error', { error: m.err })}</span>
      ${last ? html`<button type="button" class="btn sm ghost" data-act="chat-retry">${icon('i-refresh')}${T('app.chat.retry')}</button>` : ''}</div>` : ''}
  </div>`;
}
function chatLog() {
  const c = S.chat;
  return c.messages.length ? c.messages.map(chatMsg) : empty('i-spark', T('app.ai.empty'), T('ui.chat_hint'));
}
// The chat component, rendered into exactly one place at a time (ids stay unique).
function chatBox(where) {
  const c = S.chat;
  return html`<div class="chatbox ${where}" id="chatbox">
    <div class="chatlog" id="chatlog" role="log" aria-live="polite" aria-busy="${String(c.busy)}" aria-label="${T('ui.chat_title')}">${chatLog()}</div>
    ${c.busy ? '' : html`<div class="suggest" role="group" aria-label="${T('app.chat.suggested')}">${suggestions().map(s => html`<button type="button" class="chip" data-act="suggest" data-text="${s}">${s}</button>`)}</div>`}
    ${c.ctx ? html`<div class="chatctx"><span class="tag">${icon('i-devices')}${T('app.chat.about', { name: c.ctx.name })}</span>
      <button type="button" class="btn icon xs quiet" data-act="chat-unfocus" aria-label="${T('app.chat.unfocus', { name: c.ctx.name })}" title="${T('app.chat.unfocus', { name: c.ctx.name })}">${icon('i-x')}</button></div>` : ''}
    <div class="composer">
      <label class="sr" for="chatq">${T('ui.ask_placeholder')}</label>
      <textarea id="chatq" name="chatq" rows="1" maxlength="2000" placeholder="${T('ui.ask_placeholder')}" aria-describedby="chatkeys">${c.draft}</textarea>
      ${c.busy ? html`<button type="button" class="btn danger" data-act="chat-stop" aria-label="${T('app.chat.stop')}">${icon('i-stop')}<span>${T('app.chat.stop')}</span></button>`
               : html`<button type="button" class="btn" data-act="send" aria-label="${T('ui.btn_ask')}">${icon('i-send')}<span>${T('ui.btn_ask')}</span></button>`}
    </div>
    <div class="chatfoot">
      <span class="hint" id="chatkeys">${T('app.chat.keys')}</span>
      <span class="chatbtns">
        <button type="button" class="btn sm ghost" data-act="insight"${c.busy ? ' disabled' : ''}>${icon('i-spark')}${T('ui.btn_insight')}</button>
        <button type="button" class="btn sm quiet" data-act="ai-preview"${c.busy ? ' disabled' : ''}>${icon('i-eye-off')}${T('app.ai.preview')}</button>
        ${c.messages.length ? html`<button type="button" class="btn sm quiet" data-act="chat-clear"${c.busy ? ' disabled' : ''}>${T('ui.btn_clear')}</button>` : ''}
      </span>
    </div>
  </div>`;
}
function viewAI() {
  return html`${phead(T('app.nav.ai'), aiSub())}<section class="card chat" data-key="chat">${chatBox('page')}</section>`;
}
function viewChatPanel() {
  return html`<header class="chathead"><span class="ticon">${icon('i-spark')}</span>
      <div class="dt"><h2 id="chat-title">${T('ui.chat_title')}</h2><div class="sub">${aiSub(true)}</div></div>
      <a class="btn icon ghost" href="#/ai" data-act="chat-expand" aria-label="${T('app.chat.expand')}" title="${T('app.chat.expand')}">${icon('i-expand')}</a>
      <button type="button" class="btn icon ghost" data-act="chat-close" aria-label="${T('app.close')}" title="${T('app.close')} (Esc)">${icon('i-x')}</button>
    </header>${chatBox('panel')}`;
}
// Streaming updates touch only the chat (not the page underneath), at most once a frame.
let chatFrame = 0;
function renderChatSoon() {
  if (chatFrame) return;
  chatFrame = requestAnimationFrame(() => {
    chatFrame = 0;
    const log = $('#chatlog');
    if (!log) return;
    morph(log, chatLog());
    followChat();
  });
}
// While a reply streams in, keep it in view - but stop once the question reaches the top,
// so a long answer is read from its start. Scrolling the log by hand stops the following.
function followChat() {
  const log = $('#chatlog');
  if (!log || !S.chat.follow) return;
  const users = log.querySelectorAll('.msg.user'), u = users[users.length - 1];
  let top = log.scrollHeight;
  if (u) top = Math.min(top, log.scrollTop + u.getBoundingClientRect().top - log.getBoundingClientRect().top - 8);
  log.scrollTop = top;
}
function scrollChat() { const l = $('#chatlog'); if (l) l.scrollTop = l.scrollHeight; }
function saveChat() {
  const c = S.chat;
  try {
    sessionStorage.setItem(CHAT_KEY, JSON.stringify({ db: dbId(), ctx: c.ctx, draft: c.draft,
      messages: c.messages.map(m => ({ role: m.role, content: m.content, mode: m.mode, err: m.err, stopped: m.stopped,
        tools: m.tools, notes: m.notes, suggest: m.suggest, usage: m.usage })) }));
  } catch (e) { /* storage full or disabled: the chat just won't survive a reload */ }
}
// Stored chat / notified keys belong to one database (a demo and a real DB can share the
// origin); the panel's open state is NOT restored - it only opens when the user asks.
function dbId() { return (S.meta && S.meta.db_id) || ''; }
function loadChat() {
  try {
    const j = JSON.parse(sessionStorage.getItem(CHAT_KEY) || 'null');
    if (!j || !Array.isArray(j.messages) || j.db !== dbId()) return;
    S.chat.messages = j.messages.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
      .map(m => ({ role: m.role, content: m.content, mode: m.mode, err: typeof m.err === 'string' ? m.err : undefined, stopped: !!m.stopped,
        tools: cleanTools(m.tools), notes: strList(m.notes, 4), suggest: strList(m.suggest, 6), usage: cleanUsage(m.usage) }));
    S.chat.ctx = j.ctx && typeof j.ctx.mac === 'string' ? { mac: j.ctx.mac, name: String(j.ctx.name || j.ctx.mac) } : null;
    S.chat.draft = typeof j.draft === 'string' ? j.draft : '';
  } catch (e) { /* a broken entry: start fresh */ }
}
// Stored / streamed lookups and notes, shape-checked and capped (10 lookups of <= 8 KB).
function strList(a, n) { return Array.isArray(a) ? a.filter(s => typeof s === 'string').slice(0, n).map(s => s.slice(0, 500)) : undefined; }
function cleanTool(x) {
  if (!x || typeof x.label !== 'string') return null;
  return { label: x.label.slice(0, 80), detail: strList(x.detail, 6) || [], sent: String(x.sent || '').slice(0, 8192),
           local: !!x.local, redacted: !!x.redacted, truncated: !!x.truncated, error: typeof x.error === 'string' ? x.error.slice(0, 60) : undefined };
}
function cleanTools(a) { const t = Array.isArray(a) ? a.slice(0, 10).map(cleanTool).filter(Boolean) : []; return t.length ? t : undefined; }
// One SSE frame ("event: x\ndata: {...}") -> {event, data}.
function sseFrame(frame) {
  let event = 'message'; const data = [];
  frame.split('\n').forEach(l => {
    if (l.startsWith('event:')) event = l.slice(6).trim();
    else if (l.startsWith('data:')) data.push(l.slice(5).replace(/^ /, ''));
  });
  let obj = null; try { obj = JSON.parse(data.join('\n')); } catch (e) { obj = null; }
  return { event, data: obj };
}
// The answer's SSE stream (POST /api/chat/stream, or a saved one in the static demo) -> `reply`
async function readAnswer(r, reply, alert) {
  if (!r.ok || !r.body) { const j = await r.json().catch(() => ({})); throw uiError(httpMsg(j, r.status)); }
  const reader = r.body.getReader(), dec = new TextDecoder();
  let buf = '', finished = false;
  while (!finished) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let cut;
    while ((cut = buf.indexOf('\n\n')) >= 0) {
      const ev = sseFrame(buf.slice(0, cut)); buf = buf.slice(cut + 2);
      if (ev.event === 'done') { finished = true; break; }
      if (ev.event === 'error') throw uiError((ev.data && ev.data.error) || T('app.chat.cut'));
      const d = ev.data;
      if (!d) continue;
      if (ev.event === 'status') { reply.status = cleanTool(Object.assign({ sent: '' }, d)); renderChatSoon(); }
      else if (ev.event === 'tool') {
        const x = cleanTool(d); reply.status = null;
        if (x) { (reply.tools = reply.tools || []).length < 10 && reply.tools.push(x); renderChatSoon(); }
      } else if (ev.event === 'note') {
        if (typeof d.text === 'string' && !(reply.notes || []).includes(d.text)) { (reply.notes = reply.notes || []).push(d.text.slice(0, 500)); renderChatSoon(); }
      } else if (ev.event === 'suggest') { reply.suggest = demoAnswerable(strList(d.questions, 6)); }
      else if (ev.event === 'usage') { reply.usage = cleanUsage(d); renderChatSoon(); }
      else if (ev.event === 'budget') { reply.budget = { text: String(d.text || '').slice(0, 500), alert }; }
      else if (typeof d.t === 'string') { reply.status = null; reply.content += d.t; renderChatSoon(); }
    }
  }
  if (!finished) throw uiError(T('app.chat.cut'));
}
// Round 9 W: the static demo's assistant = the offline answers saved at build time for the
// suggested questions (and the follow-ups they suggest); index.json lists them per language.
const DEMO_CHAT = { lang: '', idx: null, p: null };
function demoChatLoad() {
  const lang = S.lang;
  if (DEMO_CHAT.p && DEMO_CHAT.lang === lang) return DEMO_CHAT.p;
  DEMO_CHAT.lang = lang; DEMO_CHAT.idx = null;
  DEMO_CHAT.p = fetch(window.NWDemo.chatIndex(lang)).then(r => (r.ok ? r.json() : null)).catch(() => null).then(j => {
    const idx = { suggested: strList(j && j.suggested, 20) || [], answers: strList(j && j.answers, 40) || [], insight: !!(j && j.insight),
                  devices: strList(j && j.devices, 200) || [] };
    if (DEMO_CHAT.lang === lang) { DEMO_CHAT.idx = idx; if (chatHere()) render(); }
    return idx;
  });
  return DEMO_CHAT.p;
}
function demoChatIndex() { demoChatLoad(); return DEMO_CHAT.idx; }   // null until it has loaded (then it renders)
function demoAnswerable(list) {
  if (!DEMO || !list) return list;
  const idx = DEMO_CHAT.idx;
  return list.filter(q => idx && idx.answers.includes(q.trim()));
}
async function demoAnswer(mode, q, signal) {
  const idx = await demoChatLoad();
  // Round 10b: "Ask AI about this device" -> Ask, the pre-filled question as it was put in
  // the box: the device's own saved answer (found by its MAC, not by the name in the text)
  const ctx = S.chat.ctx;
  if (mode === 'chat' && ctx && idx.devices.includes(ctx.mac) &&
      String(q || '').trim() === T('app.ask_prefill', { name: ctx.name, mac: ctx.mac }).trim()) {
    return fetch(window.NWDemo.chatFile('device', ctx.mac, S.lang), { signal });
  }
  const ok = mode === 'insight' ? idx.insight : idx.answers.includes(String(q || '').trim());
  return ok ? fetch(window.NWDemo.chatFile(mode, q, S.lang), { signal }) : null;
}
async function chat(kind) {
  const c = S.chat;
  if (c.busy) return;
  let asked = null;
  if (kind === 'send') {
    const q = c.draft.trim(); if (!q) return;
    asked = { role: 'user', content: q };
    c.messages.push(asked); c.draft = '';
    const box = $('#chatq'); if (box) { box.value = ''; box.style.height = ''; }
  }
  const mode = kind === 'insight' ? 'insight' : 'chat';
  // what the model sees: every finished turn (a stopped reply's partial text included)
  const history = c.messages.filter(m => !m.err && m.content).map(m => ({ role: m.role, content: m.content }));
  const reply = { role: 'assistant', content: '', mode, pending: true };
  c.messages.push(reply);
  const ctrl = new AbortController(), alert = mode === 'chat' ? c.alert || null : null;
  const budgetOk = !!c.budgetOk;   // round 7 C: the user just said "send anyway" (one request only)
  c.alert = null; c.budgetOk = false;
  c.busy = true; c.ctrl = ctrl; c.follow = true; saveChat(); render(); scrollChat();
  try {
    const lastQ = mode === 'chat' && history.length ? history[history.length - 1].content : '';
    const r = DEMO ? await demoAnswer(mode, lastQ, ctrl.signal)
      : await fetch(url('/api/chat/stream'), { method: 'POST', headers: { 'content-type': 'application/json' }, signal: ctrl.signal,
        body: JSON.stringify({ mode, messages: mode === 'chat' ? history : [], mac: c.ctx ? c.ctx.mac : null, alert, lang: S.lang, budget_ok: budgetOk }) });
    if (r === null) reply.notes = [T('app.demo.chat_only')];   // the static demo has no answer to this one
    else await readAnswer(r, reply, alert);
  } catch (e) {
    if (e.name === 'AbortError') reply.stopped = true;
    else reply.err = errText(e);
  } finally {
    delete reply.pending; delete reply.status;
    AIQ.at = 0;   // the questions may have changed (e.g. one was just answered)
    // stopped before a word: drop the empty reply, and put the question back in the box
    // (to edit or send again) instead of leaving it unanswered in the conversation
    let restored = false;
    const budget = reply.budget && !reply.content ? reply.budget : null;
    if ((reply.stopped || budget) && !reply.content) {
      c.messages.pop();
      if (asked && c.messages[c.messages.length - 1] === asked && !c.draft) {
        c.messages.pop(); c.draft = asked.content; restored = true;
      }
    }
    c.busy = false; c.ctrl = null; saveChat(); render(); followChat(); c.follow = false;
    const box = restored && $('#chatq');
    if (box) { box.value = c.draft; box.focus(); }
    // nothing went out: the monthly budget is used up / this answer would cross it - ask
    // (Cancel keeps the question in the box; "Send anyway" sends it once)
    if (budget) {
      delete reply.budget;
      openConfirm({ icon: 'i-gauge', title: T('app.usage.budget_title'), text: budget.text, ok: T('app.usage.send_anyway'),
                    run: () => { c.budgetOk = true; c.alert = budget.alert; chat(restored ? 'send' : (mode === 'insight' ? 'insight' : 'retry')); } });
    }
  }
}
function retryChat() {
  const c = S.chat, last = c.messages[c.messages.length - 1];
  if (c.busy || !last || !last.err) return;
  c.messages.pop();
  chat(last.mode === 'insight' ? 'insight' : 'retry');
}
function openChat(opts) {
  opts = opts || {};
  const c = S.chat;
  if (opts.ctx !== undefined) c.ctx = opts.ctx;
  if (opts.draft != null) c.draft = opts.draft;
  c.alert = opts.alert || null;   // Stage Q: "Ask AI about this alert" (sent with the next question)
  if (S.base !== 'ai' && !c.open) { c.open = true; c.back = document.activeElement; }
  saveChat(); render();
  setTimeout(() => { const q = $('#chatq'); if (q) { q.focus({ preventScroll: true }); q.setSelectionRange(q.value.length, q.value.length); } scrollChat(); }, 30);
}
function closeChat() {
  const c = S.chat; if (!c.open) return;
  c.open = false; saveChat(); render();
  const back = c.back; c.back = null;
  if (back && back !== document.body && document.contains(back) && !$('#chatpanel').contains(back)) back.focus({ preventScroll: true });
  else if (drawerOpen()) { const x = $('#drawer [data-act="close"]'); if (x) x.focus({ preventScroll: true }); }   // keep Esc going to the drawer
  else $('#btnChat').focus({ preventScroll: true });   // opened by a shortcut: back to the button that opens it
}
function toggleChat() { if (S.base === 'ai') { const q = $('#chatq'); if (q) q.focus(); } else if (S.chat.open) closeChat(); else openChat(); }

// ---------------------------------------------------------------------------------------
// Desktop notifications (opt-in, this tab only): new alerts that the automatic refresh
// finds pop up as system notifications. Permission is requested only from the toggle's
// click. Keys already notified (or present when notifications were turned on / the page
// was opened) are remembered, so nothing is ever announced twice.
const NOTIFY_KEY = 'netwarden.notify', NOTIFIED_KEY = 'netwarden.notified', NOTIFIED_MAX = 400;
function notifySupported() { return typeof window.Notification === 'function'; }
function notifyState() {
  if (!notifySupported()) return 'unsupported';
  if (Notification.permission === 'denied') return 'denied';
  return S.notify.on && Notification.permission === 'granted' ? 'on' : 'off';
}
const notifiedKey = () => NOTIFIED_KEY + '.' + dbId();   // one set per database
function loadNotified() {
  try { const a = JSON.parse(localStorage.getItem(notifiedKey()) || '[]'); return new Set(Array.isArray(a) ? a : []); } catch (e) { return new Set(); }
}
function saveNotified(set) {
  try { localStorage.setItem(notifiedKey(), JSON.stringify(Array.from(set).slice(-NOTIFIED_MAX))); } catch (e) { /* private mode */ }
}
function markSeen() { const s = loadNotified(); notifyItems().forEach(it => s.add(it.k)); saveNotified(s); }
// Stage Q: what may pop up comes from the server's ONE gate (GET /api/notify, notify.route):
// alerts + presence arrivals / departures that are not held by quiet hours, and the
// "while you were asleep" summary once the window has ended.
function notifyItems() {
  const n = S.data.notify;
  if (!n) return [];
  return (n.deliver || []).map(d => ({ k: d.key, tag: d.tag, plain: d.text, href: d.href, mac: d.mac }))
    .concat((n.summaries || []).map(s => ({ k: s.key, summary: s, tag: s.title, plain: s.text, href: '#/inbox' })));
}
async function toggleNotify() {
  if (notifyState() === 'on') {
    S.notify.on = false;
    try { localStorage.setItem(NOTIFY_KEY, '0'); } catch (e) { /* private mode */ }
    render(); toast(T('app.notify.off_toast')); return;
  }
  if (!notifySupported()) { toast(T('app.notify.unsupported'), { kind: 'err' }); return; }
  let p = Notification.permission;
  if (p === 'default') { try { p = await Notification.requestPermission(); } catch (e) { p = 'denied'; } }
  if (p !== 'granted') { render(); toast(T('app.notify.denied'), { kind: 'err' }); return; }
  S.notify.on = true;
  try { localStorage.setItem(NOTIFY_KEY, '1'); } catch (e) { /* private mode */ }
  markSeen(); render(); toast(T('app.notify.on_toast'));
}
// After every refresh: announce what the server says is new. The first data of a page
// load only primes the memory (the page itself shows those) - except an unseen quiet-hours
// summary, which is news exactly once (its key is remembered like any other).
function checkNotify() {
  if (!S.data.notify) return;
  const seen = loadNotified();
  // during quiet hours even last night's summary does not pop up (its card is on the page);
  // it stays un-announced and pops up once the window ends
  const hush = !!(S.data.notify.quiet && S.data.notify.quiet.active);
  const items = notifyItems().filter(it => !(hush && it.summary));
  if (!S.notify.primed) {
    S.notify.primed = true;
    const sums = items.filter(it => it.summary && !seen.has(it.k));
    items.forEach(it => seen.add(it.k)); saveNotified(seen);
    sums.forEach(announce);
    return;
  }
  const fresh = items.filter(it => !seen.has(it.k));
  if (!fresh.length) return;
  fresh.forEach(it => seen.add(it.k)); saveNotified(seen);
  const sums = fresh.filter(it => it.summary), rest = fresh.filter(it => !it.summary);
  sums.forEach(announce);
  if (!rest.length) return;
  if (rest.length > 3) announce({ many: rest });
  else rest.forEach(announce);
}
// One notification: a toast in the page and, when switched on, a system notification.
function announce(it) {
  const title = it.many ? T('app.notify.many', { n: fmt.num(it.many.length) }) : (it.summary ? it.summary.title : T('app.notify.msg_title', { tag: it.tag }));
  const body = it.many ? it.many.slice(0, 3).map(x => x.plain).join('\n')
    : (it.summary ? [it.summary.text].concat(it.summary.items.slice(0, 3).map(x => x.text)).join('\n') : it.plain);
  const href = it.many ? '#/inbox' : (it.href || (it.mac ? devHref(it.mac) : '#/security'));
  if (document.visibilityState === 'visible') toast(it.many || it.summary ? title : it.tag + ': ' + it.plain);
  if (notifyState() !== 'on') return;
  try {
    const n = new Notification(title, { body, tag: 'netwarden:' + (it.many ? 'many' : it.k), icon: url('/static/icon.svg') });
    n.onclick = () => { window.focus(); go(href); n.close(); };
  } catch (e) { /* e.g. a mobile browser that only allows notifications from a service worker */ }
}
// "While you were asleep": the unseen summaries (Overview + Inbox); Close = seen, with Undo
function quietCards() {
  const n = S.data.notify, list = (n && n.summaries) || [];
  // two nights read the same ("23:00-07:00"): then each card names its night
  const many = list.length > 1;
  return list.map(s => html`<section class="card quiet-sum" data-key="qs-${s.id}">
    <div class="card-h"><h2>${icon('i-moon')}${s.title}${many && s.win ? html` <span class="muted">· ${fmt.day(s.win)}</span>` : ''}</h2><div class="card-a">
      <button type="button" class="btn sm ghost" data-act="quiet-seen" data-id="${s.id}">${T('app.quiet.dismiss')}</button></div></div>
    <p class="muted" style="margin:0 0 var(--s2)">${s.text}</p>
    <ul class="plain quiet-items">${s.items.map((it, i) => html`<li data-key="${i}"><a href="${it.href}">${it.text}</a></li>`)}</ul>
    ${s.more ? html`<a class="more-link" href="#/inbox">${T('app.quiet.more', { n: fmt.num(s.more) })}</a>` : ''}</section>`);
}
async function quietSeen(id, seen) {
  try {
    await postJSON('/api/notify/seen', { id, seen });
    delete lastTag['notify' + S.lang]; delete lastTag['overview' + S.lang];   // the next refresh takes the server's list as it is
    if (seen && S.data.notify) S.data.notify.summaries = S.data.notify.summaries.filter(s => s.id !== id);
    render();
    if (seen) toast(T('app.quiet.closed'), { undo: () => quietSeen(id, false) }); else refresh();
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------------------
// Keyboard: one list feeds the "?" sheet and the System card. "g" then a letter jumps.
const GO_KEYS = { o: 'overview', n: 'inbox', d: 'devices', s: 'security', h: 'health', t: 'suggestions', p: 'privacy',
                  a: 'activity', f: 'family', i: 'ai', y: 'system', e: 'settings', w: 'people', m: 'map', r: 'report' };
// Round 9 U (WCAG 2.1.4): single-key shortcuts (letters, digits, "/", "?") can be turned
// off - the home's default is the setting ui.shortcuts (/api/meta "shortcuts"), each
// browser may choose for itself (localStorage). Ctrl/Cmd+K, Ctrl/Cmd+Z, Esc, Enter and the
// keys inside the focused map / palette always work.
const SINGLE_KEY = 'netwarden.single_keys';
function singleKeys() {
  let v = null; try { v = localStorage.getItem(SINGLE_KEY); } catch (e) { /* private mode */ }
  if (v === '1' || v === '0') return v === '1';
  return !(S.meta && S.meta.shortcuts === false);
}
function setSingleKeys(on) {
  try { localStorage.setItem(SINGLE_KEY, on ? '1' : '0'); } catch (e) { /* private mode */ }
  toast(T(on ? 'app.key.single_on_toast' : 'app.key.single_off_toast'));
  if (S.keys.open) keysBody();
  render();
}
// "/" = the page's own filter box (Devices, Map, the People picker); else the palette
function focusFilter() {
  if (drawerOpen()) return false;
  const f = document.querySelector('#view [data-filter="q"], #view [data-mapf="q"], #view [data-ppl-q]');
  if (!f || f.offsetParent === null) return false;
  f.focus(); f.select(); return true;
}
function shortcutRows() {
  const k = s => html`<kbd>${s}</kbd>`;
  return [
    [html`${k('?')}`, T('app.key.help')],
    [html`${k(MOD)}+${k('K')}`, T('app.key.palette')],
    [html`${k('/')}`, T('app.key.filter')],
    ...Object.entries(GO_KEYS).map(([l, s]) => [html`${k('g')} ${T('app.key.then')} ${k(l)}`, T('app.palette.go', { section: T('app.nav.' + s) })]),
    [html`${k('1')}–${k(String(GROUPS.length))}`, T('app.key.nav')],
    [html`${k('j')} ${k('k')} · ${k('a')} ${k('t')} ${k('m')} ${k('s')} ${k('d')} · ${k('x')} · ${k('u')}`, T('app.key.inbox')],
    [html`${k('c')}`, T('app.key.chat')],
    [html`${k('R')}`, T('app.refresh')],
    [html`${k(MOD)}+${k('Z')}`, T('app.key.undo')],
    [html`${k('+')} ${k('−')} · ${k('←')}${k('↑')}${k('→')}${k('↓')} · ${k('0')}`, T('app.key.map')],
    [html`${k('Enter')}`, T('app.key.send')],
    [html`${k('Shift')}+${k('Enter')}`, T('app.key.newline')],
    [html`${k('Esc')}`, T('app.key.close')],
  ];
}
function shortcutTable() {
  return html`<div class="kbds">${shortcutRows().map(([keys, what]) => html`<span class="kk">${keys}</span><span>${what}</span>`)}</div>`;
}
function singleKeysField(id) {
  const on = singleKeys();
  return html`<div class="field"><span id="${id}">${T('app.key.single')}</span>
    <div class="toggle-row"><button type="button" class="switch" role="switch" aria-checked="${String(on)}" aria-labelledby="${id}" aria-describedby="${id}-h" data-act="single-keys"><i></i></button>
      <span class="muted">${T(on ? 'app.notify.on' : 'app.notify.off')}</span></div>
    <p class="hint" id="${id}-h" style="margin:0">${T('app.key.single_hint')}</p></div>`;
}
function keysBody() {
  morph($('#keysbody'), html`<header class="sheet-h" data-key="h"><h2 id="keys-title">${icon('i-keyboard')}${T('app.sys.shortcuts')}</h2>
    <button type="button" class="btn icon ghost" data-act="keys-close" aria-label="${T('app.close')}" title="${T('app.close')} (Esc)">${icon('i-x')}</button></header>
    <div class="keys-pref" data-key="pref">${singleKeysField('keys-single')}</div>
    ${singleKeys() ? '' : html`<p class="hint keys-off" data-key="off">${icon('i-alert')} ${T('app.key.single_note_off', { mod: MOD })}</p>`}
    <div data-key="tbl">${shortcutTable()}</div>`);
}
function openKeys() {
  if (S.keys.open) return;
  closePalette(true);
  S.keys = { open: true, back: document.activeElement };
  keysBody();
  $('#keysheet').hidden = false;
  $('#keysheet [data-act="keys-close"]').focus();
}
function closeKeys() {
  if (!S.keys.open) return;
  $('#keysheet').hidden = true;
  const back = S.keys.back; S.keys = { open: false };
  if (back && document.contains(back)) back.focus({ preventScroll: true });
}

// ---------------------------------------------------------------------------------------
// Report (round 9 X): the shareable home-network report - one file, made on the server
// (report.py) at the privacy level chosen here. Preview opens the real file in a new tab;
// "full" (addresses, names, domains) is for an admin only - the server checks it too.
const SHARE_OPTS = { period: ['7', '30'], privacy: ['shareable', 'minimal', 'full'], names: ['type', 'keep'],
                     people: ['roles', 'keep'], format: ['html', 'md'] };
function shareUrl(o, extra) {
  const q = new URLSearchParams({ period: o.period, privacy: o.privacy, names: o.names, people: o.people, format: o.format });
  return '/api/report?' + q.toString() + (extra || '');
}
function shareSeg(key, labels, o, dis) {
  return html`<div class="seg" role="group" aria-labelledby="share-${key}">${SHARE_OPTS[key].map(v => html`<button type="button" data-act="share-opt" data-k="${key}" data-v="${v}" aria-pressed="${String(o[key] === v)}"${dis && dis(v) ? ' disabled' : ''}>${labels(v)}</button>`)}</div>`;
}
function viewReport() {
  const o = S.share, admin = !S.meta.remote, scrub = o.privacy === 'shareable';
  if (o.privacy === 'full' && !admin) o.privacy = 'shareable';
  if (o.privacy === 'full' && DEMO) o.privacy = 'shareable';   // the static demo has no full level
  const field = (key, label, body, hint) => html`<div class="field"><span id="share-${key}">${label}</span>${body}${hint ? html`<p class="hint" style="margin:0">${hint}</p>` : ''}</div>`;
  return html`${phead(T('app.nav.report'), T('app.share.sub'), demoPill())}
    <div class="grid">
      ${card({ key: 'share-opts', cls: 'span2', icon: 'i-sliders', title: T('app.share.options'), body: html`<div class="stack share-form">
        ${field('period', T('app.share.period'), shareSeg('period', v => T('app.share.days', { n: v }), o))}
        ${field('privacy', T('app.share.privacy'), shareSeg('privacy', v => T('share.level.' + v), o, v => v === 'full' && !admin),
                html`${T('share.level_desc.' + o.privacy)}${admin ? '' : html` ${T('app.share.full_admin')}`}`)}
        ${scrub ? field('names', T('app.share.names'), shareSeg('names', v => T('app.share.names_' + v), o)) : ''}
        ${scrub ? field('people', T('app.share.people'), shareSeg('people', v => T('app.share.people_' + v), o)) : ''}
        ${field('format', T('app.share.format'), shareSeg('format', v => T('app.share.fmt_' + v), o))}
        <div class="ai-acts">
          <a class="btn" href="${api(shareUrl(o))}" download="${DEMO ? `netwarden-report-${o.period}d-${o.privacy}.${o.format}` : ''}">${icon('i-download')}${T('app.share.download')}</a>
          <a class="btn ghost" href="${api(shareUrl(o, '&inline=1'))}" target="_blank" rel="noopener">${icon('i-expand')}${T('app.share.preview')}</a>
          <button type="button" class="btn ghost" data-act="share-copy">${icon('i-copy')}${T('app.share.copy_md')}</button>
        </div>
        <p class="hint" style="margin:0">${T('app.share.hint')}</p></div>` })}
      ${card({ key: 'share-what', icon: 'i-print', title: T('app.share.what'), body: html`<p style="margin:0">${T('app.share.what_text')}</p>` })}
    </div>`;
}
async function shareCopy(b) {
  try {
    const r = await fetch(api(shareUrl(Object.assign({}, S.share, { format: 'md' }))), { cache: 'no-store' });
    if (needPair(r)) return;
    const t = await r.text();
    if (!r.ok) { let j = {}; try { j = JSON.parse(t); } catch (e) { /* not JSON */ } throw new Error(httpMsg(j, r.status)); }
    await copyText(t, b);
  } catch (e) { toast(errText(e), { kind: 'err' }); }
}

// ---------------------------------------------------------------------------------------
// System: health, setup, exports, preferences, shortcuts
function srcState(s) {
  if (!s.configured) return s.reason ? 'unavailable' : 'off';
  if (s.last_error_ts && (!s.last_ok_ts || s.last_error_ts > s.last_ok_ts)) return 'error';
  if (!s.last_ok_ts) return 'never';
  return s.stale ? 'stale' : 'ok';
}
const STATE_TAG = { ok: 'tag-ok', stale: 'tag-warn', error: 'tag-bad', never: 'tag-warn' };
function viewSystem() {
  const st = S.data.status;
  if (!st) return skeleton(3);
  const db = st.db, loops = Object.entries(st.loops || {});
  // like health.ai_line(): offline by choice (--offline-ai / add-on option / settings) is not "no key"
  const why = st.ai.mode === 'offline' && ['forced', 'addon', 'chosen'].includes(st.ai.reason) ? '_' + st.ai.reason : '';
  const aiMode = T('status.ai.' + st.ai.mode + why);
  return html`${phead(T('app.nav.system'), T('app.sys.version', { version: st.version }), demoPill())}
    <div class="grid">
      ${card({ key: 'sources', cls: 'span2', icon: 'i-pulse', title: T('app.sys.sources'), body: html`<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>${T('status.col_source')}</th><th>${T('status.col_state')}</th><th>${T('status.col_last_ok')}</th><th class="num">${T('status.col_count')}</th></tr></thead>
        <tbody>${Object.entries(st.sources).map(([name, s]) => { const w = srcState(s); return html`<tr data-key="${name}">
          <td>${T('status.src.' + name)}${w === 'error' && s.last_error ? html`<div class="muted" style="font-size:var(--fs-xs)">${T('app.sys.last_error', { error: s.error_text || s.last_error })}</div>` : ''}</td>
          <td><span class="tag ${STATE_TAG[w] || ''}">${T('status.state.' + w)}</span></td>
          <td>${s.last_ok_ts ? html`<span title="${fmt.date(s.last_ok_ts)}">${fmt.rel(s.last_ok_ts)}</span>` : '—'}</td>
          <td class="num">${s.last_count == null ? '—' : fmt.num(s.last_count)}</td></tr>`; })}</tbody></table></div>
        <h3 class="hint">${(st.hints || []).length ? T('status.hints') : T('status.all_good')}</h3>
        ${(st.hints || []).length ? html`<ul class="plain">${st.hints.map(h => html`<li>${h}</li>`)}</ul>` : ''}` })}
      ${card({ key: 'engine', icon: 'i-box', title: T('app.sys.engine'), body: html`<dl class="facts">
        <dt>${T('app.sys.ai')}</dt><dd>${st.ai.mode === 'offline' ? aiMode : aiMode + ' · ' + st.ai.model}</dd>
        <dt>${T('app.sys.db')}</dt><dd>${T('status.db', { size: fmt.bytes(db.size_bytes), devices: fmt.num(db.devices), dns: fmt.num(db.dns_events), traffic: fmt.num(db.traffic_samples) }).replace(/^[^:：{·]*[:：]\s*/u, '')}</dd>
        <dt>${T('app.sys.history')}</dt><dd>${db.oldest_ts ? fmt.date(db.oldest_ts) + ' → ' + fmt.date(db.newest_ts) : '—'} · ${T('app.sys.retention', { days: db.retention_days })}</dd>
        <dt>${T('status.loops').replace(/\s*[:：]\s*$/u, '')}</dt><dd>${loops.length ? html`<ul class="plain" style="margin:0;padding-left:16px">${loops.map(([n, lp]) => html`<li>${T('status.loop_line', { name: T('cli.loop.' + n), interval: fmt.dur(lp.interval_s), state: T(lp.running ? 'status.loop_running' : 'status.loop_stopped') })}</li>`)}</ul>` : T('app.sys.no_loops')}</dd>
      </dl>` })}
      ${card({ key: 'exports', icon: 'i-download', title: T('app.sys.exports'), body: html`<div class="chips">
        <a class="btn ghost" href="${api('/api/export/devices.csv')}" download>${T('ui.export_csv')}</a>
        <a class="btn ghost" href="${api('/api/export/report.md')}" download>${T('ui.export_report')}</a>
        <a class="btn ghost" href="#/report">${icon('i-print')}${T('app.palette.report')}</a></div>
        <div class="hint">${T('app.sys.exports_hint')}</div>` })}
      ${card({ key: 'prefs', icon: 'i-sliders', title: T('app.sys.prefs'), body: html`<div class="stack">
        <div class="field"><span>${T('app.theme')}</span><div class="seg" role="group" aria-label="${T('app.theme')}">${THEMES.map(t => html`<button type="button" data-act="theme" data-v="${t}" aria-pressed="${String(S.theme === t)}">${icon(THEME_ICON[t])}${T('app.theme.' + t)}</button>`)}</div></div>
        <label class="field"><span>${T('ui.language')}</span><select name="lang" data-act="lang" aria-label="${T('ui.language')}">${(S.meta.languages || []).map(l => html`<option value="${l.code}"${l.code === S.lang ? ' selected' : ''}>${l.name}</option>`)}</select></label>
        ${notifyField()}${singleKeysField('prefs-single')}</div>` })}
      ${S.meta.remote ? phoneCard() : card({ key: 'tosettings', icon: 'i-gear', title: T('app.nav.settings'), body: html`
        <p class="muted" style="margin:0">${T('app.sys.settings_text')}</p>
        <div class="ai-acts"><a class="btn" href="#/settings">${icon('i-gear')}${T('app.sys.open_settings')}</a></div>` })}
      ${setupCard()}
      ${card({ key: 'keys', icon: 'i-keyboard', title: T('app.sys.shortcuts'), body: shortcutTable() })}
    </div>`;
}
function notifyField() {
  const st = notifyState(), on = st === 'on';
  return html`<div class="field"><span id="notify-l">${T('app.notify.title')}</span>
    <div class="toggle-row"><button type="button" class="switch" role="switch" aria-checked="${String(on)}" aria-labelledby="notify-l" data-act="notify"${st === 'unsupported' ? ' disabled' : ''}><i></i></button>
      <span class="muted">${T(on ? 'app.notify.on' : 'app.notify.off')}</span></div>
    <p class="hint" style="margin:0">${T(st === 'unsupported' ? 'app.notify.unsupported' : (st === 'denied' ? 'app.notify.denied' : 'app.notify.hint'))}</p></div>`;
}

// ---------------------------------------------------------------------------------------
// Stage M: "Open on your phone" (System). On this computer: LAN mode state, the pairing
// QR code (POST /api/pair/new - the code only ever travels in the URL fragment), the
// paired browsers with Revoke. On a paired phone: what it may do here + Sign out.
async function loadPair() {
  if (S.meta.remote) return;
  try { S.pair.s = await getJSON('/api/pair/sessions'); S.pair.err = null; } catch (e) { S.pair.err = errText(e); }
  render();
}
const pairExpired = c => !!c && parseTs(c.expires_at) <= nowMs();
function pairCodeBox() {
  const c = S.pair.code;
  if (!c) return '';
  if (pairExpired(c)) return html`<div class="pair-code" data-key="code"><p class="hint warn" role="status">${T('app.pair.expired')}</p></div>`;
  const plain = c.url.slice(0, c.url.indexOf('#'));
  return html`<div class="pair-code" data-key="code">
    <img class="pair-qr" src="${c.qr}" alt="${T('app.pair.qr_alt')}" width="220" height="220">
    <ol class="pair-steps">
      <li>${T('app.pair.step_scan')}</li>
      <li>${T('app.pair.step_type', { url: plain })}<div class="pair-big mono" aria-label="${T('app.pair.code_label')}">${c.code}</div></li>
      <li class="muted">${T('app.pair.expires', { time: fmt.date(c.expires_at) })}</li>
    </ol></div>`;
}
function pairRow(s) {
  return html`<li class="pair-row" data-key="s${s.id}">${icon('t-phone')}
    <div class="pr-main"><b>${s.device || T('app.pair.unknown_device')}</b>${s.current ? html` <span class="tag tag-ok">${T('app.pair.this_browser')}</span>` : ''}${s.admin ? html` <span class="tag tag-warn" title="${T('app.pair.admin_title')}">${icon('i-gear')}${T('app.pair.admin_badge')}</span>` : ''}
      <div class="muted pr-sub">${T('app.pair.paired_at', { when: fmt.date(s.created_at) })} · ${T('app.pair.last_used', { when: fmt.rel(s.last_seen) })}</div></div>
    <button type="button" class="btn sm ghost" data-act="pair-revoke" data-id="${s.id}" data-name="${s.device || T('app.pair.unknown_device')}">${T('app.pair.revoke')}</button></li>`;
}
// Round 6: the address phones should use when the detected one is wrong (Docker bridge,
// reverse proxy) - the registry's lan.advertised_url, saved like any settings field.
function advertisedForm() {
  const it = aiItem('lan.advertised_url');
  if (!it.key) return '';
  return html`<form class="set-form" data-set-form="phone" data-key="adv" novalidate>${setField(it)}
    ${it.editable ? html`<div class="ai-acts"><button type="submit" class="btn sm"${S.set.saving === 'phone' ? ' disabled' : ''}>${icon('i-check')}${T('app.ai.save')}</button></div>` : ''}</form>`;
}
// Under WSL the Hyper-V firewall drops a phone's connection: the two admin PowerShell
// lines that allow / remove a rule for the port (shown and copyable, never run by us).
function wslFirewallBox(w, open) {
  if (!w) return '';
  const port = (w.allow.match(/-LocalPorts (\d+)/) || [])[1] || '';
  const box = (id, title, text) => html`<div><div class="rh"><span id="${id}-l">${title}</span>${copyBtn(text)}</div>
    <textarea class="rule" id="${id}" name="${id}" readonly rows="2" aria-labelledby="${id}-l">${text}</textarea></div>`;
  return html`<details class="wsl-fw" data-key="wsl"${open ? ' open' : ''}><summary>${icon('i-alert')} ${T('app.pair.wsl_title')}</summary>
    <p class="muted">${T('app.pair.wsl_intro', { port })}</p>
    <div class="rules">${box('wsl-allow', w.subnet ? T('app.pair.wsl_allow_subnet', { subnet: w.subnet }) : T('app.pair.wsl_allow'), w.allow)}
      ${box('wsl-remove', T('app.pair.wsl_remove'), w.remove)}</div>
    <p class="hint">${T('app.pair.wsl_note', { port })}</p></details>`;
}
function phoneCard() {
  const title = T('app.pair.title');
  if (S.meta.remote) {
    return card({ key: 'phone', icon: 't-phone', title: T('app.pair.remote_title'), body: html`
      <p class="muted" style="margin:0">${T('app.pair.remote_intro')}</p>
      <div class="ai-acts"><button type="button" class="btn ghost" data-act="logout">${icon('i-x')}${T('app.pair.sign_out')}</button></div>` });
  }
  const P = S.pair, s = P.s;
  if (!s) return card({ key: 'phone', cls: 'span2', icon: 't-phone', title, body: P.err ? empty('i-alert', P.err) : html`<div class="skel w8"></div><div class="skel w6"></div>` });
  const it = aiItem('lan.enabled'), want = !!s.lan_setting;
  // Stage H: in Home Assistant (ingress) the add-on's lan_access option decides LAN mode,
  // and a code only makes sense for a phone on the LAN
  const ha = !!S.meta.addon;
  const canPair = s.lan || (s.require_auth && !ha), list = s.sessions || [];
  return card({ key: 'phone', cls: 'span2', icon: 't-phone', title, body: html`
    <p class="muted" style="margin:0 0 var(--s3)">${T('app.pair.intro')}</p>
    <dl class="facts"><dt>${T('app.pair.lan')}</dt><dd>${s.lan ? html`<span class="tag tag-ok">${icon('i-check')}${T('app.pair.lan_on')}</span> <span class="mono">${s.url}</span>`
                                                  : html`<span class="tag">${T('app.pair.lan_off')}</span>`}</dd></dl>
    ${s.lan || ha ? '' : html`<p class="hint" style="margin-top:0">${T('app.pair.lan_off_hint', { cmd: 'python3 -m netwarden run --lan' })}</p>`}
    <div class="field"><span id="lan-l">${T('settings.lan.enabled')}</span>
      <div class="toggle-row"><button type="button" class="switch" role="switch" aria-checked="${String(want)}" aria-labelledby="lan-l" data-act="lan-toggle"${it.editable && !P.busy && !ha ? '' : ' disabled'}><i></i></button>
        <span class="muted">${ha ? T('app.pair.addon_lan', { option: 'lan_access' }) : it.editable === false && it.env ? envLocked(it.env) : T('app.pair.restart_note')}</span></div></div>
    ${advertisedForm()}
    <p class="hint warn pair-warn">${icon('i-alert')} ${T('app.pair.http_warning')}</p>
    ${S.meta.admin_session ? html`<p class="hint warn" data-key="admin-note">${icon('i-gear')} ${T('app.pair.admin_session_note')}</p>` : ''}
    ${s.require_auth && !ha ? html`<p class="hint">${T('app.pair.require_auth_note')}</p>` : ''}
    ${wslFirewallBox(s.wsl_firewall, s.lan)}
    <div class="ai-acts">
      <button type="button" class="btn" data-act="pair-new"${canPair && !P.busy ? '' : ' disabled'} aria-describedby="pair-note">${icon('i-plus')}${T(P.code ? 'app.pair.new_code' : 'app.pair.show_code')}</button>
      ${P.code ? html`<button type="button" class="btn ghost" data-act="pair-hide">${T('app.pair.hide_code')}</button>` : ''}
      ${S.meta.signed_in ? html`<button type="button" class="btn ghost" data-act="logout">${T('app.pair.sign_out')}</button>` : ''}
    </div>
    <div class="hint" id="pair-note">${canPair ? '' : T('app.pair.need_lan')}</div>
    <div aria-live="polite">${pairCodeBox()}</div>
    <h3 class="hint">${T('app.pair.devices')}</h3>
    ${list.length ? html`<ul class="plain pair-list">${list.map(pairRow)}</ul>
      <div class="ai-acts"><button type="button" class="btn sm ghost danger" data-act="pair-revoke-all">${T(P.confirmAll ? 'app.pair.revoke_confirm' : 'app.pair.revoke_all')}</button></div>`
                  : html`<p class="muted" style="margin:0">${T('app.pair.none')}</p>`}` });
}
async function pairNew() {
  const P = S.pair;
  if (P.busy) return;
  P.busy = true; render();
  try { P.code = await postJSON('/api/pair/new', {}); } catch (e) { fail(e); }
  finally { P.busy = false; render(); }
  const img = $('.pair-qr'); if (img) img.scrollIntoView({ block: 'nearest' });
}
async function pairRevoke(id, name) {
  try { await postJSON('/api/pair/revoke', { id }); toast(T('app.pair.revoked', { device: name })); } catch (e) { fail(e); }
  loadPair();
}
let confirmTimer = null;
async function pairRevokeAll() {
  const P = S.pair;
  if (!P.confirmAll) {   // two steps: the first click only asks
    P.confirmAll = true; render();
    clearTimeout(confirmTimer); confirmTimer = setTimeout(() => { P.confirmAll = false; render(); }, 5000);
    return;
  }
  clearTimeout(confirmTimer); P.confirmAll = false;
  try { const r = await postJSON('/api/pair/revoke_all', {}); P.code = null; toast(T('app.pair.revoked_all', { n: r.revoked })); } catch (e) { fail(e); }
  loadPair();
}
async function toggleLan() {
  const P = S.pair, cur = !!(P.s && P.s.lan_setting);
  P.busy = true; render();
  try {
    S.ai.s = await postJSON('/api/settings', { values: { 'lan.enabled': !cur } });
    toast(T(cur ? 'app.pair.lan_setting_off' : 'app.pair.restart_needed'));
    await loadPair();
  } catch (e) { fail(e); }
  finally { P.busy = false; render(); }
}
async function signOut() {
  try { await postJSON('/api/session/logout', {}); } catch (e) { fail(e); return; }
  location.replace(url('/pair'));
}

// ---------------------------------------------------------------------------------------
// Private AI (System -> AI card): which AI answers, where its prompts go, name hiding, and
// "Test connection" for a local / LAN model server. Settings come from GET /api/settings;
// a value set in .env is shown read-only. Keys are never shown - only "configured".
const AI_KEYS = ['ai.provider', 'ai.base_url', 'ai.model', 'ai.redact', 'ai.tools', 'ai.max_tool_rounds'];
const AI_OPT = { 'ai.provider': 'app.ai.provider.', 'ai.redact': 'app.ai.redact.', 'ai.tools': 'app.ai.tools.' };
async function loadAI() {
  if (S.meta.remote) return;   // settings belong to the computer running netwarden
  const u = getJSON('/api/ai/usage').then(j => { S.ai.usage = j; }, e => { S.ai.usage = { err: errText(e) }; });
  try { S.ai.s = await getJSON('/api/settings'); } catch (e) { S.ai.err = errText(e); }
  await u;
  render();
}
// Round 7 C: Settings -> "AI usage": this month's answers, tokens and estimated cost, the
// optional budget as a bar, and where the prices come from. The fields below it (budget,
// warn at, own prices) are ordinary registry settings (section "usage").
function budgetBar(b) {
  const pct = Math.min(100, Math.round(100 * (b.share || 0)));
  const tag = { ok: 'tag-ok', near: 'tag-warn', over: 'tag-bad' }[b.state] || '';
  return html`<div class="budget lvl-${b.state}"><div class="budget-h"><span>${T('app.usage.budget_line', { spent: usd(b.spent), limit: usd(b.limit) })}</span>
      <span class="tag ${tag}">${T('app.usage.state_' + b.state, { pct: fmt.pct(b.share || 0) })}</span></div>
    <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}" aria-label="${T('app.usage.budget_used')}"><i style="--w:${pct}%"></i></div></div>`;
}
const USAGE_WARN = ['price_half', 'budget_unchecked'];   // usage.warnings()
function usageStatus() {
  const u = S.ai.usage;
  if (!u) return html`<div class="skel w8"></div>`;
  if (u.err) return html`<p class="hint bad" role="alert">${icon('i-alert')} ${u.err}</p>`;
  const m = u.month, b = u.budget;
  const price = u.ai_mode === 'offline' ? T('app.usage.offline_hint') : (u.local ? T('app.usage.local_hint')
    : (u.price ? T(u.price.source === 'settings' ? 'app.usage.price_own' : 'app.usage.price_hint', { date: u.prices_checked }) : T('app.usage.no_price')));
  return html`<div class="usage-sum" data-key="usage-sum">
    <p class="muted" style="margin:0 0 var(--s2)">${T('app.usage.intro')}</p>
    <dl class="facts"><dt>${T('app.usage.month')}</dt><dd>${T('app.usage.month_line', { n: fmt.num(m.answers), tokens: fmt.num(m.tokens) })}</dd>
      <dt>${T('app.usage.month_cost')}</dt><dd>${m.priced ? usd(m.cost_usd) : '—'}${m.unpriced ? html` <span class="muted">${T('app.usage.unpriced', { n: fmt.num(m.unpriced) })}</span>` : ''}</dd>
      ${m.cache_read_tokens ? html`<dt>${T('app.usage.cache_read')}</dt><dd>${fmt.num(m.cache_read_tokens)}</dd>` : ''}</dl>
    ${b.limit ? budgetBar(b) : html`<p class="hint">${T('app.usage.no_budget')}</p>`}
    ${(Array.isArray(u.warnings) ? u.warnings : []).filter(w => USAGE_WARN.includes(w)).map(w => html`<div class="msg-note warn" role="status" data-key="w-${w}">${icon('i-alert')}<span>${T('app.usage.warn_' + w)}</span></div>`)}
    ${m.by_model.length ? html`<div class="tbl-wrap"><table class="tbl usage-tbl"><thead><tr><th scope="col">${T('app.usage.model')}</th><th scope="col" class="num">${T('app.usage.answers')}</th>
      <th scope="col" class="num">${T('app.usage.tokens')}</th><th scope="col" class="num">${T('app.usage.cost')}</th></tr></thead>
      <tbody>${m.by_model.map((r, j) => html`<tr data-key="r${j}"><td>${r.provider} · ${r.model}</td><td class="num">${fmt.num(r.answers)}</td><td class="num">${fmt.num(r.tokens)}</td>
        <td class="num">${r.cost_usd == null ? '—' : usd(r.cost_usd)}</td></tr>`)}</tbody></table></div>` : ''}
    <p class="hint">${price}${m.estimated ? ' ' + T('app.usage.some_estimated') : ''}</p></div>`;
}
function aiItem(k) { return ((S.ai.s && S.ai.s.items) || []).find(i => i.key === k) || {}; }
function aiVal(k) { return k in S.ai.form ? S.ai.form[k] : (aiItem(k).value == null ? '' : aiItem(k).value); }
function aiField(k, label, control, hint) {
  const it = aiItem(k);
  return html`<label class="field"><span>${label}</span>${control}
    ${!it.editable && it.env ? html`<span class="hint">${icon('i-sliders')} ${envLocked(it.env)}</span>` : (hint ? html`<span class="hint">${hint}</span>` : '')}</label>`;
}
function aiSelect(k, opts) {
  const it = aiItem(k), v = aiVal(k);
  return html`<select name="${k}" data-ai="${k}" aria-label="${T('settings.' + k)}"${it.editable ? '' : ' disabled'}>${opts.map(o => html`<option value="${o}"${o === v ? ' selected' : ''}>${T(AI_OPT[k] + o)}</option>`)}</select>`;
}
function aiNumber(k) {
  const it = aiItem(k);
  return html`<input type="number" name="${k}" data-ai="${k}" value="${aiVal(k)}" min="${it.min == null ? '' : it.min}" max="${it.max == null ? '' : it.max}" step="1"
    inputmode="numeric" aria-label="${T('settings.' + k)}"${it.editable ? '' : ' disabled'}>`;
}
function aiInput(k, placeholder) {
  const it = aiItem(k);
  return html`<input type="text" name="${k}" data-ai="${k}" value="${aiVal(k)}" placeholder="${placeholder}" maxlength="${k === 'ai.base_url' ? 300 : 200}"
    autocomplete="off" spellcheck="false" aria-label="${T('settings.' + k)}"${it.editable ? '' : ' disabled'}>`;
}
function aiTestResult() {
  const r = S.ai.test;
  if (!r) return '';
  if (!r.ok) return html`<div class="ai-test" role="status"><span class="tag tag-bad">${icon('i-alert')}${T('app.ai.test_failed', { error: r.error_text || '' })}</span>
    ${r.error ? html`<div class="hint">${r.error}</div>` : ''}</div>`;
  return html`<div class="ai-test" role="status">
    <div><span class="tag tag-ok">${icon('i-check')}${T('app.ai.test_ok', { server: r.server, n: fmt.num(r.models.length), ms: fmt.num(r.latency_ms) })}</span></div>
    ${r.model ? (r.model_found === false ? html`<div class="hint warn">${T('app.ai.test_missing', { model: r.model })}</div>` : '')
              : html`<div class="hint">${T('app.ai.test_no_model')}</div>`}
    ${r.reply != null ? html`<div class="hint">${T('app.ai.test_reply', { reply: r.reply })}</div>` : ''}
    ${r.models.length ? html`<div class="field"><span>${T('app.ai.models')}</span><div class="chips">${r.models.slice(0, 24).map(m => html`<button type="button" class="chip" data-act="ai-use-model" data-v="${m}" aria-pressed="${String(m === aiVal('ai.model'))}">${m}</button>`)}</div></div>` : ''}
  </div>`;
}
function aiCard() {
  const A = S.ai, s = A.s;
  if (!s) return card({ key: 'ai', cls: 'span2', icon: 'i-spark', title: T('app.sys.ai'), body: A.err ? empty('i-alert', A.err) : html`<div class="skel w8"></div><div class="skel"></div><div class="skel w6"></div>` });
  const m = s.ai || {}, prov = aiVal('ai.provider');
  const server = prov === 'openai_compat' || prov === 'auto';
  const canTest = m.ai_mode === 'openai_compat' && (m.ai_destination === 'local' || m.ai_destination === 'lan');
  const secret = k => { const it = aiItem(k); return html`<dt>${T('settings.' + k)}</dt><dd><span class="tag ${it.configured ? 'tag-ok' : ''}">${T(it.configured ? 'app.ai.key_set' : 'app.ai.key_unset')}</span></dd>`; };
  const editable = AI_KEYS.some(k => aiItem(k).editable);
  return card({ key: 'ai', cls: 'span2', icon: 'i-spark', title: T('app.sys.ai'), body: html`
    <p class="muted" style="margin:0 0 var(--s3)">${T('app.ai.intro')}</p>
    <dl class="facts"><dt>${T('app.ai.now')}</dt><dd class="ai-now">${m.ai_mode === 'offline' ? html`${destTag('none')} <span class="muted">${aiBadge()}</span>` : html`${destTag(m.ai_destination, m.provider, m.ai_redact)} <span class="muted">${m.model}</span>`}</dd></dl>
    <form class="ai-form" data-ai-form autocomplete="off">
      ${aiField('ai.provider', T('settings.ai.provider'), aiSelect('ai.provider', ['auto', 'anthropic', 'openai_compat', 'offline']))}
      ${aiField('ai.redact', T('settings.ai.redact'), aiSelect('ai.redact', ['auto', 'on', 'off']), T('app.ai.redact_hint'))}
      ${server ? aiField('ai.base_url', T('settings.ai.base_url'), aiInput('ai.base_url', aiItem('ai.base_url').placeholder || ''), T('app.ai.base_hint')) : ''}
      ${server ? aiField('ai.model', T('settings.ai.model'), aiInput('ai.model', aiItem('ai.model').placeholder || ''), T('app.ai.model_hint')) : ''}
      ${aiField('ai.tools', T('settings.ai.tools'), aiSelect('ai.tools', ['auto', 'off']), T('app.ai.tools_hint'))}
      ${aiVal('ai.tools') === 'off' ? '' : aiField('ai.max_tool_rounds', T('settings.ai.max_tool_rounds'), aiNumber('ai.max_tool_rounds'), T('app.ai.rounds_hint'))}
      <dl class="facts span-all">${secret('ai.key')}${secret('ai.anthropic_key')}</dl>
      <div class="ai-acts span-all">
        ${editable ? html`<button type="submit" class="btn"${A.saving ? ' disabled' : ''}>${icon('i-check')}${T('app.ai.save')}</button>` : ''}
        <button type="button" class="btn ghost" data-act="ai-test"${canTest && !A.testing ? '' : ' disabled'} aria-describedby="ai-test-note">${icon('i-pulse')}${T(A.testing ? 'app.ai.testing' : 'app.ai.test')}</button>
        <button type="button" class="btn ghost" data-act="ai-preview">${icon('i-eye-off')}${T('app.ai.preview')}</button>
      </div>
      <div class="hint span-all" id="ai-test-note">${canTest ? '' : T('app.ai.test_only_local')}</div>
      <div class="span-all" aria-live="polite">${aiTestResult()}</div>
    </form>` });
}
// The AI in use changed (settings answer): the badge / chat header follow without a reload.
function refreshMeta() {
  const a = S.ai.s && S.ai.s.ai; if (!a) return;
  ['provider', 'model', 'ai_mode', 'ai_destination', 'ai_redact', 'offline_reason'].forEach(k => { delete S.meta[k]; });
  Object.assign(S.meta, a);
}
// Only the fields the user changed (and may change) are sent; "" resets one to its default.
async function saveAI() {
  const A = S.ai, values = {};
  AI_KEYS.forEach(k => { const it = aiItem(k); if (it.editable && k in A.form && String(A.form[k]).trim() !== String(it.value == null ? '' : it.value)) values[k] = String(A.form[k]).trim(); });
  if (!Object.keys(values).length) { toast(T('app.ai.saved')); return; }
  A.saving = true; render();
  try {
    A.s = await postJSON('/api/settings', { values });
    A.form = {}; A.test = null;
    refreshMeta();
    toast(T('app.ai.saved'));
    refresh();
  } catch (e) { toast(errText(e), { kind: 'err' }); }
  finally { A.saving = false; render(); }
}
async function testAI() {
  const A = S.ai;
  if (A.testing) return;
  A.testing = true; A.test = null; render();
  try { A.test = await postJSON('/api/ai/test', {}); } catch (e) { toast(errText(e), { kind: 'err' }); }
  finally { A.testing = false; render(); }
}

// "Preview what will be sent": the exact prompt (redacted when names are hidden) for what
// Send / Insight would do right now. POST /api/chat/preview never calls a model.
function previewRequest() {
  const c = S.chat, draft = c.draft.trim();
  const history = c.messages.filter(m => !m.err && m.content).map(m => ({ role: m.role, content: m.content }));
  if (draft) history.push({ role: 'user', content: draft });
  const chatMode = history.length && history[history.length - 1].role === 'user';
  return { mode: chatMode ? 'chat' : 'insight', messages: chatMode ? history : [], mac: c.ctx ? c.ctx.mac : null,
           alert: chatMode && c.alert ? c.alert : null };
}
async function openPreview() {
  if (S.ai.prev.open) return;
  S.ai.prev = { open: true, r: null, err: null, back: document.activeElement };
  renderPreview();
  $('#prevsheet').hidden = false;
  $('#prevsheet [data-act="prev-close"]').focus();
  try { S.ai.prev.r = await postJSON('/api/chat/preview', previewRequest()); }
  catch (e) { S.ai.prev.err = errText(e); }
  if (S.ai.prev.open) renderPreview();
}
function closePreview() {
  const p = S.ai.prev;
  if (!p.open) return;
  $('#prevsheet').hidden = true;
  S.ai.prev = { open: false };
  if (p.back && document.contains(p.back)) p.back.focus({ preventScroll: true });
}
// Stage A: lookups may send their results too - say so, and show one (redacted) example.
function previewTools(r) {
  const t = r.tools;
  if (!t) return '';
  if (!t.use) return html`<p class="hint prev-tools">${icon('i-search')}${T('app.ai.preview_tools_off')}</p>`;
  const ex = t.example, exLabel = T('app.ai.preview_tool_example', { tool: T('aitool.' + (ex ? ex.name : 'list_devices')) });
  return html`<h3 class="prev-h">${icon('i-search')}${T('app.ai.preview_tools_h')}</h3>
    <p class="hint">${T(r.redact ? 'app.ai.preview_tools' : 'app.ai.preview_tools_plain', { rounds: t.rounds, calls: t.max_calls })}</p>
    <p class="muted prev-tools">${(t.labels || []).join(' · ')}</p>
    ${ex ? html`<details class="prev-sys"><summary>${exLabel}</summary><pre class="prev-pre" tabindex="0" aria-label="${exLabel}">${ex.sent}</pre></details>` : ''}`;
}
function renderPreview() {
  const p = S.ai.prev, r = p.r;
  let body;
  if (p.err) body = empty('i-alert', p.err);
  else if (!r) body = html`<div class="skel w8"></div><div class="skel box"></div>`;
  else if (!r.sends) body = html`${destTag('none')}${empty('i-eye-off', T(r.ai_mode === 'offline' ? 'app.ai.preview_offline' : 'app.ai.preview_nodata'), '', true)}`;
  else body = html`<div class="prev-dest">${destTag(r.destination, r.provider, r.redact)} <span class="muted">${r.model} · ${T('app.ai.preview_size', { n: fmt.num(r.chars || 0) })}</span></div>
    <p class="hint">${T(r.redact ? 'app.ai.preview_redacted' : 'app.ai.preview_plain')}</p>
    ${r.tokens ? html`<p class="hint">${icon('i-gauge')} ${T('app.usage.preview_tokens', { n: fmt.num(r.tokens.total), system: fmt.num(r.tokens.system), tools: fmt.num(r.tokens.tools),
      context: fmt.num(r.tokens.context), history: fmt.num(r.tokens.history) })}</p>` : ''}
    ${r.legend && r.legend.length ? html`<details class="prev-legend"><summary>${T('app.ai.preview_legend')} (${fmt.num(r.legend.length)})</summary>
      <div class="tbl-wrap"><table class="tbl"><tbody>${r.legend.map(l => html`<tr><td><code>${l.token}</code></td><td>${l.real}</td></tr>`)}</tbody></table></div></details>` : ''}
    <h3 class="prev-h">${T('app.ai.preview_user')}</h3><pre class="prev-pre" tabindex="0" aria-label="${T('app.ai.preview_user')}">${r.user}</pre>
    <details class="prev-sys"><summary>${T('app.ai.preview_system')}</summary><pre class="prev-pre" tabindex="0" aria-label="${T('app.ai.preview_system')}">${r.system}</pre></details>
    ${previewTools(r)}`;
  morph($('#prevbody'), html`<header class="sheet-h"><h2 id="prev-title">${icon('i-eye-off')}${T('app.ai.preview_title')}</h2>
    <button type="button" class="btn icon ghost" data-act="prev-close" aria-label="${T('app.close')}" title="${T('app.close')} (Esc)">${icon('i-x')}</button></header>
    <div class="prev">${body}</div>`);
}

// ---------------------------------------------------------------------------------------
// Stage X - Inbox: everything that wants the user's eyes (GET /api/inbox: alerts of every
// kind + open suggestions), worst first, with keyboard triage. Every action only writes
// the user's own notes (POST /api/inbox/act) and can be undone (toast, or "u").
const INBOX_ICON = { threat: 'i-alert', exposure: 'i-port', upnp: 'i-port', outage: 'i-wifi', visibility: 'i-eye-off',
                     night: 'i-moon', bedtime: 'i-bed', spike: 'i-download', new: 'i-plus', change: 'i-swap', suggestion: 'i-bulb' };
const INBOX_LABEL = { ack: 'ui.btn_ack', done: 'app.inbox.done', trust: 'app.inbox.trust', mute: 'app.inbox.mute',
                      snooze: 'app.inbox.snooze', dismiss: 'app.sug.dismiss' };
const INBOX_KEY = { ack: 'a', done: 'a', trust: 't', mute: 'm', snooze: 's', dismiss: 'd' };
const INBOX_KEYS = { a: 'ack', t: 'trust', m: 'mute', s: 'snooze', d: 'dismiss' };
const UNDO_MAX = 20;
const snoozeDays = () => (S.data.inbox && S.data.inbox.snooze_days) || 7;
function inboxItems() { const r = S.data.inbox; return r ? r.items.filter(it => !S.inbox.gone.has(it.id)) : []; }
function inboxCount() { return inboxItems().length; }
function inboxLabel(act) { return T(INBOX_LABEL[act], { n: snoozeDays() }); }
// What a key means for one item: "Got it" on a suggestion is "Done"; "Dismiss" on an alert is "Got it".
function inboxAction(it, act) {
  if (it.kind === 'suggestion') { if (act === 'ack') act = 'done'; } else if (act === 'dismiss') act = 'ack';
  return it.actions.includes(act) ? act : null;
}
// the same tag words as the Overview / Security lists
const INBOX_TAG = { exposure: 'ui.tag_exposure', upnp: 'app.tag_upnp', outage: 'app.tag_outage', visibility: 'ui.tag_visibility',
                    night: 'ui.tag_night', bedtime: 'app.tag_bedtime', spike: 'ui.tag_spike', new: 'ui.tag_new',
                    change: 'ui.tag_changed', suggestion: 'app.inbox.kind_suggestion' };
const inboxTag = it => bare(T(it.kind === 'threat' ? (it.sev === 0 ? 'sev.malicious' : 'sev.high_risk') : INBOX_TAG[it.kind]));
const inboxRef = it => (it.kind === 'suggestion' ? { kind: it.kind, sid: it.sid, prev: 'open' } : { kind: it.kind, mac: it.mac, key: it.key });
function inboxRow(it, i) {
  const sel = i === S.inbox.sel, picked = S.inbox.picked.has(it.id);
  return html`<li class="att ib sev-${it.sev}${sel ? ' sel' : ''}${picked ? ' picked' : ''}" id="ib-${i}" data-key="${it.id}" data-i="${i}"${sel ? html` aria-current="true"` : ''}>
    <input type="checkbox" class="ib-pick" name="ib-pick" data-ib-pick="${it.id}" aria-label="${T('app.inbox.select', { what: it.title })}"${picked ? ' checked' : ''}>
    <span class="att-ic">${icon(INBOX_ICON[it.kind] || 'i-alert')}</span>
    <div class="att-b"><div class="att-t"><span class="tag tag-${it.kind === 'threat' ? 'threat' : it.kind}">${inboxTag(it)}</span><a class="ib-title" href="${it.href}">${it.title}</a></div>
      <div class="att-x">${it.text}${it.when ? html` · <span class="muted" title="${fmt.date(it.when)}">${fmt.rel(it.when)}</span>` : ''}</div>
      ${it.fix ? html`<a class="ib-fix" href="#/suggestions" data-act="sug-goto" data-id="${it.fix.sid}">${icon('i-bulb')}<span>${T('app.inbox.how_to_fix')}: ${it.fix.title}</span></a>` : ''}
      ${it.why ? whyPart('i|' + it.id, it.why, it.title, it.name) : ''}</div>
    ${inboxActs(it)}</li>`;
}
// Stage U: the everyday choice(s) as buttons - "Got it" / "Done" and, for a device, "Trust" -
// the rest (mute, snooze, dismiss, tune) one tap further, each with what it does in words.
function inboxActs(it) {
  const main = it.actions.filter((a, i) => i === 0 || a === 'trust'), rest = it.actions.filter(a => !main.includes(a));
  const btn = (a, cls) => html`<button type="button" class="btn sm ${cls || 'ghost'}" data-act="ib-do" data-v="${a}" data-id="${it.id}" title="${T('app.inbox.hint.' + a, { n: snoozeDays() })} (${INBOX_KEY[a]})">${inboxLabel(a)}</button>`;
  const tune = it.why && it.why.tune;
  const more = rest.length || tune ? html`<details class="ib-more" data-key="more-${it.id}"><summary class="btn sm quiet">${icon('i-more')}${T('app.inbox.more_actions')}</summary>
      <ul class="ib-more-l">${rest.map(a => html`<li>${btn(a)}<span class="muted">${T('app.inbox.hint.' + a, { n: snoozeDays() })}</span></li>`)}
        ${tune ? html`<li>${tuneBtn(tune, it.name)}<span class="muted">${T('app.inbox.hint.tune')}</span></li>` : ''}</ul></details>` : '';
  return html`<div class="att-a">${main.map(a => btn(a))}${more}</div>`;
}
function inboxKeysHint() {
  const k = s => html`<kbd>${s}</kbd>`;
  const rows = [[html`${k('j')} ${k('k')}`, T('app.inbox.key_move')], [k('Enter'), T('app.act.open')], [k('a'), T('ui.btn_ack')],
    [k('t'), T('app.inbox.trust')], [k('m'), T('app.inbox.mute')], [k('s'), inboxLabel('snooze')], [k('d'), T('app.sug.dismiss')],
    [k('x'), T('app.inbox.key_select')], [k('u'), T('app.toast.undo')]];
  return html`<p class="hint ib-keys">${rows.map(([key, what]) => html`<span>${key} ${what}</span>`)}</p>`;
}
function viewInbox() {
  const r = S.data.inbox, I = S.inbox;
  if (!r) return skeleton(2);
  const items = inboxItems();
  I.sel = Math.min(I.sel, Math.max(0, items.length - 1));
  const urgent = items.filter(it => it.sev <= 1).length;
  if (!items.length) {
    return html`${phead(T('app.nav.inbox'), T('app.inbox.sub_empty'), demoPill())}
      ${quietCards()}
      <section class="card ib-zero" data-key="zero"><div class="ib-zero-art">${icon('i-check')}</div>
        <h2>${T('app.inbox.zero_title')}</h2><p class="muted">${T('app.inbox.zero_text')}</p>
        <div class="chips"><a class="btn ghost" href="#/overview">${T('app.nav.overview')}</a><a class="btn ghost" href="#/devices">${T('app.nav.devices')}</a></div>
        ${I.undo.length ? html`<button type="button" class="btn sm quiet" data-act="ib-undo">${T('app.inbox.undo_last')}</button>` : ''}</section>`;
  }
  const picked = items.filter(it => I.picked.has(it.id));
  const all = picked.length === items.length;
  const bulk = picked.length ? html`<div class="ib-bulk" data-key="bulk" role="toolbar" aria-label="${T('app.inbox.bulk')}">
      <b>${T('app.inbox.n_selected', { n: fmt.num(picked.length) })}</b>
      ${['ack', 'trust', 'mute', 'snooze', 'dismiss'].filter(a => picked.some(it => inboxAction(it, a) && (a !== 'dismiss' || it.kind === 'suggestion'))).map(a =>
        html`<button type="button" class="btn sm" data-act="ib-bulk" data-v="${a}">${inboxLabel(a)}</button>`)}
      <button type="button" class="btn sm quiet" data-act="ib-none">${T('app.inbox.clear')}</button></div>` : '';
  return html`${phead(T('app.nav.inbox'), T(urgent ? 'app.inbox.sub_urgent' : 'app.inbox.sub', { n: fmt.num(items.length), urgent: fmt.num(urgent) }),
      html`${demoPill()}<button type="button" class="btn sm ghost" data-act="${all ? 'ib-none' : 'ib-all'}">${T(all ? 'app.inbox.clear' : 'app.inbox.select_all')}</button>`)}
    ${quietCards()}
    ${bulk}
    <section class="card ib-card" data-key="list"><ul class="att-list ib-list" aria-label="${T('app.nav.inbox')}">${items.map(inboxRow)}</ul></section>
    ${inboxKeysHint()}`;
}
function inboxFocus() {
  const li = $('#ib-' + S.inbox.sel); if (!li) return;
  const a = li.querySelector('.ib-title'); if (a) a.focus({ preventScroll: true });
  li.scrollIntoView({ block: 'nearest' });
}
function inboxMove(d) {
  const n = inboxCount(); if (!n) return;
  S.inbox.sel = Math.max(0, Math.min(n - 1, S.inbox.sel + d)); render(); inboxFocus();
}
// act: what was asked (a key or a button); list: the items it is for. Items it does not fit are left alone.
async function inboxDo(act, list) {
  const todo = list.map(it => [it, inboxAction(it, act)]).filter(x => x[1]);
  if (!todo.length) { toast(T('app.inbox.not_for', { action: inboxLabel(act) }), { kind: 'err' }); return; }
  const groups = {};
  todo.forEach(([it, a]) => { (groups[a] = groups[a] || []).push(it); S.inbox.gone.add(it.id); S.inbox.picked.delete(it.id); });
  render(); inboxFocus();
  const done = [];
  try {
    for (const [a, its] of Object.entries(groups)) {
      localData('inbox', await postJSON('/api/inbox/act', { action: a, items: its.map(inboxRef) }));
      done.push({ action: a, items: its });
    }
  } catch (e) { todo.forEach(([it]) => S.inbox.gone.delete(it.id)); render(); fail(e); if (done.length) refresh(); return; }
  S.inbox.gone.clear();
  S.inbox.undo.push(done); if (S.inbox.undo.length > UNDO_MAX) S.inbox.undo.shift();
  const first = todo[0];
  const what = todo.length === 1 ? first[0].title : T('app.inbox.n_items', { n: fmt.num(todo.length) });
  done.close = toast(T('app.inbox.toast.' + first[1], { what, n: snoozeDays() }), { undo: () => inboxUndo(done) });
  render(); inboxFocus(); refresh();
}
// "u" undoes the newest action; a toast's Undo button undoes exactly the action it reported.
async function inboxUndo(entry) {
  const U = S.inbox.undo, i = entry ? U.indexOf(entry) : U.length - 1;
  if (i < 0) { toast(T('app.inbox.nothing_to_undo')); return; }
  const last = U.splice(i, 1)[0];
  if (last.close) { last.close(); if (last.close.entry) undoDrop(last.close.entry); }
  try {
    for (const g of last) localData('inbox', await postJSON('/api/inbox/act', { action: 'undo', undo: g.action, items: g.items.map(inboxRef) }));
    toast(T('app.toast.undone'));
  } catch (e) { U.push(last); fail(e); }
  render(); refresh();
}
function inboxById(id) { return inboxItems().find(it => it.id === id) || null; }
// j / k / Enter / a t m s d / x / u on the Inbox page (returns true when the key was used)
function inboxKey(e) {
  const items = inboxItems(), it = items[S.inbox.sel], k = e.key;
  if (k === 'j' || k === 'J') { inboxMove(1); return true; }
  if (k === 'k' || k === 'K') { inboxMove(-1); return true; }
  if (k === 'u' || k === 'U') { inboxUndo(); return true; }
  if (!it) return false;
  if (k === 'Enter' && !e.target.closest('a,button,input')) { go(it.href); return true; }
  if (k === 'x' || k === 'X') {
    if (S.inbox.picked.has(it.id)) S.inbox.picked.delete(it.id); else S.inbox.picked.add(it.id);
    render(); inboxFocus(); return true;
  }
  const act = INBOX_KEYS[k.toLowerCase()];
  if (!act) return false;
  const picked = items.filter(x => S.inbox.picked.has(x.id));
  inboxDo(act, picked.length ? picked : [it]);
  return true;
}

// ---------------------------------------------------------------------------------------
// Stage X - "Are you sure?" sheet for actions that are not a quick, undoable note
function openConfirm(o) {
  closePalette(true);
  S.confirm = Object.assign({ open: true, back: document.activeElement }, o);
  morph($('#confirmbody'), html`<header class="sheet-h"><h2 id="confirm-title">${icon(o.icon || 'i-alert')}${o.title}</h2></header>
    <p id="confirm-text" class="confirm-text">${o.text}</p>
    <div class="ai-acts confirm-acts"><button type="button" class="btn ghost" data-act="confirm-no">${T('app.cancel')}</button>
      <button type="button" class="btn${o.danger ? ' danger' : ''}" data-act="confirm-yes">${o.ok}</button></div>`);
  $('#confirmsheet').hidden = false;
  $('#confirmsheet [data-act="confirm-no"]').focus();
}
function closeConfirm(yes) {
  const c = S.confirm;
  if (!c.open) return;
  $('#confirmsheet').hidden = true; S.confirm = { open: false };
  if (c.back && document.contains(c.back)) c.back.focus({ preventScroll: true });
  if (yes && c.run) c.run();
}
// The exposure check of every device: say exactly what happens before it starts.
function confirmCheck() {
  if (S.meta.demo) { toast(T('exposure.demo_refused'), { kind: 'err' }); return; }
  if (S.meta.remote) { toast(T('app.pair.admin_only'), { kind: 'err' }); return; }
  openConfirm({ icon: 'i-port', title: T('app.sec.check_all'), text: T('app.sec.check_confirm', { n: fmt.num(devices().length) }),
                ok: T('app.sec.check_start'), run: () => startCheck(null) });
}

// ---------------------------------------------------------------------------------------
// Stage X - Settings: every registered setting, grouped (GET /api/settings: value, where it
// comes from, help); a value set in .env is read-only and names its variable; secrets are
// only ever "configured". Plus connection tests and backup / restore (this computer only).
const SET_ICON = { general: 'i-sliders', alerts: 'i-bell', quiet: 'i-moon', push: 'i-bell', ai: 'i-spark', usage: 'i-gauge', family: 'i-family', health: 'i-wifi', phone: 't-phone' };
const CONN = ['adguard', 'pihole', 'ntopng', 'ai'];
const setId = k => 'set-' + k.replace(/[^\w]/g, '-');
function setItems(sec) { return ((S.ai.s && S.ai.s.items) || []).filter(i => i.section === sec && !i.secret); }
function setVal(it) { return it.key in S.set.form ? S.set.form[it.key] : it.value; }
function setSource(it) {
  if (it.source === 'env') return html`<span class="tag" title="${envLocked(it.env)}">${icon('i-sliders')}${T('app.set.src_env', { env: it.env })}</span>`;
  return html`<span class="tag${it.source === 'db' ? ' tag-ok' : ''}">${T(it.source === 'db' ? 'app.set.src_db' : 'app.set.src_default')}</span>`;
}
function setControl(it) {
  const v = setVal(it), id = setId(it.key), dis = it.editable ? '' : ' disabled';
  const desc = html` aria-describedby="${id}-h"`;
  if (it.type === 'bool') {
    return html`<div class="toggle-row"><button type="button" class="switch" role="switch" id="${id}" aria-checked="${String(!!v)}" aria-labelledby="${id}-l" data-act="set-bool" data-k="${it.key}"${desc}${dis}><i></i></button>
      <span class="muted">${T(v ? 'app.set.on' : 'app.set.off')}</span></div>`;
  }
  if (it.type === 'choice') {
    const name = c => (it.key === 'ui.language' ? ((S.meta.languages || []).find(l => l.code === c) || { name: c }).name
      : it.key === 'push.weekly_day' ? T('act.wd.' + c) : c);
    return html`<select id="${id}" data-set="${it.key}"${desc}${dis}>${(it.choices || []).map(c => html`<option value="${c}"${c === v ? ' selected' : ''}>${name(c)}</option>`)}</select>`;
  }
  if (it.type === 'int') {
    return html`<input type="number" id="${id}" data-set="${it.key}" value="${v == null ? '' : v}" inputmode="numeric"${it.min != null ? html` min="${it.min}" max="${it.max}"` : ''}${desc}${dis}>`;
  }
  if (it.type === 'time') return html`<input type="time" id="${id}" data-set="${it.key}" value="${v == null ? '' : v}"${desc}${dis}>`;
  if (it.key === 'quiet.days') return quietDays(it, id, dis);
  const im = it.inputmode === 'decimal' ? html` inputmode="decimal"` : '';   // money: a number keyboard on phones
  return html`<input type="text" id="${id}" data-set="${it.key}" value="${v == null ? '' : v}" placeholder="${it.placeholder || ''}" maxlength="300" autocomplete="off" spellcheck="false"${im}${desc}${dis}>`;
}
function setField(it) {
  const id = setId(it.key), err = S.set.errs[it.key];
  return html`<div class="field set-field${err ? ' invalid' : ''}" data-key="${it.key}">
    <div class="set-l">${it.key === 'quiet.days'   // (a group of fields: named by aria-labelledby, not a <label for>)
      ? html`<span class="set-cap" id="${id}-l">${it.label}</span>` : html`<label for="${id}" id="${id}-l">${it.label}</label>`}${setSource(it)}</div>
    ${setControl(it)}
    ${err ? html`<span class="hint bad" role="alert">${icon('i-alert')} ${err}</span>` : ''}
    <span class="hint" id="${id}-h">${!it.editable ? envLocked(it.env) : it.key === 'quiet.days' ? T('app.quiet.days_help') : it.help}${it.invalid ? html` <span class="tag tag-warn">${T('app.set.invalid')}</span>` : ''}</span></div>`;
}
// Stage Q: quiet hours per weekday ("4=23:30-09:00,5=off"): one row per night with
// usual / different hours / none. The text stays the setting's value (the server checks it).
function parseQuietDays(s) {
  const out = {};
  String(s || '').split(',').map(x => x.trim()).filter(Boolean).forEach(p => {
    const m = /^([0-6])=(?:(off)|(\d{1,2}:\d{2})-(\d{1,2}:\d{2}))$/.exec(p);
    if (m) out[m[1]] = m[2] ? null : [m[3].padStart(5, '0'), m[4].padStart(5, '0')];
  });
  return out;
}
function quietDaysText(days) {
  return Object.keys(days).sort().map(d => d + '=' + (days[d] ? days[d].join('-') : 'off')).join(',');
}
function quietDays(it, id, dis) {
  const days = parseQuietDays(setVal(it)), start = setVal(aiItem('quiet.start')) || '22:30', end = setVal(aiItem('quiet.end')) || '07:00';
  return html`<div class="qdays" id="${id}" role="group" aria-labelledby="${id}-l">${[0, 1, 2, 3, 4, 5, 6].map(d => {
    const v = days[d], mode = v === undefined ? 'usual' : (v === null ? 'none' : 'custom');
    return html`<div class="qday" data-key="${d}"><span class="qday-n">${T('act.wd.' + d)}</span>
      <select name="qday-${d}" data-qday="${d}" aria-label="${T('act.wd.' + d)}"${dis}>${['usual', 'custom', 'none'].map(m => html`<option value="${m}"${m === mode ? ' selected' : ''}>${T('app.quiet.' + m)}</option>`)}</select>
      ${mode === 'custom' ? html`<span class="qday-t"><input type="time" name="qday-${d}-start" data-qday-t="${d}:0" value="${v[0]}" aria-label="${T('settings.quiet.start')} · ${T('act.wd.' + d)}"${dis}>
        <span aria-hidden="true">–</span><input type="time" name="qday-${d}-end" data-qday-t="${d}:1" value="${v[1]}" aria-label="${T('settings.quiet.end')} · ${T('act.wd.' + d)}"${dis}></span>`
      : (mode === 'usual' ? html`<span class="muted">${start}–${end}</span>` : '')}</div>`;
  })}</div>`;
}
function setQuietDay(d, mode, idx, value) {
  const it = aiItem('quiet.days'), days = parseQuietDays(setVal(it));
  const start = setVal(aiItem('quiet.start')) || '22:30', end = setVal(aiItem('quiet.end')) || '07:00';
  if (mode === 'usual') delete days[d];
  else if (mode === 'none') days[d] = null;
  else if (mode === 'custom') days[d] = days[d] || [start, end];
  else if (days[d] && value) days[d][idx] = value;   // a time changed
  S.set.form['quiet.days'] = quietDaysText(days); delete S.set.errs['quiet.days'];
}
function quietStatus() {
  const q = S.data.notify && S.data.notify.quiet;
  if (!q) return '';
  return html`<p class="quiet-state${q.active ? ' on' : ''}">${icon(q.active ? 'i-moon' : 'i-bell')}<span>${q.text}${q.days_text ? html` <span class="muted">· ${q.days_text}</span>` : ''}
    ${q.active && S.data.notify.held ? html`<br><span class="muted">${T('app.quiet.held', { n: fmt.num(S.data.notify.held) })}</span>` : ''}</span></p>`;
}
function setDirty(sec) { return setItems(sec).some(it => it.key in S.set.form && String(S.set.form[it.key]) !== String(it.value == null ? '' : it.value)); }
function setCard(sec) {
  const items = setItems(sec.key), editable = items.some(i => i.editable && i.type !== 'bool');
  return card({ key: 'set-' + sec.key, icon: SET_ICON[sec.key] || 'i-sliders', title: sec.label, body: html`
    ${sec.key === 'quiet' ? quietStatus() : ''}${sec.key === 'usage' ? usageStatus() : ''}
    <form class="set-form" data-set-form="${sec.key}" novalidate>${items.map(setField)}
      ${editable ? html`<div class="ai-acts"><button type="submit" class="btn"${S.set.saving === sec.key ? ' disabled' : ''}>${icon('i-check')}${T('app.ai.save')}</button>
        ${setDirty(sec.key) ? html`<button type="button" class="btn ghost" data-act="set-discard" data-v="${sec.key}">${T('app.set.discard')}</button>` : ''}</div>` : ''}
    </form>` });
}
// Only what changed (and may change) is sent; the server validates all of it or nothing.
async function saveSettings(sec, only) {
  const values = {};
  setItems(sec).forEach(it => {
    if (!it.editable || !(it.key in S.set.form) || (only && it.key !== only)) return;
    const v = S.set.form[it.key];
    if (String(v) !== String(it.value == null ? '' : it.value)) values[it.key] = typeof v === 'string' ? v.trim() : v;
  });
  const saved = T(sec === 'ai' ? 'app.ai.saved' : 'app.set.saved');
  if (!Object.keys(values).length) { toast(saved); return; }
  S.set.saving = sec; Object.keys(values).forEach(k => { delete S.set.errs[k]; }); render();
  try {
    S.ai.s = await postJSON('/api/settings', { values });
    Object.keys(values).forEach(k => { delete S.set.form[k]; });
    if (sec === 'usage') loadAI();   // the budget bar follows the new budget / prices
    toast(saved);
    refresh();
  } catch (e) {
    const k = e.body && e.body.key;
    if (k) { S.set.errs[k] = errText(e); if (only) delete S.set.form[only]; } else fail(e);
  } finally { S.set.saving = null; render(); }
}
function connRow(n) {
  const c = (S.ai.s && S.ai.s.connections) || { sources: {} }, conf = !!c.sources[n];
  const r = S.set.tests[n], busy = !!S.set.testing[n];
  const inUse = (n === 'adguard' || n === 'pihole') && c.dns_source === n;
  const cloud = n === 'ai' && S.ai.s && S.ai.s.ai && S.ai.s.ai.ai_mode === 'anthropic';
  let res = '';
  if (busy) res = html`<span class="muted">${T('app.conn.testing')}</span>`;
  else if (r && r.ok) res = html`<span class="tag tag-ok">${icon('i-check')}${T('app.conn.ok', { ms: fmt.num(r.latency_ms) })}</span>`;
  else if (r) res = html`<span class="tag tag-bad">${icon('i-alert')}${r.error_text}</span>`;
  return html`<tr data-key="${n}"><th scope="row">${T('app.conn.' + n)}${inUse ? html` <span class="tag tag-ok">${T('app.conn.in_use')}</span>` : ''}</th>
    <td><span class="tag${conf ? ' tag-ok' : ''}">${T(conf ? 'app.ai.key_set' : 'app.conn.not_set')}</span></td>
    <td aria-live="polite">${res}</td>
    <td class="num"><button type="button" class="btn sm ghost" data-act="conn-test" data-v="${n}"${conf && !busy && !cloud ? '' : ' disabled'}
      title="${cloud ? T('app.ai.test_only_local') : (conf ? '' : T(S.meta.addon ? 'app.conn.addon_not_set' : 'app.conn.not_set_hint'))}">${icon('i-pulse')}${T('app.conn.test')}</button></td></tr>`;
}
function connCard() {
  return card({ key: 'conn', cls: 'span2', icon: 'i-pulse', title: T('app.conn.title'), body: html`
    <p class="muted" style="margin:0 0 var(--s2)">${T('app.conn.intro')}</p>
    <div class="tbl-wrap"><table class="tbl conn-tbl"><thead><tr><th scope="col">${T('status.col_source')}</th><th scope="col">${T('app.conn.col_config')}</th><th scope="col">${T('app.conn.col_result')}</th><td></td></tr></thead>
      <tbody>${CONN.map(connRow)}</tbody></table></div>
    <p class="hint">${T(S.meta.addon ? 'app.conn.addon_hint' : 'app.conn.env_hint')}</p>` });
}
async function testConn(n) {
  if (S.set.testing[n]) return;
  S.set.testing[n] = true; S.set.tests[n] = null; render();
  try { S.set.tests[n] = await postJSON('/api/test/' + n, {}); } catch (e) { fail(e); }
  finally { S.set.testing[n] = false; render(); }
}
// Backup / restore: the user's own notes as one JSON file; a restore always shows what it
// would change first (POST /api/backup/preview), "replace" asks once more.
const BK_MAX = 1000000;   // bytes; the server takes 1 MB per request
function bkSection(s) {
  const n = (k, cls) => (s[k] ? html`<span class="${cls}">${T('app.bk.' + k, { n: fmt.num(s[k]) })}</span>` : '');
  const nothing = !s.add && !s.change && !s.remove;
  // a settings line names the setting the way the Settings page does
  const what = x => (s.key === 'settings' ? (aiItem(x.what).label || x.what) : x.what);
  return html`<li data-key="${s.key}"><b>${T('app.backup.sec.' + s.key)}</b>
    <span class="bk-n">${nothing ? html`<span class="muted">${T('app.bk.same_all')}</span>` : html`${n('add', 'ok')}${n('change', 'warn')}${n('remove', 'bad')}`}${n('skipped', 'muted')}</span>
    ${(s.samples || []).length ? html`<ul class="bk-samples">${s.samples.map(x => html`<li><span class="bk-op bk-${x.op}">${T('app.bk.op_' + x.op)}</span> ${what(x)}${x.after != null ? html` <span class="muted">→ ${x.after}</span>` : ''}</li>`)}</ul>` : ''}</li>`;
}
function backupCard() {
  const B = S.set.bk;
  let pv = '';
  if (B) {
    pv = html`<div class="bk-pv" data-key="pv" aria-live="polite">
      <div class="bk-file">${icon('i-box')}<b>${B.name}</b>${B.busy ? html` <span class="muted">${T('ui.loading')}</span>` : ''}</div>
      ${B.err ? html`<p class="hint bad" role="alert">${icon('i-alert')} ${B.err}</p>` : ''}
      ${B.doc ? html`<div class="field"><span id="bk-mode-l">${T('app.bk.mode')}</span><div class="seg" role="group" aria-labelledby="bk-mode-l">${['merge', 'replace'].map(m =>
        html`<button type="button" data-act="bk-mode" data-v="${m}" aria-pressed="${String(B.mode === m)}">${T('app.backup.mode_' + m)}</button>`)}</div>
        <span class="hint">${T('app.bk.mode_' + B.mode + '_hint')}</span></div>` : ''}
      ${B.pv ? html`<h3 class="hint">${B.pv.changes ? T('app.bk.would', { n: fmt.num(B.pv.changes) }) : T('app.bk.nothing')}</h3>
        <ul class="plain bk-list">${B.pv.sections.map(bkSection)}</ul>` : ''}
      <div class="ai-acts">
        ${B.pv && B.pv.changes ? html`<button type="button" class="btn${B.mode === 'replace' ? ' danger' : ''}" data-act="bk-apply"${B.busy ? ' disabled' : ''}>${icon('i-check')}${T('app.bk.restore')}</button>` : ''}
        <button type="button" class="btn ghost" data-act="bk-cancel">${T('app.cancel')}</button></div></div>`;
  }
  return card({ key: 'backup', cls: 'span2', icon: 'i-download', title: T('app.bk.title'), body: html`
    <p class="muted" style="margin:0 0 var(--s2)">${T('app.bk.intro')}</p>
    <div class="ai-acts">
      <a class="btn ghost" href="${url('/api/backup')}" download data-act="bk-download">${icon('i-download')}${T('app.bk.download')}</a>
      <label class="btn ghost file-btn">${icon('i-box')}<span>${T('app.bk.choose')}</span><input type="file" id="bk-file" class="sr" accept=".json,application/json" data-bk-file></label>
    </div>
    <p class="hint">${T('app.bk.what')} ${T('app.push.backup_note')}</p>
    ${pv}` });
}
async function bkLoad(file) {
  if (!file) return;
  S.set.bk = { name: file.name, mode: 'merge', doc: null, pv: null, err: null, busy: true };
  render();
  const B = S.set.bk;
  if (file.size > BK_MAX) { B.err = T('err.backup_too_large'); B.busy = false; render(); return; }
  try { B.doc = JSON.parse(await file.text()); } catch (e) { B.err = T('err.backup_format'); B.busy = false; render(); return; }
  bkPreview();
}
async function bkPreview() {
  const B = S.set.bk; if (!B || !B.doc) return;
  B.busy = true; B.err = null; B.pv = null; render();
  try { B.pv = await postJSON('/api/backup/preview', { backup: B.doc, mode: B.mode }); }
  catch (e) { B.err = errText(e); }
  if (S.set.bk === B) { B.busy = false; render(); }
}
function bkApply() {
  const B = S.set.bk; if (!B || !B.pv) return;
  const run = async () => {
    B.busy = true; render();
    try {
      const r = await postJSON('/api/restore', { backup: B.doc, mode: B.mode });
      S.set.bk = null; S.hidden.clear();
      toast(T('app.bk.restored', { n: fmt.num(r.changes) }));
      loadAI(); loadChoices(); refresh();
    } catch (e) { B.err = errText(e); B.busy = false; render(); }
  };
  if (B.mode === 'replace') openConfirm({ title: T('app.bk.replace_title'), text: T('app.bk.replace_text'), ok: T('app.bk.restore'), danger: true, run });
  else run();
}
// ---------------------------------------------------------------------------------------
// Round 10 N - Notifications: push channels (GET /api/channels, admins only). Off until the
// user adds one; a new channel starts paused. Credentials are write-only: the page only
// ever learns "set" / "not set" and the endpoint's scheme + host. The editor shows the
// EXACT request for a sample (POST /api/channels/preview, never sends); "Send test" is the
// only thing that sends, one message, on a click.
const PUSH_SAMPLES = ['alert', 'test', 'weekly', 'daily'];
const PUSH_SEV = ['critical', 'high', 'medium', 'low'];
let pushPvTimer = null;
async function loadPush() {
  if (!S.meta || S.meta.remote) return;
  try { S.push.d = await getJSON('/api/channels'); S.push.err = null; } catch (e) { S.push.err = errText(e); }
  render();
}
function pushType(t) { return ((S.push.d && S.push.d.types) || []).find(x => x.type === t); }
function pushNew(type) {
  const ty = pushType(type); if (!ty) return;
  S.push.ed = { id: null, type, name: ty.name, fields: {}, secrets: {}, clear: {}, level: 'standard', language: '',
                categories: ['security', 'devices', 'health'], min_sev: 3, quiet_bypass: true, rate: 10, daily: false,
                confirm: false, errs: {}, err: null, saving: false, sample: 'alert', helper: null };
  S.push.pv = null; render(); pushPreview();
  const f = $('#push-ed-name'); if (f) f.focus();
}
function pushEdit(id) {
  const c = ((S.push.d && S.push.d.channels) || []).find(x => x.id === id); if (!c || !c.editable) return;
  S.push.ed = { id, type: c.type, name: c.name, fields: Object.assign({}, c.fields), secrets: {}, clear: {}, level: c.level,
                language: c.lang || '', categories: c.categories.slice(), min_sev: c.min_sev, quiet_bypass: c.quiet_bypass,
                rate: c.rate, daily: c.daily, confirm: false, errs: {}, err: null, saving: false, sample: 'alert', helper: null };
  S.push.pv = null; render(); pushPreview();
  const f = $('#push-ed-name'); if (f) f.focus();
}
// what the server gets: typed secrets only (left empty = keep), null = clear
function pushPayload() {
  const E = S.push.ed, secrets = {};
  Object.keys(E.secrets).forEach(k => { if (E.secrets[k]) secrets[k] = E.secrets[k]; });
  Object.keys(E.clear).forEach(k => { if (E.clear[k]) secrets[k] = null; });
  const p = { name: E.name, fields: E.fields, secrets, level: E.level, language: E.language, categories: E.categories,
              min_sev: +E.min_sev, quiet_bypass: !!E.quiet_bypass, rate: +E.rate || 10, daily: !!E.daily };
  if (E.id) p.id = E.id; else p.type = E.type;
  if (E.confirm) p.confirm = true;
  return p;
}
function pushPreview(now) {
  clearTimeout(pushPvTimer);
  if (DEMO) return;   // the static demo: nothing to ask
  pushPvTimer = setTimeout(async () => {
    const E = S.push.ed; if (!E) return;
    try { S.push.pv = await postJSON('/api/channels/preview', { channel: pushPayload(), sample: E.sample }); S.push.pvErr = null; }
    catch (e) { S.push.pvErr = errText(e); }
    if (S.push.ed === E) render();
  }, now ? 0 : 350);
}
function pushPvText(pv) {
  const r = pv.request;
  return r.method + ' ' + r.url + '\n' + Object.keys(r.headers).map(k => k + ': ' + r.headers[k]).join('\n') + '\n\n' + r.body;
}
async function pushSave() {
  const E = S.push.ed; if (!E || E.saving) return;
  E.saving = true; E.errs = {}; E.err = null; render();
  try {
    S.push.d = await postJSON('/api/channels/save', pushPayload());
    S.push.ed = null; S.push.pv = null;
    toast(T(E.id ? 'app.push.saved' : 'app.push.created'));
  } catch (e) {
    const f = e.body && e.body.field;
    if (f) E.errs[f] = errText(e); else E.err = errText(e);
    E.saving = false;
  }
  render();
  if (!S.push.ed) { const h = $('[data-key="set-push"] h2'); if (h) { h.setAttribute('tabindex', '-1'); h.focus(); } }
}
async function pushAct(path, body, done) {
  try { S.push.d = await postJSON(path, body); if (done) toast(done); } catch (e) { fail(e); }
  render();
}
async function pushTest(id) {
  if (S.push.busy[id]) return;
  S.push.busy[id] = true; S.push.res[id] = null; render();
  try { S.push.res[id] = await postJSON('/api/channels/test', { id }); speak(S.push.res[id].ok ? T('app.push.test_ok') : S.push.res[id].error_text); }
  catch (e) { S.push.res[id] = { ok: false, error_text: errText(e) }; }
  S.push.busy[id] = false;
  loadPush();
}
async function pushLog(id) {
  if (S.push.logOpen === id) { S.push.logOpen = null; render(); return; }
  S.push.logOpen = id; render();
  await pushLogLoad(id);
}
async function pushLogLoad(id) {
  try { S.push.log[id] = (await getJSON('/api/channels/log?id=' + id)).log; } catch (e) { S.push.log[id] = null; fail(e); }
  render();
}
function pushDelete(id, name) {
  openConfirm({ icon: 'i-alert', title: T('app.push.delete_title', { name }), text: T('app.push.delete_text'), ok: T('app.push.delete'),
                danger: true, run: () => pushAct('/api/channels/delete', { id }, T('app.push.deleted')) });
}
async function pushHelper(kind) {
  const E = S.push.ed; if (!E) return;
  E.helper = { kind, busy: true }; render();
  const body = { secrets: {} };
  if (E.id) body.id = E.id;
  if (E.secrets.token) body.secrets.token = E.secrets.token;
  if (kind === 'ha') body.fields = { url: E.fields.url || '', pin: E.fields.pin || '' };
  try {
    const r = await postJSON(kind === 'tg' ? '/api/channels/telegram' : '/api/channels/ha_services', body);
    E.helper = { kind, items: kind === 'tg' ? r.chats : r.services, err: r.ok ? null : r.error_text };
  } catch (e) { E.helper = { kind, items: [], err: errText(e) }; }
  render();
}
function pushStatus(c) {
  if (c.source === 'env') return html`<span class="tag" title="${T('app.push.env_hint', { prefix: S.push.d.env_prefix + c.env_slot + '_' })}">${icon('i-sliders')}${T('app.push.env')}</span>`;
  return html`<span class="tag ${c.enabled ? 'tag-ok' : 'tag-warn'}">${T(c.enabled ? 'app.push.on' : 'app.push.paused')}</span>`;
}
function pushLast(c) {
  if (c.last_error) return html`<p class="hint bad push-err">${icon('i-alert')} ${c.error_text} <span class="muted">(${fmt.rel(c.last_error_ts)})</span></p>`;
  return html`<span class="hint">${c.last_ok_ts ? T('app.push.last_ok', { when: fmt.rel(c.last_ok_ts) }) : T('app.push.never')}</span>`;
}
function pushLogTable(c) {
  const rows = S.push.log[c.id];
  if (!rows) return html`<p class="hint">${T('ui.loading')}</p>`;
  if (!rows.length) return html`<p class="hint">${T('app.push.log_empty')}</p>`;
  return html`<div class="tbl-wrap"><table class="tbl push-log"><caption class="sr">${T('app.push.log_title', { name: c.name })}</caption>
    <thead><tr><th scope="col">${T('app.push.col_time')}</th><th scope="col">${T('app.push.col_what')}</th><th scope="col">${T('app.push.col_result')}</th></tr></thead>
    <tbody>${rows.map((r, i) => html`<tr data-key="${i}"><td>${fmt.date(r.ts)}</td><td>${T('app.push.what.' + r.kind)}${r.n > 1 ? html` <span class="muted">(${fmt.num(r.n)})</span>` : ''}</td>
      <td>${r.ok ? html`<span class="tag tag-ok">${icon('i-check')}${T('app.push.delivered')}</span>` : html`<span class="tag tag-bad">${r.error}</span> <span class="hint">${r.text}</span>`}</td></tr>`)}</tbody></table></div>`;
}
function pushRow(c) {
  const ty = pushType(c.type) || { name: c.type }, r = S.push.res[c.id], busy = !!S.push.busy[c.id];
  return html`<li class="push-row" data-key="${c.id}">
    <div class="push-h"><b>${c.name}</b><span class="tag">${ty.name}</span>${pushStatus(c)}<span class="tag">${T('push.level.' + c.level)}</span>
      ${c.hosted ? html`<span class="tag tag-warn" title="${T('app.push.hosted_note', { service: ty.name })}">${T('app.push.hosted')}</span>` : ''}</div>
    <div class="push-m"><span class="mono">${c.endpoint || '—'}</span> · ${pushLast(c)}${c.waiting ? html` · <span class="hint">${T('app.push.waiting', { n: fmt.num(c.waiting) })}</span>` : ''}</div>
    <div aria-live="polite">${busy ? html`<span class="muted">${T('app.push.testing')}</span>` : r ? (r.ok ? html`<span class="tag tag-ok">${icon('i-check')}${T('app.push.test_ok')}</span>`
      : html`<p class="hint bad">${icon('i-alert')} ${r.error_text}</p>`) : ''}</div>
    <div class="ai-acts">
      <button type="button" class="btn sm ghost" data-act="push-test" data-id="${c.id}"${busy || S.push.d.demo ? ' disabled' : ''}>${icon('i-pulse')}${T('app.push.test')}</button>
      ${c.editable ? html`<button type="button" class="btn sm ghost" data-act="push-edit" data-id="${c.id}">${icon('i-edit')}${T('app.push.edit')}</button>
        <button type="button" class="btn sm ghost" data-act="push-enable" data-id="${c.id}" data-v="${c.enabled ? '0' : '1'}">${T(c.enabled ? 'app.push.pause' : 'app.push.resume')}</button>` : ''}
      <button type="button" class="btn sm ghost" data-act="push-log" data-id="${c.id}" aria-expanded="${String(S.push.logOpen === c.id)}">${T('app.push.log')}</button>
      ${c.editable ? html`<button type="button" class="btn sm ghost danger" data-act="push-delete" data-id="${c.id}" data-name="${c.name}">${T('app.push.delete')}</button>` : ''}
    </div>
    ${S.push.logOpen === c.id ? pushLogTable(c) : ''}</li>`;
}
function pushField(f) {
  const E = S.push.ed, id = 'push-f-' + f.name, err = E.errs[f.name];
  const c = E.id && ((S.push.d.channels || []).find(x => x.id === E.id) || {}), set = !!(c && c.secrets && c.secrets[f.name]);
  const secret = f.kind.indexOf('secret') === 0;
  const req = f.required ? html` <span class="muted">*</span>` : '';
  let ctl;
  if (secret) {
    ctl = html`<input type="password" id="${id}" data-push-s="${f.name}" value="${E.secrets[f.name] || ''}" maxlength="4096" autocomplete="new-password" spellcheck="false"
      placeholder="${set ? T('app.push.keep') : f.placeholder}" aria-describedby="${id}-h"${E.clear[f.name] ? ' disabled' : ''}>`;
  } else {
    ctl = html`<input type="text" id="${id}" data-push-f="${f.name}" value="${E.fields[f.name] || ''}" maxlength="${f.max > 300 ? 500 : f.max}" autocomplete="off" spellcheck="false"
      placeholder="${f.placeholder}" aria-describedby="${id}-h">`;
  }
  return html`<div class="field set-field${err ? ' invalid' : ''}" data-key="${f.name}">
    <div class="set-l"><label for="${id}">${f.label}${req}</label>${secret ? html`<span class="tag${set && !E.clear[f.name] ? ' tag-ok' : ''}">${T(set && !E.clear[f.name] ? 'app.push.set' : 'app.push.not_set')}</span>` : ''}</div>
    ${ctl}
    ${err ? html`<span class="hint bad" role="alert">${icon('i-alert')} ${err}</span>` : ''}
    <span class="hint" id="${id}-h">${secret ? T('app.push.secret_hint') : f.name === 'pin' ? T('app.push.pin_hint') : ''}
      ${secret && set && !f.required ? html` <button type="button" class="btn sm quiet" data-act="push-clear" data-k="${f.name}" aria-pressed="${String(!!E.clear[f.name])}">${T(E.clear[f.name] ? 'app.push.undo_clear' : 'app.push.clear')}</button>` : ''}</span></div>`;
}
function pushSwitch(k, label, hint) {
  const E = S.push.ed, id = 'push-o-' + k;
  return html`<div class="field set-field" data-key="${k}"><div class="set-l"><span id="${id}-l">${label}</span></div>
    <div class="toggle-row"><button type="button" class="switch" role="switch" id="${id}" aria-checked="${String(!!E[k])}" aria-labelledby="${id}-l" aria-describedby="${id}-h" data-act="push-bool" data-k="${k}"><i></i></button>
      <span class="muted">${T(E[k] ? 'app.set.on' : 'app.set.off')}</span></div><span class="hint" id="${id}-h">${hint}</span></div>`;
}
function pushHelperBox() {
  const E = S.push.ed, H = E.helper;
  if (E.type !== 'telegram' && E.type !== 'homeassistant') return '';
  const kind = E.type === 'telegram' ? 'tg' : 'ha';
  let res = '';
  if (H && H.kind === kind) {
    if (H.busy) res = html`<span class="muted">${T('ui.loading')}</span>`;
    else if (H.err) res = html`<p class="hint bad">${icon('i-alert')} ${H.err}</p>`;
    else if (!H.items.length) res = html`<p class="hint">${T(kind === 'tg' ? 'app.push.tg_none' : 'app.push.ha_none')}</p>`;
    else res = html`<ul class="plain push-pick">${H.items.map((x, i) => (kind === 'tg'
      ? html`<li data-key="${i}"><button type="button" class="btn sm ghost" data-act="push-use" data-k="chat_id" data-v="${x.id}">${x.title || x.id} <span class="muted mono">${x.id}</span></button></li>`
      : html`<li data-key="${i}"><button type="button" class="btn sm ghost" data-act="push-use" data-k="service" data-v="${x}"><span class="mono">notify.${x}</span></button></li>`))}</ul>`;
  }
  return html`<div class="push-helper"><button type="button" class="btn sm ghost" data-act="push-helper" data-v="${kind}">${icon('i-search')}${T(kind === 'tg' ? 'app.push.tg_find' : 'app.push.ha_list')}</button>
    <span class="hint">${T(kind === 'tg' ? 'app.push.tg_find_hint' : 'app.push.ha_list_hint')}</span><div aria-live="polite">${res}</div></div>`;
}
function pushEditor() {
  const E = S.push.ed, ty = pushType(E.type), pv = S.push.pv, cats = S.push.d.categories;
  const cloud = pv && pv.destination === 'cloud';
  const langs = S.meta.languages || [];
  return html`<form class="set-form push-ed" data-push-form novalidate aria-labelledby="push-ed-h" data-key="ed">
    <h3 id="push-ed-h">${T(E.id ? 'app.push.edit_title' : 'app.push.add_title', { type: ty.name })}</h3>
    <p class="hint">${ty.help} <a href="${ty.docs}" target="_blank" rel="noopener noreferrer" aria-label="${T('app.push.docs')} (${T('app.about.new_tab')})">${T('app.push.docs')}</a></p>
    ${ty.hosted ? html`<p class="push-note warn" role="note">${icon('i-globe')}<span>${T('app.push.hosted_note', { service: ty.name })}</span></p>` : ''}
    ${E.err ? html`<p class="hint bad" role="alert">${icon('i-alert')} ${E.err}</p>` : ''}
    <div class="field set-field${E.errs.name ? ' invalid' : ''}" data-key="name"><div class="set-l"><label for="push-ed-name">${T('app.push.name')}</label></div>
      <input type="text" id="push-ed-name" data-push="name" value="${E.name}" maxlength="40" autocomplete="off">
      ${E.errs.name ? html`<span class="hint bad" role="alert">${icon('i-alert')} ${E.errs.name}</span>` : ''}</div>
    ${ty.fields.map(pushField)}
    ${pushHelperBox()}
    <div class="field set-field${E.errs.level ? ' invalid' : ''}" data-key="level"><span id="push-lvl-l">${T('app.push.level')}</span>
      <div class="seg" role="group" aria-labelledby="push-lvl-l">${S.push.d.levels.map(l => html`<button type="button" data-act="push-level" data-v="${l}" aria-pressed="${String(E.level === l)}">${T('push.level.' + l)}</button>`)}</div>
      <span class="hint">${T('push.level_help.' + E.level)}</span>
      ${E.level === 'detailed' && cloud ? html`<label class="check"><input type="checkbox" id="push-ed-confirm" data-push-confirm${E.confirm ? ' checked' : ''}> ${T('app.push.confirm_detailed')}</label>` : ''}
      ${E.errs.level ? html`<span class="hint bad" role="alert">${icon('i-alert')} ${E.errs.level}</span>` : ''}</div>
    <fieldset class="field push-cats" data-key="cats"><legend>${T('app.push.categories')}</legend>
      ${cats.map(c => html`<label class="check" data-key="${c}"><input type="checkbox" id="push-cat-${c}" data-push-cat="${c}"${E.categories.includes(c) ? ' checked' : ''}> ${T('push.cat.' + c)}</label>`)}</fieldset>
    <div class="push-grid">
      <div class="field set-field" data-key="min_sev"><div class="set-l"><label for="push-o-sev">${T('app.push.min_sev')}</label></div>
        <select id="push-o-sev" data-push="min_sev">${PUSH_SEV.map((s, i) => html`<option value="${i}"${+E.min_sev === i ? ' selected' : ''}>${T('push.sev.' + s)}</option>`)}</select></div>
      <div class="field set-field" data-key="language"><div class="set-l"><label for="push-o-lang">${T('app.push.language')}</label></div>
        <select id="push-o-lang" data-push="language"><option value=""${E.language ? '' : ' selected'}>${T('app.push.lang_ui')}</option>${langs.map(l => html`<option value="${l.code}"${E.language === l.code ? ' selected' : ''}>${l.name}</option>`)}</select></div>
      <div class="field set-field${E.errs.rate ? ' invalid' : ''}" data-key="rate"><div class="set-l"><label for="push-o-rate">${T('app.push.rate')}</label></div>
        <input type="number" id="push-o-rate" data-push="rate" value="${E.rate}" min="${S.push.d.rate[0]}" max="${S.push.d.rate[1]}" inputmode="numeric" aria-describedby="push-o-rate-h">
        <span class="hint" id="push-o-rate-h">${T('app.push.rate_hint')}</span></div>
    </div>
    ${pushSwitch('quiet_bypass', T('app.push.quiet_bypass'), T('app.push.quiet_bypass_hint'))}
    ${pushSwitch('daily', T('app.push.daily'), T('app.push.daily_hint'))}
    <div class="push-pv" data-key="pv"><div class="field"><span id="push-smp-l">${T('app.push.preview')}</span>
      <div class="seg" role="group" aria-labelledby="push-smp-l">${PUSH_SAMPLES.map(s => html`<button type="button" data-act="push-sample" data-v="${s}" aria-pressed="${String(E.sample === s)}">${T('app.push.sample.' + s)}</button>`)}</div></div>
      ${DEMO ? html`<p class="hint">${T('app.push.demo_note')}</p>` : S.push.pvErr ? html`<p class="hint bad">${icon('i-alert')} ${S.push.pvErr}</p>`
        : pv ? html`<p class="hint">${T('app.push.preview_hint')}${S.push.d.advertised ? '' : ' ' + T('app.push.no_link')}</p>
          <pre class="push-req mono" tabindex="0" aria-label="${T('app.push.preview')}">${pushPvText(pv)}</pre>` : html`<p class="hint">${T('ui.loading')}</p>`}</div>
    <div class="ai-acts"><button type="submit" class="btn"${E.saving ? ' disabled' : ''}>${icon('i-check')}${T(E.id ? 'app.ai.save' : 'app.push.create')}</button>
      <button type="button" class="btn ghost" data-act="push-cancel">${T('app.cancel')}</button></div>
    ${E.id ? '' : html`<p class="hint">${T('app.push.starts_paused')}</p>`}
  </form>`;
}
function pushCard(sec) {
  const P = S.push, d = P.d, items = setItems('push');
  let body;
  if (!d) body = P.err ? html`<p class="hint bad">${icon('i-alert')} ${P.err}</p>` : html`<p class="hint">${T('ui.loading')}</p>`;
  else {
    body = html`
      <p class="muted" style="margin:0 0 var(--s2)">${T('app.push.intro')}</p>
      <p class="push-note" role="note">${icon('i-shield')}<span>${T('app.push.promise')}</span></p>
      ${DEMO || d.demo ? html`<p class="push-note" role="note">${icon('i-bulb')}<span>${T(DEMO ? 'app.push.demo_readonly' : 'app.push.demo_db')}</span></p>` : ''}
      ${d.channels.length ? html`<ul class="plain push-list">${d.channels.map(pushRow)}</ul>` : html`<p class="hint">${T('app.push.none')}</p>`}
      ${P.ed ? pushEditor() : html`<div class="field push-add"><label for="push-type">${T('app.push.add')}</label>
        <div class="push-add-row"><select id="push-type" data-push-type><option value="">${T('app.push.choose_type')}</option>
          <optgroup label="${T('app.push.self_hosted')}">${d.types.filter(t => !t.hosted).map(t => html`<option value="${t.type}">${t.name}</option>`)}</optgroup>
          <optgroup label="${T('app.push.hosted_group')}">${d.types.filter(t => t.hosted).map(t => html`<option value="${t.type}">${t.name}</option>`)}</optgroup></select>
          <button type="button" class="btn" data-act="push-new"${d.channels.length >= d.max ? ' disabled' : ''}>${icon('i-plus')}${T('app.push.add_btn')}</button></div></div>`}
      <form class="set-form" data-set-form="push" novalidate>${items.map(setField)}
        <div class="ai-acts"><button type="submit" class="btn ghost"${S.set.saving === 'push' ? ' disabled' : ''}>${icon('i-check')}${T('app.ai.save')}</button></div></form>
      <p class="hint">${T('app.push.env_doc', { prefix: d.env_prefix })}</p>`;
  }
  return card({ key: 'set-push', cls: 'span2', icon: 'i-bell', title: sec.label, body });
}

// Round 8: "netwarden 0.1.0 · AGPL-3.0-or-later · Source code" for EVERY signed-in user
// (AGPL section 13: people using a modified version over the network can find its source).
// Version, license and URL come from /api/meta (netwarden.SOURCE_URL - one constant); only
// an https URL becomes a link. External, so a new tab, never through url().
function aboutCard() {
  const m = S.meta, src = typeof m.source_url === 'string' && /^https:\/\//.test(m.source_url) ? m.source_url : '';
  const ext = (href, text) => html`<a href="${href}" target="_blank" rel="noopener noreferrer"
    aria-label="${text} (${T('app.about.new_tab')})">${text}</a>`;
  return card({ key: 'about', icon: 'i-shield', title: T('app.about.title'), body: html`
    <p class="about-line" style="margin:0"><b>netwarden ${m.version || ''}</b>
      <span aria-hidden="true"> · </span>${src && m.license ? ext(src + '/blob/main/LICENSE', m.license) : (m.license || '')}
      ${src ? html`<span aria-hidden="true"> · </span>${ext(src, T('app.about.source'))}` : ''}</p>
    ${m.copyright ? html`<p class="hint" style="margin:6px 0 0">${m.copyright}</p>` : ''}
    <p class="hint">${T('app.about.note')}</p>` });
}
function viewSettings() {
  if (S.meta.remote) return html`${phead(T('app.nav.settings'), T('app.set.sub_remote'))}<div class="grid">${phoneCard()}${tuningCard()}${aboutCard()}</div>`;
  const s = S.ai.s;
  if (!s) return S.ai.err ? html`${phead(T('app.nav.settings'))}${card({ key: 'err', body: empty('i-alert', S.ai.err) })}` : skeleton(4);
  return html`${phead(T('app.nav.settings'), T('app.set.sub'), demoPill())}
    <div class="grid">
      ${(s.sections || []).map(sec => (sec.key === 'ai' ? aiCard() : sec.key === 'phone' ? phoneCard() : sec.key === 'push' ? pushCard(sec) : setCard(sec)))}
      ${tuningCard()}
      ${connCard()}
      ${backupCard()}
      ${card({ key: 'wizard', icon: 'i-check', title: T('app.wz.title'), body: html`<p class="muted" style="margin:0">${T('app.wz.again_text')}</p>
        <div class="ai-acts"><a class="btn ghost" href="#/welcome">${T('app.wz.open')}</a></div>` })}
      ${aboutCard()}
    </div>`;
}

// ---------------------------------------------------------------------------------------
// Stage X - First-run wizard (#/welcome): DNS source, a first scan, language + time zone,
// which AI (and where its data goes), phone access. Skippable; GET/POST /api/setup keeps
// the step, so it resumes where it was left.
const WZ_STEPS = ['dns', 'scan', 'language', 'ai', 'phone'];
const WZ_AI = { offline: 'offline', local: 'openai_compat', cloud: 'anthropic' };
let wzTimer = null;
async function loadSetup() {
  if (S.meta.remote) return;
  try { S.setup.s = await getJSON('/api/setup'); S.setup.err = null; } catch (e) { S.setup.err = errText(e); }
  render();
}
function setupNeeded() { const s = S.setup.s; return !!(s && s.needed && !S.meta.remote); }
function resumeCard() {
  const s = S.setup.s, i = Math.max(0, WZ_STEPS.indexOf(s.step));
  return card({ key: 'resume', cls: 'wz-resume', icon: 'i-check', title: T('app.wz.resume_title'), body: html`
    <p class="muted" style="margin:0">${T('app.wz.resume_text', { step: fmt.num(i + 1), n: fmt.num(WZ_STEPS.length) })}</p>
    <div class="ai-acts"><a class="btn" href="#/welcome">${T('app.wz.resume')}</a><button type="button" class="btn quiet" data-act="wz-skip">${T('app.wz.skip')}</button></div>` });
}
function wzStep() { const s = S.setup.s; return S.setup.step || (s && s.step) || WZ_STEPS[0]; }
function wzGo(step) {
  if (!WZ_STEPS.includes(step)) return;
  S.setup.step = step; S.setup.test = null;
  postJSON('/api/setup', { step }).then(r => { S.setup.s = r; }).catch(() => {});
  render();
  const h = $('.wz-card h2'); if (h) { h.setAttribute('tabindex', '-1'); h.focus(); }
}
async function wzFinish(skipped) {
  try { S.setup.s = await postJSON('/api/setup', { done: true }); } catch (e) { fail(e); return; }
  toast(T(skipped ? 'app.wz.skipped' : 'app.wz.done'));
  S.setup.step = null; go('#/overview');
}
async function wzSave(values) {
  try { S.ai.s = await postJSON('/api/settings', { values }); await loadSetup(); return true; }
  catch (e) { fail(e); return false; }
}
async function wzScan() {
  try {
    const j = await postJSON('/api/setup/scan', {});
    S.setup.scan = { job: j.job, state: j.state, found: null }; render(); wzPoll();
  } catch (e) { fail(e); }
}
async function wzPoll() {
  const sc = S.setup.scan; if (!sc || !sc.job) return;
  try {
    const j = await getJSON('/api/setup/scan/status?job=' + enc(sc.job));
    Object.assign(sc, { state: j.state, found: j.found, error: j.error });
    if (j.state === 'running') { render(); setTimeout(wzPoll, 1500); return; }
    if (S.setup.scanToast) {   // started from the palette: say how it went
      S.setup.scanToast = false;
      if (j.state === 'done') toast(T('app.wz.scan_done', { n: fmt.num(j.found || 0) })); else toast(T('ui.check_failed', { error: j.error || '?' }), { kind: 'err' });
    }
    loadSetup(); refresh();
  } catch (e) { sc.state = 'error'; fail(e); }
  render();
}
function wzChoice(key, cur, title, text, dest, provider) {
  return html`<button type="button" class="wz-opt" role="radio" aria-checked="${String(cur)}" data-act="wz-ai" data-v="${key}">
    <span class="wz-opt-h"><b>${title}</b>${destTag(dest, provider)}</span><span class="muted">${text}</span></button>`;
}
function wzBody(step, s) {
  const W = S.setup;
  if (step === 'dns') {
    const d = s.dns, t = W.test;
    const live = d.configured && s.dns_events > 0 && d.last_ok_ts && !d.error;
    return html`<p>${T('app.wz.dns_intro')}</p>
      ${d.configured ? html`<dl class="facts">
          <dt>${T('app.wz.dns_source')}</dt><dd>${T('app.conn.' + d.source)} ${live ? html`<span class="tag tag-ok">${icon('i-check')}${T('app.wz.dns_live')}</span>`
            : html`<span class="tag tag-warn">${T(d.error ? 'status.state.error' : 'app.wz.dns_waiting')}</span>`}</dd>
          <dt>${T('status.col_last_ok')}</dt><dd>${d.last_ok_ts ? fmt.rel(d.last_ok_ts) : T('status.never')}</dd>
          <dt>${T('app.wz.dns_events')}</dt><dd>${fmt.num(s.dns_events)}</dd></dl>
        <div class="ai-acts"><button type="button" class="btn ghost" data-act="wz-test"${t === 'busy' ? ' disabled' : ''}>${icon('i-pulse')}${T('app.conn.test')}</button>
          <span aria-live="polite">${t && t !== 'busy' ? (t.ok ? html`<span class="tag tag-ok">${icon('i-check')}${T('app.conn.ok', { ms: fmt.num(t.latency_ms) })}</span>` : html`<span class="tag tag-bad">${icon('i-alert')}${t.error_text}</span>`) : ''}</span></div>`
        : html`<p class="hint warn">${icon('i-alert')} ${T('app.wz.dns_none')}</p>
          <div class="cmd"><code>${DNS_ENV_LINES}</code>${copyBtn(DNS_ENV_LINES)}</div>
          <p class="hint">${T('app.wz.dns_pihole')}</p>`}
      <p class="hint">${T('app.wz.dns_live_note')}</p>`;
  }
  if (step === 'scan') {
    const sc = W.scan;
    if (!s.scan.available) return html`<p>${T('app.wz.scan_intro')}</p><p class="hint warn">${icon('i-alert')} ${T('app.wz.scan_off.' + (s.scan.reason || 'no_lan'))}</p>`;
    return html`<p>${T('app.wz.scan_intro')}</p>
      <div class="ai-acts"><button type="button" class="btn" data-act="wz-scan"${sc && sc.state === 'running' ? ' disabled' : ''}>${icon('i-search')}${T(sc && sc.state === 'running' ? 'app.wz.scanning' : 'app.wz.scan')}</button></div>
      <p aria-live="polite">${sc && sc.state === 'done' ? html`<span class="tag tag-ok">${icon('i-check')}${T('app.wz.scan_done', { n: fmt.num(sc.found || 0) })}</span>`
        : (sc && sc.state === 'error' ? html`<span class="tag tag-bad">${T('ui.check_failed', { error: sc.error || '?' })}</span>` : '')}</p>
      <p class="hint">${s.scan.last_ok_ts ? T('app.wz.scan_last', { when: fmt.rel(s.scan.last_ok_ts), n: fmt.num(s.devices) }) : T('app.wz.scan_note')}</p>
      ${s.scan.wsl ? html`<p class="hint">${icon('i-bulb')} ${T('discovery.wsl_few')}</p>` : ''}`;
  }
  if (step === 'language') {
    const tz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } })();
    const lang = aiItem('ui.language'), tzi = aiItem('time.timezone');
    const tzVal = W.tz != null ? W.tz : (s.timezone || '');
    return html`<p>${T('app.wz.lang_intro')}</p>
      <label class="field"><span>${T('ui.language')}</span><select name="lang" data-act="lang" aria-label="${T('ui.language')}">${(S.meta.languages || []).map(l => html`<option value="${l.code}"${l.code === S.lang ? ' selected' : ''}>${l.name}</option>`)}</select>
        ${lang.editable === false ? html`<span class="hint">${envLocked(lang.env)}</span>` : html`<span class="hint">${T('app.wz.lang_hint')}</span>`}</label>
      <label class="field"><span>${T('settings.time.timezone')}</span><input type="text" name="tz" data-wz-tz value="${tzVal}" placeholder="Asia/Taipei" maxlength="64" autocomplete="off" spellcheck="false"${tzi.editable === false ? ' disabled' : ''}>
        ${tzi.editable === false ? html`<span class="hint">${envLocked(tzi.env)}</span>` : html`<span class="hint">${T('app.wz.tz_hint')}</span>`}</label>
      ${tz && tzi.editable !== false && tz !== tzVal ? html`<div class="ai-acts"><button type="button" class="btn sm ghost" data-act="wz-tz" data-v="${tz}">${T('app.wz.tz_use', { tz })}</button></div>` : ''}`;
  }
  if (step === 'ai') {
    const ch = s.ai.choice === 'auto' ? ({ anthropic: 'cloud', openai_compat: 'local' }[s.ai.mode] || 'offline')
                                      : ({ anthropic: 'cloud', openai_compat: 'local' }[s.ai.choice] || 'offline');
    const prov = aiItem('ai.provider'), key = aiItem('ai.anthropic_key');
    return html`<p>${T('app.wz.ai_intro')}</p>
      <div class="wz-opts" role="radiogroup" aria-label="${T('settings.ai.provider')}">
        ${wzChoice('offline', ch === 'offline', T('app.wz.ai_offline'), T('app.wz.ai_offline_text'), 'none')}
        ${wzChoice('local', ch === 'local', T('app.wz.ai_local'), T('app.wz.ai_local_text'), 'local')}
        ${wzChoice('cloud', ch === 'cloud', T('app.wz.ai_cloud'), T('app.wz.ai_cloud_text'), 'cloud', 'Anthropic')}</div>
      ${prov.editable === false ? html`<p class="hint">${envLocked(prov.env)}</p>` : ''}
      ${ch === 'cloud' && !key.configured ? html`<p class="hint warn">${icon('i-alert')} ${T('app.wz.ai_cloud_key')}</p>` : ''}
      ${ch === 'local' ? html`<p class="hint">${T('app.wz.ai_local_more')} <a href="#/settings">${T('app.nav.settings')}</a></p>` : ''}
      <p class="hint">${T('app.wz.ai_change')}</p>`;
  }
  // phone
  const lan = aiItem('lan.enabled'), on = !!s.lan_enabled;
  return html`<p>${T('app.wz.phone_intro')}</p>
    <div class="field"><span id="wz-lan-l">${T('settings.lan.enabled')}</span>
      <div class="toggle-row"><button type="button" class="switch" role="switch" aria-checked="${String(on)}" aria-labelledby="wz-lan-l" data-act="wz-lan"${lan.editable === false ? ' disabled' : ''}><i></i></button>
        <span class="muted">${lan.editable === false ? envLocked(lan.env) : T('app.pair.restart_note')}</span></div></div>
    <p class="hint warn pair-warn">${icon('i-alert')} ${T('app.pair.http_warning')}</p>
    <p class="hint">${T('app.wz.phone_later')}</p>`;
}
// A step left behind only gets its check mark when it actually worked: DNS data arrived,
// a scan ran. Clicking "Next" past a source that is still waiting is not "done".
function wzDone(step, s) {
  if (step === 'dns') return !!(s.dns.configured && s.dns_events > 0 && s.dns.last_ok_ts && !s.dns.error);
  if (step === 'scan') return !!(s.scan.last_ok_ts || (S.setup.scan && S.setup.scan.state === 'done'));
  return true;
}
function viewWelcome() {
  const W = S.setup, s = W.s;
  if (S.meta.remote || S.meta.demo) {
    return html`${phead(T('app.wz.title'))}${card({ key: 'wz-na', body: empty('i-check', T(S.meta.demo ? 'app.wz.demo' : 'app.pair.admin_only'),
      html`<a class="btn ghost" href="#/overview">${T('app.nav.overview')}</a>`, true) })}`;
  }
  if (!s) return W.err ? card({ key: 'wz-err', body: empty('i-alert', W.err) }) : skeleton(1);
  const step = wzStep(), i = WZ_STEPS.indexOf(step), last = i === WZ_STEPS.length - 1;
  return html`<div class="wz" data-key="wz">
    <div class="wz-head"><h1>${T('app.wz.title')}</h1><p class="muted">${T('app.wz.intro')}</p></div>
    <ol class="wz-steps">${WZ_STEPS.map((k, j) => { const ok = j < i && wzDone(k, s); return html`<li class="${ok ? 'done' : (j === i ? 'cur' : '')}" data-key="${k}">
      <button type="button" data-act="wz-go" data-v="${k}"${j === i ? html` aria-current="step"` : ''}><span class="mark">${ok ? icon('i-check') : j + 1}</span><span class="lbl">${T('app.wz.step.' + k)}</span></button></li>`; })}</ol>
    ${card({ key: 'wz-' + step, cls: 'wz-card', title: html`${T('app.wz.step_n', { n: i + 1, total: WZ_STEPS.length })} · ${T('app.wz.step.' + step)}`, body: wzBody(step, s) })}
    <div class="wz-nav">
      ${i > 0 ? html`<button type="button" class="btn ghost" data-act="wz-go" data-v="${WZ_STEPS[i - 1]}">${T('app.wz.back')}</button>` : ''}
      <span class="sp"></span>
      <button type="button" class="btn quiet" data-act="wz-skip">${T('app.wz.skip')}</button>
      <button type="button" class="btn" data-act="${last ? 'wz-finish' : 'wz-next'}">${T(last ? 'app.wz.finish' : 'app.wz.next')}</button>
    </div></div>`;
}
async function wzNext() {
  const step = wzStep(), s = S.setup.s;
  if (step === 'language') {   // the page language is already switched; make it (and the time zone) the server's too
    const values = {};
    if (aiItem('ui.language').editable && s.language !== S.lang) values['ui.language'] = S.lang;
    if (aiItem('time.timezone').editable && S.setup.tz != null && S.setup.tz.trim() !== (s.timezone || '')) values['time.timezone'] = S.setup.tz.trim();
    if (Object.keys(values).length && !(await wzSave(values))) return;
  }
  wzGo(WZ_STEPS[WZ_STEPS.indexOf(step) + 1]);
}
function wzTick() {   // the DNS step shows live status: ask again every few seconds while it is open
  clearTimeout(wzTimer);
  if (S.base !== 'welcome') return;
  wzTimer = setTimeout(() => { if (S.base === 'welcome' && wzStep() === 'dns' && document.visibilityState === 'visible') loadSetup(); wzTick(); }, 5000);
}

// ---------------------------------------------------------------------------------------
// Drawer: device detail, or a reverse lookup (service / domain)
function drawerOpen() { return isDrawerRoute(S.route); }
function drawerHead(ic, title, sub, extra) {
  return html`<header class="dhead"><span class="ticon">${ic}</span><div class="dt"><h2 id="drawer-title">${title}</h2>
    ${sub ? html`<div class="sub">${sub}</div>` : ''}${extra || ''}</div>
    <button type="button" class="btn icon ghost" data-act="close" aria-label="${T('app.close')}" title="${T('app.close')} (Esc)">${icon('i-x')}</button></header>`;
}
function viewDrawer() {
  if (S.route.name === 'device') return viewDevice();
  if (S.route.name === 'service' || S.route.name === 'domain') return viewLookup();
  return '';
}
function viewDevice() {
  const { d, act, tl, err } = S.dev;
  if (err) return html`${drawerHead(icon('i-alert'), T('err.device_not_found'), S.dev.mac)}<div class="dbody">${empty('i-search', err)}${demoBack()}</div>`;
  if (!d) return html`${drawerHead(icon('t-unknown'), T('ui.loading'), S.dev.mac)}<div class="dbody"><div class="skel h"></div><div class="skel box"></div><div class="skel w8"></div></div>`;
  const inv = findDev(d.mac) || {};
  const online = inv.online, ti = d.type_info || {};
  const shown = dname(d).split(' · ');   // a nameless device is already titled "Phone · Mom"
  const sub = [ti.type_name, d.owner, d.room].filter(p => p && !shown.includes(p)).join(' · ');
  const extra = html`<div class="badges">${online ? html`<span class="tag tag-ok"><span class="dot on"></span>${T('app.online')}</span>` : html`<span class="tag">${T('app.offline_dev')}</span>`}${badges(Object.assign({}, inv, { trusted: d.trusted }))}</div>`;
  const demo = S.meta && S.meta.demo, checking = S.check.job && S.check.mac === d.mac;
  // Stage Q: this device's alerts (every kind) with "Why this alert?" + Tune, and how each kind is tuned
  const dal = d.alerts || [], tuned = Object.entries(d.tuning || {}).filter(([, v]) => v.level !== 'normal');
  const alertsBody = html`${dal.length ? html`<ul class="att-list">${dal.map(it => html`<li class="att sev-${it.sev}" data-key="${it.id}">
      <span class="att-ic">${icon(INBOX_ICON[it.kind] || 'i-alert')}</span>
      <div class="att-b"><div class="att-t"><span class="tag tag-${it.kind}">${inboxTag(it)}</span><span>${it.title}</span></div>
        <div class="att-x">${it.text}</div>${it.why ? whyPart('d|' + it.id, it.why, it.title, dname(d)) : ''}</div>
      <div class="att-a">${it.why ? tuneBtn(it.why.tune, dname(d)) : ''}</div></li>`)}</ul>` : ''}
    ${tuned.length ? html`<h3 class="hint">${T('app.tune.device')}</h3><ul class="rows">${tuned.map(([k, v]) => html`<li data-key="tu-${k}">
      <span class="grow"><b>${tuneKind(k)}</b> <span class="tag ${v.level === 'less' ? 'tag-acc' : 'tag-warn'}">${T('app.tune.level.' + v.level)}</span>${v.scope === 'all' ? html` <span class="muted">${T('app.tune.whole')}</span>` : ''}
        <div class="muted" style="font-size:var(--fs-xs)">${v.until ? T('app.tune.until', { when: fmt.date(v.until) }) : T('app.tune.no_end')}</div></span>
      ${tuneBtn({ kind: k, mac: d.mac }, dname(d))}</li>`)}</ul>` : ''}`;
  const p = d.ports, pv = d.privacy, id = d.identity || {}, ups = d.upnp || [];
  // "Use this name": only an announced name the user has not chosen a label over
  const suggest = id.suggested_name && !d.label ? id.suggested_name : '';
  return html`${drawerHead(typeIcon(d.type), dname(d), sub, extra)}
    <div class="dacts">
      <button type="button" class="btn sm ghost" data-act="${d.trusted ? 'untrust' : 'trust'}" data-mac="${d.mac}" data-name="${dname(d)}">${icon('i-shield')}${T(d.trusted ? 'app.d.untrust' : 'ui.btn_trust')}</button>
      <button type="button" class="btn sm ghost" data-act="ask" data-mac="${d.mac}" data-name="${dname(d)}">${icon('i-spark')}${T('app.d.ask')}</button>
    </div>
    <div class="dbody">
      ${card({ key: 'ov', title: T('app.nav.overview'), body: html`<form class="edit-grid" data-mac="${d.mac}" data-drawer-form>${editFields(d, '', true)}</form>
        ${suggest ? html`<div class="suggest-name" data-key="suggest">${icon('i-spark')}<span class="grow">${T('app.ident.suggest', { name: suggest })}</span>
          <button type="button" class="btn sm" data-act="use-name" data-mac="${d.mac}" data-name="${suggest}">${T('app.ident.use_name')}</button></div>` : ''}
        <dl class="facts">
          <dt>${T('app.d.vendor')}</dt><dd>${d.vendor || id.manufacturer || '—'}</dd>
          ${id.model ? html`<dt>${T('app.ident.model')}</dt><dd>${id.model}</dd>` : ''}
          ${(id.sources || []).length ? html`<dt>${T('app.ident.via')}</dt><dd><span class="badges">${(id.evidence || []).map(e => html`<span class="tag tag-acc">${e.source_name}</span>`)}</span></dd>` : ''}
          <dt>${T('ui.th_ip')}</dt><dd class="mono">${(d.ips || []).join(', ') || '—'}</dd>
          <dt>${T('app.d.mac')}</dt><dd class="mono">${d.mac}${d.randomized ? html` <span class="tag">${T('app.d.randomized')}</span>` : ''}</dd>
          <dt>${T('app.d.first_seen')}</dt><dd>${d.first_seen ? html`${fmt.date(d.first_seen)} <span class="muted">(${fmt.rel(d.first_seen)})</span>` : '—'}</dd>
          <dt>${T('app.last_seen')}</dt><dd>${inv.last_active ? html`${fmt.date(inv.last_active)} <span class="muted">(${fmt.rel(inv.last_active)})</span>` : (d.last_seen ? fmt.date(d.last_seen) : '—')}</dd>
          <dt>${T('ui.type')}</dt><dd>${ti.type_name || '—'} <span class="muted">${ti.reason ? '· ' + T('ui.type_reason', { reason: ti.reason, pct: Math.round((ti.confidence || 0) * 100) }) : ''}</span></dd>
        </dl>` })}
      ${dal.length || tuned.length ? card({ key: 'alerts', icon: 'i-alert', title: T('app.d.alerts'), body: alertsBody }) : ''}
      ${(id.evidence || []).length ? card({ key: 'ident', icon: 'i-search', title: T('app.ident.title'), body: html`<ul class="rows">${id.evidence.map(e => html`<li data-key="${e.source}">
          <span class="tag">${e.source_name}</span><span class="grow">${[e.name, e.manufacturer, e.model].filter(Boolean).join(' · ') || '—'}
          <div class="muted" style="font-size:var(--fs-xs)">${[e.detail, T('app.ident.seen', { when: fmt.rel(e.last_seen) })].filter(Boolean).join(' · ')}</div></span></li>`)}</ul>
        <div class="hint">${T('app.ident.hint')}</div>` }) : ''}
      ${card({ key: 'svc', icon: 'i-globe', title: T('app.d.services'), body: html`
        ${(d.services || []).length ? html`<div class="svc-chips">${(d.top_domains || []).filter((t, i, a) => t.service_id && a.findIndex(x => x.service_id === t.service_id) === i)
          .map(t => html`<a class="chip" href="#/service/${enc(t.service_id)}">${t.service}</a>`)}</div>` : ''}
        ${(d.top_domains || []).length ? html`<div class="tbl-wrap"><table class="tbl"><thead><tr><th>${T('ui.th_domain')}</th><th>${T('ui.th_service')}</th><th class="num">${T('ui.th_queries')}</th></tr></thead>
          <tbody>${d.top_domains.map(t => html`<tr data-key="${t.domain}"><td><a href="#/domain/${enc(t.domain)}"><code>${t.domain}</code></a>${t.blocked ? html` <span class="tag tag-warn">${T('ui.th_blocked_short')}</span>` : ''}${t.routine ? html` <span class="tag tag-routine" title="${t.routine.text}">${t.routine.name}</span>` : ''}</td>
            <td>${t.service_id ? html`<a href="#/service/${enc(t.service_id)}">${t.service}</a>` : (t.service || '—')}</td><td class="num">${fmt.num(t.count)}</td></tr>`)}</tbody></table></div>
          <div class="hint">${T('app.d.lookup_hint')}</div>` : empty('i-globe', T('app.d.no_dns'))}` })}
      ${card({ key: 'act', icon: 'i-pulse', title: act ? T('ui.activity_title', { tz: act.tz }) : T('app.nav.activity'), body: act ? (act.total ? html`${heatmap(act)}
        <div class="hint">${joinHint(act.summary, act.night_share_text)}</div>
        ${act.unusual ? html`<p><span class="tag tag-night">${T('ui.tag_night')}</span> ${act.unusual.text}</p>` : ''}` : empty('i-pulse', T('activity.no_data'))) : html`<div class="skel box"></div>` })}
      ${S.dev.st && S.dev.st.minutes ? card({ key: 'screen', icon: 'i-family', title: T('app.d.screen'),
        actions: html`<a class="btn sm quiet" href="#/family">${T('app.d.screen_more')}</a>`, body: html`
        <p class="screen-today" style="margin:0"><strong>${S.dev.st.today_text}</strong></p>
        <div class="muted fam-small">${T('app.d.screen_week', { dur: famDur(S.dev.st.minutes) })}</div>
        ${minuteBars(S.dev.st.by_day, T('app.d.screen_week', { dur: famDur(S.dev.st.minutes) }))}
        ${svcChips(S.dev.st.top_services)}
        <div class="hint">${T('digest.family_note')}</div>` }) : ''}
      ${card({ key: 'trend', icon: 'i-download', title: T('app.d.trends'), body: html`
        ${(d.trend || []).length ? html`<h3 class="hint" style="margin-top:0">${T('ui.trend_title')}</h3>${queryBars(d.trend)}` : ''}
        <h3 class="hint">${T('bw.trend_title')}</h3>
        ${(d.bandwidth_trend || []).some(x => x.rx_bytes || x.tx_bytes) ? bwBars(d.bandwidth_trend) : html`<div class="hint" style="margin-top:0">${T(d.has_bandwidth ? 'bw.no_device' : 'bw.no_sensor')}</div>`}` })}
      ${card({ key: 'priv', icon: 'i-eye-off', title: T('app.nav.privacy'), body: pv ? html`
        <div style="display:flex;gap:var(--s3);align-items:center">${grade(pv.grade, true)}<div>${T('ui.privacy_line', { grade: pv.grade, reason: pv.reason })}</div></div>
        ${(pv.top_trackers || []).length ? html`<div class="tbl-wrap section-gap"><table class="tbl"><thead><tr><th>${T('ui.th_tracker')}</th><th>${T('ui.th_category')}</th><th>${T('ui.th_company')}</th><th class="num">${T('ui.th_queries')}</th><th class="num">${T('ui.th_blocked_short')}</th></tr></thead>
          <tbody>${pv.top_trackers.map(t => html`<tr data-key="${t.entry}"><td><a href="#/domain/${enc(t.entry)}"><code>${t.entry}</code></a></td><td>${t.category_name}</td><td>${t.company || '—'}</td>
            <td class="num">${fmt.num(t.count)}</td><td class="num">${t.blocked ? fmt.num(t.blocked) : ''}</td></tr>`)}</tbody></table></div>
          ${pv.rules && pv.rules.adguard ? rulesBox(pv.rules) : ''}` : ''}` : empty('i-eye-off', T('app.d.no_dns')) })}
      ${card({ key: 'ports', icon: 'i-port', title: T('ui.ports_title'), actions: html`<button type="button" class="btn sm" data-act="check" data-mac="${d.mac}"${d.check_allowed && !S.check.job ? '' : ' disabled'} title="${d.check_allowed ? '' : d.check_note}">${T('ui.check_now')}</button>`, body: html`
        ${checking ? progress(S.check.done, S.check.total) : ''}
        ${!p ? html`<div class="muted">${T('ui.ports_never')}</div>` : (!p.open.length ? html`<div class="muted">${T('app.d.ports_none', { n: fmt.num(p.checked), when: fmt.date(p.ts) })}</div>`
          : html`<div class="muted" style="font-size:var(--fs-sm)">${T('app.d.ports_checked', { when: fmt.date(p.ts) })}</div><ul class="rows">${p.open.map(o => html`<li data-key="p${o.port}">
            <strong class="risk-${o.risk} nowrap">${o.port} ${o.service}</strong><span class="grow"><span class="risk-${o.risk}">${o.risk_name}</span>${o.new ? html` <span class="tag tag-bad">${T('ui.port_new')}</span>` : ''}
            <div class="muted" style="font-size:var(--fs-xs)">${o.note}</div></span></li>`)}</ul>`)}
        <div class="hint">${d.check_note || ''}</div>
        ${ups.length ? html`<h3 class="hint">${T('app.upnp.title')}</h3><ul class="rows">${ups.map(m => html`<li data-key="u${m.protocol}${m.external_port}">
          <strong class="risk-${m.risky ? 'high' : 'low'} nowrap">${m.protocol} ${m.external_port}</strong><span class="grow">${m.risky ? html`<span class="risk-high">${m.risk_name}</span> ` : ''}${m.new ? html`<span class="tag tag-bad">${T('ui.port_new')}</span>` : ''}
          <div class="muted" style="font-size:var(--fs-xs)">${m.text}</div></span></li>`)}</ul>
          <div class="hint">${T('upnp.howto')}</div>` : ''}` })}
      ${card({ key: 'tl', icon: 'i-swap', title: T('ui.timeline_title'), body: tl ? ((tl.items || []).length ? html`<ul class="tl">${tl.items.map((i, n) => html`<li class="k-${i.kind}" data-key="${n}:${i.ts}:${i.kind}">
          <time class="when" datetime="${i.ts}">${fmt.date(i.ts)}</time>${i.text}</li>`)}</ul>` : empty('i-swap', T('ui.timeline_empty'))) : html`<div class="skel box"></div>` })}
    </div>`;
}
function viewLookup() {
  const L = S.look, title = S.route.name === 'domain' ? S.route.arg : ((L.r && L.r.name) || S.route.arg);
  const ic = icon(S.route.name === 'domain' ? 'i-globe' : 'i-box');
  if (L.err) return html`${drawerHead(ic, title)}<div class="dbody">${empty('i-search', L.err)}${demoBack()}</div>`;
  const r = L.r;
  if (!r) return html`${drawerHead(ic, title)}<div class="dbody"><div class="skel box"></div></div>`;
  return html`${drawerHead(ic, S.route.name === 'domain' ? r.domain : r.name, r.category_name)}
    <div class="dbody">
      ${r.routine ? card({ key: 'routine', icon: 'i-check', title: T('app.routine.title'), body: html`
        <p style="margin:0"><span class="tag tag-routine">${r.routine.name}</span> ${r.routine.text}</p>` }) : ''}
      ${r.threat || r.tracker ? card({ key: 'flags', body: html`
        ${r.threat ? html`<p style="margin-top:0"><span class="tag tag-threat">${icon('i-alert')}${r.threat.label}</span> <span class="muted">${r.threat.why}</span></p>` : ''}
        ${r.tracker ? html`<p style="margin:0">${T('ui.flag_tracker', { category: r.tracker.category_name })}${r.tracker.company ? ' · ' + r.tracker.company : ''}</p>` : ''}` }) : ''}
      ${card({ key: 'who', icon: 'i-devices', title: T('ui.lookup_used_by', { days: r.days }), body: (r.devices || []).length ? html`<ul class="rows">${r.devices.map(d => html`<li data-key="${d.mac || d.name}">
          <span class="grow">${d.mac ? html`<a href="${devHref(d.mac)}">${rowName(d)}</a>` : d.name}
          <div class="muted" style="font-size:var(--fs-xs)">${T('app.look.line', { n: fmt.num(d.queries), first: fmt.date(d.first_seen), last: fmt.rel(d.last_seen) })}</div></span></li>`)}</ul>`
        : empty('i-devices', T('ui.timeline_empty')) })}
      ${(r.domains || []).length > 1 ? card({ key: 'doms', icon: 'i-globe', title: T('ui.search_domains'), body: html`<div class="svc-chips">${r.domains.slice(0, 40).map(x => html`<a class="chip" href="#/domain/${enc(x)}"><code>${x}</code></a>`)}</div>` }) : ''}
    </div>`;
}

// ---------------------------------------------------------------------------------------
// Stage T - the network map (#/map): Internet -> router -> devices, grouped by person or
// by category. The layout is a pure function in static/map.js (NWMap.layout, checked by
// tests/js/map_layout_test.js); this part decides groups, status and size and draws SVG
// through the same escaping html`` tag as every view. Pan / zoom only rewrite one
// transform attribute (no re-render); a phone starts with the grouped list.
const MAP_STATUS = ['alert', 'blind', 'new', 'online', 'offline'];
const MAP_K = [0.3, 6];                  // zoom range
const MAP_LABEL_MAX = 40;                // up to this many devices: names shown at any zoom
let mapCache = { sig: '', out: null, ms: 0 };
const clampK = k => Math.min(MAP_K[1], Math.max(MAP_K[0], k));
function mapNarrow() { return !!(window.matchMedia && window.matchMedia('(max-width: 640px)').matches); }
function mapMode() { return S.map.mode || (mapNarrow() ? 'list' : 'map'); }
function typeName(k) { const t = S.types.find(x => x.key === k); return t ? t.name : T('devtype.' + k); }
// a device's person group, whatever the map is grouped by (the person filter uses it too)
function personKey(d) { const p = personOf(d); return p ? 'p:' + p.id : (d.shared ? 'shared' : 'none'); }
function mapAlertMacs() {
  const out = new Set();
  // 'new' and 'visibility' have their own rings (new / blind spot)
  inboxItems().forEach(it => { if (it.mac && !['new', 'suggestion', 'visibility'].includes(it.kind)) out.add(it.mac); });
  return out;
}
// one status ring per device, the most important first
function mapStatus(d, alerting) {
  if (d.threat_count || alerting.has(d.mac)) return 'alert';
  if (d.dns_visibility) return 'blind';
  if (d.new) return 'new';
  return d.online ? 'online' : 'offline';
}
function mapGroups() {
  if (S.map.by === 'type') return TYPE_KEYS.map(k => ({ key: 't:' + k, label: typeName(k), ic: 't-' + k }));
  return persons().map(p => ({ key: 'p:' + p.id, label: p.name, person: p }))
    .concat([{ key: 'shared', label: T('app.ppl.shared'), ic: 'i-home' }, { key: 'none', label: T('app.map.nobody'), ic: 'i-user' }]);
}
function mapModel() {
  const alerting = mapAlertMacs(), bw = !!(S.data.inv && S.data.inv.has_bandwidth);
  const groups = mapGroups();
  const items = devices().filter(d => d.mac).map(d => ({
    d, id: d.mac, group: S.map.by === 'type' ? 't:' + typeKey(d.type) : personKey(d), person: personKey(d),
    weight: bw ? bwTotal(d) : (d.queries || 0), order: d.first_seen || '', status: mapStatus(d, alerting) }));
  // the layout only changes with the groups, the devices and their size
  const sig = S.map.by + '|' + groups.map(g => g.key).join(',') + '|' + items.map(i => i.id + '>' + i.group + '>' + i.weight).join(',');
  if (sig !== mapCache.sig) {
    const t = performance.now();
    const out = window.NWMap.layout({ groups: groups.map(g => ({ key: g.key })), devices: items });
    mapCache = { sig, out, ms: performance.now() - t };
  }
  const q = S.map.q.trim(), f = S.map;
  items.forEach(it => {
    const d = it.d;
    it.shown = (!f.person || it.person === f.person) && (!f.type || typeKey(d.type) === f.type) && (!f.status || it.status === f.status);
    it.hit = !!q && matches(q, devHay(d));
  });
  return { items, groups, lay: mapCache.out, bw };
}
const mapStatusName = s => T('app.map.st.' + s);
function mapRouter() {
  const h = S.data.hyg, u = S.data.upnp;
  const n = u && u.mappings ? u.mappings.length : 0;
  return { status: (h && h.status) || 'unknown', summary: (h && h.summary) || '', ports: n,
           name: (u && u.gateway && u.gateway.name) || T('app.map.router') };
}
function mapSvg(m) {
  const L = m.lay, b = L.bounds, v = S.map.view, R = mapRouter();
  const byKey = Object.fromEntries(m.groups.map(g => [g.key, g]));
  // names under the nodes: always for a small home, when zoomed in for a big one
  const seen = S.map.seen, label = v.k >= 1.5 || m.items.filter(it => it.shown).length <= MAP_LABEL_MAX;
  const node = it => {
    const p = L.nodes[it.id]; if (!p || !it.shown) return '';
    const d = it.d, s = Math.round(p.r * 1.1), name = dname(d);
    const cls = 'mnode st-' + it.status + (it.hit ? ' hit' : '') + (S.map.q.trim() && !it.hit ? ' dim' : '') +
                (seen && !seen.has(it.id) ? ' enter' : '') + (isFlash('dev:' + it.id) ? ' flash' : '');
    return html`<a class="${cls}" href="${devHref(d.mac)}" data-mac="${d.mac}" data-key="n:${d.mac}" transform="translate(${p.x} ${p.y})"
        aria-label="${T('app.map.node_label', { name, status: mapStatusName(it.status), group: (byKey[it.group] || {}).label || '' })}">
      <circle class="ring" r="${p.r + 3.5}"/><circle class="core" r="${p.r}"/>
      <use class="mic" href="#t-${typeKey(d.type)}" x="${-s / 2}" y="${-s / 2}" width="${s}" height="${s}"/>
      ${label ? html`<text class="mlabel" y="${p.r + 13}">${name.length > 18 ? name.slice(0, 17) + '…' : name}</text>` : ''}</a>`;
  };
  // focus order: group by group, each in name order (the layout's spiral order is visual only)
  const coll = new Intl.Collator(S.lang);
  const ordered = L.groups.map(g => m.items.filter(it => it.group === g.key).sort((a, c) => coll.compare(dname(a.d), dname(c.d))));
  const shown = m.items.filter(it => it.shown).length;
  return html`<svg id="mapsvg" class="mapsvg${label ? ' zoomed' : ''}" viewBox="${b.x} ${b.y} ${b.w} ${b.h}" tabindex="0" role="group"
      aria-label="${T('app.map.aria', { n: fmt.num(shown) })}" aria-describedby="maphelp">
    <g id="mapvp" transform="translate(${v.x} ${v.y}) scale(${v.k})">
      <g class="mlinks" aria-hidden="true">
        <line x1="0" y1="0" x2="${L.internet.x}" y2="${L.internet.y}" class="up"/>
        ${L.groups.map(g => html`<line x1="0" y1="0" x2="${g.x}" y2="${g.y}"/>`)}
      </g>
      <a class="mhub inet" href="#/health" data-key="inet" transform="translate(${L.internet.x} ${L.internet.y})" aria-label="${T('app.map.internet_label', { state: S.data.health ? (S.data.health.verdict.title || T('app.h.state.' + S.data.health.verdict.level)) : '' })}">
        <circle class="ring lvl-${S.data.health ? S.data.health.verdict.level : 'idle'}" r="27"/><circle class="core" r="23"/>
        <use class="mic" href="#i-globe" x="-12" y="-12" width="24" height="24"/><text class="mhlabel" y="42">${T('app.map.internet')}</text></a>
      <a class="mhub router hyg-${R.status}" href="#/security" data-key="router" aria-label="${T('app.map.router_label', { name: R.name, hygiene: R.summary, n: fmt.num(R.ports) })}">
        <circle class="ring" r="31"/><circle class="core" r="27"/>
        <use class="mic" href="#t-network" x="-14" y="-14" width="28" height="28"/>
        <text class="mhlabel" y="47">${R.name}</text></a>
      ${R.ports ? html`<g class="mhub-badge badge" transform="translate(22 -22)" aria-hidden="true"><circle r="10"/><text y="4">${R.ports > 99 ? '99+' : R.ports}</text></g>` : ''}
      ${L.groups.map((g, i) => { const G = byKey[g.key] || {}; return html`<g class="mgroup" data-key="g:${g.key}">
        <circle class="halo" cx="${g.x}" cy="${g.y}" r="${g.r}" aria-hidden="true"/>
        <text class="mglabel" x="${g.lx}" y="${g.ly}" text-anchor="${g.anchor}" aria-hidden="true">${G.label || ''} · ${fmt.num(ordered[i].length)}</text>
        ${ordered[i].map(node)}</g>`; })}
    </g></svg>`;
}
function mapList(m) {
  const R = mapRouter(), coll = new Intl.Collator(S.lang);
  const groups = m.groups.map(g => [g, m.items.filter(it => it.group === g.key && it.shown).sort((a, c) => coll.compare(dname(a.d), dname(c.d)))])
    .filter(([, list]) => list.length);
  return html`<div class="maplist">
    <p class="map-route">${icon('i-globe')}<a href="#/health">${T('app.map.internet')}</a> → ${icon('t-network')}<a href="#/security">${R.name}</a>
      <span class="tag ${HYG_TAG[R.status] || ''}">${R.summary || T('hyg.status.' + R.status)}</span>
      ${R.ports ? html`<span class="tag tag-upnp">${T('app.map.ports', { n: fmt.num(R.ports) })}</span>` : ''}</p>
    ${groups.map(([g, list]) => html`<section class="map-group" data-key="lg:${g.key}">
      <h3>${g.person ? avatar(g.person) : icon(g.ic || 'i-devices')}<span>${g.label}</span><span class="muted"> · ${fmt.num(list.length)}</span></h3>
      <ul class="rows">${list.map(it => html`<li data-key="${it.id}" class="${it.hit ? 'hit' : ''}${isFlash('dev:' + it.id) ? ' flash' : ''}">
        <a class="dev" href="${devHref(it.id)}"><span class="ticon">${typeIcon(it.d.type)}</span><span class="grow">${dname(it.d)}</span></a>
        <span class="mst st-${it.status}"><i aria-hidden="true"></i>${mapStatusName(it.status)}</span></li>`)}</ul></section>`)}
    ${groups.length ? '' : empty('i-search', T('app.dev.empty'), '')}</div>`;
}
function viewMap() {
  const inv = S.data.inv;
  if (!inv) return skeleton(1);
  const m = mapModel(), mode = mapMode(), f = S.map;
  const shown = m.items.filter(it => it.shown).length, hits = m.items.filter(it => it.shown && it.hit).length;
  const active = f.q || f.person || f.type || f.status;
  const pOpts = [['', T('app.f.all_owners')]].concat(persons().map(p => ['p:' + p.id, p.name]), [['shared', T('app.ppl.shared')], ['none', T('app.map.nobody')]]);
  const tOpts = [['', T('app.f.all_types')]].concat(TYPE_KEYS.filter(k => m.items.some(it => typeKey(it.d.type) === k)).map(k => [k, typeName(k)]));
  const sel = (name, label, opts) => html`<select name="map-${name}" data-mapf="${name}" aria-label="${label}">${opts.map(([v, l]) => html`<option value="${v}"${f[name] === v ? ' selected' : ''}>${l}</option>`)}</select>`;
  const seg = (act, cur, opts, label) => html`<div class="seg" role="group" aria-label="${label}">${opts.map(([v, l, ic]) => html`<button type="button" class="chip" data-act="${act}" data-v="${v}" aria-pressed="${String(cur === v)}">${ic ? icon(ic) : ''}${l}</button>`)}</div>`;
  return html`${phead(T('app.nav.map'), T('app.map.sub'), html`${demoPill()}${seg('map-mode', mode, [['map', T('app.map.mode_map'), 'i-map'], ['list', T('app.map.mode_list'), 'i-devices']], T('app.map.view'))}`)}
    <section class="card map-card" data-key="map">
      <div class="toolbar" role="search">
        <label class="q"><span class="sr">${T('app.map.search')}</span>${icon('i-search')}<input type="search" name="map-q" data-mapf="q" value="${f.q}" placeholder="${T('app.map.search')}" autocomplete="off" maxlength="100"></label>
        ${seg('map-by', f.by, [['person', T('app.map.by_person')], ['type', T('app.map.by_type')]], T('app.map.group_by'))}
        ${sel('person', T('app.owner'), pOpts)}${sel('type', T('ui.type'), tOpts)}
      </div>
      <div class="toolbar">
        <div class="chips" role="group" aria-label="${T('app.map.status')}">${[''].concat(MAP_STATUS).map(s => html`<button type="button" class="chip${s ? ' mchip st-' + s : ''}" data-act="map-status" data-v="${s}" aria-pressed="${String(f.status === s)}">${s ? html`<i aria-hidden="true"></i>` : ''}${s ? mapStatusName(s) : T('app.f.all')}</button>`)}</div>
        ${active ? html`<button type="button" class="btn sm quiet" data-act="map-clear">${icon('i-x')}${T('app.f.clear')}</button>` : ''}
        <span class="meta" aria-live="polite">${f.q.trim() ? T('app.map.hits', { n: fmt.num(hits) }) + ' · ' : ''}${T('app.dev.count', { n: fmt.num(shown), total: fmt.num(m.items.length) })}</span>
      </div>
      ${mode === 'map' ? html`<div class="mapbox" id="mapbox">
          ${mapSvg(m)}
          <div class="mapctl" role="group" aria-label="${T('app.map.zoom')}">
            <button type="button" class="btn icon sm ghost" data-act="map-zoom" data-v="in" aria-label="${T('app.map.zoom_in')}" title="${T('app.map.zoom_in')} (+)">${icon('i-plus')}</button>
            <button type="button" class="btn icon sm ghost" data-act="map-zoom" data-v="out" aria-label="${T('app.map.zoom_out')}" title="${T('app.map.zoom_out')} (−)"><svg class="ic" aria-hidden="true"><path d="M5 12h14"/></svg></button>
            <button type="button" class="btn icon sm ghost" data-act="map-zoom" data-v="fit" aria-label="${T('app.map.fit')}" title="${T('app.map.fit')} (0)">${icon('i-expand')}</button>
          </div>
          <div class="maptip" id="maptip" role="tooltip" hidden data-keep></div>
        </div>
        <div class="maplegend" aria-hidden="true">${MAP_STATUS.map(s => html`<span class="mst st-${s}"><i></i>${mapStatusName(s)}</span>`)}<span class="faint">${T(m.bw ? 'app.map.size_bw' : 'app.map.size_dns')}</span></div>
        <p class="hint" id="maphelp">${T('app.map.help')}</p>` : mapList(m)}
    </section>`;
}
// The viewport: translate + scale in viewBox units on #mapvp, written directly (no render)
function mapApply() {
  const vp = $('#mapvp'), svg = $('#mapsvg'), v = S.map.view;
  if (!vp) return;
  vp.setAttribute('transform', `translate(${v.x} ${v.y}) scale(${v.k})`);
  const z = v.k >= 1.5;
  if (svg.classList.contains('zoomed') !== z) render();   // node labels appear / go
}
function mapPoint(cx, cy) {
  const svg = $('#mapsvg'), m = svg && svg.getScreenCTM();
  if (!m) return { x: 0, y: 0 };
  const p = svg.createSVGPoint(); p.x = cx; p.y = cy;
  return p.matrixTransform(m.inverse());
}
function mapZoom(f, cx, cy) {
  const svg = $('#mapsvg'); if (!svg) return;
  if (cx == null) { const r = svg.getBoundingClientRect(); cx = r.left + r.width / 2; cy = r.top + r.height / 2; }
  const p = mapPoint(cx, cy), v = S.map.view, k = clampK(v.k * f);
  v.x = p.x - (p.x - v.x) * (k / v.k); v.y = p.y - (p.y - v.y) * (k / v.k); v.k = k;
  mapApply();
}
function mapPan(dx, dy) {   // screen pixels
  const svg = $('#mapsvg'), m = svg && svg.getScreenCTM(); if (!m) return;
  S.map.view.x += dx / m.a; S.map.view.y += dy / m.d; mapApply();
}
function mapFit() { S.map.view = { x: 0, y: 0, k: 1 }; mapApply(); }
// pointer: drag pans (a click without movement still opens the device), two fingers pinch
const MP = { pts: new Map(), drag: false, start: null, dist: 0, moved: false, raf: 0, dx: 0, dy: 0 };
function mapPointerDown(e) {
  const svg = e.target.closest && e.target.closest('#mapsvg'); if (!svg || e.button > 0) return;
  MP.pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (MP.pts.size === 1) { MP.start = { x: e.clientX, y: e.clientY }; MP.moved = false; }
  if (MP.pts.size === 2) { const [a, b] = Array.from(MP.pts.values()); MP.dist = Math.hypot(a.x - b.x, a.y - b.y); }
}
function mapPointerMove(e) {
  if (!MP.pts.has(e.pointerId)) { if (e.target.closest && e.target.closest('.mnode')) mapTip(e.target.closest('.mnode')); return; }
  const prev = MP.pts.get(e.pointerId); MP.pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (MP.pts.size === 2) {
    const [a, b] = Array.from(MP.pts.values()), d = Math.hypot(a.x - b.x, a.y - b.y);
    if (MP.dist) mapZoom(d / MP.dist, (a.x + b.x) / 2, (a.y + b.y) / 2);
    MP.dist = d; MP.moved = true; return;
  }
  if (!MP.moved && Math.hypot(e.clientX - MP.start.x, e.clientY - MP.start.y) < 5) return;
  if (!MP.moved) { MP.moved = true; const svg = $('#mapsvg'); if (svg && svg.setPointerCapture) { try { svg.setPointerCapture(e.pointerId); } catch (x) { /* gone */ } } mapTip(null); }
  MP.dx += e.clientX - prev.x; MP.dy += e.clientY - prev.y;
  if (!MP.raf) MP.raf = requestAnimationFrame(() => { MP.raf = 0; const dx = MP.dx, dy = MP.dy; MP.dx = MP.dy = 0; mapPan(dx, dy); });
}
function mapPointerUp(e) {
  if (!MP.pts.has(e.pointerId)) return;
  MP.pts.delete(e.pointerId);
  if (MP.pts.size < 2) MP.dist = 0;
  if (!MP.pts.size && MP.moved) { MP.drag = true; setTimeout(() => { MP.drag = false; }, 0); }
}
function mapWheel(e) {
  if (!(e.target.closest && e.target.closest('#mapsvg'))) return;
  e.preventDefault();
  mapZoom(Math.exp(-Math.max(-100, Math.min(100, e.deltaY)) / 300), e.clientX, e.clientY);
}
// hover / focus tooltip: plain text nodes only (device names are hostile input)
function mapTip(a) {
  const tip = $('#maptip'), box = $('#mapbox');
  if (!tip || !box) return;
  if (!a || !a.dataset.mac) { tip.hidden = true; return; }
  const d = findDev(a.dataset.mac); if (!d) { tip.hidden = true; return; }
  const p = personOf(d), it = mapModel().items.find(x => x.id === d.mac);
  const lines = [[dname(d), 'b'], [[d.type_info && d.type_info.type_name, p ? p.name : (d.shared ? T('app.ppl.shared') : '')].filter(Boolean).join(' · ')],
    [it ? mapStatusName(it.status) : ''], [(d.ips || []).join(', ')],
    [d.bandwidth ? '↓ ' + fmt.bytes(d.bandwidth.rx_bytes) + ' · ↑ ' + fmt.bytes(d.bandwidth.tx_bytes) : T('app.map.lookups', { n: fmt.num(d.queries || 0) })]];
  tip.replaceChildren(...lines.filter(([t]) => t).map(([t, b]) => { const el = document.createElement(b ? 'strong' : 'div'); el.textContent = t; return el; }));
  const r = a.getBoundingClientRect(), br = box.getBoundingClientRect();
  tip.hidden = false;
  const x = Math.min(br.width - tip.offsetWidth - 8, Math.max(8, r.left - br.left + r.width / 2 - tip.offsetWidth / 2));
  const above = r.top - br.top - tip.offsetHeight - 8;
  tip.style.left = x + 'px'; tip.style.top = (above > 4 ? above : r.bottom - br.top + 8) + 'px';
}
function mapKey(e) {
  const k = e.key;
  if (k === '+' || k === '=') mapZoom(1.25);
  else if (k === '-' || k === '_') mapZoom(0.8);
  else if (k === '0') mapFit();
  else if (k === 'ArrowLeft') mapPan(60, 0);
  else if (k === 'ArrowRight') mapPan(-60, 0);
  else if (k === 'ArrowUp') mapPan(0, 60);
  else if (k === 'ArrowDown') mapPan(0, -60);
  else return false;
  return true;
}
// after a render: remember which nodes were there (only later ones animate in)
function mapAfterRender() {
  if (S.base !== 'map' || !S.data.inv) return;
  const macs = devices().map(d => d.mac).filter(Boolean);
  if (!S.map.seen) S.map.seen = new Set(macs);
  else if (macs.some(m => !S.map.seen.has(m))) setTimeout(() => { macs.forEach(m => S.map.seen.add(m)); }, 900);
}
function mapCard() {
  const list = devices(), online = list.filter(d => d.online).length;
  const alerting = mapAlertMacs(), n = list.filter(d => d.mac && mapStatus(d, alerting) === 'alert').length;
  return card({ key: 'mapcard', icon: 'i-map', title: T('app.nav.map'), actions: html`<a class="btn sm quiet" href="#/map">${T('app.map.open')}</a>`,
    body: html`<a class="mapmini" href="#/map" aria-label="${T('app.map.open')}">
      <span class="mm-i">${icon('i-globe')}</span><span class="mm-l"></span><span class="mm-i">${icon('t-network')}</span><span class="mm-l"></span>
      <span class="mm-d">${list.slice(0, 12).map(d => html`<i class="${d.online ? 'on' : ''}${alerting.has(d.mac) ? ' al' : ''}"></i>`)}</span></a>
      <div class="hint">${T('app.map.card', { n: fmt.num(list.length), online: fmt.num(online) })}${n ? ' · ' + T('app.map.card_alert', { n: fmt.num(n) }) : ''}</div>` });
}

// ---------------------------------------------------------------------------------------
// Stage T - "Since your last visit" (Overview). This browser remembers when the dashboard
// was last open (localStorage, per database); a later visit asks /api/since what happened
// after that. Nothing on the very first visit; dismissible; a reload keeps the same start.
const VISIT_MIN = 10 * 60 * 1000;        // gone at least this long before anything is "since"
const visitKey = () => 'netwarden.visit.' + dbId();
function sinceInit() {
  if (DEMO) return;   // "since your last visit" needs the live server (any time can be asked)
  let base = '';
  try {
    base = sessionStorage.getItem(visitKey());
    if (base == null) { base = localStorage.getItem(visitKey()) || ''; sessionStorage.setItem(visitKey(), base); }
    S.since.off = sessionStorage.getItem(visitKey() + '.off') === '1';
  } catch (e) { base = ''; }
  sinceStamp();
  const t = parseTs(base);
  if (!t || nowMs() - t < VISIT_MIN || S.since.off) return;
  S.since.t = base;
  sinceLoad();
}
// in netwarden's clock (Stage G): /api/since compares it with the server's own timestamps
function sinceStamp() { try { localStorage.setItem(visitKey(), new Date(nowMs()).toISOString()); } catch (e) { /* private mode */ } }
async function sinceLoad() {
  if (!S.since.t) return;
  try { S.since.r = await getJSON('/api/since?t=' + enc(S.since.t)); render(); } catch (e) { S.since.r = null; }
}
function sinceOff() {
  S.since.off = true; S.since.r = null;
  try { sessionStorage.setItem(visitKey() + '.off', '1'); } catch (e) { /* private mode */ }
  render(); const m = $('#main'); if (m) m.focus({ preventScroll: true });
}
const SINCE_ROWS = [['devices', 'i-devices'], ['alerts', 'i-alert'], ['outages', 'i-wifi'], ['arrivals', 'i-home'], ['effects', 'i-check']];
function sinceBanner() {
  const r = S.since.r;
  if (!r || !r.total || S.since.off) return '';
  return html`<section class="card since" data-key="since" aria-labelledby="since-title">
    <div class="card-h"><h2 id="since-title">${icon('i-refresh')}${T('app.since.title', { ago: fmt.rel(r.since) })}</h2>
      <div class="card-a"><button type="button" class="btn icon sm ghost" data-act="since-off" aria-label="${T('app.since.dismiss')}" title="${T('app.since.dismiss')}">${icon('i-x')}</button></div></div>
    <div class="since-chips">${SINCE_ROWS.filter(([k]) => r[k].n).map(([k, ic]) => html`<button type="button" class="chip" data-act="since-go" data-v="${k}">${icon(ic)}${T('app.since.' + k, { n: fmt.num(r[k].n) })}</button>`)}</div>
  </section>`;
}
function sinceGo(k) {
  const r = S.since.r; if (!r) return;
  const one = r[k].n === 1 ? r[k].items[0] : null;
  if (k === 'devices') {
    if (one) { go(devHref(one.mac)); return; }
    Object.assign(S.f, { q: '', type: '', owner: '', room: '', show: 'all', since: r.since }); go('#/devices');
  } else if (k === 'alerts') go('#/inbox');
  else if (k === 'outages') go('#/health');
  else if (k === 'arrivals') go(one && one.person ? '#/people/' + one.person : '#/people');
  else { S.sugTab = 'done'; go('#/suggestions'); }
}

// ---------------------------------------------------------------------------------------
// Stage T - live updates: one EventSource on /api/stream (the server's ONE change detector
// decides what changed). An event names what to fetch again; only those datasets are
// requested, and only what changed re-renders, with a short highlight. The page shows
// live / reconnecting / paused; reconnects with backoff; pauses while the tab is hidden
// and catches up on return (Last-Event-ID, or a full refresh when that is too old).
// Toasts for new alerts still come from /api/notify (quiet hours apply there); data never waits.
const LIVE_SETS = {
  device_new: ['inv', 'alerts', 'inbox', 'notify'], device_online: ['inv', 'pres'], device_offline: ['inv', 'pres'],
  alert_new: ['alerts', 'inbox', 'notify', 'inv'], inbox_changed: ['inbox', 'alerts', 'inv'],
  presence_changed: ['pres', 'notify'], health_changed: ['health', 'status', 'score', 'notify'],
  suggestion_changed: ['sug', 'score', 'inbox'], settings_changed: ['notify', 'status', 'pres'],
  notes_changed: ['inv', 'alerts', 'inbox', 'sug', 'pres'],
};
const LIVE_REFRESH_MS = 5 * 60 * 1000;   // the safety-net full refresh while the stream is live
const LIVE = { es: null, state: 'off', last: '', tries: 0, timer: null, want: new Set(), flush: null };
const FLASH_MS = 1600;
function flashOn(key) { S.flash[key] = Date.now() + FLASH_MS; clearTimeout(S.flashTimer); S.flashTimer = setTimeout(render, FLASH_MS + 50); }
function isFlash(key) { return (S.flash[key] || 0) > Date.now(); }
function liveSupported() { return typeof window.EventSource === 'function'; }
function liveState(st) { if (LIVE.state !== st) { LIVE.state = st; liveIndicator(); schedule(); } }
function liveIndicator() {
  const el = $('#live'); if (!el || !F) return;
  const st = LIVE.state;
  el.className = 'live st-' + st;
  el.hidden = st === 'off';
  el.title = st === 'off' ? '' : T('app.live.' + st + '_hint');
  morph(el, st === 'off' ? '' : html`<i aria-hidden="true"></i><span class="lbl">${T('app.live.' + st)}</span>`);
}
function liveConnect() {
  if (DEMO || !liveSupported() || !S.meta) return;   // the static demo is a snapshot: no stream
  clearTimeout(LIVE.timer);
  if (LIVE.es) return;
  if (document.visibilityState !== 'visible') { liveState('paused'); return; }
  const es = new EventSource(url('/api/stream') + (LIVE.last ? '?last=' + enc(LIVE.last) : ''));
  LIVE.es = es;
  es.addEventListener('hello', ev => {
    try { LIVE.last = JSON.parse(ev.data).id || LIVE.last; } catch (e) { /* keep the last id */ }
    const was = LIVE.state; LIVE.tries = 0; liveState('live');
    // a long gap, or the page is showing "can't reach netwarden": catch up now (Stage G)
    if (was === 'reconnecting' && (S.offline || S.loadErr || Date.now() - S.updated > REFRESH_MS)) refresh();
  });
  es.addEventListener('resync', () => { LIVE.want.clear(); refresh(); });
  Object.keys(LIVE_SETS).forEach(t => es.addEventListener(t, ev => liveEvent(t, ev)));
  es.onerror = () => {
    es.close();
    if (LIVE.es !== es) return;
    LIVE.es = null;
    if (document.visibilityState !== 'visible') { liveState('paused'); return; }
    LIVE.tries++;
    const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(LIVE.tries - 1, 5))) * (0.8 + 0.4 * Math.random());
    const wasLive = LIVE.state === 'live';
    liveState('reconnecting');
    // the stream just dropped: ask once right away, so a stopped server shows its banner
    // (and the data's real age) within seconds instead of at the next 30 s refresh
    if (wasLive) refresh();
    LIVE.timer = setTimeout(liveConnect, delay);
  };
}
function liveStop(state) {
  clearTimeout(LIVE.timer);
  if (LIVE.es) { const es = LIVE.es; LIVE.es = null; es.close(); }
  liveState(state);
}
function liveEvent(type, ev) {
  let d = {};
  try { d = JSON.parse(ev.data) || {}; } catch (e) { return; }
  if (ev.lastEventId) LIVE.last = ev.lastEventId;
  LIVE_SETS[type].forEach(k => LIVE.want.add(k));
  if (typeof d.mac === 'string') flashOn('dev:' + d.mac);
  clearTimeout(LIVE.flush);
  LIVE.flush = setTimeout(() => { const keys = Array.from(LIVE.want); LIVE.want.clear(); refreshSome(keys); }, 250);
}

// ---------------------------------------------------------------------------------------
// Stage T - Undo everywhere: every toast with an Undo button also lands on this stack, so
// Ctrl/Cmd+Z (outside text fields) undoes the newest action - the same function its
// toast's button runs. Entries live 2 minutes: long enough to notice a mistake, short
// enough that a stray Ctrl+Z much later never reverts something long forgotten (the
// server keeps undo tokens 15 min; older actions are undone from their own page).
const UNDO_STACK = [], UNDO_TTL_MS = 2 * 60 * 1000;
function undoPush(run, close) {
  const entry = { run, close, at: Date.now() };
  UNDO_STACK.push(entry);
  while (UNDO_STACK.length > UNDO_MAX) UNDO_STACK.shift();
  return entry;
}
function undoDrop(entry) { const i = UNDO_STACK.indexOf(entry); if (i >= 0) UNDO_STACK.splice(i, 1); }
function undoRun(entry) { undoDrop(entry); if (entry.close) entry.close(); entry.run(); }
function undoLast() {
  while (UNDO_STACK.length && Date.now() - UNDO_STACK[UNDO_STACK.length - 1].at > UNDO_TTL_MS) UNDO_STACK.pop();
  const entry = UNDO_STACK[UNDO_STACK.length - 1];
  if (!entry) { toast(T('app.inbox.nothing_to_undo')); return; }
  undoRun(entry);
}

// ---------------------------------------------------------------------------------------
// Render
const VIEWS = { overview: viewOverview, devices: viewDevices, security: viewSecurity, health: viewHealth,
                suggestions: viewSuggestions, privacy: viewPrivacy, activity: viewActivity, family: viewFamily,
                ai: viewAI, system: viewSystem, inbox: viewInbox, settings: viewSettings, welcome: viewWelcome,
                people: viewPeople, map: viewMap, report: viewReport };
// Page badges (sub-tabs): inbox = everything to do, security = attention items,
// suggestions = open suggestions, health = an outage now
function navCount(s) {
  if (s === 'inbox') return inboxCount();
  if (s === 'security') return securityCount();
  if (s === 'suggestions') return sugCount();
  if (s === 'health') return S.data.health && S.data.health.verdict.level === 'bad' ? 1 : 0;
  return 0;
}
const NAV_COUNT_LABEL = { inbox: 'app.inbox.count', security: 'app.stat.alerts', suggestions: 'app.sug.open_n', health: 'app.h.down_now' };
// Place badges: ONE number to act on (the inbox already holds every alert and suggestion,
// so they are not counted twice) + "the internet is down now" on Network.
function groupCount(g) {
  if (g === 'inbox') return inboxCount();
  if (g === 'network') return navCount('health');
  return 0;
}
const GROUP_COUNT_LABEL = { inbox: 'app.inbox.count', network: 'app.h.down_now' };
const NAV_GO = Object.fromEntries(Object.entries(GO_KEYS).map(([l, s]) => [s, l]));
const groupHere = () => GROUP_OF[S.base] || 'overview';
function navLink(g, prefix) {
  const i = GROUPS.findIndex(x => x[0] === g), n = groupCount(g), label = groupLabel(g), first = groupPages(g)[0];
  return html`<a href="#/${first}" data-key="${(prefix || '') + 'g-' + g}"${groupHere() === g ? html` aria-current="page"` : ''} title="${label} (${i + 1})"${prefix ? html` role="menuitem"` : ''}>
    ${icon(GROUP_ICON[g])}<span class="lbl">${label}</span>${n ? html`<span class="count${isFlash('nav:' + (g === 'network' ? 'health' : g)) ? ' flash' : ''}" aria-label="${T(GROUP_COUNT_LABEL[g], { n })}">${n}</span>` : ''}</a>`;
}
function navLinks() { return GROUPS.map(x => navLink(x[0])); }
// The pages of the current place as tabs above the page (none for a one-page place)
function subTabs() {
  const g = groupHere(), pages = groupPages(g);
  if (pages.length < 2 || !pages.includes(S.base)) return '';
  return html`<nav class="subtabs" data-key="subtabs-${g}" aria-label="${T('app.subnav', { section: groupLabel(g) })}">${pages.map(p => {
    const n = navCount(p);
    return html`<a href="#/${p}" data-key="st-${p}"${S.base === p ? html` aria-current="page"` : ''}>${icon(SEC_ICON[p])}<span>${T('app.nav.' + p)}</span>${n ? html`<span class="count${p === 'suggestions' ? ' info' : ''}${isFlash('nav:' + p) ? ' flash' : ''}" aria-label="${T(NAV_COUNT_LABEL[p], { n })}">${n}</span>` : ''}</a>`;
  })}</nav>`;
}
// Phones: four places in the bottom bar, the others behind "More" (Esc closes it).
function bottomNav() {
  const rest = GROUPS.map(x => x[0]).filter(g => !NAV_PRIMARY.includes(g)), here = rest.includes(groupHere());
  const n = rest.reduce((sum, g) => sum + groupCount(g), 0);
  // always "More" (renaming it after the current place hid the way to the others); the
  // button is highlighted while one of its places is open, and the menu marks which one
  return html`${NAV_PRIMARY.map(g => navLink(g))}
    <button type="button" class="more-btn" id="btnMore" data-key="more" data-act="more" aria-haspopup="menu" aria-expanded="${String(S.more)}" aria-controls="moremenu"${here ? html` aria-current="page"` : ''}>
      ${icon('i-more')}<span class="lbl">${T('app.nav.more')}</span>${n ? html`<span class="count" aria-label="${T('app.nav.more_count', { n })}">${n}</span>` : ''}</button>
    ${S.more ? html`<div class="moremenu" id="moremenu" role="menu" data-key="moremenu" aria-label="${T('app.nav.more')}">${rest.map(g => navLink(g, 'm-'))}</div>` : ''}`;
}
function closeMore(focus) {
  if (!S.more) return;
  S.more = false; render();
  if (focus) { const b = $('#btnMore'); if (b) b.focus(); }
}
function render() {
  if (!S.meta || !F) return;
  morph($('#nav'), navLinks());
  morph($('#bottomnav'), bottomNav());
  morph($('#sidefoot'), html`${S.meta.demo ? html`<div class="demo-pill">${T('ui.demo_badge')}</div>` : ''}`);
  S.skel = false;
  morph($('#view'), html`${subTabs()}${VIEWS[S.base]()}`);
  $('#main').setAttribute('aria-busy', String(S.skel));   // skeleton() sets it while data is on its way
  // WCAG 2.4.2: the tab title names the page (its own heading, e.g. a person's name)
  const h1 = $('#view h1'), head = S.base === 'overview' ? T('app.nav.overview')   // its heading is a count
    : h1 ? h1.textContent.replace(/\s+/g, ' ').trim() : '';
  const ttl = head && head !== 'netwarden' ? head + ' - netwarden' : 'netwarden';
  if (document.title !== ttl) document.title = ttl;
  // the chat side panel / bottom sheet: everywhere except the #/ai page itself
  const chatOpen = S.chat.open && S.base !== 'ai', cp = $('#chatpanel');
  if (chatOpen) morph($('#chatpanelbody'), viewChatPanel());
  if (chatOpen) cp.setAttribute('aria-modal', String(chatIsSheet()));   // modal only as the phone's bottom sheet
  if (chatOpen !== !cp.hidden) {
    cp.hidden = !chatOpen; document.body.classList.toggle('chat-open', chatOpen);
    if (!chatOpen) morph($('#chatpanelbody'), '');
  }
  const cb = $('#btnChat'); cb.setAttribute('aria-expanded', String(chatOpen)); cb.classList.toggle('on', chatOpen || S.base === 'ai');
  const open = drawerOpen(), dr = $('#drawer');
  if (open) morph($('#drawerbody'), viewDrawer());
  if (open !== dr.classList.contains('open')) {
    dr.classList.toggle('open', open); $('#backdrop').classList.toggle('open', open);
    document.body.classList.toggle('locked', open);
    if (open) {
      dr.removeAttribute('inert'); S.returnFocus = S.returnFocus || document.activeElement;
      const want = S.drawerFocus; S.drawerFocus = null;
      if (want) focusWhenReady(want, '#drawer [data-act="close"]'); else focusSoon('#drawer [data-act="close"]');
    }
    else {
      dr.setAttribute('inert', ''); const rf = S.returnFocus; S.returnFocus = null; if (rf && document.contains(rf)) rf.focus({ preventScroll: true });
      // no stale dialog left in the page once it has slid out (any route that closes it)
      setTimeout(() => { if (!drawerOpen()) morph($('#drawerbody'), ''); }, 400);
    }
  }
  // Stage G: one banner over the page - unreachable > an error > some parts missing - with
  // Retry; shown only while older data is still on screen (otherwise the page itself says it)
  const b = $('#banner'), bmsg = S.offline ? T('app.offline') : S.loadErr ? T('app.toast.error', { error: S.loadErr })
    : (S.partial.length ? T('app.load.partial') : '');
  b.hidden = !bmsg || !S.updated;
  if (!b.hidden) morph(b, html`${icon('i-alert')}<span>${bmsg}</span><button type="button" class="btn sm ghost" data-act="retry"${S.refreshing ? ' disabled' : ''}>${S.refreshing ? T('ui.loading') : T('app.retry')}</button>`);
  noticeBar();
  demoBar();
  liveIndicator();
  mapAfterRender();
  tick();
  viewSave();
  tryScroll();
}
// Round 9 W: the static demo's banner over every page - made-up data, read-only, nothing is
// sent anywhere; links to the install guide and the source. Hidden for this tab once closed.
const DEMO_BAR_KEY = 'netwarden.demo.bar_hidden';
function demoBar() {
  if (!DEMO) return;
  let el = $('#demobar');
  if (!el) {
    el = document.createElement('div'); el.id = 'demobar'; el.className = 'banner info demobar'; el.setAttribute('role', 'note');
    $('#banner').before(el);
  }
  let hidden = false; try { hidden = sessionStorage.getItem(DEMO_BAR_KEY) === '1'; } catch (e) { /* private mode */ }
  el.hidden = hidden;
  if (hidden) return;
  const sd = S.meta.static_demo || {}, zh = /^zh/.test(S.lang);
  const ext = (href, label) => (/^https:\/\//.test(href || '') ? html`<a href="${href}" target="_blank" rel="noopener noreferrer">${label}</a>` : '');
  morph(el, html`${icon('i-eye-off')}<span>${T('app.demo.banner')} <span class="demolinks">${ext(zh ? sd.install_url_zh : sd.install_url, T('app.demo.install'))}${ext(sd.source_url, T('app.demo.source'))}</span></span>
    <button type="button" class="btn icon sm quiet" data-act="demo-hide" aria-label="${T('app.demo.hide')}" title="${T('app.demo.hide')}">${icon('i-x')}</button>`);
}
// Round 10b: a drawer for something the demo home does not have (#/device/<any mac>): a
// way back to the start instead of a dead end. Nothing in the real app.
function demoBack() {
  return DEMO ? html`<p class="demo-back"><a class="btn sm" href="#/">${icon('i-home')}${T('app.demo.back')}</a></p>` : '';
}
// Round 10b: first visit to the static demo - one card on top of Overview: what this is,
// three findings the made-up home really has (taken from its own alerts, so the links can
// never point at something that is not there) and the install guide. Dismissed for good
// in this browser (localStorage); never in the real app.
const DEMO_WELCOME_KEY = 'netwarden.demo.welcome_hidden';
function demoWelcomeHidden() { try { return localStorage.getItem(DEMO_WELCOME_KEY) === '1'; } catch (e) { return false; } }
function demoWelcome() {
  if (!DEMO || S.demoWelcomeOff || demoWelcomeHidden()) return '';
  const a = S.data.alerts || {}, sd = (S.meta && S.meta.static_demo) || {};
  const first = (list, ok) => (list || []).find(x => x && x.mac && (!ok || ok(x)));
  const finds = [
    ['threat', first(a.threats)],
    ['bypass', first(a.visibility, v => v.kind === 'bypass') || first(a.visibility)],
    ['night', first(a.unusual_hours)],
  ].filter(f => f[1]).map(([k, it]) => html`<li><a href="${devHref(it.mac)}">${T('app.demo.w.' + k, { name: devName(it.mac, it.name || it.device) })}</a></li>`);
  const inst = /^zh/.test(S.lang) ? sd.install_url_zh : sd.install_url;
  return html`<section class="card demo-welcome" data-key="demo-welcome" aria-labelledby="demoWelcomeH">
    <div class="card-h"><h2 id="demoWelcomeH">${icon('i-spark')}${T('app.demo.w.title')}</h2>
      <div class="card-a"><button type="button" class="btn icon sm quiet" data-act="demo-welcome-hide" aria-label="${T('app.demo.w.hide')}" title="${T('app.demo.w.hide')}">${icon('i-x')}</button></div></div>
    <p>${T('app.demo.w.text')}</p>
    ${finds.length ? html`<p class="hint">${T('app.demo.w.try')}</p><ul class="demo-finds">${finds}</ul>` : ''}
    ${/^https:\/\//.test(inst || '') ? html`<p><a class="btn sm" href="${inst}" target="_blank" rel="noopener noreferrer">${icon('i-download')}${T('app.demo.install')}</a></p>` : ''}
  </section>`;
}
function demoWelcomeHide() {
  S.demoWelcomeOff = true;
  try { localStorage.setItem(DEMO_WELCOME_KEY, '1'); } catch (e) { /* private mode: hidden until a reload */ }
  render();
  speak(T('app.demo.w.hidden'));
  const h = $('#view h1'); if (h) { h.setAttribute('tabindex', '-1'); h.focus({ preventScroll: true }); }
}
function demoHide() {
  try { sessionStorage.setItem(DEMO_BAR_KEY, '1'); } catch (e) { /* private mode: hidden until a reload */ }
  const el = $('#demobar'); if (el) el.hidden = true;
  const m = $('#main'); if (m) m.focus({ preventScroll: true });
}
// Stage G: move focus into a layer that is sliding in. It cannot take focus while still
// `visibility: hidden` (the first frames of its transition), so try again for ~1 s; the
// person's own focus move meanwhile (they clicked / tabbed elsewhere) wins.
// focus `sel` once it exists (the drawer's body arrives with its data), up to ~3 s;
// `fallback` gets focus if it never shows up
function focusWhenReady(sel, fallback) {
  let n = 60;
  (function again() {
    const el = $(sel);
    if (el) { el.focus({ preventScroll: true }); return; }
    if (--n > 0) setTimeout(again, 50); else if (fallback) focusSoon(fallback);
  })();
}
function focusSoon(sel, tries) {
  const was = document.activeElement;
  (function again(n) {
    setTimeout(() => {
      const el = $(sel);
      if (!el || document.activeElement === el) return;
      if (document.activeElement !== was && n < (tries || 25)) return;   // focus moved on by itself
      el.focus({ preventScroll: true });
      if (document.activeElement !== el && n > 0) again(n - 1);
    }, 40);
  })(tries || 25);
}
function tick() {
  const u = $('#updated');
  // "just now" is its own sentence: Intl's "now" inside "{ago}更新" reads as "update now"
  if (u && F) u.textContent = S.refreshing && !S.updated ? T('ui.loading') : (!S.updated ? ''
    : Date.now() - S.updated < 60000 ? T('app.updated_just_now') : T('app.updated', { ago: fmt.rel(S.updated + skewMs()) }));   // our clock -> netwarden's
  const r = $('#btnRefresh'); if (r) r.classList.toggle('spinning', S.refreshing);
  const c = S.pair.code;   // a pairing code that just ran out: say so instead of showing it
  if (c && !c.gone && pairExpired(c)) { c.gone = true; render(); }
}
function applyStatic() {
  document.documentElement.lang = S.lang;
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = T(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.placeholder = T(el.dataset.i18nPlaceholder); });
  document.querySelectorAll('[data-i18n-aria]').forEach(el => { el.setAttribute('aria-label', T(el.dataset.i18nAria)); });
  $('#langsel').value = S.lang;
  $('#btnRefresh').title = T('app.refresh') + ' (R)';
  $('#btnChat').title = T('app.chat.open') + ' (C)';
  $('#btnKeys').title = T('app.sys.shortcuts') + ' (?)';
  applyTheme();
}

// ---------------------------------------------------------------------------------------
// Data loading
// The Overview's datasets (the same names as web.OVERVIEW). Stage T: a full refresh is ONE
// request (/api/overview, every dataset + a hash of each); a live event refetches only the
// datasets it names from their own endpoints. Both send the last ETag (If-None-Match): an
// unchanged answer is a body-less 304, and an unchanged dataset keeps its old object, so
// nothing re-renders for nothing.
const DATASETS = { inv: '/api/inventory', alerts: '/api/alerts', privacy: '/api/privacy', vis: '/api/visibility',
                   status: '/api/status', homeAct: '/api/activity', upnp: '/api/upnp',
                   health: '/api/health', sug: '/api/suggestions', score: '/api/score', inbox: '/api/inbox',
                   pres: '/api/presence', notify: '/api/notify', hyg: '/api/hygiene' };
const NAV_OF = { inbox: 'inbox', alerts: 'security', sug: 'suggestions', health: 'health' };   // what flashes when a dataset changes
let refreshTimer = null;
const lastTag = {};   // dataset (+ lang) -> the ETag / hash of what S.data holds
// GET a JSON endpoint with the ETag we hold: -> {tag, text} or null when unchanged (304)
async function getTagged(path, tag) {
  const r = await fetch(api(path), { cache: 'no-store', headers: tag ? { 'if-none-match': tag } : {} });
  needPair(r);   // (+ netwarden's clock from the Date header)
  if (r.status === 304) return null;
  const t = await r.text();
  if (!r.ok) { let j = {}; try { j = JSON.parse(t); } catch (e) { /* not JSON */ } const err = new Error(httpMsg(j, r.status)); err.status = r.status; throw err; }
  return { tag: r.headers.get('etag') || '', text: t };
}
// a dataset's new value (or the old object when its hash is unchanged) -> did it change?
// a dataset the page got from an action's answer: the next refresh must not keep it
// Every request that may write datasets gets a sequence number when it STARTS; a dataset
// remembers the number of the request that wrote it, so a slow /api/overview never
// overwrites a fresher live refetch (or an action's own answer) that landed meanwhile.
let dataSeq = 0;
const dataAt = {};
function localData(k, value) { S.data[k] = value; dataAt[k] = ++dataSeq; delete lastTag[k + S.lang]; delete lastTag['overview' + S.lang]; }
function takeData(k, tag, value, live, seq) {
  if (seq !== undefined && (dataAt[k] || 0) > seq) return false;   // fresher data is here already
  if (tag && lastTag[k + S.lang] === tag) return false;
  S.data[k] = value; lastTag[k + S.lang] = tag;
  if (seq !== undefined) dataAt[k] = seq;
  if (live && NAV_OF[k]) flashOn('nav:' + NAV_OF[k]);
  return true;
}
async function refresh() {
  if (S.refreshing) return;
  S.refreshing = true; tick();
  const lang = S.lang;
  let net = 0, changed = false, err = null, partial = S.partial;
  const seq = ++dataSeq;
  // Stage G: a first load that takes long says so (Slow 3G); the retry button shows progress
  const slow = setTimeout(() => { if (S.refreshing && !S.updated) { S.slow = true; render(); } }, 6000);
  const wasBad = S.offline || S.loadErr;
  if (wasBad) render();         // the Retry buttons show "Loading…" meanwhile
  try {
    const r = await getTagged('/api/overview', lastTag['overview' + lang]);
    if (lang !== S.lang) { S.refreshing = false; clearTimeout(slow); return; }    // the language changed meanwhile
    if (r) {
      const j = JSON.parse(r.text);
      let stale = false;
      Object.keys(j.parts || {}).forEach(k => {
        if ((dataAt[k] || 0) > seq) { stale = true; return; }
        if (takeData(k, j.etags[k], j.parts[k], false, seq)) changed = true;
      });
      // a part was older than what we hold (or missing): the bundle's ETag does not describe S.data
      partial = Array.isArray(j.failed) ? j.failed : [];
      if (stale || partial.length) delete lastTag['overview' + lang]; else lastTag['overview' + lang] = r.tag;
    }
  } catch (e) { if (isNetErr(e)) net++; else err = errText(e); }
  clearTimeout(slow);
  if (wasBad || S.offline !== net > 0 || S.loadErr !== err || S.slow || String(S.partial) !== String(partial)) changed = true;
  S.offline = net > 0; S.loadErr = err; S.slow = false; S.partial = partial;
  if (!S.offline && !err) S.updated = Date.now();
  S.loading = false;
  if (S.route.name === 'device' && !S.offline) { await loadDevice(true); changed = true; }
  if (S.base === 'family' && !S.offline) loadFamily();   // renders itself when it lands
  if (S.base === 'people' && !S.offline) loadPeople();   // so does this
  if (S.base === 'security' && !S.offline) loadHyg();    // Stage Q: the hygiene card
  // a device-context chip left over from another session / DB: drop it if the device is gone
  if (S.chat.ctx && S.data.inv && !findDev(S.chat.ctx.mac)) { S.chat.ctx = null; saveChat(); changed = true; }
  S.refreshing = false;
  if (changed) render(); else tick();
  checkNotify();
  schedule();
}
// Stage T: what a live event named - only those datasets, each from its own endpoint
async function refreshSome(keys) {
  keys = keys.filter(k => DATASETS[k]);
  if (!keys.length || !S.meta) return;
  const lang = S.lang, seq = ++dataSeq;
  const res = await Promise.allSettled(keys.map(k => getTagged(DATASETS[k], lastTag[k + lang])));
  if (lang !== S.lang) return;
  let changed = false;
  res.forEach((r, i) => {
    if (r.status === 'fulfilled' && r.value && takeData(keys[i], r.value.tag, JSON.parse(r.value.text), true, seq)) changed = true;
  });
  if (!changed) return;
  delete lastTag['overview' + lang];      // the bundle's own ETag no longer matches what we hold
  S.updated = Date.now();
  if (S.route.name === 'device' && keys.includes('inv')) await loadDevice(true);
  render();
  if (keys.includes('notify')) checkNotify();   // quiet hours apply to the pop-ups (server-side), never to the data
}
const RETRY_MS = 10000;   // Stage G: unreachable / an error -> try again sooner (a restart takes seconds)
function schedule() {
  clearTimeout(refreshTimer);
  if (DEMO) return;   // saved files never change: no periodic refresh
  const every = S.offline || S.loadErr ? RETRY_MS : LIVE.state === 'live' ? LIVE_REFRESH_MS : REFRESH_MS;   // live: a slow safety net only
  refreshTimer = setTimeout(() => { if (document.visibilityState === 'visible') refresh(); else schedule(); }, every);
}
async function loadChoices() {
  const lang = S.lang;
  const [t, p, r] = await Promise.allSettled([getJSON('/api/types'), getJSON('/api/people'), getJSON('/api/rooms')]);
  if (lang !== S.lang) return;
  if (t.status === 'fulfilled') S.types = t.value.types || [];
  if (p.status === 'fulfilled') setPersons(p.value);
  if (r.status === 'fulfilled') S.rooms = r.value.items || [];
  morph($('#peopleList'), S.people.map(i => html`<option value="${i.name}"></option>`));
  morph($('#roomList'), S.rooms.map(i => html`<option value="${i.name}"></option>`));
  render();
}
async function loadDevice(quiet) {
  const mac = S.dev.mac; if (!mac) return;
  const q = '?mac=' + enc(mac);
  const [d, a, t, s] = await Promise.allSettled([getJSON('/api/device' + q), getJSON('/api/activity' + q), getJSON('/api/timeline' + q),
                                                 getJSON('/api/screentime?days=7&device=' + enc(mac))]);
  if (S.dev.mac !== mac) return;
  if (d.status === 'fulfilled') { S.dev.d = d.value; S.dev.err = null; }
  else if (!isNetErr(d.reason)) S.dev.err = errText(d.reason);
  if (a.status === 'fulfilled') S.dev.act = a.value;
  if (t.status === 'fulfilled') S.dev.tl = t.value;
  if (s.status === 'fulfilled') S.dev.st = (s.value.devices || [])[0] || { minutes: 0 };
  if (!quiet) render();
}
async function loadLookup() {
  const { name, arg } = S.route, key = name + ':' + arg;
  try {
    const r = await getJSON(name === 'domain' ? '/api/domain?d=' + enc(arg) : '/api/service?name=' + enc(arg));
    if (S.look.key === key) { S.look.r = r; S.look.err = null; }
  } catch (e) { if (S.look.key === key) S.look.err = errText(e); }
  render();
}

// ---------------------------------------------------------------------------------------
// Round 9 U - remember the view. Per page, its filters / sort / tab live in ONE place:
//   - the hash query of that page's history entry (#/devices?owner=Mia&show=online,
//     #/suggestions?tab=done, #/map?by=type): shareable, survives reload and Back, and is
//     relative to the page, so it works under the Home Assistant ingress base path too;
//   - localStorage "netwarden.view.v1.<db>" (versioned; anything unknown, outdated or
//     corrupt is dropped value by value): the page opens the way it was left.
// A page link without a query keeps the remembered view; a query sets it exactly.
// Scroll: every history entry gets an id (history.state.nw); its scroll position is kept in
// sessionStorage, so Back - and a reload - returns to where the page was.
const VIEW_V = 1;
const viewKey = () => 'netwarden.view.v' + VIEW_V + '.' + dbId();
const vStr = n => v => (typeof v === 'string' && v.length <= n && !/[\u0000-\u001f]/.test(v) ? v : undefined);
const vOne = list => v => (list.includes(v) ? v : undefined);
const VIEW_PAGES = {
  devices: { def: { q: '', type: '', owner: '', room: '', show: 'all', group: '', sort: 'queries', dir: -1 },
             get: () => S.f, set: o => Object.assign(S.f, o),
             schema: { q: vStr(100), type: vOne([''].concat(TYPE_KEYS)), owner: vStr(64), room: vStr(64), show: vOne(['all', 'online', 'risky', 'new']),
                       group: vOne(['', 'owner', 'room', 'type']), sort: v => (typeof v === 'string' && Object.prototype.hasOwnProperty.call(SORTS, v) ? v : undefined),
                       dir: v => ({ '1': 1, '-1': -1 })[String(v)] } },
  map: { def: { by: 'person', mode: '', q: '', person: '', type: '', status: '' },
         get: () => Object.assign({}, S.map, { mode: S.map.mode || '' }), set: o => Object.assign(S.map, o, { mode: o.mode || null }),
         schema: { by: vOne(['person', 'type']), mode: vOne(['', 'map', 'list']), q: vStr(100), person: vStr(80), type: vOne([''].concat(TYPE_KEYS)),
                   status: v => ([''].concat(MAP_STATUS).includes(v) ? v : undefined) } },
  suggestions: { def: { tab: 'open' }, get: () => ({ tab: S.sugTab }), set: o => { S.sugTab = o.tab; }, schema: { tab: vOne(SUG_TABS) } },
  report: { def: { period: '7', privacy: 'shareable', names: 'type', people: 'roles', format: 'html' },
            get: () => S.share, set: o => Object.assign(S.share, o),
            schema: Object.fromEntries(Object.entries(SHARE_OPTS).map(([k, vs]) => [k, vOne(vs)])) },
};
// {key: valid value} from any object / URLSearchParams; missing or invalid keys -> default
function viewClean(page, src, get) {
  const P = VIEW_PAGES[page], out = {};
  Object.keys(P.def).forEach(k => { const v = src == null ? undefined : P.schema[k](get ? get(k) : src[k]); out[k] = v === undefined ? P.def[k] : v; });
  return out;
}
function viewQuery(page) {
  const P = VIEW_PAGES[page], cur = P.get(), p = new URLSearchParams();
  Object.keys(P.def).forEach(k => { if (cur[k] !== P.def[k] && cur[k] != null && cur[k] !== '') p.set(k, cur[k]); });
  return p.toString();
}
function viewLoad() {
  let o = null;
  try { o = JSON.parse(localStorage.getItem(viewKey()) || 'null'); } catch (e) { o = null; }
  if (!o || typeof o !== 'object' || o.v !== VIEW_V) return;
  const pages = o.pages && typeof o.pages === 'object' ? o.pages : {};
  Object.keys(VIEW_PAGES).forEach(pg => { if (pages[pg] && typeof pages[pg] === 'object') VIEW_PAGES[pg].set(viewClean(pg, pages[pg])); });
  if (o.open && typeof o.open === 'object') Object.keys(o.open).slice(0, 40).forEach(k => { if (/^[\w.-]{1,40}$/.test(k) && typeof o.open[k] === 'boolean') S.openSec[k] = o.open[k]; });
  if (Array.isArray(o.sug)) o.sug.slice(0, 30).forEach(id => { if (typeof id === 'string' && id.length <= 120) S.sugOpen.add(id); });
}
let viewSaved = '', viewHashT = null;
function viewSave() {
  const pages = {};
  Object.keys(VIEW_PAGES).forEach(pg => { const q = viewQuery(pg); if (q) pages[pg] = Object.fromEntries(new URLSearchParams(q)); });
  const s = JSON.stringify({ v: VIEW_V, pages, open: S.openSec, sug: Array.from(S.sugOpen).slice(-30) });
  if (s !== viewSaved && dbId()) { viewSaved = s; try { localStorage.setItem(viewKey(), s); } catch (e) { /* private mode / full */ } }
  // the page's own entry carries its view (replaceState: no new history entry; debounced -
  // some browsers limit how often it may be called)
  if (S.route.name !== S.base || !VIEW_PAGES[S.base]) return;
  const q = viewQuery(S.base), want = '#/' + S.base + (q ? '?' + q : '');
  if (location.hash === want) return;
  clearTimeout(viewHashT);
  viewHashT = setTimeout(() => {
    if (S.route.name !== S.base || location.hash.split('?')[0] !== '#/' + S.base) return;
    const q2 = viewQuery(S.base), w2 = '#/' + S.base + (q2 ? '?' + q2 : '');
    if (location.hash !== w2) try { history.replaceState(history.state, '', w2); } catch (e) { /* rate-limited: next change */ }
  }, 250);
}
// scroll per history entry
const SCROLL_KEY = 'netwarden.scroll', SCROLL_MAX = 60;
let scrollMap = {};
try { const m = JSON.parse(sessionStorage.getItem(SCROLL_KEY) || '{}'); if (m && typeof m === 'object' && !Array.isArray(m)) scrollMap = m; } catch (e) { scrollMap = {}; }
if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
function entryId() { const s = history.state; return s && typeof s.nw === 'string' ? s.nw : null; }
let curEntry = null;   // the entry on screen (hashchange: history.state is already the next one)
// a new entry gets an id (null = it is new); a known one (Back / Forward / reload) returns it.
// The entry being left keeps its scroll position (the new page has not scrolled yet).
function entryVisit() {
  if (curEntry && !S.wantY) scrollKeep(curEntry);
  let id = entryId(); const known = !!id;
  if (!known) {
    id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    try { history.replaceState(Object.assign({}, history.state, { nw: id }), ''); } catch (e) { id = null; }
  }
  curEntry = id;
  return known ? id : null;
}
let scrollSaveT = null;
function scrollSaved() { const id = entryId(); if (id && id === curEntry && !S.wantY) scrollKeep(id); }
function scrollKeep(id) {
  delete scrollMap[id]; scrollMap[id] = Math.round(window.scrollY);
  const keys = Object.keys(scrollMap); if (keys.length > SCROLL_MAX) keys.slice(0, keys.length - SCROLL_MAX).forEach(k => delete scrollMap[k]);
  clearTimeout(scrollSaveT);
  scrollSaveT = setTimeout(() => { try { sessionStorage.setItem(SCROLL_KEY, JSON.stringify(scrollMap)); } catch (e) { /* private mode */ } }, 300);
}
// the page may still be loading (People, Family): try again after each render for 3 s
function restoreScroll(y) { S.wantY = { y, until: Date.now() + 3000 }; tryScroll(); }
function tryScroll() {
  const w = S.wantY; if (!w) return;
  const max = document.documentElement.scrollHeight - window.innerHeight;
  window.scrollTo(0, Math.min(w.y, Math.max(0, max)));
  if (max >= w.y || Date.now() > w.until) S.wantY = null;
}
window.addEventListener('scroll', scrollSaved, { passive: true });
['wheel', 'touchstart', 'keydown', 'mousedown'].forEach(t => window.addEventListener(t, () => { S.wantY = null; }, { passive: true, capture: true }));
window.addEventListener('pagehide', () => {
  if (curEntry && !S.wantY) scrollMap[curEntry] = Math.round(window.scrollY);
  try { sessionStorage.setItem(SCROLL_KEY, JSON.stringify(scrollMap)); } catch (e) { /* private mode */ }
});
// <details data-persist="id">: open / closed is remembered (toggle does not bubble: capture)
document.addEventListener('toggle', e => { const id = e.target.dataset && e.target.dataset.persist; if (id) { S.openSec[id] = e.target.open; viewSave(); } }, true);
const persistOpen = id => (S.openSec[id] ? ' open' : '');

// ---------------------------------------------------------------------------------------
// Routing
function parseHash() {
  const full = location.hash.replace(/^#\/?/, ''), qi = full.indexOf('?');
  const h = qi < 0 ? full : full.slice(0, qi);
  const i = h.indexOf('/'), name = i < 0 ? h : h.slice(0, i);
  let arg = i < 0 ? '' : h.slice(i + 1);
  try { arg = decodeURIComponent(arg); } catch (e) { arg = ''; }
  if (['device', 'service', 'domain'].includes(name) && arg) return { name, arg };
  if (name === 'people' && /^\d{1,9}$/.test(arg)) return { name, arg };   // one person
  const r = { name: PAGES.includes(name) ? name : 'overview' };
  if (qi >= 0 && VIEW_PAGES[r.name]) r.query = new URLSearchParams(full.slice(qi + 1, qi + 1 + 600));
  return r;
}
function onRoute() {
  const r = parseHash(), was = S.base;
  S.route = r; S.more = false;
  if (!isDrawerRoute(r) && r.name !== 'devices' && S.bulk.size) S.bulk.clear();
  // #/people/<id> stays the page underneath while a device drawer is open over it
  if (r.name === 'people' && (was !== 'people' || !S.ppl.r || (r.arg || '') !== S.ppl.id)) {
    S.ppl.id = r.arg || ''; S.ppl.form = null; S.ppl.q = ''; S.ppl.detErr = null;
    if (S.meta) loadPeople();
  }
  if (r.name !== 'people' && !isDrawerRoute(r)) { S.ppl.form = null; S.ppl.id = ''; S.ppl.assignAfter = null; S.ppl.wantForm = false; }
  if (PAGES.includes(r.name)) S.base = r.name;
  // a deep link's query sets that page's view exactly (each value checked, the rest default)
  if (r.query) VIEW_PAGES[r.name].set(viewClean(r.name, r.query, k => (r.query.has(k) ? r.query.get(k) : undefined)));
  if (r.name === 'people' && S.ppl.r) setTimeout(openPersonFormSoon);   // "Add a person…" from a device (People already loaded)
  if (S.base === 'ai' && S.chat.open) { S.chat.open = false; saveChat(); }   // the page IS the chat
  const fresh = ['system', 'settings', 'welcome'];
  if (fresh.includes(S.base) && was !== S.base) { S.ai.test = null; S.set.errs = {}; loadAI(); loadPair(); if (S.base === 'settings') loadPush(); }   // fresh settings on each visit
  if (S.base === 'welcome' && was !== 'welcome') { loadSetup(); wzTick(); }
  if (S.base !== 'settings' && S.pair.code) S.pair.code = null;   // a pairing code is not left on screen
  if (S.base !== 'settings' && S.set.bk) S.set.bk = null;         // nor a half-done restore
  if (S.base !== 'settings' && S.push.ed) { S.push.ed = null; S.push.pv = null; }   // nor typed tokens
  if (S.base !== 'inbox') S.inbox.picked.clear();
  if (S.base === 'family' && was !== 'family' && S.meta) loadFamily();
  if (S.base === 'security' && was !== 'security' && S.meta) loadHyg();
  if (S.base === 'settings' && was !== 'settings' && S.meta) loadTuning();
  if (S.base !== 'family' && S.fam.form) { S.fam.form = null; S.fam.prev = {}; }   // an unsaved rule draft is dropped on leaving
  if (r.name === 'device') {
    if (S.dev.mac !== r.arg) { S.dev = { mac: r.arg, d: null, act: null, tl: null, err: null }; delete S.draft[r.arg]; loadDevice(); }
  } else S.dev = { mac: null, d: null, act: null, tl: null, err: null };
  if (r.name === 'service' || r.name === 'domain') {
    const key = r.name + ':' + r.arg;
    if (S.look.key !== key) { S.look = { key, r: null, err: null }; loadLookup(); }
  } else S.look = {};
  render();
  const back = S.backY; S.backY = null;   // Back / Forward / reload: where that entry was scrolled to
  if (was !== S.base || back != null) {
    if (back != null && !drawerOpen()) restoreScroll(back); else if (was !== S.base) window.scrollTo(0, 0);
    if (S.base === 'inbox' && inboxCount() && !drawerOpen() && back == null) inboxFocus();   // triage starts on the first item
    else if (!drawerOpen() && was !== S.base) $('#main').focus({ preventScroll: true });
  }
  if (S.base === 'ai' && S.focusChat) { S.focusChat = false; const q = $('#chatq'); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }
}
// (the page's own link while it shows a remembered view - "#/devices" on "#/devices?show=new" -
// is the same page: no second history entry)
function go(hash) { if (location.hash === hash || (!hash.includes('?') && location.hash.split('?')[0] === hash)) onRoute(); else location.hash = hash; }
function closeDrawer() {
  if (!drawerOpen()) return;
  if (S.cameFromBase) history.back(); else go('#/' + S.base);
}

// ---------------------------------------------------------------------------------------
// Actions: optimistic, with Undo
// Stage G: screen readers hear a message ONCE, from a live region that already exists
// (#say polite, #shout for errors); clearing it first makes a repeated message heard again.
function speak(msg, urgent) {
  const el = $(urgent ? '#shout' : '#say'); if (!el) return;
  el.textContent = '';
  setTimeout(() => { el.textContent = msg; }, 50);
}
function toast(msg, opts) {
  opts = opts || {};
  const box = $('#toasts'), t = document.createElement('div');
  t.className = 'toast' + (opts.kind === 'err' ? ' err' : '');
  const span = document.createElement('span'); span.textContent = msg; t.appendChild(span);
  speak(msg, opts.kind === 'err');
  let timer = null, left = opts.undo ? 8000 : 4500, since = 0;
  const close = () => { clearTimeout(timer); t.classList.add('out'); setTimeout(() => t.remove(), 200); };
  // WCAG 2.2.1: a toast never runs out while the pointer or the keyboard is on it
  const resume = () => { clearTimeout(timer); since = Date.now(); timer = setTimeout(close, Math.max(left, 2000)); };
  const hold = () => { if (timer) { clearTimeout(timer); timer = null; left -= Date.now() - since; } };
  t.addEventListener('mouseenter', hold); t.addEventListener('focusin', hold);
  t.addEventListener('mouseleave', () => { if (!t.contains(document.activeElement)) resume(); });
  t.addEventListener('focusout', e => { if (!t.contains(e.relatedTarget) && !t.matches(':hover')) resume(); });
  if (opts.undo) {
    // Stage T: the same undo is on the Ctrl/Cmd+Z stack (it outlives the toast)
    const entry = close.entry = undoPush(opts.undo, close);
    const u = document.createElement('button'); u.type = 'button'; u.className = 'u'; u.textContent = T('app.toast.undo');
    u.title = T('app.toast.undo') + ' (Ctrl+Z)';
    u.onclick = () => undoRun(entry); t.appendChild(u);
  }
  const x = document.createElement('button'); x.type = 'button'; x.setAttribute('aria-label', T('app.close')); x.textContent = '✕';
  x.onclick = close; t.appendChild(x);
  box.appendChild(t);
  while (box.children.length > 4) box.firstChild.remove();
  resume();
  return close;
}
function fail(e) {
  if (e && e.demo) { demoNote(e.message); return; }   // the static demo said no: a note, not an error
  toast(T('app.toast.error', { error: errText(e) }), { kind: 'err' });
}
// Round 9 W: "this is a read-only demo" - once, however many times a click asks again
let demoNoteAt = { msg: '', t: 0 };
function demoNote(msg) {
  msg = msg || T('app.demo.readonly');
  if (demoNoteAt.msg === msg && Date.now() - demoNoteAt.t < 4000) return;
  demoNoteAt = { msg, t: Date.now() };
  toast(msg);
}

async function ack(mac, key, label, undoing) {
  const hk = hiddenKey(mac, key), dev = findDev(mac);
  S.hidden.add(hk); if (!key && dev) dev.trusted = true;
  if (!key && S.dev.d && S.dev.d.mac === mac) S.dev.d.trusted = true;
  render();
  try {
    await postJSON('/api/ack', { mac, domain: key });
    if (!undoing) toast(key ? T('app.toast.muted', { what: label }) : T('app.toast.trusted', { name: label }), { undo: () => unack(mac, key, label, true) });
    refresh();
  } catch (e) { S.hidden.delete(hk); if (!key && dev) dev.trusted = false; render(); fail(e); }
}
async function unack(mac, key, label, undoing) {
  const hk = hiddenKey(mac, key), dev = findDev(mac);
  S.hidden.delete(hk); if (!key && dev) dev.trusted = false;
  if (!key && S.dev.d && S.dev.d.mac === mac) S.dev.d.trusted = false;
  render();
  try {
    await postJSON('/api/unack', { mac, domain: key });
    toast(undoing ? T('app.toast.undone') : T('app.toast.untrusted', { name: label }), undoing ? {} : { undo: () => ack(mac, key, label, true) });
    refresh();
  } catch (e) { fail(e); refresh(); }
}
// Save the user's notes (label/type/owner/room) - only fields that changed - with Undo.
function applyLocal(mac, ch) {
  [findDev(mac), S.dev.d && S.dev.d.mac === mac ? S.dev.d : null].forEach(d => {
    if (!d) return;
    if ('label' in ch) { d.label = ch.label || null; d.name = ch.label || d.hostname || null; }
    ['owner', 'room'].forEach(f => { if (f in ch) { if (ch[f]) d[f] = ch[f]; else delete d[f]; } });
    if ('type' in ch && ch.type) {
      const t = S.types.find(x => x.key === ch.type);
      d.type = ch.type; d.type_info = Object.assign({}, d.type_info, { type: ch.type, type_name: t ? t.name : ch.type, source: 'user', confidence: 1, reason: T('devtype.reason.user') });
    }
  });
}
async function saveDevice(mac, changes, undoing) {
  const d = findDev(mac) || (S.dev.d && S.dev.d.mac === mac ? S.dev.d : null);
  if (!d) return;
  const ch = {}, prev = {};
  Object.keys(changes).forEach(k => { const v = (changes[k] || '').trim(); if (v !== current(d, k)) { ch[k] = v; prev[k] = current(d, k); } });
  delete S.draft[mac];
  if (S.edit === mac) S.edit = null;
  if (!Object.keys(ch).length) { render(); return; }
  applyLocal(mac, ch); render();
  try {
    if ('label' in ch) await postJSON('/api/label', { mac, label: ch.label });
    const prof = {}; ['type', 'owner', 'room'].forEach(k => { if (k in ch) prof[k] = ch[k]; });
    if (Object.keys(prof).length) await postJSON('/api/profile', Object.assign({ mac }, prof));
    toast(undoing ? T('app.toast.undone') : T('app.toast.saved', { name: dname(d) }), undoing ? {} : { undo: () => saveDevice(mac, prev, true) });
    loadChoices(); refresh();
  } catch (e) { applyLocal(mac, prev); render(); fail(e); refresh(); }
}
async function startCheck(mac) {
  if (S.check.job) return;
  try {
    const j = await postJSON('/api/check', mac ? { mac } : { all: true });
    S.check = { job: j.job, mac: mac || null, done: j.done || 0, total: j.total || 0 };
    toast(T('app.toast.check_started'));
    render(); pollCheck();
  } catch (e) { fail(e); }
}
async function pollCheck() {
  try {
    const j = await getJSON('/api/check/status?job=' + enc(S.check.job));
    S.check.done = j.done; S.check.total = j.total;
    if (j.state === 'running') { render(); setTimeout(pollCheck, 700); return; }
    S.check = { job: null };
    if (j.state === 'error') toast(T('ui.check_failed', { error: j.error || '?' }), { kind: 'err' });
    else toast(T('app.toast.check_done'));
  } catch (e) { S.check = { job: null }; fail(e); }
  refresh();
}
async function copyText(text, btn) {
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else {
      const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', '');
      ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    toast(T('ui.copied'));
  } catch (e) { fail(e); }
  if (btn) btn.focus();
}
function download(path) {
  if (DEMO && !DEMO_FILES.test(path)) { demoNote(T('app.demo.needs_install')); return; }   // e.g. the backup
  const a = document.createElement('a'); a.href = api(path); a.download = ''; document.body.appendChild(a); a.click(); a.remove();
}
const DEMO_FILES = /^\/(api\/export\/|api\/report\?|report\/weekly)/;   // the downloads the static demo has saved

// ---------------------------------------------------------------------------------------
// Theme + language
function applyTheme() {
  const root = document.documentElement;
  if (S.theme === 'auto') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', S.theme);
  $('#themeIcon').setAttribute('href', '#' + THEME_ICON[S.theme]);
  const b = $('#btnTheme'), label = T('app.theme') + ': ' + T('app.theme.' + S.theme);
  b.title = label; b.setAttribute('aria-label', label);
}
function setTheme(t) {
  S.theme = THEMES.includes(t) ? t : 'auto';
  try { localStorage.setItem(THEME_KEY, S.theme); } catch (e) { /* private mode */ }
  applyTheme(); render();
}
// -> false when the strings could not be loaded (the page keeps the language it had)
async function setLang(code, persist) {
  let j = null;
  try {
    const r = await fetch(url('/api/locale?lang=' + enc(code)));
    if (r.ok) j = await r.json();
  } catch (e) { j = null; }
  if (!j || !j.strings) {
    if (S.lang) { $('#langsel').value = S.lang; toast(T('app.offline'), { kind: 'err' }); }
    return false;
  }
  S.lang = j.lang; S.L = j.strings; fmtInit();
  if (persist) { try { localStorage.setItem(LANG_KEY, S.lang); } catch (e) { /* private mode */ } }
  applyStatic(); render();                  // chrome switches instantly; data follows
  S.look.key = null; if (drawerOpen() && S.route.name !== 'device') { S.look = { key: S.route.name + ':' + S.route.arg }; loadLookup(); }
  loadChoices(); refresh();
  // pages whose server texts were fetched once per visit: fetch them in the new language
  if (['system', 'settings', 'welcome'].includes(S.base)) loadAI();
  S.push.log = {};   // the delivery logs' texts are localized too: an open one is fetched again
  if (S.base === 'settings') { loadTuning(); loadPush(); if (S.push.logOpen != null) pushLogLoad(S.push.logOpen); }
  return true;
}

// Stage G: netwarden did not answer before the page could start (it stopped, is
// restarting, or answered with an error). The words come with index.html (#off-texts, every
// language) since the locale itself could not be loaded; the page retries every 5 s and
// reloads as soon as netwarden answers. Nothing raw, nothing technical.
let bootTimer = null;
// the browser's own language among `codes` (exact, then by its first part), or null
function navLang(codes) {
  const nav = (navigator.languages || [navigator.language || '']).map(x => String(x).toLowerCase()
    .replace(/^zh-(tw|hk|mo)(-.*)?$/, 'zh-hant').replace(/^zh-(cn|sg)(-.*)?$/, 'zh-hans'));   // regions -> scripts
  return codes.find(c => nav.includes(c.toLowerCase()))
    || codes.find(c => nav.some(n => n.split('-')[0] === c.toLowerCase().split('-')[0])) || null;
}
function bootFailed() {
  let texts = {};
  try { texts = JSON.parse($('#off-texts').textContent) || {}; } catch (e) { texts = {}; }
  let saved = null; try { saved = localStorage.getItem(LANG_KEY); } catch (e) { /* private mode */ }
  const code = (texts[saved] && saved) || navLang(Object.keys(texts)) || 'zh-Hant';
  const t = texts[code] || texts.en;
  if (!t) return;
  document.documentElement.lang = code;
  document.title = t.title;
  $('#main').setAttribute('aria-busy', 'false');
  document.body.classList.add('boot-failed');   // the header's buttons have no words yet: hidden
  morph($('#view'), html`<section class="offline-card boot-fail" role="alert">
    ${icon('i-shield', 'offline-logo')}
    <h1>${t.title}</h1><p>${t.lead}</p>
    <p><button type="button" class="btn" data-act="boot-retry">${icon('i-refresh')}${t.retry}</button></p>
    <p class="offline-auto">${t.auto}</p></section>`);
  clearInterval(bootTimer);
  bootTimer = setInterval(() => bootRetry(false), 5000);
}
async function bootRetry(manual) {
  const b = $('[data-act="boot-retry"]'); if (b) b.disabled = true;
  try {
    const r = await fetch(url('/api/meta'), { cache: 'no-store' });
    if (r.ok || r.status === 401) { location.reload(); return; }
  } catch (e) { /* still down */ }
  if (b) { b.disabled = false; if (manual) b.focus(); }
}

// ---------------------------------------------------------------------------------------
// Command palette (Ctrl+K / Cmd+K, the header's search button; "/" when the page has no filter)
// Round 9 U: one matcher for the palette and every page filter. fold() makes text case-,
// accent- and width-insensitive (NFKD: full-width "ＴＶ" = "tv", "é" = "e") and maps the
// Traditional Chinese characters of the UI's vocabulary to Simplified, so a word typed in
// either script finds the other. Hangul / kana are recomposed (NFC) after the accents are dropped.
const TS_PAIRS = '並并佔占併并來来個个們们備备僅仅價价儀仪儲储內内兩两別别刪删動动務务匯汇參参員员問问嗎吗' +
  '圖图執执報报塊块夠够夾夹媽妈學学寢寝實实寫写將将對对屬属帳账幾几庫库廠厂廣广廳厅彙汇後后從从惡恶態态' +
  '慮虑憑凭應应戲戏戶户掃扫換换擇择據据擬拟擷撷攔拦攝摄敗败數数斷断於于時时暫暂會会東东條条標标樣样檔档' +
  '檢检權权歷历歸归決决沒没況况減减準准濾滤瀏浏為为無无牆墙狀状獨独現现產产異异當当發发監监盤盘確确碼码' +
  '種种稱称筆笔範范篩筛約约組组絕绝給给統统經经綴缀編编緩缓縮缩總总繞绕續续聯联聽听脅胁腦脑著着蓋盖處处' +
  '號号螢萤裝装裡里製制複复見见規规覽览觸触記记設设許许註注評评詢询試试話话該该詳详認认語语誤误誰谁調调' +
  '請请證证識识議议讀读讓让費费資资蹤踪躍跃軟软輪轮輯辑輸输轉转辦办這这週周遊游過过達达遙遥遞递遠远適适' +
  '遲迟遺遗針针銷销錯错鍵键鐘钟鑰钥長长門门閉闭間间關关隨随險险隱隐離离雲云電电靈灵靜静韌韧頁页項项須须' +
  '頭头題题類类顯显風风體体麼么點点網网絡络線线機机視视錄录驗验測测鄰邻區区兒儿隊队層层選选單单頻频寬宽' +
  '帶带傳传載载際际連连雙双圍围簡简齊齐臥卧廚厨書书樂乐響响聲声鬧闹訊讯啟启開开嚴严劃划歡欢舊旧親亲爺爷' +
  '陽阳業业專专夢梦寶宝紅红綠绿藍蓝黃黄愛爱習习課课藝艺術术環环購购買买賣卖鎖锁訪访維维護护錢钱銀银鈕钮' +
  '鏈链擴扩導导蘋苹華华樹树禮礼齡龄觀观計计討讨論论優优勢势構构衛卫憶忆詐诈騙骗釣钓魚鱼殺杀擊击協协閘闸' +
  '橋桥熱热鬆松歲岁驅驱雜杂飾饰濟济';
const TS = new Map();
for (let i = 0; i + 1 < TS_PAIRS.length; i += 2) TS.set(TS_PAIRS[i], TS_PAIRS[i + 1]);
const TS_RE = new RegExp('[' + Array.from(TS.keys()).join('') + ']', 'g');
const foldCache = new Map();
function fold(s) {
  s = s == null ? '' : String(s);
  let v = foldCache.get(s);
  if (v === undefined) {
    v = s.normalize('NFKD').replace(/[̀-ͯ]/g, '').normalize('NFC').toLowerCase()
      .replace(/ß/g, 'ss').replace(TS_RE, c => TS.get(c));
    if (foldCache.size > 4000) foldCache.clear();
    foldCache.set(s, v);
  }
  return v;
}
// a word starts here: after a separator, or any CJK / kana / Hangul character (no spaces there)
const CJK_RE = /[぀-ヿ㐀-鿿가-힯豈-﫿]/;
const wordStart = (t, j) => j === 0 || /[\s·\-_.:/()'’,|«»“”"]/.test(t[j - 1]) || CJK_RE.test(t[j]);
// Fuzzy match on folded text, best first: the query as a substring (earlier and at a word
// start = better); every word of it somewhere; or initials / word prefixes in order ("lrt" =
// Living Room Tv, "sams tv"). Letters scattered inside words do not count. 0 = no match.
function fuzzy(q, text) {
  q = fold(q).trim().replace(/\s+/g, ' '); text = fold(text);
  if (!q) return 1;
  const i = text.indexOf(q);
  if (i >= 0) return 30 + (i === 0 ? 10 : 0) + (wordStart(text, i) ? 6 : 0) - Math.min(i, 40) * 0.05;
  const words = q.split(' ');
  if (words.length > 1 && words.every(w => text.includes(w))) return 20 + (words.every(w => wordStart(text, text.indexOf(w))) ? 4 : 0);
  let at = 0, run = 0, score = 0, first = -1;
  for (const ch of q) {
    if (ch === ' ') { run = 0; continue; }
    let j = text.indexOf(ch, at);
    while (j >= 0 && !(run && j === at) && !wordStart(text, j)) j = text.indexOf(ch, j + 1);
    if (first < 0) first = j;
    if (j < 0 || j - first > 32) return 0;   // initials of ONE phrase, not of far-apart fields
    run = run && j === at ? run + 1 : 1;
    score += run * 2 + 1;
    at = j + ch.length;
  }
  return Math.min(score, 19);
}
// the page filters: a plain (folded) substring, every word of the query somewhere
function matches(q, hay) {
  const words = fold(q).split(/\s+/).filter(Boolean), h = fold(hay);
  return words.every(w => h.includes(w));
}
const RECENT_MAX = 6;
const recentKey = () => 'netwarden.recent.' + dbId();
function loadRecent() { try { const a = JSON.parse(localStorage.getItem(recentKey()) || '[]'); return Array.isArray(a) ? a.filter(x => typeof x === 'string').slice(0, RECENT_MAX) : []; } catch (e) { return []; } }
function saveRecent(id) {
  const a = [id].concat(loadRecent().filter(x => x !== id)).slice(0, RECENT_MAX);
  try { localStorage.setItem(recentKey(), JSON.stringify(a)); } catch (e) { /* private mode */ }
}
// A palette entry: {id, group, label, hint (plain text), keys (a shortcut, shown as <kbd>),
// ic, run, kw (extra words it is found by)}. `single` keys are hidden while single-key
// shortcuts are off; Ctrl/Cmd ones always show.
function palEntry(id, group, label, o) { return Object.assign({ id, group, label, hint: '', keys: null, ic: 'i-search', kw: '' }, o); }
// The non-critical alert kinds "Pause everyday alerts for 1 hour" snoozes for the whole
// home (tuning.CRITICAL_KINDS - threats, open ports, risky forwards - always stay on).
const PAUSE_KINDS = ['visibility', 'night', 'bedtime', 'spike', 'change', 'new', 'outage'];
// Everything the palette can do. Actions follow their buttons' rules: what a paired phone
// may not do (admin: port checks, scans, pairing, backup, settings) is not offered there.
function paletteActions(q) {
  const acts = [], local = !S.meta.remote;
  const a = (id, label, ic, run, o) => acts.push(palEntry(id, 'act', label, Object.assign({ ic, run }, o)));
  // every page, named "Place › Page" when it shares its place (so "Security" is found under Network too)
  NAV_ORDER.forEach(s => {
    const g = GROUP_OF[s], shared = groupPages(g).length > 1;
    const name = shared ? groupLabel(g) + ' › ' + T('app.nav.' + s) : T('app.nav.' + s);
    acts.push(palEntry('nav:' + s, 'nav', T('app.palette.go', { section: name }), { ic: SEC_ICON[s], run: () => go('#/' + s),
      keys: NAV_GO[s] ? ['g', NAV_GO[s]] : null, kw: s + ' ' + g }));
  });
  if (q) a('ask', T('app.palette.ask', { q: S.pal.q.trim() }), 'i-spark', () => openChat({ draft: S.pal.q.trim() }), { hint: T('app.palette.ask_hint'), kw: q, always: true });
  a('act:refresh', T('app.refresh'), 'i-refresh', refresh, { keys: ['R'] });
  const unread = inboxItems().filter(it => it.kind !== 'suggestion' && it.actions.includes('ack'));
  if (unread.length) a('act:read-all', T('app.palette.read_all', { n: fmt.num(unread.length) }), 'i-check', () => inboxDo('ack', unread), { kw: 'inbox read got it ack' });
  a('act:pause', T('app.palette.pause'), 'i-bell', pauseAlerts, { kw: 'mute snooze quiet 1h hour' });
  if (local && !S.meta.demo) a('act:scan', T('app.palette.scan'), 'i-wifi', paletteScan, { kw: 'scan discover sweep devices' });
  a('act:csv', T('ui.export_csv'), 'i-download', () => download('/api/export/devices.csv'), { kw: 'csv excel' });
  a('act:report', T('ui.export_report'), 'i-download', () => download('/api/export/report.md'), { kw: 'markdown md' });
  a('act:print', T('app.fam.print'), 'i-print', () => window.open(api('/report/weekly'), '_blank', 'noopener'), { kw: 'pdf' });
  a('act:share', T('app.palette.report'), 'i-print', () => go('#/report'), { kw: 'report share send helper friend pdf markdown html' });
  a('act:bed', T('app.bed.add'), 'i-bed', () => { if (S.base === 'family' && S.fam.bed) { if (!S.fam.form) openBedForm(null); } else { S.fam.wantForm = true; go('#/family'); } });
  if (local) a('act:check', T('app.sec.check_all'), 'i-port', confirmCheck, { kw: 'port scan' });
  a('act:chat', T('app.d.ask_any'), 'i-spark', () => openChat(), { keys: ['c'], kw: 'ai chat' });
  a('act:keys', T('app.sys.shortcuts'), 'i-keyboard', openKeys, { keys: ['?'], kw: 'keyboard' });
  // Stage Q: the Tuning panel and the quiet-hours settings
  const toCard = key => () => { go('#/settings'); setTimeout(() => { const c = document.querySelector(`[data-key="${key}"]`); if (c) c.scrollIntoView({ block: 'start' }); }, 150); };
  a('act:tuning', T('app.tune.title'), 'i-bell', toCard('tuning'), { kw: 'tune mute snooze alerts sensitivity' });
  if (local) a('act:quiet', T('settings.section.quiet'), 'i-moon', toCard('set-quiet'), { kw: 'quiet hours night do not disturb' });
  // Round 10 N: push notification channels (admins only, like everything about channels)
  if (local) a('act:push', T('settings.section.push'), 'i-bell', toCard('set-push'), { kw: 'push notifications ntfy gotify telegram discord slack line matrix webhook home assistant phone' });
  if (local) a('act:push-add', T('app.push.add'), 'i-bell', () => { go('#/settings'); setTimeout(() => { const s = $('#push-type'); if (s) { s.scrollIntoView({ block: 'center' }); s.focus({ preventScroll: true }); } }, 300); }, { kw: 'push notification channel add new' });
  if (inboxCount()) a('act:inbox-undo', T('app.inbox.undo_last'), 'i-refresh', inboxUndo, { keys: ['u'] });
  if (UNDO_STACK.length) a('act:undo', T('app.key.undo'), 'i-refresh', undoLast, { keys: [MOD, 'Z'] });
  if (local) {
    a('act:pair', T('app.palette.pair'), 't-phone', () => { go('#/settings'); setTimeout(() => { const P = S.pair; if (P.s && (P.s.lan || (P.s.require_auth && !S.meta.addon))) pairNew(); else toast(T('app.pair.need_lan')); }, 300); }, { kw: 'qr phone' });
    a('act:backup', T('app.bk.download'), 'i-download', () => download('/api/backup'), { kw: 'backup json' });
    a('act:restore', T('app.bk.choose'), 'i-box', () => { go('#/settings'); setTimeout(() => { const f = $('#bk-file'); if (f) f.click(); }, 300); }, { kw: 'restore import' });
    a('act:wizard', T('app.wz.open'), 'i-check', () => go('#/welcome'), { kw: 'setup wizard' });
  }
  if (notifySupported()) a('act:notify', T(notifyState() === 'on' ? 'app.notify.disable' : 'app.notify.enable'), 'i-bell', toggleNotify);
  a('act:single', T(singleKeys() ? 'app.palette.single_off' : 'app.palette.single_on'), 'i-keyboard', () => setSingleKeys(!singleKeys()), { kw: 'shortcuts keyboard' });
  THEMES.forEach(t => a('theme:' + t, T('app.palette.theme', { name: T('app.theme.' + t) }), THEME_ICON[t], () => setTheme(t), { kw: 'theme' }));
  // a language is also found by its name in English and in the current language ("chinese", "日文")
  if (q) (S.meta.languages || []).forEach(l => a('lang:' + l.code, T('app.palette.lang', { name: l.name }), 'i-globe', () => setLang(l.code, true),
    { hint: l.code, kw: 'language ' + langNames(l.code) }));
  return acts;
}
function langNames(code) {
  return [S.lang, 'en'].map(ui => {
    try { return new Intl.DisplayNames([ui], { type: 'language' }).of(code) || ''; } catch (e) { return ''; }
  }).join(' ');
}
// People, "Shared" and rooms (the family's groups of devices)
function peopleEntries() {
  const out = persons().map(p => {
    const n = devices().filter(d => d.owner === p.name).length;
    return palEntry('person:' + p.id, 'ppl', p.name, { ic: 'i-user', hint: T('app.palette.n_devices', { n: fmt.num(n) }), run: () => go('#/people/' + p.id), kw: T('app.ppl.person') });
  });
  const shared = devices().filter(d => d.shared).length;
  if (shared) out.push(palEntry('shared', 'ppl', T('app.ppl.shared'), { ic: 'i-family', hint: T('app.palette.n_devices', { n: fmt.num(shared) }), run: () => go('#/people') }));
  Array.from(new Set(devices().map(d => d.room).filter(Boolean))).forEach(r =>
    out.push(palEntry('room:' + r, 'ppl', T('app.palette.room', { room: r }), { ic: 'i-home', kw: T('app.room'), run: () => go('#/devices?room=' + enc(r)) })));
  return out;
}
// Settings by label, section and key (this computer only: GET /api/settings, on first use)
function settingEntries() {
  if (S.meta.remote || !S.ai.s) return [];
  const secs = Object.fromEntries((S.ai.s.sections || []).map(s => [s.key, s.label]));
  return (S.ai.s.items || []).filter(it => !it.secret).map(it => palEntry('set:' + it.key, 'set', it.label, {
    ic: SET_ICON[it.section] || 'i-gear', hint: secs[it.section] || '', kw: it.key, run: () => gotoSetting(it.key) }));
}
function gotoSetting(key) {
  go('#/settings');
  let tries = 0;
  (function find() {
    const f = document.querySelector(`.set-field[data-key="${key}"]`);
    if (!f) { if (++tries < 20) setTimeout(find, 100); return; }
    f.scrollIntoView({ block: 'center' });
    const c = f.querySelector('input,select,textarea,button'); if (c) c.focus({ preventScroll: true });
  })();
}
// What a device row offers: open it, (un)trust it, mute its inbox alerts (now / for an hour)
function deviceActions(d) {
  const name = dname(d), out = [palEntry('dev:' + d.mac, 'dev', name, { hint: (d.ips || [])[0] || '', ic: 't-' + typeKey(d.type), run: () => go(devHref(d.mac)) })];
  out.push(d.trusted ? palEntry('untrust:' + d.mac, 'act', T('app.palette.untrust', { name }), { ic: 'i-x', run: () => unack(d.mac, '', name) })
                     : palEntry('trust:' + d.mac, 'act', T('app.palette.trust', { name }), { ic: 'i-check', run: () => ack(d.mac, '', name) }));
  const mine = inboxItems().filter(it => it.mac === d.mac);
  const mutable = mine.filter(it => it.actions.includes('mute'));
  if (mutable.length) out.push(palEntry('mute:' + d.mac, 'act', T('app.palette.mute', { name, n: fmt.num(mutable.length) }), { ic: 'i-bell', run: () => inboxDo('mute', mutable) }));
  const kinds = Array.from(new Set(mine.map(it => it.why && it.why.tune && it.why.tune.mac ? it.why.tune.kind : null).filter(Boolean)));
  if (kinds.length) out.push(palEntry('mute1h:' + d.mac, 'act', T('app.palette.mute_hour', { name }), { ic: 'i-moon', run: () => snoozeKinds(kinds, d.mac, name) }));
  return out;
}
// "off" for 1 hour per kind (POST /api/tuning, the Tune sheet's "1 hour"), ONE toast whose
// Undo puts every row back. Kinds the user already tuned for this target are left alone,
// so a pause never shortens an "off until I change it".
async function snoozeKinds(kinds, mac, name) {
  let tuned = [];
  try { tuned = ((await getJSON('/api/tuning')).entries || []).filter(e => e.source !== 'snooze' && e.mac === (mac || 'all')).map(e => e.kind); }
  catch (e) { fail(e); return; }
  const todo = kinds.filter(k => !tuned.includes(k)), done = [];
  if (!todo.length) { toast(T('app.palette.pause_none')); return; }
  try {
    for (const kind of todo) done.push(Object.assign({ kind }, await postJSON('/api/tuning', { kind, mac: mac || null, level: 'off', for: '1h' })));
  } catch (e) { fail(e); }
  if (!done.length) return;
  const when = T('app.tune.until', { when: fmt.date(done[0].until) });
  toast(mac ? T('app.palette.mute_hour_done', { name, until: when }) : T('app.palette.pause_done', { until: when }), { undo: async () => {
    try { for (const r of done) await postJSON('/api/tuning/undo', { kind: r.kind, mac: r.mac, before: r.before }); toast(T('app.toast.undone')); } catch (e) { fail(e); }
    afterTune();
  } });
  afterTune();
}
function pauseAlerts() { return snoozeKinds(PAUSE_KINDS, null, ''); }
// "Scan the network now": the first-run wizard's sweep (POST /api/setup/scan, this computer
// only); the toast says when it is done.
async function paletteScan() {
  if (S.setup.scan && S.setup.scan.state === 'running') { toast(T('app.wz.scanning')); return; }
  S.setup.scan = null; S.setup.scanToast = true;
  await wzScan();
  if (S.setup.scan) toast(T('app.wz.scanning')); else S.setup.scanToast = false;   // refused: wzScan said why
}
// Stage P: "Assign <device> to <person>" when the query names a person (or "Shared") and
// what is left of it matches a device: "ipad 小孩", "assign tv to shared"
function assignActions(q) {
  const targets = persons().map(p => ({ v: 'p:' + p.id, name: p.name })).concat([{ v: 'shared', name: T('app.ppl.shared') }])
    .filter(t => t.name && q.includes(fold(t.name)));
  const out = [];
  targets.forEach(t => {
    // drop the person's name and the "assign / to" words (whole words; CJK ones anywhere)
    const kw = fold(T('app.palette.assign_kw')).split(/\s+/).filter(Boolean);
    let rest = q.split(fold(t.name)).join(' ');
    kw.filter(w => /[　-鿿가-힯]/.test(w)).forEach(w => { rest = rest.split(w).join(' '); });
    rest = rest.split(/\s+/).filter(w => w && !kw.includes(w)).join(' ');
    if (!rest) return;
    devices().filter(d => d.mac && assignValue(d) !== t.v)
      .map(d => ({ d, s: fuzzy(rest, [dname(d), d.vendor, d.mac, (d.ips || []).join(' ')].join(' ')) }))
      .filter(x => x.s > 0).sort((x, y) => y.s - x.s).slice(0, 3)
      .forEach(x => out.push({ s: x.s + 20, x: palEntry('assign:' + x.d.mac + ':' + t.v, 'act', T('app.palette.assign', { name: dname(x.d), person: t.name }),
                                                  { ic: 'i-user', run: () => assignDevices([x.d.mac], t.v) }) }));
  });
  return out;
}
// a device is found by its name, label, owner, room, vendor, IP and MAC (also a prefix
// typed with or without separators: "aa:bb", "aabb")
const devHay = d => [dname(d), d.label, d.hostname, d.vendor, d.mac, (d.mac || '').replace(/[:-]/g, ''), (d.ips || []).join(' '), d.owner, d.room,
                     d.type_info && d.type_info.type_name].join(' ');
function paletteItems() {
  const raw = S.pal.q.trim(), q = fold(raw), out = [];
  const acts = paletteActions(q);
  if (!q) {   // recent first, then every section and action
    const byId = {};
    acts.concat(peopleEntries(), settingEntries()).forEach(x => { byId[x.id] = x; });
    loadRecent().forEach(id => {
      const mac = id.startsWith('dev:') ? id.slice(4) : null, d = mac && findDev(mac);
      const it = d ? deviceActions(d)[0] : byId[id];
      if (it) out.push(Object.assign({}, it, { group: 'recent' }));
    });
    return out.concat(acts.filter(x => !out.some(r => r.id === x.id)));
  }
  const score = x => fuzzy(q, x.label + ' ' + (x.hint || '') + ' ' + (x.kw || ''));
  const devs = devices().map(d => ({ d, s: fuzzy(q, devHay(d)) })).filter(x => x.s > 0).sort((x, y) => y.s - x.s).slice(0, 8);
  devs.forEach(x => out.push(deviceActions(x.d)[0]));
  const top = (list, n) => list.map(x => ({ x, s: score(x) })).filter(r => r.s > 0).sort((a, b) => b.s - a.s).slice(0, n).map(r => r.x);
  const ranked = acts.filter(x => !x.always).map(x => ({ x, s: score(x) })).filter(r => r.s > 0);
  devs.slice(0, 3).forEach(r => deviceActions(r.d).slice(1).forEach(x => ranked.push({ x, s: r.s - 1 })));
  assignActions(q).forEach(r => ranked.push(r));
  const group = (g, n) => ranked.filter(r => r.x.group === g).sort((a, b) => b.s - a.s).slice(0, n).forEach(r => out.push(r.x));
  group('nav', 8);
  top(peopleEntries(), 6).forEach(x => out.push(x));
  const rm = S.pal.remote;
  if (rm && rm.q === raw) {
    (rm.services || []).slice(0, 6).forEach(v => out.push(palEntry('svc:' + v.id, 'svc', v.name, { hint: T('ui.search_counts', { n: fmt.num(v.queries), devices: fmt.num(v.devices) }), ic: 'i-box', run: () => go('#/service/' + enc(v.id)) })));
    (rm.domains || []).slice(0, 6).forEach(d => out.push(palEntry('dom:' + d.domain, 'dom', d.domain, { hint: T('ui.search_counts', { n: fmt.num(d.queries), devices: fmt.num(d.devices) }), ic: 'i-globe', run: () => go('#/domain/' + enc(d.domain)) })));
  }
  group('act', 12);
  top(settingEntries(), 8).forEach(x => out.push(x));
  // last: hand the words to the assistant (pre-filled, never sent)
  acts.filter(x => x.always).forEach(x => out.push(Object.assign({}, x, { group: 'ask' })));
  return out;
}
const PAL_GROUPS = { recent: 'app.palette.recent', dev: 'ui.search_devices', ppl: 'app.palette.people', svc: 'ui.search_services',
                     dom: 'ui.search_domains', nav: 'app.palette.sections', act: 'app.palette.actions', set: 'app.nav.settings',
                     ask: 'app.nav.ai' };
// a shortcut as keys: ["g", "o"] -> g then o; [MOD, "Z"] -> Ctrl+Z / ⌘Z
const MOD = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '') ? '⌘' : 'Ctrl';
function keysHtml(keys) {
  if (!keys || (!singleKeys() && keys[0] !== MOD)) return '';
  const k = s => html`<kbd>${s}</kbd>`;
  return html`<span class="pkeys" aria-hidden="true">${keys[0] === MOD ? html`${k(MOD)}${k(keys[1])}` : keys.map(k)}</span>`;
}
// WAI-ARIA APG combobox + listbox with grouped options: <li role="group"> per group, the
// input owns aria-activedescendant; the count is announced politely.
function renderPalette() {
  const items = S.pal.items = paletteItems();
  S.pal.sel = Math.min(S.pal.sel, Math.max(0, items.length - 1));
  const groups = [];
  items.forEach((it, i) => {
    if (!groups.length || groups[groups.length - 1].g !== it.group) groups.push({ g: it.group, rows: [] });
    groups[groups.length - 1].rows.push([it, i]);
  });
  morph($('#pallist'), groups.length ? groups.map(({ g, rows }, gi) => html`<li role="group" aria-labelledby="pg-${gi}" data-key="g-${g}-${gi}">
      <div class="ph" id="pg-${gi}" role="presentation">${T(PAL_GROUPS[g])}</div>
      <ul role="presentation">${rows.map(([it, i]) => html`<li class="pi${it.group === 'ask' ? ' two' : ''}" role="option" id="pi-${i}" data-i="${i}" aria-selected="${String(i === S.pal.sel)}" data-key="${it.group}:${it.id}">
        ${icon(it.ic)}<span class="pl">${it.label}</span>${it.hint ? html`<span class="phint">${it.hint}</span>` : ''}${keysHtml(it.keys)}</li>`)}</ul></li>`)
    : html`<li class="pnone" role="presentation">${T('app.palette_none')}</li>`);
  const inp = $('#palq');
  inp.setAttribute('aria-expanded', String(items.length > 0));
  if (items.length) inp.setAttribute('aria-activedescendant', 'pi-' + S.pal.sel); else inp.removeAttribute('aria-activedescendant');
  const sel = $('#pi-' + S.pal.sel); if (sel) sel.scrollIntoView({ block: 'nearest' });
  const n = T('app.palette.n_results', { n: fmt.num(items.length) });
  clearTimeout(S.pal.sayT);
  S.pal.sayT = setTimeout(() => { const c = $('#palcount'); if (c && S.pal.open && c.textContent !== n) c.textContent = n; }, 400);
}
let palTimer = null;
function openPalette() {
  if (S.pal.open) return;
  S.pal = { open: true, q: '', sel: 0, remote: null, items: [], back: document.activeElement, inert: [] };
  // aria-modal is a promise: the page behind (and an open drawer / chat) can't be reached
  // while the palette is open - only what was not inert already, so closing gives back
  // exactly that (the drawer keeps its own inert when it is closed)
  S.pal.inert = ['.app', '#drawer', '#chatpanel'].map(s => $(s)).filter(el => el && !el.inert);
  S.pal.inert.forEach(el => { el.inert = true; });
  $('#palette').hidden = false; $('#palq').value = ''; $('#palcount').textContent = ''; renderPalette(); $('#palq').focus();
  // settings are found by name too: their list loads on first use (this computer only)
  if (!S.meta.remote && !S.ai.s && !S.ai.loading) { S.ai.loading = true; loadAI().finally(() => { S.ai.loading = false; if (S.pal.open) renderPalette(); }); }
}
function closePalette(keepFocus) {
  if (!S.pal.open) return;
  S.pal.open = false; $('#palette').hidden = true;
  // (a drawer that closed meanwhile - Back, a live update - stays inert)
  (S.pal.inert || []).forEach(el => { if (el.id !== 'drawer' || el.classList.contains('open')) el.inert = false; }); S.pal.inert = [];
  if (!keepFocus && S.pal.back && document.contains(S.pal.back)) S.pal.back.focus({ preventScroll: true });
}
// Focus goes back to where it was BEFORE the entry runs: an entry that opens a page, the
// drawer or the chat then moves it on itself, one that does not (theme, mute) leaves it there.
function runPalette(i) {
  const it = S.pal.items[i]; if (!it) return;
  if (it.id && it.id !== 'ask') saveRecent(it.id);
  closePalette(false); it.run();
}
$('#palq').addEventListener('input', e => {
  S.pal.q = e.target.value; S.pal.sel = 0; renderPalette();
  clearTimeout(palTimer);
  const q = S.pal.q.trim();
  // (the static demo has no server search: pages, devices and actions are matched here)
  if (q.length >= 2 && !DEMO) palTimer = setTimeout(() => getJSON('/api/search?q=' + enc(q)).then(r => {
    if (S.pal.open && S.pal.q.trim() === q) { S.pal.remote = Object.assign({ q }, r); renderPalette(); }
  }).catch(() => {}), 160);
});
$('#palq').addEventListener('keydown', e => {
  if (e.isComposing || e.keyCode === 229) return;   // the IME's own Enter / arrows
  const n = S.pal.items.length;
  if (e.key === 'ArrowDown') { e.preventDefault(); S.pal.sel = n ? (S.pal.sel + 1) % n : 0; renderPalette(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); S.pal.sel = n ? (S.pal.sel - 1 + n) % n : 0; renderPalette(); }
  else if (e.key === 'Home' && e.ctrlKey) { e.preventDefault(); S.pal.sel = 0; renderPalette(); }
  else if (e.key === 'End' && e.ctrlKey) { e.preventDefault(); S.pal.sel = Math.max(0, n - 1); renderPalette(); }
  else if (e.key === 'PageDown' || e.key === 'PageUp') { e.preventDefault(); S.pal.sel = Math.max(0, Math.min(n - 1, S.pal.sel + (e.key === 'PageDown' ? 8 : -8))); renderPalette(); }
  else if (e.key === 'Enter') { e.preventDefault(); runPalette(S.pal.sel); }
  else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); if (S.pal.q) { e.target.value = S.pal.q = ''; S.pal.sel = 0; renderPalette(); } else closePalette(); }
  else if (e.key === 'Tab') e.preventDefault();      // focus stays in the palette
});
$('#pallist').addEventListener('mousemove', e => {
  const li = e.target.closest('.pi'); if (li && +li.dataset.i !== S.pal.sel) { S.pal.sel = +li.dataset.i; renderPalette(); }
});
$('#pallist').addEventListener('click', e => { const li = e.target.closest('.pi'); if (li) runPalette(+li.dataset.i); });
// A click outside the panel closes it; anywhere inside (a result, a group heading, the hint
// line) the text box keeps the focus - so Esc, Tab and the arrows always reach it.
$('#palette').addEventListener('mousedown', e => {
  if (e.target.id === 'palette') { e.preventDefault(); closePalette(); }
  else if (e.target !== $('#palq') && !(e.target.id === 'pallist' && e.offsetX >= e.target.clientWidth)) e.preventDefault();
});   // (not on the list's scrollbar: dragging it must work; Esc / Tab still reach the palette)

// ---------------------------------------------------------------------------------------
// Events (all delegated, so morph() never has to re-bind anything)
// Stage T: the map's pointer / wheel handling (a drag that ended on a node must not open it)
document.addEventListener('pointerdown', mapPointerDown);
document.addEventListener('pointermove', mapPointerMove);
document.addEventListener('pointerup', mapPointerUp);
document.addEventListener('pointercancel', mapPointerUp);
document.addEventListener('pointerout', e => { const a = e.target.closest && e.target.closest('.mnode'); if (a && !a.contains(e.relatedTarget)) mapTip(null); });
document.addEventListener('wheel', mapWheel, { passive: false });
document.addEventListener('click', e => { if (MP.drag && e.target.closest && e.target.closest('#mapsvg')) { e.preventDefault(); e.stopPropagation(); MP.drag = false; } }, true);
document.addEventListener('focusin', e => { const a = e.target.closest && e.target.closest('.mnode'); mapTip(a || null); });
// Round 9 W: in the static demo a button that would change something (or needs a running
// netwarden) explains itself instead - before anything optimistic happens on the page.
// Everything else (pages, drawers, filters, the palette, theme, language) works as usual;
// postJSON() refusing is the safety net behind this list.
const DEMO_WRITES = new Set(['mute', 'trust', 'untrust', 'edit', 'ib-do', 'ib-bulk', 'ib-undo', 'set-bool', 'bk-mode',
  'bk-apply', 'wz-go', 'wz-next', 'wz-finish', 'wz-skip', 'wz-ai', 'wz-lan', 'tune', 'tune-set', 'tune-restore',
  'quiet-seen', 'use-name', 'sug-set', 'probe-off', 'pair-revoke', 'pair-revoke-all', 'lan-toggle', 'logout', 'bed-new',
  'bed-edit', 'bed-delete', 'bed-toggle', 'ppl-new', 'ppl-edit', 'add-person-for', 'ppl-delete', 'ppl-add-dev',
  'ppl-rm-dev', 'ppl-link', 'ppl-link-no', 'pres-on', 'pres-off', 'pres-forget', 'pres-dev', 'pres-default',
  'pres-notify', 'bulk-assign', 'push-enable', 'push-delete']);
const DEMO_INSTALL = new Set(['push-test', 'push-helper', 'check', 'check-all', 'conn-test', 'wz-scan', 'wz-test', 'ai-test', 'ai-preview',
  'bk-download', 'pair-new']);
if (DEMO) {
  document.addEventListener('click', e => {
    const b = e.target.closest && e.target.closest('[data-act]');
    if (!b || b.disabled) return;
    const act = b.dataset.act;
    const key = DEMO_WRITES.has(act) ? 'app.demo.readonly' : DEMO_INSTALL.has(act) ? 'app.demo.needs_install'
      : act === 'share-opt' && b.dataset.k === 'privacy' && b.dataset.v === 'full' ? 'app.demo.full_report' : '';
    if (!key) return;
    e.preventDefault(); e.stopPropagation();
    demoNote(T(key));
  }, true);
  document.addEventListener('submit', e => {
    if (e.target.closest('form')) { e.preventDefault(); e.stopPropagation(); demoNote(); }
  }, true);
  // a field that saves on change (a device's name / owner / room, "assign to", a backup file)
  document.addEventListener('change', e => {
    const el = e.target, d = el.dataset || {};
    if (!((d.draft && el.closest('form[data-drawer-form]')) || 'assign' in d || 'bkFile' in d)) return;
    e.stopPropagation();
    if (el.tagName === 'SELECT') Array.from(el.options).forEach(o => { o.selected = o.defaultSelected; });
    else if (el.type !== 'file') el.value = el.defaultValue;
    else el.value = '';
    if (d.mac) delete S.draft[d.mac];
    demoNote();
  }, true);
}
document.addEventListener('click', e => {
  if (S.more && !e.target.closest('#bottomnav')) { S.more = false; render(); }   // a click outside closes "More"
  const b = e.target.closest('[data-act]');
  if (!b || b.disabled || b.tagName === 'SELECT') return;
  const act = b.dataset.act, mac = b.dataset.mac;
  switch (act) {
    case 'mute': ack(mac, b.dataset.ack, b.dataset.what || b.dataset.ack); break;
    case 'trust': ack(mac, '', b.dataset.name || mac); break;
    case 'untrust': unack(mac, '', b.dataset.name || mac); break;
    case 'edit': S.edit = mac; S.draft[mac] = {}; render(); { const i = document.querySelector('form.rowedit input'); if (i) i.focus(); } break;
    case 'edit-cancel': S.edit = null; delete S.draft[mac]; render(); { const eb = document.querySelector(`[data-act="edit"][data-mac="${CSS.escape(mac)}"]`); if (eb) eb.focus(); } break;
    case 'sort': { const c = b.dataset.col; if (S.f.sort === c) S.f.dir = -S.f.dir; else { S.f.sort = c; S.f.dir = ['queries', 'privacy', 'traffic', 'last'].includes(c) ? -1 : 1; } render(); break; }
    case 'show': S.f.show = b.dataset.v; render(); break;
    case 'clear-filters': Object.assign(S.f, { q: '', type: '', owner: '', room: '', show: 'all', since: '' }); render(); break;
    case 'filter-owner': Object.assign(S.f, { q: '', type: '', room: '', show: 'all', owner: b.dataset.v, since: '' }); go('#/devices'); break;
    // Stage T: the network map, "Since your last visit"
    case 'map-mode': S.map.mode = b.dataset.v; render(); break;
    case 'map-by': S.map.by = b.dataset.v; render(); break;
    case 'map-status': S.map.status = b.dataset.v; render(); break;
    case 'map-clear': Object.assign(S.map, { q: '', person: '', type: '', status: '' }); render(); break;
    case 'map-zoom': if (b.dataset.v === 'fit') mapFit(); else mapZoom(b.dataset.v === 'in' ? 1.25 : 0.8); break;
    case 'since-off': sinceOff(); break;
    case 'since-go': sinceGo(b.dataset.v); break;
    case 'since-clear': S.f.since = ''; render(); break;
    case 'check': startCheck(mac); break;
    case 'check-all': confirmCheck(); break;
    // Stage X: inbox, confirm sheet, settings, connection tests, backup, wizard
    case 'ib-do': { const it = inboxById(b.dataset.id); if (it) { S.inbox.sel = Math.max(0, inboxItems().indexOf(it)); inboxDo(b.dataset.v, [it]); } break; }
    case 'ib-bulk': inboxDo(b.dataset.v, inboxItems().filter(it => S.inbox.picked.has(it.id))); break;
    case 'ib-all': inboxItems().forEach(it => S.inbox.picked.add(it.id)); render(); break;
    case 'ib-none': S.inbox.picked.clear(); render(); break;
    case 'ib-undo': inboxUndo(); break;
    case 'confirm-yes': closeConfirm(true); break;
    case 'confirm-no': closeConfirm(false); break;
    case 'set-bool': {
      const it = aiItem(b.dataset.k); if (!it.editable || S.set.saving) break;
      S.set.form[it.key] = !setVal(it); saveSettings(it.section, it.key); break;
    }
    case 'set-discard': setItems(b.dataset.v).forEach(it => { delete S.set.form[it.key]; delete S.set.errs[it.key]; }); render(); break;
    case 'conn-test': testConn(b.dataset.v); break;
    case 'bk-mode': if (S.set.bk && S.set.bk.mode !== b.dataset.v) { S.set.bk.mode = b.dataset.v; bkPreview(); } break;
    case 'bk-apply': bkApply(); break;
    case 'bk-cancel': S.set.bk = null; render(); { const f = $('#bk-file'); if (f) f.focus(); } break;
    case 'wz-go': wzGo(b.dataset.v); break;
    case 'wz-next': wzNext(); break;
    case 'wz-finish': wzFinish(false); break;
    case 'wz-skip': wzFinish(true); break;
    case 'wz-scan': wzScan(); break;
    case 'wz-test': {
      const src = S.setup.s && S.setup.s.dns.source; if (!src) break;
      S.setup.test = 'busy'; render();
      postJSON('/api/test/' + src, {}).then(r => { S.setup.test = r; }).catch(err => { S.setup.test = null; fail(err); }).then(() => { render(); loadSetup(); });
      break;
    }
    case 'wz-tz': S.setup.tz = b.dataset.v; render(); break;
    case 'wz-ai': {
      const prov = WZ_AI[b.dataset.v]; if (!prov || aiItem('ai.provider').editable === false) break;
      wzSave({ 'ai.provider': prov }).then(ok => { if (ok) { toast(T('app.ai.saved')); refreshMeta(); } });
      break;
    }
    case 'wz-lan': {
      if (aiItem('lan.enabled').editable === false) break;
      const on = !(S.setup.s && S.setup.s.lan_enabled);
      wzSave({ 'lan.enabled': on }).then(ok => { if (ok) toast(T(on ? 'app.pair.restart_needed' : 'app.pair.lan_setting_off')); });
      break;
    }
    // Stage Q: "Why this alert?", alert tuning, hygiene checks, quiet-hours summaries
    case 'why': { const k = b.dataset.k; if (S.whyOpen.has(k)) S.whyOpen.delete(k); else S.whyOpen.add(k); render(); break; }
    case 'why-ask': {
      // pre-fills the question about THIS alert (it travels with the next message) - never sends
      const ref = { kind: b.dataset.kind, mac: b.dataset.mac || null, key: b.dataset.key || '' };
      openChat({ ctx: ref.mac && findDev(ref.mac) ? { mac: ref.mac, name: b.dataset.name || ref.mac } : undefined,
                 draft: T('app.why.ask_text', { title: b.dataset.title || '' }), alert: ref });
      break;
    }
    case 'tune': openTune(b.dataset.kind, b.dataset.mac || null, b.dataset.name || ''); break;
    case 'tune-scope': if (S.confirm.tune) { S.confirm.tune.scope = b.dataset.v; tuneSheet(); { const x = $(`#confirmsheet [data-act="tune-scope"][data-v="${b.dataset.v}"]`); if (x) x.focus(); } } break;
    case 'tune-set': {
      const t = S.confirm.tune; if (!t) break;
      const mac = t.scope === 'device' ? t.mac : null, v = b.dataset.v, f = b.dataset.for || null;
      closeConfirm(false);
      // silencing a security alert type for the WHOLE home: this computer only, and only
      // after saying what it means (tuning.CRITICAL_KINDS; the server checks both)
      if (v === 'off' && !mac && TUNE_CRITICAL.includes(t.kind)) {
        if (S.meta.remote) { toast(T('app.tune.local_only'), { kind: 'err' }); break; }
        openConfirm({ icon: 'i-alert', title: T('app.tune.heading', { kind: tuneKind(t.kind) }),
                      text: T('app.tune.critical_confirm', { kind: tuneKind(t.kind) }), ok: T('app.tune.critical_ok'),
                      danger: true, run: () => setTune(t.kind, null, v, f, true) });
        break;
      }
      setTune(t.kind, mac, v, f); break;
    }
    case 'tune-all': e.preventDefault(); closeConfirm(false); go('#/settings');
      setTimeout(() => { const c = document.querySelector('[data-key="tuning"]'); if (c) c.scrollIntoView({ block: 'start' }); }, 120); break;
    case 'tune-restore': restoreTune(b.dataset.id, b.dataset.kind); break;
    case 'hyg-toggle': { const k = b.dataset.k; if (S.hygOpen.has(k)) S.hygOpen.delete(k); else S.hygOpen.add(k); render(); break; }
    case 'quiet-seen': quietSeen(+b.dataset.id, true); break;
    case 'extip': S.showExtIp = !S.showExtIp; render(); break;
    case 'use-name': saveDevice(mac, { label: b.dataset.name || '' }); break;
    case 'copy': copyText(b.dataset.text || '', b); break;
    case 'share-opt': if (SHARE_OPTS[b.dataset.k] && SHARE_OPTS[b.dataset.k].includes(b.dataset.v)) { S.share[b.dataset.k] = b.dataset.v; render(); } break;
    case 'share-copy': shareCopy(b); break;
    case 'retry': refresh(); break;
    case 'demo-hide': demoHide(); break;
    case 'demo-welcome-hide': demoWelcomeHide(); break;
    case 'boot-retry': bootRetry(true); break;
    case 'close': closeDrawer(); break;
    case 'theme': setTheme(b.dataset.v); break;
    // "Ask AI about this device": opens the chat about it with a question pre-filled - never sends
    case 'ask': openChat({ ctx: { mac, name: b.dataset.name || mac }, draft: T('app.ask_prefill', { name: b.dataset.name, mac }) }); break;
    case 'suggest': if (!S.chat.busy) { S.chat.draft = b.dataset.text; chat('send'); } break;
    case 'insight': chat('insight'); break;
    case 'send': chat('send'); break;
    case 'chat-stop': if (S.chat.ctrl) S.chat.ctrl.abort(); break;
    case 'chat-retry': retryChat(); break;
    case 'chat-clear': S.chat.messages = []; S.chat.ctx = null; saveChat(); render(); { const q = $('#chatq'); if (q) q.focus(); } break;
    case 'chat-unfocus': S.chat.ctx = null; saveChat(); render(); { const q = $('#chatq'); if (q) q.focus(); } break;
    case 'chat-close': closeChat(); break;
    case 'chat-expand': S.chat.open = false; saveChat(); break;     // the link itself goes to #/ai
    case 'copy-msg': { const m = S.chat.messages[+b.dataset.i]; if (m) copyText(m.content, b); break; }
    case 'notify': toggleNotify(); break;
    case 'keys-close': closeKeys(); break;
    case 'single-keys': setSingleKeys(!singleKeys()); break;
    case 'ai-test': testAI(); break;
    case 'ai-preview': openPreview(); break;
    case 'prev-close': closePreview(); break;
    case 'ai-use-model': S.ai.form['ai.model'] = b.dataset.v; render(); break;
    case 'more': S.more = !S.more; render(); if (S.more) { const f = $('#moremenu a'); if (f) f.focus(); } break;
    case 'sug-tab': S.sugTab = b.dataset.v; render(); break;
    case 'sug-toggle': { const id = b.dataset.id; if (S.sugOpen.has(id)) S.sugOpen.delete(id); else S.sugOpen.add(id); render(); break; }
    case 'sug-plat': S.sugPlat[b.dataset.id] = b.dataset.v; render(); break;
    case 'sug-set': {
      const g = S.data.sug, cur = g && SUG_TABS.map(t => (g[t] || []).find(x => x.id === b.dataset.id)).find(Boolean);
      setSug(b.dataset.id, b.dataset.v, cur ? cur.status : 'open'); break;
    }
    case 'sug-goto': {   // from the Overview: open that suggestion on the Suggestions page
      e.preventDefault(); const id = b.dataset.id; S.sugTab = 'open'; S.sugOpen.add(id); go('#/suggestions');
      setTimeout(() => { const h = document.getElementById('sh-' + id); if (h) { h.scrollIntoView({ block: 'center' }); h.focus({ preventScroll: true }); } }, 40);
      break;
    }
    case 'probe-off': saveProbe(''); break;
    case 'pair-new': pairNew(); break;
    case 'pair-hide': S.pair.code = null; render(); break;
    case 'pair-revoke': pairRevoke(+b.dataset.id, b.dataset.name); break;
    case 'pair-revoke-all': pairRevokeAll(); break;
    case 'lan-toggle': toggleLan(); break;
    case 'logout': signOut(); break;
    case 'bed-new': openBedForm(null); break;
    case 'bed-edit': { const r = S.fam.bed && S.fam.bed.rules.find(x => x.id === +b.dataset.id); if (r) openBedForm(r); break; }
    case 'bed-cancel': closeBedForm(); break;
    case 'bed-delete': deleteBedRule(+b.dataset.id); break;
    case 'bed-toggle': toggleBedRule(+b.dataset.id); break;
    case 'bed-day': if (S.fam.form) { const v = +b.dataset.v, d = S.fam.form.days; S.fam.form.days = d.includes(v) ? d.filter(x => x !== v) : d.concat(v).sort(); render(); bedPreview(); } break;
    case 'bed-preset': if (S.fam.form) { S.fam.form.days = BED_PRESETS[b.dataset.v].slice(); render(); bedPreview(); } break;
    // Stage P: people, devices to people, presence
    case 'ppl-new': openPersonForm(null); break;
    case 'add-person-for': addPersonFor(b.dataset.mac); break;
    case 'ppl-edit': if (S.ppl.det) openPersonForm(S.ppl.det); break;
    case 'pf-cancel': closePersonForm(); break;
    case 'pf-color': if (S.ppl.form) { S.ppl.form.color = b.dataset.v; render(); } break;
    case 'pf-child': if (S.ppl.form) { S.ppl.form.child = !S.ppl.form.child; render(); } break;
    case 'ppl-delete': deletePerson(+b.dataset.id); break;
    case 'ppl-add-dev': assignDevices([mac], 'p:' + b.dataset.id); break;
    case 'ppl-rm-dev': assignDevices([mac], ''); break;
    case 'ppl-link': presLink(mac, +b.dataset.id, false); break;
    case 'ppl-link-no': presLink(mac, +b.dataset.id, true); break;
    case 'pres-on': presEnable(+b.dataset.id); break;
    case 'pres-off': presDisable(+b.dataset.id); break;
    case 'pres-forget': presForget(+b.dataset.id); break;
    case 'pres-dev': presDevice(+b.dataset.id, mac); break;
    case 'pres-default': {
      const p = S.ppl.det; if (!p || p.id !== +b.dataset.id) break;
      // custom -> default: back to "phones"; default -> custom: start from what is used now
      if (!p.default_devices) presSet(p.id, { default_devices: true });
      else { p.default_devices = false; p.presence_macs = ((p.presence_info || {}).devices || []).map(d => d.mac); render(); presSet(p.id, { devices: p.presence_macs }); }
      break;
    }
    case 'pres-notify': presNotify(+b.dataset.id, b.dataset.k); break;
    // Round 10 N: notification channels
    case 'push-new': { const t = ($('#push-type') || {}).value; if (t) pushNew(t); else { const x = $('#push-type'); if (x) x.focus(); } break; }
    case 'push-edit': pushEdit(+b.dataset.id); break;
    case 'push-cancel': S.push.ed = null; S.push.pv = null; render(); { const x = $('#push-type'); if (x) x.focus(); } break;
    case 'push-test': pushTest(+b.dataset.id); break;
    case 'push-enable': pushAct('/api/channels/enable', { id: +b.dataset.id, enabled: b.dataset.v === '1' }, T(b.dataset.v === '1' ? 'app.push.resumed' : 'app.push.paused_toast')); break;
    case 'push-delete': pushDelete(+b.dataset.id, b.dataset.name || ''); break;
    case 'push-log': pushLog(+b.dataset.id); break;
    case 'push-level': if (S.push.ed) { S.push.ed.level = b.dataset.v; delete S.push.ed.errs.level; render(); pushPreview(true); } break;
    case 'push-sample': if (S.push.ed) { S.push.ed.sample = b.dataset.v; render(); pushPreview(true); } break;
    case 'push-bool': if (S.push.ed) { const k = b.dataset.k; S.push.ed[k] = !S.push.ed[k]; render(); pushPreview(); } break;
    case 'push-clear': if (S.push.ed) { const k = b.dataset.k; S.push.ed.clear[k] = !S.push.ed.clear[k]; S.push.ed.secrets[k] = ''; render(); pushPreview(); } break;
    case 'push-helper': pushHelper(b.dataset.v); break;
    case 'push-use': if (S.push.ed) { S.push.ed.fields[b.dataset.k] = b.dataset.v; render(); pushPreview(); { const x = $('#push-f-' + b.dataset.k); if (x) x.focus(); } } break;
    case 'bulk-all': filtered().forEach(d => { if (d.mac) S.bulk.add(d.mac); }); render(); break;
    case 'bulk-none': S.bulk.clear(); render(); break;
    case 'bulk-assign': {
      const macs = Array.from(S.bulk), to = S.bulkTo; if (to === '-' || !macs.length) break;
      assignDevices(macs, to).then(ok => { if (ok) { S.bulk.clear(); S.bulkTo = '-'; render(); } }); break;
    }
  }
});
document.addEventListener('submit', e => {
  if (e.target.closest('form[data-bed-form]')) { e.preventDefault(); submitBedForm(); return; }
  if (e.target.closest('form[data-person-form]')) { e.preventDefault(); savePerson(); return; }
  if (e.target.closest('form[data-ai-form]')) { e.preventDefault(); saveAI(); return; }
  if (e.target.closest('form[data-push-form]')) { e.preventDefault(); pushSave(); return; }
  { const sf = e.target.closest('form[data-set-form]'); if (sf) { e.preventDefault(); saveSettings(sf.dataset.setForm); return; } }
  if (e.target.closest('form[data-probe-form]')) { e.preventDefault(); saveProbe((S.probe != null ? S.probe : ((S.data.health || {}).internet || {}).target || '').trim()); return; }
  const f = e.target.closest('form[data-mac]'); if (!f) return;
  e.preventDefault();
  const mac = f.dataset.mac, ch = {};
  f.querySelectorAll('[data-draft]').forEach(el => { ch[el.dataset.draft] = el.value; });
  saveDevice(mac, ch);
});
document.addEventListener('input', e => {
  const el = e.target;
  if (el.dataset.filter) { S.f[el.dataset.filter] = el.value; render(); }
  else if (el.dataset.mapf) { S.map[el.dataset.mapf] = el.value; render(); }
  else if (el.dataset.ai) S.ai.form[el.dataset.ai] = el.value;
  else if (el.dataset.set) { S.set.form[el.dataset.set] = el.value; delete S.set.errs[el.dataset.set]; }
  else if (S.push.ed && (el.dataset.push || el.dataset.pushF || el.dataset.pushS)) {
    const E = S.push.ed;
    if (el.dataset.push) { E[el.dataset.push] = el.value; delete E.errs[el.dataset.push]; }
    else if (el.dataset.pushF) { E.fields[el.dataset.pushF] = el.value; delete E.errs[el.dataset.pushF]; }
    else { E.secrets[el.dataset.pushS] = el.value; delete E.errs[el.dataset.pushS]; }
    pushPreview();
  }
  else if ('wzTz' in el.dataset) S.setup.tz = el.value;
  else if ('probe' in el.dataset) S.probe = el.value;
  else if (el.dataset.bed && S.fam.form) {
    const k = { name: 'name', target: 'target', start: 'start', end: 'end', min: 'min_minutes' }[el.dataset.bed];
    S.fam.form[k] = el.value;
    if (k === 'end' || k === 'start' || k === 'target') render();   // "(next morning)" / preview state
    if (k !== 'name') bedPreview();
  }
  else if (el.dataset.pf && S.ppl.form) S.ppl.form[el.dataset.pf] = el.value;
  else if ('pplQ' in el.dataset) { S.ppl.q = el.value; render(); }
  else if (el.dataset.draft) { const m = el.dataset.mac; S.draft[m] = Object.assign(S.draft[m] || {}, { [el.dataset.draft]: el.value }); }
  else if (el.id === 'chatq') { S.chat.draft = el.value; el.style.height = 'auto'; el.style.height = Math.min(200, el.scrollHeight + 2) + 'px'; saveChat(); }
});
document.addEventListener('change', e => {
  const el = e.target;
  if (el.dataset.act === 'lang') { setLang(el.value, true); return; }
  if (el.dataset.mapf) { S.map[el.dataset.mapf] = el.value; render(); return; }
  if (el.dataset.ai) { S.ai.form[el.dataset.ai] = el.value; if (el.tagName === 'SELECT') render(); return; }
  if (el.dataset.set) { S.set.form[el.dataset.set] = el.value; render(); return; }
  if (S.push.ed && el.dataset.push && el.tagName === 'SELECT') { S.push.ed[el.dataset.push] = el.value; render(); pushPreview(true); return; }
  if (S.push.ed && 'pushCat' in el.dataset) {
    const E = S.push.ed, c = el.dataset.pushCat;
    E.categories = el.checked ? E.categories.concat(c) : E.categories.filter(x => x !== c); pushPreview(); return;
  }
  if (S.push.ed && 'pushConfirm' in el.dataset) { S.push.ed.confirm = el.checked; delete S.push.ed.errs.level; return; }
  if ('qday' in el.dataset) { setQuietDay(el.dataset.qday, el.value); render(); return; }
  if ('qdayT' in el.dataset) { const [d, i] = el.dataset.qdayT.split(':'); setQuietDay(d, null, +i, el.value); render(); return; }
  if ('ibPick' in el.dataset) {
    const id = el.dataset.ibPick, i = inboxItems().findIndex(it => it.id === id);
    if (el.checked) S.inbox.picked.add(id); else S.inbox.picked.delete(id);
    if (i >= 0) S.inbox.sel = i;
    render(); return;
  }
  if ('bulk' in el.dataset) { if (el.checked) S.bulk.add(el.dataset.bulk); else S.bulk.delete(el.dataset.bulk); render(); return; }
  if ('bulkTo' in el.dataset) { S.bulkTo = el.value; render(); return; }
  if ('assign' in el.dataset) { assignDevices([el.dataset.mac], el.value); return; }
  if ('bkFile' in el.dataset) { const f = el.files && el.files[0]; el.value = ''; bkLoad(f); return; }
  // Drawer fields save on change (blur / Enter / pick); table rows save with their form.
  if (el.dataset.draft && el.closest('form[data-drawer-form]')) saveDevice(el.dataset.mac, { [el.dataset.draft]: el.value });
});
$('#langsel').addEventListener('change', e => setLang(e.target.value, true));
$('#btnPalette').addEventListener('click', openPalette);
$('#btnRefresh').addEventListener('click', () => refresh());
$('#btnTheme').addEventListener('click', () => setTheme(THEMES[(THEMES.indexOf(S.theme) + 1) % THEMES.length]));
$('#backdrop').addEventListener('click', closeDrawer);
$('#btnChat').addEventListener('click', toggleChat);
// the user scrolling the chat log by hand takes over from followChat()
['wheel', 'touchmove'].forEach(t => document.addEventListener(t, e => {
  if (S.chat.follow && e.target.closest && e.target.closest('#chatlog')) S.chat.follow = false;
}, { passive: true }));
$('#btnKeys').addEventListener('click', openKeys);
$('#chatscrim').addEventListener('click', closeChat);
$('#keysheet').addEventListener('mousedown', e => { if (e.target.id === 'keysheet') { e.preventDefault(); closeKeys(); } });
$('#prevsheet').addEventListener('mousedown', e => { if (e.target.id === 'prevsheet') { e.preventDefault(); closePreview(); } });
$('#confirmsheet').addEventListener('mousedown', e => { if (e.target.id === 'confirmsheet') { e.preventDefault(); closeConfirm(false); } });
// Inbox: whatever row the user tabs / clicks into becomes the one the keys act on
document.addEventListener('focusin', e => {
  const li = S.base === 'inbox' && e.target.closest ? e.target.closest('.ib') : null;
  if (li && +li.dataset.i !== S.inbox.sel) { S.inbox.sel = +li.dataset.i; render(); }
});
function isTyping(el) {
  if (!el) return false;
  if (el.tagName === 'INPUT') return !['checkbox', 'radio', 'button'].includes(el.type);   // a ticked box does not type
  return el.isContentEditable || ['TEXTAREA', 'SELECT'].includes(el.tagName);
}
// Keep Tab inside the open layer(s): the drawer, plus the chat panel when it sits beside it.
function trapFocus(e, roots) {
  const f = [].concat(...roots.filter(Boolean).map(r => Array.from(r.querySelectorAll('a[href],button:not([disabled]),input,select,textarea,[tabindex]:not([tabindex="-1"])'))))
    .filter(x => x.offsetParent !== null || x === document.activeElement);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (!f.includes(document.activeElement)) { e.preventDefault(); first.focus(); }
  else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}
const chatPanelOpen = () => S.chat.open && S.base !== 'ai';
const chatIsSheet = () => window.matchMedia('(max-width: 760px)').matches;   // app.css: the bottom sheet
document.addEventListener('keydown', e => {
  const el = e.target;
  // an IME composition (Chinese / Japanese / Korean typing) owns every key until it ends
  if (e.isComposing || e.keyCode === 229) return;
  if ((e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey)) { e.preventDefault(); if (S.pal.open) closePalette(); else { closeKeys(); openPalette(); } return; }
  if (S.pal.open) {                // modal: whatever has the focus, no page shortcut fires
    if (el !== $('#palq')) {       // (the text box handles its own keys)
      if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
      else if (e.key === 'Tab' || e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); $('#palq').focus(); }
    }
    return;
  }
  if (S.keys.open) {               // the shortcuts sheet is modal
    if (e.key === 'Escape' || e.key === '?') { e.preventDefault(); closeKeys(); }
    else if (e.key === 'Tab') trapFocus(e, [$('#keysheet')]);
    return;
  }
  if (S.ai.prev.open) {            // so is the "what will be sent" preview
    if (e.key === 'Escape') { e.preventDefault(); closePreview(); }
    else if (e.key === 'Tab') trapFocus(e, [$('#prevsheet')]);
    return;
  }
  if (S.confirm.open) {            // ... and "Are you sure?"
    if (e.key === 'Escape') { e.preventDefault(); closeConfirm(false); }
    else if (e.key === 'Tab') trapFocus(e, [$('#confirmsheet')]);
    return;
  }
  if (S.more && e.key === 'Escape') { e.preventDefault(); closeMore(true); return; }
  // Stage G: the phone's "More" menu is a menu: arrows / Home / End move, Tab leaves (and closes it)
  if (S.more && el.closest && el.closest('#moremenu')) {
    const items = Array.from(document.querySelectorAll('#moremenu [role="menuitem"]')), i = items.indexOf(el);
    const to = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: items.length - 1 }[e.key];
    if (to !== undefined && items.length) { e.preventDefault(); items[(to + items.length) % items.length].focus(); return; }
    if (e.key === 'Tab') { closeMore(true); return; }   // focus is back on "More"; Tab goes on from there
  }
  // ... and the chat is a modal bottom sheet on phones (a side panel beside the page on desktop)
  if (e.key === 'Tab' && chatPanelOpen() && !drawerOpen() && chatIsSheet()) { trapFocus(e, [$('#chatpanel')]); return; }
  // Stage T: Ctrl/Cmd+Z undoes the newest action (a text field keeps its own undo)
  if ((e.key === 'z' || e.key === 'Z') && (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && !isTyping(el)) {
    e.preventDefault(); if (!e.repeat) undoLast(); return;   // holding the keys = ONE undo
  }
  // ... and inside the map: + - 0 and the arrows zoom / pan (before the digit shortcuts)
  if (!e.ctrlKey && !e.metaKey && !e.altKey && el.closest && el.closest('#mapsvg') && mapKey(e)) { e.preventDefault(); return; }
  if (el.dataset && el.dataset.draft) {          // inline editing: Enter saves, Esc reverts
    if (e.key === 'Escape') {
      e.preventDefault(); const m = el.dataset.mac;
      if (S.edit === m) { S.edit = null; delete S.draft[m]; render(); return; }
      if (S.draft[m]) delete S.draft[m][el.dataset.draft];
      const d = findDev(m) || S.dev.d; if (d) el.value = current(d, el.dataset.draft);
      el.blur(); return;
    }
    // Enter saves (the blur fires "change") and the cursor stays where it was (round 9 U)
    if (e.key === 'Enter' && el.tagName === 'INPUT' && el.closest('form[data-drawer-form]')) { e.preventDefault(); el.blur(); el.focus({ preventScroll: true }); return; }
  }
  // round 9 U: Enter in the Devices filter goes to the results - the device itself when
  // only one is left, else the first row (Tab / arrows from there)
  if (e.key === 'Enter' && el.dataset && el.dataset.filter === 'q' && S.base === 'devices') {
    const list = filtered().filter(d => d.mac);
    if (list.length === 1) { e.preventDefault(); go(devHref(list[0].mac)); return; }
    const a = $('#view .tbl a.dev'); if (a) { e.preventDefault(); a.focus(); return; }
  }
  // Enter sends, Shift+Enter is a new line (and an IME composition's Enter is left alone)
  if (el.id === 'chatq' && e.key === 'Enter' && !e.shiftKey && !e.isComposing && e.keyCode !== 229) { e.preventDefault(); chat('send'); return; }
  if (e.key === 'Tab' && drawerOpen()) { trapFocus(e, [$('#drawer'), chatPanelOpen() ? $('#chatpanel') : null]); return; }
  if (e.key === 'Escape') {
    if (el.dataset && el.dataset.filter === 'q' && el.value) return;   // native clear of the search box
    if (S.fam.form && el.closest && el.closest('form[data-bed-form]')) { e.preventDefault(); closeBedForm(); return; }
    if (S.ppl.form && el.closest && el.closest('form[data-person-form]')) { e.preventDefault(); closePersonForm(); return; }
    if ('pplQ' in (el.dataset || {}) && el.value) return;   // native clear of the picker's search
    // the topmost layer first: the chat panel (it opens over the drawer), unless focus is
    // inside the drawer itself; then the drawer. (Focus may sit on <body> after a re-render.)
    if (chatPanelOpen() && ($('#chatpanel').contains(el) || !$('#drawer').contains(el))) { e.preventDefault(); closeChat(); }
    else if (drawerOpen()) { e.preventDefault(); closeDrawer(); }
    return;
  }
  if (isTyping(el) || e.altKey || e.ctrlKey || e.metaKey) return;
  const inboxHere = S.base === 'inbox' && !drawerOpen() && !chatPanelOpen();
  if (!singleKeys()) {             // WCAG 2.1.4: only Enter (open the inbox row) is left
    if (e.key === 'Enter' && inboxHere && inboxKey(e)) e.preventDefault();
    return;
  }
  const gPending = Date.now() - S.gAt < 1500;
  S.gAt = 0;
  if (gPending && GO_KEYS[e.key.toLowerCase()]) { e.preventDefault(); go('#/' + GO_KEYS[e.key.toLowerCase()]); }
  else if (e.key === 'g' || e.key === 'G') S.gAt = Date.now();
  else if (inboxHere && inboxKey(e)) e.preventDefault();
  else if (e.key === '?') { e.preventDefault(); openKeys(); }
  else if (e.key === '/') { e.preventDefault(); if (!focusFilter()) openPalette(); }
  else if (e.key === 'c' || e.key === 'C') { e.preventDefault(); toggleChat(); }
  else if (e.key === 'r' || e.key === 'R') refresh();
  else if (/^[1-9]$/.test(e.key) && GROUPS[+e.key - 1]) go('#/' + GROUPS[+e.key - 1][1][0]);   // 1..7 = the places
});
// Closing the slide-over goes "back" when it was opened from a section page, so the
// browser history stays the natural one; otherwise (deep link, drawer -> drawer) it
// navigates to the section underneath.
const isDrawerRoute = r => ['device', 'service', 'domain'].includes(r.name);
window.addEventListener('hashchange', () => {
  S.cameFromBase = isDrawerRoute(parseHash()) && !isDrawerRoute(S.route);
  const id = entryVisit();          // a known entry = Back / Forward: its scroll comes back
  S.backY = id && typeof scrollMap[id] === 'number' ? scrollMap[id] : null;
  onRoute();
});
document.addEventListener('visibilitychange', () => {
  if (!S.meta) return;
  if (document.visibilityState !== 'visible') { sinceStamp(); liveStop('paused'); return; }
  if (Date.now() - S.updated > REFRESH_MS) refresh();
  liveConnect();      // resumes from the last event id (or a full refresh when that is gone)
});
window.addEventListener('pagehide', () => { if (S.meta) sinceStamp(); });
setInterval(tick, 5000);

// ---------------------------------------------------------------------------------------
// Boot: saved choice > browser language (if supported) > server default
(async function boot() {
  try { S.theme = localStorage.getItem(THEME_KEY) || 'auto'; } catch (e) { S.theme = 'auto'; }
  if (!THEMES.includes(S.theme)) S.theme = 'auto';
  if (S.theme !== 'auto') document.documentElement.setAttribute('data-theme', S.theme);
  try { S.notify.on = localStorage.getItem(NOTIFY_KEY) === '1'; } catch (e) { S.notify.on = false; }
  const langs = (navigator.languages && navigator.languages.length) ? navigator.languages : [navigator.language || ''];
  try {
    const mr = await fetch(url('/api/meta?accept=' + enc(langs.join(','))), { cache: 'no-store' });
    if (needPair(mr)) return;
    if (!mr.ok) throw new Error('meta');
    S.meta = await mr.json();
  } catch (e) { bootFailed(); return; }
  if (DEMO) {
    // the static demo: no Accept-Language reached a server, and "now" is when it was built
    // (every time in the saved answers is relative to that moment)
    S.meta.browser_lang = navLang(S.meta.languages.map(l => l.code));
    const built = parseTs((S.meta.static_demo || {}).built_at);
    if (built) S.skew = built - Date.now();
    document.body.classList.add('static-demo');
  }
  loadChat();   // needs meta.db_id
  $('#langsel').innerHTML = S.meta.languages.map(l => `<option value="${esc(l.code)}">${esc(l.name)}</option>`).join('');
  let saved = null; try { saved = localStorage.getItem(LANG_KEY); } catch (e) { /* private mode */ }
  const codes = S.meta.languages.map(l => l.code);
  // Stage X: a fresh install (no devices / DNS / source yet, wizard not done or skipped)
  // opens the first-run wizard instead of an empty Overview
  if (!S.meta.remote && !S.meta.demo) {
    try { S.setup.s = await getJSON('/api/setup'); } catch (e) { S.setup.s = null; }
    const h = location.hash.replace(/^#\/?/, '');
    if (S.setup.s && S.setup.s.needed && (!h || h === 'overview')) history.replaceState(null, '', '#/welcome');
  }
  const r = parseHash(); S.base = PAGES.includes(r.name) ? r.name : (r.name === 'device' ? 'devices' : 'overview');
  viewLoad();   // round 9 U: the views as they were left (a deep link's query still wins)
  $('#palkbd').textContent = MOD === '⌘' ? '⌘K' : 'Ctrl K';
  if (!await setLang(codes.includes(saved) ? saved : (S.meta.browser_lang || S.meta.default_lang), false)) { bootFailed(); return; }
  const id = entryVisit();   // a reload keeps its history entry: back to where it was scrolled
  S.backY = id && typeof scrollMap[id] === 'number' ? scrollMap[id] : null;
  onRoute();
  if (['system', 'settings', 'welcome'].includes(S.base)) { loadAI(); loadPair(); }   // opened straight on one of them
  if (S.base === 'welcome') { loadSetup(); wzTick(); }
  if (S.base === 'settings') { loadTuning(); loadPush(); }
  if (S.base === 'security') loadHyg();
  sinceInit();
  setInterval(sinceStamp, 60000);
  liveConnect();
  registerWorker();
})();

// Installable app (Stage X): a service worker on this computer only (127.0.0.1 /
// localhost) whose single job is the "netwarden is not running" page when the server is
// down. Network first, nothing personal cached (static/sw.js).
function registerWorker() {
  if (DEMO || !('serviceWorker' in navigator) || !['127.0.0.1', 'localhost'].includes(location.hostname)) return;
  navigator.serviceWorker.register(url('/sw.js'), { scope: url('/') }).catch(() => { /* private mode / disabled: fine */ });
}

})();
