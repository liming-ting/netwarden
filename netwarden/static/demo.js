/* netwarden - demo.js: the static live demo's request map (round 9 W). PURE, no DOM.
 *
 * The GitHub Pages demo (scripts/build_static_demo.py) is the real dashboard on made-up
 * data, served as plain files: every GET the page makes was answered once at build time
 * by the real server and saved under demo-data/. This file says which file answers which
 * request - the builder has the same function in Python (static_name) and both are
 * checked against one fixture (tests/fixtures/static_demo_names.json):
 *
 *   NWDemo.file('/api/device?mac=aa%3Abb&lang=en')  -> 'demo-data/en/api/device.q1a2b3c4d.json'
 *   NWDemo.chatFile('chat', 'Is my network OK?', 'en') -> 'demo-data/en/chat/9f0e1d2c.txt'
 *
 * Rules: the language comes from ?lang= (else the page's); lang / accept / inline are not
 * part of the name; the rest of the query is sorted and hashed (FNV-1a 32 over UTF-8).
 * /api/report: names / people only count for the "shareable" level; the HTML report is
 * .html, the Markdown one .txt (a static host serves it as text/plain, so Preview shows it
 * in the tab; the page names the downloaded file itself).
 * Only index.html of the static build loads this file; the real app never does.
 *
 * Loaded by the demo page (window.NWDemo) and by node (module.exports):
 * tests/js/static_demo_test.js.
 */
'use strict';
(function (root) {
  const DIR = 'demo-data/';
  const DEFAULT_LANG = 'zh-Hant';
  const LANG_FREE = ['/api/meta'];              // answered before the page knows its language
  const DROP = ['lang', 'accept', 'inline'];
  const LANG_RE = /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,4})?$/;

  function utf8(s) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s);
    return Buffer.from(s, 'utf8');   // node without TextEncoder (never in a browser)
  }
  function fnv(s) {
    let h = 0x811c9dc5;
    for (const b of utf8(String(s))) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  }
  const byPair = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
  function langOf(v, fallback) { return LANG_RE.test(v || '') ? v : (LANG_RE.test(fallback || '') ? fallback : DEFAULT_LANG); }

  // A request path ("/api/x?a=1&lang=en", as the page builds it) -> its file under the demo root
  function file(request, fallbackLang) {
    const s = String(request), i = s.indexOf('?');
    const path = i < 0 ? s : s.slice(0, i);
    const q = new URLSearchParams(i < 0 ? '' : s.slice(i + 1));
    const lang = langOf(q.get('lang'), fallbackLang);
    let ext = /\.(csv|md)$/.test(path) ? '' : path === '/report/weekly' ? '.html' : '.json';
    if (path === '/api/report') {
      if (q.get('privacy') !== 'shareable') { q.delete('names'); q.delete('people'); }
      ext = q.get('format') === 'md' ? '.txt' : '.html';
    }
    const pairs = Array.from(q.entries()).filter(p => !DROP.includes(p[0])).sort(byPair);
    const canon = pairs.map(p => p[0] + '=' + p[1]).join('&');
    return DIR + (LANG_FREE.includes(path) ? '' : lang + '/') + path.replace(/^\/+/, '') +
      (canon ? '.q' + fnv(canon) : '') + ext;
  }
  // One pre-computed assistant answer (the raw SSE stream the real server sent)
  function chatFile(mode, question, lang) {
    return DIR + langOf(lang) + '/chat/' + fnv(mode + '\n' + String(question || '').trim()) + '.txt';
  }
  // The list of questions that have an answer, per language
  function chatIndex(lang) { return DIR + langOf(lang) + '/chat/index.json'; }

  const api = { file, chatFile, chatIndex, fnv, DIR };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.NWDemo = api;
})(typeof window !== 'undefined' ? window : this);
