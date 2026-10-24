// netwarden service worker (GET /sw.js; registered by app.js on 127.0.0.1 / localhost
// only). It exists for ONE thing: when the local server is not running, show a friendly
// "netwarden is not running" page instead of the browser's error.
//
//  - network first for everything; the cache is only an offline fallback
//  - it caches just that fallback page + its stylesheet, script and icon - never an
//    /api/ answer, a report or anything else with personal data
//  - the version below is the asset hash (web.py stamps it in), so a new release
//    installs a new worker, which drops the old cache: no hard refresh ever needed
'use strict';
const VERSION = '__V__';
const CACHE = 'netwarden-' + VERSION;
// Stage H: everything is relative to where the worker was registered: / normally,
// /api/hassio_ingress/<token>/ under Home Assistant ingress
const ROOT = new URL(self.registration.scope).pathname.replace(/\/$/, '');
const FALLBACK = ROOT + '/offline';
const PRECACHE = [FALLBACK, ROOT + '/static/app.css?v=' + VERSION, ROOT + '/static/offline.js?v=' + VERSION,
                  ROOT + '/static/icon.svg'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k.startsWith('netwarden-') && k !== CACHE)
                                  .map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // data, reports, pairing, downloads: straight to the network, never stored
  if (!url.pathname.startsWith(ROOT + '/')) return;
  const path = url.pathname.slice(ROOT.length);
  if (path.startsWith('/api/') || path.startsWith('/report/') || path.startsWith('/pair')) return;
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match(FALLBACK)));
    return;
  }
  if (path.startsWith('/static/')) {
    event.respondWith(fetch(req).catch(() => caches.match(req).then(r => r || Response.error())));
  }
});
