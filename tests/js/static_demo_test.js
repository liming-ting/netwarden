// netwarden - the static live demo's request map (round 9 W): netwarden/static/demo.js must
// name the same files as scripts/build_static_demo.py static_name() / chat_name(). Both are
// checked against tests/fixtures/static_demo_names.json (the Python side in
// tests/test_round9_w.py). Run from the repo root:
//     node tests/js/static_demo_test.js
// It exits non-zero (with the failed check) when something is off.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const D = require(path.join(root, 'netwarden', 'static', 'demo.js'));
const fx = JSON.parse(fs.readFileSync(path.join(root, 'tests', 'fixtures', 'static_demo_names.json'), 'utf8'));

let checks = 0;
function check(name, fn) { fn(); checks++; console.log('ok  ' + name); }

check('FNV-1a 32 over UTF-8', () => {
  assert.strictEqual(D.fnv(''), '811c9dc5');
  assert.strictEqual(D.fnv('a'), 'e40c292c');
  assert.strictEqual(D.fnv('foobar'), 'bf9cf968');
  assert.match(D.fnv('網路'), /^[0-9a-f]{8}$/);
});

check('request -> file, as the builder names it', () => {
  assert.ok(fx.files.length >= 20);
  for (const [request, fallback, want] of fx.files) {
    assert.strictEqual(D.file(request, fallback === null ? undefined : fallback), want, request);
  }
});

check('chat answers and the index', () => {
  for (const [mode, q, lang, want] of fx.chat) assert.strictEqual(D.chatFile(mode, q, lang), want, q);
  for (const [lang, want] of fx.index) assert.strictEqual(D.chatIndex(lang), want);
});

check('every name stays under demo-data/, relative, without ..', () => {
  const odd = ['/api/overview?lang=../../etc', '/api/device?mac=../../x&lang=en', '/api/meta?lang=<b>'];
  for (const r of odd.concat(fx.files.map(f => f[0]))) {
    const f = D.file(r);
    assert.ok(f.startsWith('demo-data/') && !f.includes('..') && !f.includes('//'), f);
  }
});

console.log(checks + ' checks passed');
