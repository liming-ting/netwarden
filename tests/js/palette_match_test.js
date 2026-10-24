// netwarden - the command palette's matcher (round 9 U): fold() / fuzzy() / matches() as
// they are in static/app.js (the block is cut out of the file and evaluated, so this tests
// the shipped code, not a copy). Run from the repo root:
//     node tests/js/palette_match_test.js
// It exits non-zero (with the failed check) when something is off.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'netwarden', 'static', 'app.js'), 'utf8');
const start = src.indexOf('const TS_PAIRS'), end = src.indexOf('const RECENT_MAX');
assert.ok(start > 0 && end > start, 'matcher block not found in app.js');
// eslint-disable-next-line no-new-func
const M = new Function(src.slice(start, end) + '\nreturn { fold, fuzzy, matches, TS };')();

let checks = 0;
function check(name, fn) { fn(); checks++; console.log('ok  ' + name); }

check('case, accents and widths fold away', () => {
  assert.strictEqual(M.fold('ÉCRAN Télé'), 'ecran tele');
  assert.strictEqual(M.fold('ＴＶ　Ｒｏｏｍ'), 'tv room');          // full-width letters + space
  assert.strictEqual(M.fold('Straße'), 'strasse');
  assert.strictEqual(M.fold('Ёлка'), 'елка');
  assert.strictEqual(M.fold('ｶﾒﾗ'), 'カメラ');                       // half-width katakana
});

check('Traditional and Simplified Chinese match each other', () => {
  assert.strictEqual(M.fold('裝置'), M.fold('装置'));
  assert.strictEqual(M.fold('網路設定'), M.fold('网路设定'));
  assert.ok(M.fuzzy('设备', '備份 · 設備') > 0);
  assert.ok(M.matches('电视', '客廳電視'));
});

check('scripts that need their marks keep them (Hindi, Korean, kana voicing)', () => {
  assert.strictEqual(M.fold('डिवाइस'), 'डिवाइस');
  assert.strictEqual(M.fold('기기'), '기기');                         // recomposed after NFKD
  assert.ok(M.fuzzy('기', '기기 검색') > 0);
  assert.ok(M.matches('ガ', 'ガレージ'));
});

check('the table has no chains and no identity pairs', () => {
  for (const [t, s] of M.TS) { assert.notStrictEqual(t, s); assert.ok(!M.TS.has(s), t + s); }
  assert.ok(M.TS.size > 200);
});

check('fuzzy: substrings > all words > initials; scattered letters do not match', () => {
  assert.strictEqual(M.fuzzy('xyz', 'living room tv'), 0);
  assert.ok(M.fuzzy('lrt', 'living room tv') > 0);                      // initials
  assert.ok(M.fuzzy('liv ro', 'living room tv') > 0);                   // word prefixes
  assert.ok(M.fuzzy('room', 'living room tv') > M.fuzzy('lrt', 'living room tv'));
  assert.ok(M.fuzzy('tv', 'TV · Living room') > M.fuzzy('tv', 'Smart tv box'));
  assert.ok(M.fuzzy('tv room', 'living room tv') > M.fuzzy('lrt', 'living room tv'));
  assert.ok(M.fuzzy('phone', "Dad's iPhone") > 0);                      // inside a word: as a substring
  assert.strictEqual(M.fuzzy('mia', 'ipcam Shenzhen (generic IP camera)'), 0);   // m..i..a scattered
  assert.strictEqual(M.fuzzy('', 'anything'), 1);
});

check('matches: every word somewhere, any order; MAC prefixes', () => {
  assert.ok(M.matches('ipad mia', "Mia's iPad · Apple"));
  assert.ok(M.matches('MIA  IPAD', "Mia's iPad · Apple"));
  assert.ok(!M.matches('ipad leo', "Mia's iPad · Apple"));
  assert.ok(M.matches('aa:bb', 'aa:bb:cc:00:00:01 aabbcc000001'));
  assert.ok(M.matches('aabb', 'aa:bb:cc:00:00:01 aabbcc000001'));
});

check('300 devices x 10 keystrokes stay fast', () => {
  const hay = Array.from({ length: 300 }, (_, i) => `Device ${i} · Vendor ${i % 17} · 192.168.1.${i % 250} aa:bb:cc:00:${(i >> 8).toString(16)}:${(i & 255).toString(16)} 客廳 Mia`);
  const t = Date.now();
  for (const q of ['d', 'de', 'dev', 'devi', 'vend', '192', 'aa:bb', '客', 'mia', 'xyz']) hay.forEach(h => M.fuzzy(q, h));
  assert.ok(Date.now() - t < 500, 'too slow: ' + (Date.now() - t) + ' ms');
});

console.log(checks + ' checks passed');
