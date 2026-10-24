// netwarden - the chat's tiny markdown (round 10c): md() as it is in static/app.js (the
// block is cut out of the file and evaluated, so this tests the shipped code). Run from the
// repo root:
//     node tests/js/chat_md_test.js
// It exits non-zero (with the failed check) when something is off.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'netwarden', 'static', 'app.js'), 'utf8');
const start = src.indexOf('class Html'), end = src.indexOf('const enc = encodeURIComponent');
assert.ok(start > 0 && end > start, 'md() block not found in app.js');
// eslint-disable-next-line no-new-func
const md = new Function(src.slice(start, end) + '\nreturn t => md(t).toString();')();

let checks = 0;
function check(name, fn) { fn(); checks++; console.log('ok  ' + name); }

check('the screen-time note renders as emphasis, not underscores', () => {
  assert.strictEqual(md('_Estimates from DNS lookups, for family conversations - not surveillance._'),
    '<em>Estimates from DNS lookups, for family conversations - not surveillance.</em>');
  assert.strictEqual(md('_依 DNS 查詢估算,供家人溝通參考,不是監控。_'), '<em>依 DNS 查詢估算,供家人溝通參考,不是監控。</em>');
  assert.strictEqual(md('a *quiet* night'), 'a <em>quiet</em> night');
});

check('bold, bullets and code are unchanged', () => {
  assert.strictEqual(md('**Offline mode** - x'), '<strong>Offline mode</strong> - x');
  assert.strictEqual(md('- one\n* two'), '• one<br>• two');
  assert.strictEqual(md('`secu100.net`'), '<code>secu100.net</code>');
});

check('snake_case, lone stars and mismatched markers stay text', () => {
  assert.strictEqual(md('top_domains and svc_name_x'), 'top_domains and svc_name_x');
  assert.strictEqual(md('2 * 3 * 4'), '2 * 3 * 4');
  assert.strictEqual(md('_open* text'), '_open* text');
  assert.strictEqual(md('file_name_'), 'file_name_');
});

check('emphasis can never carry markup in', () => {
  assert.strictEqual(md('_<img src=x onerror=alert(1)>_'), '<em>&lt;img src=x onerror=alert(1)&gt;</em>');
});

console.log(checks + ' checks passed');
