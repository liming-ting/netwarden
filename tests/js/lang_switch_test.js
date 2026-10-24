// netwarden - what a language change refreshes (round 10d): LANG_DEPS / langChanged() as
// they are in static/app.js (the block is cut out of the file and evaluated with stand-ins
// for the page's state and loaders, so this tests the shipped list). Run from the repo root:
//     node tests/js/lang_switch_test.js
// It exits non-zero (with the failed check) when something is off.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'netwarden', 'static', 'app.js'), 'utf8');
const start = src.indexOf('const FRESH_PAGES'), end = src.indexOf('// end LANG_DEPS');
assert.ok(start > 0 && end > start, 'LANG_DEPS block not found in app.js');

// one page state -> the loaders a language change calls (name -> times)
async function run(state) {
  const calls = {};
  const hit = name => () => { calls[name] = (calls[name] || 0) + 1; return Promise.resolve(); };
  const S = Object.assign({ base: 'overview', route: { name: 'overview' }, meta: { remote: false }, ai: { s: null },
                            since: { r: null }, push: { ed: null, logOpen: null }, pal: { open: false }, keys: { open: false },
                            look: {} }, state);
  const env = { S, drawerOpen: () => !!state.drawer, loadLookup: hit('lookup'), loadChoices: hit('choices'),
                refresh: hit('refresh'), sinceLoad: hit('since'), loadAI: hit('settings'), loadPair: hit('pair'),
                loadSetup: hit('setup'), loadTuning: hit('tuning'), loadPush: hit('push'), pushLogLoad: hit('pushlog'),
                pushPreview: hit('preview'), renderPalette: hit('palette'), keysBody: hit('keys'), relabelToasts: hit('toasts') };
  // eslint-disable-next-line no-new-func
  const f = new Function(...Object.keys(env), src.slice(start, end) + '\nreturn { langChanged, LANG_DEPS };');
  const M = f(...Object.values(env));
  M.langChanged();
  await new Promise(r => setTimeout(r, 0));   // the settings list's .then()
  return { calls, M };
}

let checks = 0;
async function check(name, fn) { await fn(); checks++; console.log('ok  ' + name); }

(async () => {
  await check('the Overview: the datasets, the pickers, the toasts - nothing more', async () => {
    const { calls } = await run({});
    assert.deepStrictEqual(Object.keys(calls).sort(), ['choices', 'refresh', 'toasts']);
  });

  await check('a settings list kept from the Settings page is fetched again (the palette reads it)', async () => {
    const { calls } = await run({ ai: { s: { items: [] } }, pal: { open: true } });
    assert.strictEqual(calls.settings, 1);
    assert.strictEqual(calls.palette, 2);   // at once, and again when the new list lands
  });

  await check('a viewer on another device never asks for settings', async () => {
    const { calls } = await run({ meta: { remote: true }, ai: { s: { items: [] } }, base: 'settings' });
    assert.ok(!calls.settings);
  });

  await check('the Settings page: its own lists, an open delivery log, an open preview', async () => {
    const { calls } = await run({ base: 'settings', push: { ed: { type: 'ntfy' }, logOpen: 3 } });
    for (const k of ['settings', 'pair', 'tuning', 'push', 'pushlog', 'preview']) assert.strictEqual(calls[k], 1, k);
    assert.ok(!calls.setup);
  });

  await check('the first-run wizard and the System page', async () => {
    const w = (await run({ base: 'welcome' })).calls, s = (await run({ base: 'system' })).calls;
    assert.strictEqual(w.setup, 1); assert.strictEqual(w.settings, 1);
    assert.ok(!s.setup); assert.strictEqual(s.pair, 1);
  });

  await check('an open service / domain drawer, the "since" banner, the shortcuts sheet', async () => {
    const { calls } = await run({ drawer: true, route: { name: 'domain', arg: 'example.com' }, since: { r: {} }, keys: { open: true } });
    assert.strictEqual(calls.lookup, 1); assert.strictEqual(calls.since, 1); assert.strictEqual(calls.keys, 1);
    const dev = (await run({ drawer: true, route: { name: 'device', arg: 'aa:bb' } })).calls;
    assert.ok(!dev.lookup);   // a device drawer comes with refresh()
  });

  await check('no request storm: every source at most once, whatever is open', async () => {
    const { calls } = await run({ base: 'settings', drawer: true, route: { name: 'service', arg: 'x' }, ai: { s: {} },
                                  since: { r: {} }, push: { ed: {}, logOpen: 1 }, pal: { open: true }, keys: { open: true } });
    for (const [k, v] of Object.entries(calls)) assert.ok(v <= (k === 'palette' ? 2 : 1), k + ' x' + v);
  });

  await check('every entry is [what, when, how]', async () => {
    const { M } = await run({});
    assert.ok(M.LANG_DEPS.length >= 10);
    for (const e of M.LANG_DEPS) assert.ok(typeof e[0] === 'string' && typeof e[1] === 'function' && typeof e[2] === 'function');
  });

  console.log(`\n${checks} checks passed`);
})().catch(e => { console.error(e); process.exit(1); });
