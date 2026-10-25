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
                            look: {}, fam: { st: null }, ppl: { r: null }, set: { errs: {}, tests: {} }, confirm: { open: false } }, state);
  const env = { S, drawerOpen: () => !!state.drawer, loadLookup: hit('lookup'), loadChoices: hit('choices'),
                refresh: hit('refresh'), sinceLoad: hit('since'), loadAI: hit('settings'), loadPair: hit('pair'),
                loadSetup: hit('setup'), loadTuning: hit('tuning'), loadPush: hit('push'), pushLogLoad: hit('pushlog'),
                pushPreview: hit('preview'), renderPalette: hit('palette'), keysBody: hit('keys'), relabelToasts: hit('toasts'),
                tuneSheet: hit('tunesheet'), closeConfirm: hit('closeconfirm'), bedPreview: hit('bedpreview'),
                reloadPreview: hit('aipreview') };
  // eslint-disable-next-line no-new-func
  const f = new Function(...Object.keys(env), src.slice(start, end) + '\nreturn { langChanged, LANG_DEPS, LANG_NEUTRAL };');
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

  await check('a page\'s data kept after leaving it is forgotten; the page on screen keeps its own', async () => {
    const kept = () => ({ fam: { st: { x: 1 }, wk: {}, bed: {}, form: { name: 'draft' } }, ppl: { r: { people: [] }, det: {}, q: 'typed' },
                          ai: { s: null, test: { ok: false, error_text: 'old' } }, set: { errs: { a: 'old' }, tests: { adguard: {} } } });
    const st = kept(); await run(st);   // (run() works on the state object it is given)
    assert.strictEqual(st.fam.st, null); assert.strictEqual(st.ppl.r, null); assert.strictEqual(st.ppl.det, null);
    assert.strictEqual(st.fam.form.name, 'draft'); assert.strictEqual(st.ppl.q, 'typed');   // the user's typing stays
    assert.strictEqual(st.ai.test, null); assert.deepStrictEqual(st.set.errs, {}); assert.deepStrictEqual(st.set.tests, {});
    const onFam = Object.assign(kept(), { base: 'family' }); await run(onFam);
    assert.ok(onFam.fam.st);   // refresh() loads the open page again; nothing blank meanwhile
    const onPpl = Object.assign(kept(), { base: 'people' }); await run(onPpl);
    assert.ok(onPpl.ppl.r);
  });

  await check('an open sheet: the tuning sheet is drawn again, a question is closed', async () => {
    assert.strictEqual((await run({ confirm: { open: true, tune: { kind: 'night' } } })).calls.tunesheet, 1);
    const q = (await run({ confirm: { open: true, title: 'Sure?' } })).calls;
    assert.strictEqual(q.closeconfirm, 1); assert.ok(!q.tunesheet);
    assert.ok(!(await run({})).calls.closeconfirm);
  });

  await check('an open rule draft and an open AI preview are asked again (server texts)', async () => {
    const st = { fam: { st: null, form: { name: 'draft', target: 'mac:aa' }, prev: { key: 'k', r: { text: 'old' } } } };
    const c = (await run(st)).calls;
    assert.strictEqual(c.bedpreview, 1); assert.deepStrictEqual(st.fam.prev, {});   // the old words never linger
    assert.strictEqual(st.fam.form.name, 'draft');
    assert.strictEqual((await run({ ai: { s: null, prev: { open: true } } })).calls.aipreview, 1);
    const none = (await run({ ai: { s: null, prev: { open: false } } })).calls;
    assert.ok(!none.aipreview && !none.bedpreview);
  });

  await check('every part of S is kept current by a row or listed as holding no translated text', async () => {
    // the state object as app.js declares it (cut out and evaluated)
    const s0 = src.indexOf('const S = {'), s1 = src.indexOf('\n};\n', s0);
    assert.ok(s0 > 0 && s1 > s0, 'const S not found in app.js');
    // eslint-disable-next-line no-new-func
    const S = new Function(src.slice(s0, s1) + '\n};\nreturn S;')();
    const { M } = await run({});
    const covered = new Set(M.LANG_DEPS.flatMap(e => e[3] || []));
    const neutral = new Set(Object.keys(M.LANG_NEUTRAL).flatMap(k => k.split(' ')));
    for (const p of covered) assert.ok(!neutral.has(p), p + ' is both kept current and "neutral"');
    const known = p => covered.has(p) || neutral.has(p);
    const missing = [];
    for (const [k, v] of Object.entries(S)) {
      if (known(k)) continue;
      const sub = v && typeof v === 'object' && !(v instanceof Set) && !Array.isArray(v) ? Object.keys(v) : null;
      // an object may be split per field (ai.s kept current, ai.form neutral) - then every field must be named
      if (sub && sub.length && [...covered, ...neutral].some(p => p.startsWith(k + '.'))) {
        sub.filter(f => !known(k + '.' + f)).forEach(f => missing.push(k + '.' + f));
      } else missing.push(k);
    }
    assert.deepStrictEqual(missing, [], 'add these to a LANG_DEPS row (4th column) or to LANG_NEUTRAL: ' + missing.join(', '));
    for (const [k, why] of Object.entries(M.LANG_NEUTRAL)) assert.ok(String(why).trim(), k);
    for (const p of [...covered, ...neutral]) assert.ok(p.split('.')[0] in S, p + ' is not part of S');
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
    for (const e of M.LANG_DEPS) assert.ok(typeof e[0] === 'string' && typeof e[1] === 'function' && typeof e[2] === 'function'
                                           && Array.isArray(e[3]) && e[3].length, e[0]);
  });

  console.log(`\n${checks} checks passed`);
})().catch(e => { console.error(e); process.exit(1); });
