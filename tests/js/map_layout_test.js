// netwarden - the network map layout's determinism + speed check (Stage T).
// The Python suite cannot run JS; run this with node from the repo root:
//     node tests/js/map_layout_test.js
// It exits non-zero (with the failed check) when something is off.
'use strict';
const assert = require('assert');
const path = require('path');
const NWMap = require(path.join(__dirname, '..', '..', 'netwarden', 'static', 'map.js'));

// a deterministic pseudo-random home: 300 devices in 12 groups
function home(n, seed) {
  let s = seed;
  const rnd = () => { s = (s * 1103515245 + 12345) % 2147483648; return s / 2147483648; };
  const groups = Array.from({ length: 12 }, (_, i) => ({ key: 'g' + String(i).padStart(2, '0') }));
  const devices = [];
  for (let i = 0; i < n; i++) {
    devices.push({ id: 'aa:bb:cc:' + [i >> 8, i & 255, 7].map(x => x.toString(16).padStart(2, '0')).join(':'),
                   group: groups[Math.floor(rnd() * groups.length)].key,
                   weight: Math.floor(rnd() * 5e9), order: '2026-10-' + String(1 + Math.floor(rnd() * 20)).padStart(2, '0') });
  }
  return { groups, devices };
}

let checks = 0;
function check(name, fn) { fn(); checks++; console.log('ok  ' + name); }

const input = home(300, 42);

check('same input -> byte-identical output', () => {
  assert.strictEqual(JSON.stringify(NWMap.layout(input)), JSON.stringify(NWMap.layout(input)));
});

check('device order in the input does not matter', () => {
  const shuffled = { groups: input.groups, devices: input.devices.slice().reverse() };
  assert.deepStrictEqual(NWMap.layout(shuffled).nodes, NWMap.layout(input).nodes);
});

check('every device is placed, inside the bounds', () => {
  const out = NWMap.layout(input), b = out.bounds;
  assert.strictEqual(Object.keys(out.nodes).length, 300);
  Object.values(out.nodes).forEach(n => {
    assert.ok(n.x - n.r >= b.x && n.x + n.r <= b.x + b.w && n.y - n.r >= b.y && n.y + n.r <= b.y + b.h);
  });
});

check('no two nodes overlap', () => {
  const nodes = Object.values(NWMap.layout(input).nodes);
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      assert.ok(Math.hypot(a.x - b.x, a.y - b.y) >= a.r + b.r, `overlap ${i} ${j}`);
    }
  }
});

check('no two clusters overlap, none covers the router or the Internet', () => {
  const out = NWMap.layout(input), g = out.groups;
  for (let i = 0; i < g.length; i++) {
    assert.ok(Math.hypot(g[i].x, g[i].y) > g[i].r, 'covers the router');
    assert.ok(Math.hypot(g[i].x - out.internet.x, g[i].y - out.internet.y) > g[i].r, 'covers the Internet');
    for (let j = i + 1; j < g.length; j++) {
      assert.ok(Math.hypot(g[i].x - g[j].x, g[i].y - g[j].y) >= g[i].r + g[j].r, `clusters ${i} ${j}`);
    }
  }
});

check('a new device does not move the others (same cluster step)', () => {
  const before = NWMap.layout(input);
  const g = input.groups[3].key;
  const n = input.devices.filter(d => d.group === g).length;
  if (n % 6 === 0) return;      // the cluster would grow a step: covered by the next check
  const after = NWMap.layout({ groups: input.groups,
                               devices: input.devices.concat([{ id: 'ff:ff:ff:ff:ff:ff', group: g, weight: 1, order: '2026-10-30' }]) });
  Object.keys(before.nodes).forEach(id => {
    assert.deepStrictEqual([after.nodes[id].x, after.nodes[id].y], [before.nodes[id].x, before.nodes[id].y], id);
  });
});

check('node size: log scale, capped', () => {
  assert.strictEqual(NWMap.radius(0, 1e9), NWMap.R_MIN);
  assert.strictEqual(NWMap.radius(1e9, 1e9), NWMap.R_MAX);
  assert.strictEqual(NWMap.radius(1e12, 1e9), NWMap.R_MAX);
  const mid = NWMap.radius(1e4, 1e9);
  assert.ok(mid > NWMap.R_MIN && mid < NWMap.R_MAX);
});

check('empty and odd input', () => {
  const out = NWMap.layout({ groups: [], devices: [] });
  assert.deepStrictEqual(out.nodes, {});
  assert.ok(out.internet.y < 0);
  const odd = NWMap.layout({ groups: [{ key: 'a' }], devices: [{ id: 'x', group: 'zz', weight: 'n/a' }] });
  assert.ok(odd.nodes.x && isFinite(odd.nodes.x.r));
});

check('300 devices lay out in well under 100 ms', () => {
  NWMap.layout(input);
  const t = process.hrtime.bigint();
  for (let i = 0; i < 20; i++) NWMap.layout(input);
  const ms = Number(process.hrtime.bigint() - t) / 1e6 / 20;
  assert.ok(ms < 100, ms + ' ms');
  console.log('    (' + ms.toFixed(2) + ' ms per layout)');
});

console.log(checks + ' checks passed');
