/* netwarden - map.js: the network map's layout (Stage T). A PURE function, no DOM.
 *
 *   NWMap.layout({ groups: [{ key }], devices: [{ id, group, weight, order }] })
 *     -> { internet, router, groups: [{ key, x, y, r, lx, ly, anchor }],
 *          nodes: { id: { x, y, r, group } }, bounds: { x, y, w, h } }
 *
 * Radial clusters: the router in the middle, the Internet and one cluster per group on a
 * ring around it (the Internet always at the top), each cluster's devices on a sunflower
 * spiral around its centre. Deterministic: the same input gives the same output, byte
 * for byte, and nothing depends on input order except where the caller says so - groups
 * keep the order given, devices are placed by (order, id) inside their group. A new
 * device sorts by its `order` (the page uses first_seen), so it lands on the next free
 * spot of its spiral and the others stay where they were; ring and cluster sizes grow
 * in steps (CAP_STEP) for the same reason. Node radius = traffic on a log scale, capped.
 *
 * Loaded by the dashboard (window.NWMap) and by node for the determinism check
 * (module.exports): tests/js/map_layout_test.js.
 */
'use strict';
(function (root) {
  const R_MIN = 7, R_MAX = 17;        // node radius range (px at zoom 1)
  const GAP = 8;                      // free space between two nodes
  const SPIRAL = 0.62;                // sunflower spacing factor (no overlaps at R_MAX)
  const GOLDEN = Math.PI * (3 - Math.sqrt(5));
  const CAP_STEP = 6;                 // cluster sizes grow in steps of this many devices
  const LABEL = 26;                   // room for a cluster's label outside it
  const RING_MIN = 170;               // the smallest ring radius
  const INTERNET_R = 34;              // the Internet's slot on the ring

  const round = v => Math.round(v * 10) / 10;

  // radius from a non-negative weight (bytes or lookups) on a log scale, capped at `cap`
  function radius(weight, cap) {
    const w = Math.max(0, +weight || 0), c = Math.max(1, +cap || 1);
    const f = Math.min(1, Math.log10(1 + w) / Math.log10(1 + c));
    return round(R_MIN + (R_MAX - R_MIN) * (isFinite(f) ? f : 0));
  }

  function cmp(a, b) {
    const x = String(a.order == null ? '' : a.order), y = String(b.order == null ? '' : b.order);
    if (x !== y) return x < y ? -1 : 1;
    return String(a.id) < String(b.id) ? -1 : (String(a.id) > String(b.id) ? 1 : 0);
  }

  // offset of spiral slot k from its cluster centre
  function slot(k) {
    const step = (2 * R_MAX + GAP) * SPIRAL;
    const rho = step * Math.sqrt(k + 0.5);
    const a = k * GOLDEN;
    return [rho * Math.cos(a), rho * Math.sin(a)];
  }

  function clusterRadius(n) {
    const cap = Math.max(1, Math.ceil(n / CAP_STEP) * CAP_STEP);
    const step = (2 * R_MAX + GAP) * SPIRAL;
    return round(step * Math.sqrt(cap - 0.5) + R_MAX + GAP);
  }

  function layout(input) {
    const groups = (input && input.groups) || [], devices = (input && input.devices) || [];
    const byGroup = new Map(groups.map(g => [String(g.key), []]));
    const cap = devices.reduce((m, d) => Math.max(m, +d.weight || 0), 0);
    devices.forEach(d => {
      const k = String(d.group);
      if (!byGroup.has(k)) byGroup.set(k, []);   // a group the caller forgot: still placed (last)
      byGroup.get(k).push(d);
    });
    const keys = Array.from(byGroup.keys()).filter(k => byGroup.get(k).length);
    const sizes = keys.map(k => clusterRadius(byGroup.get(k).length));
    // the ring: the Internet's slot + every cluster's diameter + a margin, end to end
    const span = [2 * INTERNET_R + 2 * LABEL].concat(sizes.map(r => 2 * r + 2 * LABEL));
    const circ = span.reduce((a, b) => a + b, 0);
    const maxR = sizes.reduce((a, b) => Math.max(a, b), 0);
    const ring = round(Math.max(RING_MIN, circ / (2 * Math.PI), maxR + 90));
    const out = { internet: null, router: { x: 0, y: 0 }, groups: [], nodes: {}, ring };
    let at = -span[0] / 2;                        // the Internet's slot is centred at the top
    span.forEach((len, i) => {
      const mid = at + len / 2, angle = -Math.PI / 2 + 2 * Math.PI * (mid / circ);
      at += len;
      const cx = round(ring * Math.cos(angle)), cy = round(ring * Math.sin(angle));
      if (i === 0) { out.internet = { x: 0, y: round(-ring) }; return; }
      const key = keys[i - 1], r = sizes[i - 1];
      const ux = Math.cos(angle), uy = Math.sin(angle);
      out.groups.push({ key, x: cx, y: cy, r, angle: round(angle * 1000) / 1000,
                        lx: round(cx + ux * (r + 14)), ly: round(cy + uy * (r + 14) + (uy > 0.3 ? 8 : 0)),
                        anchor: Math.abs(ux) < 0.35 ? 'middle' : (ux > 0 ? 'start' : 'end') });
      byGroup.get(key).slice().sort(cmp).forEach((d, k) => {
        const [dx, dy] = slot(k);
        out.nodes[d.id] = { x: round(cx + dx), y: round(cy + dy), r: radius(d.weight, cap), group: key };
      });
    });
    let x0 = -60, y0 = out.internet.y - 60, x1 = 60, y1 = 60;
    out.groups.forEach(g => {
      x0 = Math.min(x0, g.x - g.r - 120); x1 = Math.max(x1, g.x + g.r + 120);
      y0 = Math.min(y0, g.y - g.r - 40); y1 = Math.max(y1, g.y + g.r + 40);
    });
    out.bounds = { x: round(x0), y: round(y0), w: round(x1 - x0), h: round(y1 - y0) };
    return out;
  }

  const api = { layout, radius, R_MIN, R_MAX };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.NWMap = api;
})(typeof window !== 'undefined' ? window : this);
