# Stage G - accessibility and graceful degradation

Target: **WCAG 2.2 AA** for the dashboard (`static/`), the pairing page (`/pair`), the
offline page and the printable weekly report. Also: every failure the page can meet has a
plain, localized state with a way out. Tests: `tests/test_stage_g.py`.

## How it was audited

- **Browser:** chrome-devtools on a test server (127.0.0.1:8799, `--offline-ai`, a copy of
  the demo DB, the perf DB (300 devices) and a stress DB (50 people with long, RTL,
  emoji and `<script>` names; 60-character labels)). Port 8787 was never touched.
- **Lighthouse accessibility (snapshot mode).** Run on overview, inbox, devices, the
  device drawer, map, people, family, health, privacy (phone, chat sheet open), AI,
  settings and welcome, on desktop 1280 px and phone 375 px. All score **100** after the
  fixes below. The only remaining Lighthouse failure is SEO `meta-description`, which
  doesn't matter for a local app.
- **Accessibility-tree scripts** (`evaluate_script`), run on every route and the drawer in
  **all 12 languages**:
  - every visible control has an accessible name;
  - `<html lang>` equals the selected language;
  - no raw locale key (`app.x.y`) leaks into the page.
- **Overflow scripts** (any element past the viewport, document `scrollWidth`):
  - at 375 px in all 12 languages, light and dark, with the stress and perf DBs;
  - at 640×400 (1280×800 at 200 % zoom);
  - with the WCAG 1.4.12 text-spacing bookmarklet values (line-height 1.5, paragraph
    spacing 2em, letter-spacing 0.12em, word-spacing 0.16em).
- **Keyboard by hand:** Tab and Shift+Tab, Esc, arrow keys in menus, focus return after
  closing the drawer, chat sheet, shortcuts sheet and More menu.
- **Emulation:** `prefers-reduced-motion: reduce`, Slow 3G, a stopped and restarted server,
  faked `/api/meta` and `/api/overview` failures (503), and a browser clock 3 h off.

## Contrast (computed from the CSS variables; `ContrastTests` keeps it so)

| pair | light | dark |
|---|---|---|
| `--fg` on `--bg` / `--surface` / `--surface-2` | 16.45 / 17.79 / 15.86 | 15.81 / 14.60 / 13.52 |
| `--mut` on the same | 5.54 / 5.99 / 5.34 | 7.60 / 7.03 / 6.51 |
| `--faint` on the same | 4.77 / 5.15 / 4.60 | 6.01 / 5.55 / 5.14 |
| `--acc` (links) on the same | 5.70 / 6.16 / 5.49 | 7.85 / 7.25 / 6.71 |
| `--ok` / `--warn` / `--bad` on `--surface` | 6.01 / 5.72 / 5.70 | 9.49 / 10.29 / 6.92 |
| status text on its soft tag (`--ok-soft` ...) | ok 5.26, warn 5.12, bad 4.82 | 7.77, 8.60, 6.20 |
| `--acc-fg` on `--acc` (primary button) | 6.16 | 7.89 |
| `--on-bad` on `--bad`, `--on-ok` on `--ok` (counts, danger, toasts) | 5.70, 6.01 | 7.62, 9.26 |
| `--line-ctl` (input / switch borders, 1.4.11) on `--surface` / `--bg` | 3.63 / 3.36 | 3.85 / 4.17 |

Avatar colours are all at least 4.97:1 with their white initials. `--faint` on
`--surface-3` is 4.47 in dark, but no text uses that pair (surface-3 is only for
skeletons and hover fills).

## Fixes

**Perceivable**
- **Tokens:**
  - darker `--faint` (light) and lighter `--faint` (dark);
  - darker light `--ok` / `--warn`;
  - new `--line-ctl` for control borders;
  - new `--on-bad` / `--on-ok` instead of `#fff` on status fills (white on the light
    dark-theme `--bad` / `--ok` fills was far below 4.5:1).
  - The `--focus` ring is solid `--acc`.
- **Status is never colour alone.** Each is paired with an icon, a word or a shape:
  - Live indicator: a dot when live, a hollow ring when reconnecting, a bar when paused.
    The word stays for screen readers on phones (visually hidden, not `display:none`).
  - Tags carry icons; inbox severity has a word.
- **Live regions are quiet.** `#say` (polite) and `#shout` (`role=alert`) are the only
  announcers, through `speak()`. Toasts are a labelled region (`app.toasts_label`) with no
  role of their own, so nothing is read twice. While data loads, `#main` has
  `aria-busy=true` and the skeleton has one `role=status` line.
- **Headings:**
  - The tab title follows the page (`<page heading> - netwarden`, WCAG 2.4.2).
  - Health has one `h1` (the hero verdict is an `h2`).
  - The Settings connection table has `th scope=col/row` (Lighthouse `td-has-header`).
- **Map (2.5.3 label in name):** the router's port badge was moved out of its link, so the
  link's name starts with its visible text.

**Operable**
- **Dialogs:**
  - The drawer and the chat panel are `<div role=dialog>`, not `<aside>`.
  - Opening the drawer focuses its close button. `focusSoon()` retries while the drawer
    is still `visibility:hidden` mid-transition; before, focus silently stayed behind.
  - Tab is trapped inside the drawer, and Esc closes it and returns focus to the opener.
  - On phones the chat is a modal bottom sheet: `aria-modal=true` and Tab is trapped. On
    desktop it is a side panel and not modal.
  - Closing the chat returns focus to the opener, or to the AI button.
- **More menu:** ArrowUp/Down/Home/End move between items, Tab closes it, Esc closes it
  and returns focus.
- **Toasts** pause their timer while hovered or focused (2.2.1).
- **Targets (2.5.8):**
  - Buttons use `min-height` instead of a fixed height: `.btn` 36, `.sm` 30, `.icon.xs`
    24, segment and chip 24+.
  - Inline "Why this alert?" / "more" links and `summary` are at least 24 px.
  - On phones `.btn` is **44 px**, and icon buttons and the search and chat buttons are 40 px.
- **Reduced motion:** transitions and the shimmer, spin and pulse animations are off. The
  spinners become static.

**Understandable / robust**
- **No raw errors:**
  - `errText()` maps a network error to `app.offline`, a server error to its (already
    localized) message, and anything else to `err.internal`. It replaced about 15 places
    that showed `e.message`.
  - The server never sends a traceback. A GET that raises gets a localized JSON 500
    (`err.internal`), or 503 (`err.busy`) when SQLite is locked. It is logged through
    `health.sanitize_error`.
- **Long text:** user-text buttons (`Open <name>`, the person link) wrap (`.btn.wrap`).
  Avatars with 3+ initial characters shrink their font (`.av.long`). Nothing overflows
  at 375 px in any language with the stress DB.

## Degradation states

| situation | what the page shows | recovery |
|---|---|---|
| netwarden stops or restarts with the page open | banner `app.offline`; the live mark turns into a hollow ring; old data stays | Retry button; auto-retry every 10 s; refreshes on its own when the live stream says hello |
| netwarden unreachable at first load (index cached or served, `/api/meta` fails) | full-page card in the browser's language (texts ride in `index.html` `#off-texts`, all 12 languages) | Retry; polls every 5 s and reloads when it answers |
| `/offline` (service worker, server down) | unchanged Stage X page | - |
| an API error before any data | card (`role=alert`): title, the localized message, `app.load.auto`, Retry | Retry + auto-retry 10 s |
| part of `/api/overview` fails | `failed: [...]`; banner `app.load.partial`; the other parts still render | Retry; the next refresh fetches everything again (no ETag reuse) |
| Slow network | skeleton + `role=status` "Loading…"; after 6 s a visible "still loading" line | - |
| SQLite busy (a long write / VACUUM) | 503 `err.busy` ("busy, try again in a moment") | auto-retry |
| AdGuard / Pi-hole unreachable, ntopng absent, scanner not running | Stage C status hints (`/api/status` `hints[]`, System page, Overview hero "no data yet") | each hint says what to do; `/api/test/<src>` |
| no DNS data / empty DB | Overview "no data yet" (not "all good"); empty states with a next step; the welcome wizard | the wizard link |
| very large DB | perf DB: `/api/overview` about 80 ms warm; the device list and map stay usable (map has a list alternative) | - |
| browser clock off by more than 5 min | notice `app.clock.skew` ("this device's clock is off by about 3 hours"); relative times use the server clock beyond 1 min | - |
| browser time zone differs from netwarden's | notice `app.clock.tz`; absolute times in netwarden's zone (`/api/meta` `tz`, `tz_offset_min`) | - |
| expired / removed phone session | API 401 `{pair, expired: true}` -> `/pair?expired=1`; pages 303 there; the pair page says "this phone's access has ended - pair again" (`app.pair.session_ended`) | scan a new code |

## Remaining known issues

- **Live indicator:** many tabs open at once can stay "reconnecting". The SSE stream cap
  is 3 per client (Stage T), and the extra tabs fall back to the 30 s refresh. This is by
  design, but the ring doesn't say why.
- **Small inline links:** these rely on the 2.5.8 spacing exception rather than being
  24 px tall: chips in sentences, device names in tables, "see all".
- **Map:** an SVG map can't be made fully usable with a screen reader. Each node is a
  named link, and the **List** view is the equivalent.
- **Day labels** ("Mon", heatmap rows) use the browser's zone. Only absolute date-times
  are shifted to netwarden's zone. The clock notice explains the difference.
- **Time zone mismatch** wasn't browser-emulated, because the DevTools tool has no
  timezone option. It was checked by code and with a shifted browser clock.
- **The "still loading" line** (after 6 s) wasn't seen under Slow 3G: the demo answers
  within 6 s even then. It was checked by code.
- **Boot card:** it appears only when `index.html` itself loads. A browser that never
  reaches the server gets the service worker's `/offline` page, or the browser's own error.
- **Screen readers:** no NVDA / VoiceOver pass was done here. Roles, names and live
  regions were checked through the accessibility tree and Lighthouse only.
- **Printable weekly report and CSV export:** not re-audited beyond contrast. The report
  uses the same tokens.
