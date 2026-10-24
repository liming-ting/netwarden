# Static live demo (round 9 W)

The live demo on GitHub Pages is the real dashboard on the made-up demo home, served as
plain files. Nothing in the frontend is forked: `scripts/build_static_demo.py` asks the real
server for every answer the page needs and saves it; `static/app.js` reads those files when
the page says it is the static demo.

```bash
python3 scripts/build_static_demo.py --out /tmp/nw_site                 # all 12 languages, ~15 MB, ~25 s
python3 scripts/build_static_demo.py --out /tmp/nw_site --langs en,zh-Hant --quick   # a small one
# look at it under a sub-path, as Pages serves it:
mkdir -p /tmp/nw_root && cp -r /tmp/nw_site /tmp/nw_root/netwarden
python3 -m http.server 8799 --bind 127.0.0.1 --directory /tmp/nw_root   # http://127.0.0.1:8799/netwarden/
```

## How the build works

1. `demo.build()` seeds a fresh demo home in a temp dir (never `data/demo.db` or
   `data/netwarden.db`), with "now" = the wall clock floored to the minute, in the demo's
   zone (Asia/Taipei) - one home per HOUSEHOLD (round 10b): the family's names, rooms,
   bedtime rule and announced device names are user text, so they follow the language
   through `demo.HOUSEHOLDS` / `demo.household_for()`: zh-Hant and zh-Hans get the
   Chinese family in their own script, every other language the English-speaking one
   (Dad, Mom, Kid; Living room, Kid's room, ...). Same `now`, same RNG: the same story,
   MACs and ids. The built-in demo (`data/demo.db`) stays the Taiwanese household; a DB
   keeps the household it was first seeded with (meta `demo_household`).
2. `web.make_server()` serves each home on an ephemeral 127.0.0.1 port inside the build
   process, with `NETWARDEN_OFFLINE_AI=1`, and its languages are crawled from it. The build
   refuses to go on unless `/api/meta` says `demo: true` and `ai_mode: "offline"`.
3. The crawl: `/api/meta`, every page in `PAGES`, every person, every device drawer
   (`DEVICE_GETS`), the service and domain drawers the answers link to (followed until
   nothing new, up to `MAX_LOOKUPS`), the report at its shareable (4 name/people choices)
   and minimal levels for 7 and 30 days in HTML and Markdown, the exports and the weekly
   family report - then the same list in every other language.
4. The assistant: the insight, the suggested questions (`/api/ai/questions` and the chat's
   own `app.ai.s1..s3`) and the follow-ups the offline answers suggest, up to
   `MAX_ANSWERS` per language, plus (round 10b) every saved device's answer to its drawer's
   pre-filled "Ask AI about this device" question (`device_chat_name()`, sent with the
   device as focus). Each raw SSE stream is saved as it came.
5. Post-processing - the only places where saved answers differ from the server's:
   - `/api/meta`: `db_id` = `static-demo`, no `browser_lang`, plus `static_demo`
     (`built_at`, install and source links);
   - `/api/pair/sessions`: describes the machine it runs on, so its LAN URL becomes the
     demo's (`DEMO_LAN_URL`) and the WSL firewall lines are dropped;
   - HTML answers: root-absolute `src` / `href` made relative (`relative_static`);
   - `static/manifest.webmanifest` (`demo_manifest()`): `"id"` = the site's path
     (`/netwarden/`). An id resolves against the ORIGIN, so the source manifest has none -
     it then defaults to `start_url` (`../` from the manifest: `/` at the root of the real
     app's own origin, the ingress base under Home Assistant) - and `"id": "/"` would have
     claimed all of `liming-ting.github.io`.
6. `index.html` = `web.index_html("")` with relative asset URLs, `data-static-demo="1"`,
   `static/demo.js`, a CSP meta tag (`default-src 'none'`; scripts, styles, images and
   `connect-src` from `'self'` only - no other host can be reached), a description and
   Open Graph / Twitter card tags (`og-image.png` = `docs/images/social-preview.png`, 1280x640,
   absolute URL from `--site-url`), and `.nojekyll`.
7. `privacy_scan()` before anything is written: the temp dir and DB path, the home
   directory, any home-directory-looking path, the build machine's own IP addresses
   (minus loopback and the demo's 192.168.1.0/24). It names the file, line and category,
   never the value. `_write()` replaces only an empty directory or an earlier build.

## Request -> file

`NWDemo.file(request, pageLang)` (`static/demo.js`) and `static_name()` (the builder) are
the same function, pinned by `tests/fixtures/static_demo_names.json` (checked from Python
and from node, `tests/js/static_demo_test.js`):

- `demo-data/<lang>/<path>[.q<fnv1a32(sorted query)>]<ext>`; `lang` from `?lang=` (else
  the page's, else zh-Hant); `lang`, `accept` and `inline` are not part of the name.
- `/api/meta` has no language; `.csv` / `.md` paths keep their name; `/report/weekly` is
  `.html`; `/api/report` is `.html` or `.txt` (Markdown, so a static host shows it as
  text) and ignores `names` / `people` unless the level is shareable.
- Assistant answers: `demo-data/<lang>/chat/<fnv1a32(mode + "\n" + question)>.txt`;
  a device's answer is mode `device` + its MAC (`NWDemo.chatFile('device', mac, lang)`);
  `chat/index.json` lists what has an answer (`suggested`, `answers`, `insight`, `devices`).

A new GET in app.js that the builder does not fetch is a 404 in the demo: add it to
`PAGES` or `DEVICE_GETS` (or to the crawl) when you add it to the page.

## Demo mode in app.js

`const DEMO` is true only when `<html data-static-demo="1">` AND `window.NWDemo` exists -
only the static build's index.html has either. In the real app nothing changes (tests:
`RealAppUnchanged` in tests/test_round9_w.py). In DEMO:

- `url()` maps `/api/...` and `/report/...` to files; `postJSON()` throws a "demo" error
  before any request, shown as an info toast (`app.demo.readonly` / `needs_install` /
  `full_report`); click / submit / change guards keep buttons from looking broken.
- The chat answers only questions in `chat/index.json` (from the saved stream, through the
  same reader as a live answer); others get the `app.demo.chat_only` note. "Ask AI about
  this device" -> Ask: when the question is still exactly the pre-filled one, the device's
  own answer (looked up by MAC, so the page needs no copy of the name in the text).
  Round 10c: the standing chips (`app.ai.s1..s3`) have intent answers of their own
  (`ai_intents.STANDING`: alerts / new devices + changes / night), saved like the others.
- Language switch (round 10c, real app too): the page holds ONE copy of the data, so the
  ETags are per dataset (`lastTag[k]`) and `setLang()` forgets them all (`forgetTags()`):
  a static host's 304 for `en/overview.json` can never keep the other language's data on
  screen. Earlier chat messages keep their language (`m.lang`) under `app.chat.other_lang`.
  A `refresh()` that was running when the language changed (e.g. awaiting an open
  drawer's `loadDevice`) checks `lang !== S.lang` at its end and runs again.
- Offline answers end with a "tap one" heading (`offline.try_these`) when they carry
  chips: on the `suggest` SSE event the page moves that last paragraph into `m.sugHead`
  and shows it only with the chips (hidden for other-language messages / filtered demo
  chips). Counts go through `i18n.tn` - suggestions too (`sug.<kind>.*_one` carry `{n}`).
  The health intent leads with the outages of the asked window (`intent.health_had_outages`),
  then "Right now" = the Network health page's own 24 h verdict (`intent.health_now`), so
  "All good" never sits above a list of outages and the numbers are the page's.
- The assistant's subtitle is `app.demo.ai_mode` ("demo: saved answers, no AI is
  called"), never the real app's "chosen with --offline-ai".
- A 404 without a message reads `app.demo.not_found` ("not part of the demo") with a
  "Back to the overview" link (`demoBack()`); the real app says `err.not_found`, never
  "Server error (HTTP 404)" (`httpMsg()`).
- First visit: `demoWelcome()` on top of Overview - what this is, three findings taken
  from the home's own alerts (threat, DNS bypass, night activity) and the install link;
  dismissed for good in `localStorage` (`netwarden.demo.welcome_hidden`).
- Off: the live stream, periodic refresh, "since your last visit", the service worker,
  palette server search, the clock-skew notice. "Now" is `static_demo.built_at`.
- The report page never offers the full level; downloads get a proper file name.
- The banner (`demoBar()`, all 12 languages) can be hidden for the session.

## Publishing

`.github/workflows/pages.yml`, manual only (`workflow_dispatch`): build job (contents +
pages read; `configure-pages` gives the site URL for the og tags; size check < 20 MB;
`upload-pages-artifact` with hidden files for `.nojekyll`), deploy job (`pages: write`,
`id-token: write`, environment `github-pages`). The steps to switch it on are in the
internal release checklist; the README link is added only after the first deploy works.
