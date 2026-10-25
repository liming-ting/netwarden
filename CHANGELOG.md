# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (before 1.0, minor versions may
contain breaking changes).

## [Unreleased]

### Added

- Integration audit against the current AdGuard Home, Pi-hole v6, ntopng and Home
  Assistant documentation (compatibility matrix in `docs/dev/integrations.md`).
- Plain-language connection problems for "Test connection", `netwarden status` and the
  dashboard: untrusted HTTPS certificate, Pi-hole 2FA (use an app password), a Pi-hole v5
  server or v5 API token, no free Pi-hole API session vs. login rate limiting, and a query
  log that is switched off (AdGuard Home) or hidden by Pi-hole's privacy level.
- `ADGUARD_VERIFY_TLS` and `NTOPNG_VERIFY_TLS` (like `PIHOLE_VERIFY_TLS`; certificates are
  verified unless set to 0), `NTOPNG_TOKEN` (ntopng API token instead of user + password),
  and the matching Home Assistant add-on options.
- Pi-hole: a gap longer than Pi-hole's in-memory day is read from its database; sessions
  left behind by a crashed netwarden are ended at the next login (only netwarden's own).
- Command palette (Ctrl+K / Cmd+K or the header search box, also on phones): finds
  devices by name, label, owner, room, vendor, IP or MAC prefix, people, Shared and rooms,
  pages and settings (by label or key); runs actions - mark all alerts read, pause routine
  alerts or one device's alerts for an hour (one Undo), scan now, undo, theme, language,
  single-key shortcuts on/off - and opens the assistant with the typed text (never sent).
  Fuzzy matching ignores case, accents, full-width forms and Traditional/Simplified
  Chinese; recent entries first; grouped WAI-ARIA combobox + listbox. This-computer-only
  actions and settings are not offered to paired phones.
- Shortcuts: `/` focuses the page filter, shortcuts never fire while typing or during IME
  composition, and single-key shortcuts can be switched off (setting `ui.shortcuts` for
  the home, plus a per-browser choice in the shortcuts sheet and System > Preferences).
- The dashboard remembers each page's view (Devices filters and sort, Map filters,
  Suggestions tab, open sections) and puts it in the address (`#/devices?room=...`), so
  links, reload and Back restore it; Back and reload also restore the scroll position.
- Shareable home report (`docs/report.md`): a 7- or 30-day plain-language summary (score
  and its drivers, top suggestions with steps, devices, security and privacy findings,
  network health, notable events) as one self-contained HTML file (inline CSS and SVG, no
  script, no external request, A4/Letter print stylesheet) or Markdown. Privacy levels
  full / shareable (default: no MAC, IP or raw domain; devices by type and people by role
  unless kept) / minimal (score and suggestions). Dashboard page Overview > Report (`g r`,
  palette), `netwarden report --period --privacy --names --people --format --lang --out`,
  and `GET /api/report` (attachment; `inline=1`). Full detail needs admin in LAN mode.
- Static live demo: `scripts/build_static_demo.py --out DIR` turns the real dashboard on
  the made-up demo home into plain files (every page, drawer, report level, export and the
  offline assistant's answers to its suggested questions, in all 12 languages; ~14 MB) that
  work from any sub-path with no server. A dismissible banner says the data is made up and
  links to the install docs and the source; writes, live updates and free-form questions
  explain that they need an install. No external request, cookie or analytics; the output
  is scanned for the build machine's paths and addresses. Open Graph / Twitter card tags
  for link previews. `.github/workflows/pages.yml` (manual only) publishes it on GitHub
  Pages.
- Opt-in push notifications (`docs/notifications.md`): ntfy, Gotify, Home Assistant (URL +
  long-lived token), a JSON webhook with an optional HMAC-SHA256 signature, Discord, Slack,
  Telegram (with a "find my chat id" helper), LINE Messaging API and Matrix. Per channel:
  categories, minimum severity, privacy level (minimal / standard / detailed), language,
  messages per hour (the excess is bundled into one message), an optional daily digest, and
  urgent security alerts during quiet hours. A live preview shows the exact request; secrets
  are write-only and never in an API answer, log, export, report or backup. Persistent
  queue with retries (Retry-After honoured), delivery log, optional pinned certificate,
  redirects never followed. Channels from `NETWARDEN_NOTIFY_<n>_*` environment variables.
  Settings > Notifications, palette entries, `netwarden notify list | test NAME |
  send-digest`, settings `push.digest_time` / `push.weekly_day`, admin-only
  `/api/channels*`. The demo home has two paused example channels and never sends.
  A saved token is only sent to the server it was entered for (changing a channel's host
  asks for it again); below "detailed", every IPv4 / IPv6 / MAC form is masked; each
  delivery has an 8-second total deadline.

### Changed

- Several "While you were asleep" summaries name their night; Enter in a drawer field saves
  and keeps the focus there; Enter in the Devices filter opens the only match.
- README (English and Traditional Chinese) rewritten for newcomers: live demo link, the
  three ways to install with their shortest commands, what you need (and what works
  without AdGuard Home / Pi-hole), a grouped feature list, exactly what can leave your
  network and when, honest limitations. Screenshots refreshed from the current dashboard.
- New `docs/images/social-preview.png` (1280x640), also used as the live demo's
  link-preview image.
- Live demo polish: the made-up family's names, rooms and bedtime rule follow the page
  language (Chinese in Traditional or Simplified script for zh-Hant / zh-Hans, an
  English-speaking family - Dad, Mom, Kid - for every other language) everywhere they
  appear, including alerts, saved answers, reports and exports; the English screenshots
  and the social preview show the English-speaking family. "Ask AI about this device"
  has a saved answer for every demo device; the assistant's header says it is a demo
  with saved answers instead of naming a command-line flag; a first-visit welcome card
  on Overview (dismissible, remembered in the browser) links to three findings and the
  install guide.
- The app's web manifest no longer sets `"id": "/"`: the id now defaults to the start
  URL, which is right at the root of the app's own address, under the Home Assistant
  ingress path and under the live demo's `/netwarden/` path.
- Sizes, percents and milliseconds in server texts (alerts, health, suggestions, offline
  answers, reports, the AI lookups) are written exactly like the dashboard writes them in
  each language: `14,5 Go` in French, `14,5 ГБ` and `12 мс` in Russian, `14 %` in German,
  Spanish, French and Russian. Russian numbers group from 4 digits (`1 234`).
- Russian, French, Spanish, Portuguese and Hindi texts about a device name it as a
  device ("L'appareil ipcam a été actif…") instead of guessing its grammatical gender;
  arrivals and departures read "{name}: возвращение домой" instead of "пришёл(ла)".
- German uses "24 Std." everywhere (the Inbox mixed it with "24 h").
- The device drawer's domain table and the domain drawer say which period they count
  ("Queries (24 h)"; "Lookups: 412 · last 24 h: 58 · …"); the DNS server's statistics on
  Network health say why they can differ from the Overview.

### Fixed

- The demo PC could show a false "DNS blind spot" alert for a few hours each day; the
  computer netwarden runs on is no longer treated as a quiet device.
- A device the router still knows by name (reverse DNS) no longer stays "online" after it
  left: only a sweep, ARP, DNS or the device's own announcements count as being there.
- The bedtime rule preview and the "What the AI will receive" dialog now follow a language
  switch.
- Russian device texts no longer use a masculine verb after a device name ("новые сервисы:",
  "Впервые замечено").
- The `traffic` CLI writes bitrates the language's way ("1,23 Мбит/с", "1,23 Mbit/s"), and
  bedtime nights use local date order ("Пн 19.10", "Mon 10/19").
- Query counts in the device list and the tracker table say "(24 h)"; the Network health
  tile and summary show the same DNS failure rate ("8.2%").
- French "Comment corriger : …" now has its space before the colon.
- The device drawer's Person list followed the first language after a language switch;
  every cached list the page keeps is now refreshed, or known to hold no translated words
  (a test fails when a new one is neither).
- Results and error messages from another page (Family, People, Settings tests) no longer
  stay in the previous language after a switch; an open question is closed.
- The computer netwarden runs on is always online in the device list, the map and the AI
  lookups (when it is identified by one of its own network interfaces, not just by an
  old sweep), and "last seen" uses the newest evidence: the LAN sweep / ARP table, DNS, or
  what the device announced (DHCP, mDNS, SSDP).
- Live demo: every suggested question has a saved answer (including the chips built from
  the home's own alerts, in every language, also in the device drawer); the PC running
  netwarden is online; the AdGuard Home box counts the same lookups as the Overview; the
  camera has a week of steady history; announcement times are never newer than "last
  seen".

- A page or drawer for something that does not exist says "Not found" (in the live demo:
  "not part of the demo", with a link back) instead of "Server error (HTTP 404)".
- Offline mode no longer opens its answer to "Ask AI about this device" with "cannot
  answer free-form questions"; in the live demo the answers say they were saved when the
  site was built instead of "computed on this computer".
- Home Assistant add-on: with the `offline_ai` option on, the assistant and System page
  say offline mode was chosen in the add-on options, not with `--offline-ai`.
- Pi-hole: `PIHOLE_URL` ending in `/admin` or `/api` works; a re-login after HTTP 401
  frees the old session first; queries hidden by the privacy level are no longer stored
  as the domain "hidden".
- ntopng without valid credentials reports "Login refused" instead of "not JSON".
- Internationalized domain names are stored in one (ASCII) form for every source.
- One ingest run reads at most 100,000 queries, so a first run on a very large log
  stays within memory.
- Switching the language and back no longer leaves cards (summaries, names, score,
  next steps, privacy) in the previous language until a reload; open drawers and the
  "since your last visit" card follow the new language too.
- After a language switch the assistant keeps earlier messages as they were, under a note
  saying which language they are in, and hides their old-language follow-up questions.
- Offline mode: "Ask AI about this device" gives the full device profile (risky domains,
  open ports, router port forwards) in every language - in Chinese and Japanese it used to
  list only the top domains; the chat's standing questions ("Which devices are active at
  night?", "What changed this week?", "Which device is the most unusual?") get their own
  answers, the same in every language, instead of the general summary or an unrelated one.
- Offline answers: service names in the answer's language (as in the device drawer),
  "1 more person" / "1 new device" instead of "1 more people" / "device(s)", and the
  screen-time note shown in italics instead of with literal underscores.
- Offline answers: "Was the internet down recently?" names the period its numbers cover
  (the Network health page shows the last 24 h, the answer the last 7 days); "Which device
  is the most unusual right now?" names one device first; night activity lines no longer
  repeat the device name; the "tap one" heading is shown only together with its questions
  (it was left empty after a language switch).
- A language switch while an open device drawer was still loading is no longer lost.
- Suggestions follow each language's singular/plural rule (e.g. Russian "21 устройство").
- A nameless device with a private address is titled in its drawer with the name it
  announces (as in the device list), not its vendor.
- Demo: the made-up internet outage always ends well before the "right now" hour of the
  health card, so it no longer reports most DNS lookups failing right now.
- Every count follows the language's singular/plural rules (CLDR; Russian one/few/many),
  everywhere in the dashboard, answers, alerts, reports, push messages and the CLI: no more
  "1 new devices", "1 personal devices" or hedges like "router forward(s)". Texts with
  several counts read "Devices: 15 · Lookups: 682".
- After a language switch the command palette (Settings results too), open lookups, the
  delivery log, the channel preview, the shortcuts sheet and the Undo buttons change at
  once; each source is fetched once, and only when it is on screen or kept.
- The Network health summary says that its router and DNS figures cover the last 24 hours.
- Offline answers agree with the pages: "Was the internet down recently?" opens with the
  week's outages, then "Right now" with the Network health page's own verdict and numbers
  (it used to say "All good (last 7 days)" above a list of outages, with other DNS
  numbers); "Anything new this week?" lists the week's new devices and labels its behavior
  changes "last 24 h", as the summary does; the summary's headings name their period.
- The suggested question "What did <device> connect to after 23:00?" is offered only for a
  device that had lookups then.
- Language names in the dashboard are written in the dashboard's language; lists use the
  language's separator (Chinese and Japanese 、, also in "Looked up" lines, which keep
  their answer's language after a switch); numbers in server texts use the language's
  decimal mark and digit grouping (e.g. "3,5 мс", "1.234,5").
- The computer netwarden runs on is marked with a "this computer" tag in its language
  instead of an English "(this machine)" in its vendor.
- Russian, French, Portuguese and Hindi texts no longer say "once" for 21, 31, ... (or 0)
  outages or risky lookups: the singular form keeps the number where it covers more than 1.
- The assistant's suggestion chips get on-topic answers, the same in every language:
  "Is the open port 23 on <device> dangerous?" explains that port (it listed the router's
  UPnP forwards), "Who was online around 01:04 at night?" lists that night's activity (in
  Chinese it answered who is home), and the data-usage, tracker, new-device, risky-device
  and "anything unusual" chips no longer depend on the language's keywords.
- "Which device is the most unusual right now?" opens with the same alert total as the
  Overview, then "N more alerts" after that device's own.
- Demo device vendors are brand names only (no English "(robot vacuum)" in other
  languages); weekly highlights and the report's chart text use the language's number
  format and list separator; earlier chat answers keep their "Looked up" heading in their
  own language after a switch.

## [0.1.0] - 2026-10-24

First public release (initial public preview; the date is set when `v0.1.0` is
tagged). Everything below is new.

### Added

- **See:** LAN discovery (ping sweep + TCP knock -> ARP), MAC vendors (optional download of
  the vendor database), randomized-MAC detection, identification via mDNS, SSDP/UPnP,
  NetBIOS, DHCP names and reverse DNS; device types with confidence and a reason; one display
  name per device (your label > hostname > announced name > vendor).
- **Watch:** per-device DNS from AdGuard Home or Pi-hole v6 (read-only); optional bytes per
  device from ntopng; network health (router ping, DNS failures, optional internet probe) with
  an outage log that tells router / ISP / DNS apart.
- **Explain:** alerts (new devices, changes, risky clouds, night activity, DNS blind spots,
  open ports from an opt-in check, UPnP port mappings, large transfers, privacy) with "Why
  this alert?"; privacy grades A-F with copyable AdGuard / Pi-hole rules; a 0-100 home score
  with suggestions; screen-time estimates, notify-only bedtime rules and a printable weekly
  family report; people and opt-in presence ("who's home").
- **Assistant:** Anthropic (cloud), any OpenAI-compatible server (Ollama, LM Studio, ...) or a
  deterministic offline mode; read-only lookup tools; redaction of names, owners, rooms, MACs
  and private IPs by default for cloud destinations; "Preview what will be sent". The model
  is only called when you ask.
- **AI usage, local only:** every answer records provider, model, tokens and an estimated
  cost in your own database; a note under each answer ("about N tokens, ~US$x"); an "AI
  usage" card in Settings with this month's totals and an optional monthly budget that warns
  when close and asks before going over. Own prices for other cloud services; local models
  show tokens only. The budget is checked again before each lookup round of an answer and
  on the JSON AI endpoints (`409` until you confirm); the card says when only one own
  price is set or when a budget can't be checked (a cloud AI without a price). Long chats
  say when their oldest messages were left out.
- **Cheaper AI requests:** Anthropic prompt caching for the instructions, tool descriptions
  and tool loops; a compact network snapshot (about half the size) and capped chat history.
  Redaction is unchanged.
- **Dashboard:** inbox with undo, quiet hours and alert tuning, network map, live updates,
  "since your last visit", search and command palette, settings page, backup / restore,
  first-run setup; 12 languages (default Traditional Chinese); light and dark; phone and
  desktop; keyboard and screen-reader support (WCAG 2.2 AA target).
- **Phone / LAN mode:** off by default; pairing codes and sessions; admin actions limited to
  this computer or an admin session.
- **Packaging:** Docker image and compose files, headless mode with a one-time admin claim,
  Linux / Raspberry Pi systemd installer, `pip` / `pipx` install, Home Assistant add-on with
  ingress.
- **License:** GNU AGPL v3 or later (`AGPL-3.0-or-later`, PEP 639 metadata in the package,
  LICENSE and THIRD_PARTY_NOTICES.md inside the container images). Settings > About shows
  the version, the license, the copyright notice and a link to the source code for every
  signed-in user; `netwarden --version` prints the license and the source URL after the
  version line; `/api/meta` has `license`, `source_url` and `copyright`.
- Project files: README (English, Traditional Chinese), contributing guide (contributions
  under the project license, no CLA / DCO), security policy, code of conduct, issue and
  pull-request templates, third-party notices, `.gitattributes` (LF everywhere, CRLF for
  Windows `.cmd` files).
- CI: tests on Python 3.11 and 3.15 for every push to main and pull request, 3.11-3.15 for
  version tags and manual runs; locale check; map layout test; sdist + wheel build with a
  license-metadata check; container build + smoke test (images are pushed to
  `ghcr.io/liming-ting/netwarden` and `-addon` only from version tags); Dependabot for
  GitHub Actions and the base image.

### Known limitations

- Under WSL2 and Docker Desktop discovery sees only a few devices.
- Translations other than English and Traditional Chinese are machine-assisted.
- The container images and the Home Assistant add-on have only been built and smoke-tested
  in CI, not yet on real Home Assistant hardware.
- The optional threat-feed download (`python3 -m netwarden.threatintel --update "URL"`) has no
  built-in address: abuse.ch URLhaus downloads now need a personal, free Auth-Key, so you pass
  your own link (see THIRD_PARTY_NOTICES.md). The built-in starter list works without it.

[0.1.0]: https://github.com/liming-ting/netwarden/releases/tag/v0.1.0
