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

### Fixed

- Pi-hole: `PIHOLE_URL` ending in `/admin` or `/api` works; a re-login after HTTP 401
  frees the old session first; queries hidden by the privacy level are no longer stored
  as the domain "hidden".
- ntopng without valid credentials reports "Login refused" instead of "not JSON".
- Internationalized domain names are stored in one (ASCII) form for every source.
- One ingest run reads at most 100,000 queries, so a first run on a very large log
  stays within memory.

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
