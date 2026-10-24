# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (before 1.0, minor versions may
contain breaking changes).

## [0.1.0] - Unreleased

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
