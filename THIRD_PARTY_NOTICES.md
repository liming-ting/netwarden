# Third-party notices

netwarden itself is Copyright (C) 2026 liming-ting and contributors, licensed under the
GNU AGPL v3 or later (SPDX `AGPL-3.0-or-later`, full text in [LICENSE](LICENSE)). The parts
listed below keep their own licenses.

netwarden has **no runtime dependencies**: it uses only the Python standard library. This file
lists third-party code and text that is bundled with netwarden, plus the external data that
netwarden can download at runtime when you ask it to (nothing is downloaded otherwise).
Each conclusion names the source it was checked against (checked on 2026-10-24).

## Bundled code

### QR Code generator library (Python) - Project Nayuki

- File: `netwarden/vendor/qrcodegen.py` (vendored unchanged; a test pins the upstream SHA-256)
- Source: https://github.com/nayuki/QR-Code-generator (`python/qrcodegen.py`),
  https://www.nayuki.io/page/qr-code-generator-library
- License: **MIT** - "Copyright (c) Project Nayuki. (MIT License)", as stated in the header of
  https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/python/qrcodegen.py.
  The full permission notice is kept in the file header, as the license requires.
- Used for: the pairing QR codes (`netwarden/qr.py`).

This is the only third-party code in the repository. A search of the code, scripts, tests and
dashboard for copyright lines, license headers, attribution comments and links to snippets
found nothing else.

## Bundled text

### Contributor Covenant 2.1

- File: `CODE_OF_CONDUCT.md`
- Source: https://www.contributor-covenant.org/version/2/1/code_of_conduct/
  (the official file:
  https://raw.githubusercontent.com/EthicalSource/contributor_covenant/release/content/version/2/1/code_of_conduct.md)
- Terms: the Contributor Covenant is published for projects to adopt; the official file is a
  template with an `[INSERT CONTACT METHOD]` placeholder and ends with its own attribution
  section. Neither the official site nor its repository README states a separate license
  for the text (the repository's `LICENSE.md` is the Hippocratic License 3.0, which covers
  the site's source code); third-party copies describe the text as CC BY 4.0, which needs
  attribution only. Either way the attribution section is kept unchanged.
- Changes: compared section by section with the official file; the only change is the
  contact in the "Enforcement" section, which fills in that placeholder.

## Bundled data

All of the following lists were compiled for netwarden by hand. They contain facts (domain
names, company names, port numbers, public registry assignments) and short descriptions
written for this project; none is a copy of a third-party blocklist or database.

| Data | Where | Source / basis | License note |
|---|---|---|---|
| Tracker domains (~195) with categories and companies | `netwarden/privacy.py` (`TRACKERS`) | netwarden's own compilation of well-known tracker / ad / analytics domains | part of netwarden |
| Threat starter list (curated "malicious" / "high-risk" domains, e.g. cheap IP-camera clouds) and their explanations | `netwarden/threatintel.py` | own compilation from public reporting on those services; nothing from URLhaus | part of netwarden |
| Service map (domain -> service and category) | `netwarden/services.py` | own compilation | part of netwarden |
| Routine-traffic map (connectivity checks, time, updates, certificates, CDNs) | `netwarden/routine.py` | own compilation | part of netwarden |
| DoH/DoT bootstrap names and the Firefox canary domain | `netwarden/visibility.py` | own compilation from the providers' public documentation | part of netwarden |
| Device-type rules (hostname / vendor keywords, ports) | `netwarden/devicetype.py`, `netwarden/exposure.py` | own rules; port meanings are public IANA / vendor facts | part of netwarden |
| Built-in OUI fallback (2 prefixes: Raspberry Pi) | `netwarden/discovery.py` (`BUILTIN_OUI`) | IEEE public MA-L registry assignments (facts) | facts, no license needed |
| Synthetic demo home | `netwarden/demo.py`, `scripts/demo_seed.py` | invented; device and company names only describe typical products | part of netwarden |
| Translations | `netwarden/locales/*.json` | written for netwarden (machine-assisted) | part of netwarden |
| Icons (SVG sprite in `netwarden/static/index.html`, `icon.svg`, PNGs from `scripts/make_icons.py`, `ha-addon/icon.png` + `logo.png`) | `netwarden/static/`, `ha-addon/` | drawn for netwarden - see "Icons" below | part of netwarden |

### Icons

The dashboard icons are simple 24x24 line drawings written by hand into the SVG sprite; the
app / PWA / add-on icon is a shield with a dot on a blue square, rasterized by
`scripts/make_icons.py` with the standard library (its "netwarden" wordmark is drawn from
strokes, no font). No icon set, font or image library is used.

Before publication every sprite path was compared with the well-known open icon sets (Feather,
Lucide, Material, Heroicons, Font Awesome, Tabler, Bootstrap Icons). The handful whose geometry
followed a Feather / Lucide drawing too closely (eye-off, sun, moon, pulse, expand, keyboard,
wifi, light bulb, smart-home bulb, gauge) were redrawn from scratch. What is left are basic
geometric forms (a cross, a plus, a chevron, a check mark, a magnifier, rectangles and circles)
that every icon set draws the same way.

## Data downloaded only on request (never bundled)

Neither file below is in the repository, the Python package or the container images: they
are fetched on the user's machine only when the user runs the command, and are stored outside
the source tree. The Dockerfile copies only `pyproject.toml`, `README.md` and `netwarden/`,
runs no download at build time, and sets `HOME=/data`, so a download made inside a running
container lands in the `/data` volume, never in an image layer.

| Data | When | Where it is stored | Source | License / terms |
|---|---|---|---|---|
| MAC vendor database (`manuf`) | only with `netwarden scan --update-vendors` | `~/.cache/netwarden/manuf.txt` | Wireshark, https://www.wireshark.org/download/automated/data/manuf (fallback: the Wireshark repository on GitHub) | Wireshark is GPL software (https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING, GNU GPL version 2; its sources are marked GPL-2.0-or-later). The file is generated by TShark (`tshark -G manuf`, per its header) from Wireshark's data, which comes from the IEEE public OUI registry. netwarden treats it as GPL-2.0-or-later: it only downloads and reads it on the user's machine and never redistributes it. |
| Threat feed (malware hosts) | only with `python3 -m netwarden.threatintel --update "URL"` | `threatfeed.json` in the data directory (domains + the source's host name only) | a hosts-format list of the user's choice, for example their personal abuse.ch URLhaus host file link | URLhaus terms: https://abuse.ch/terms-of-use/ (see below). Not redistributed. |

### URLhaus (abuse.ch)

- **Access now needs a free account.** URLhaus downloads require a personal `Auth-Key` that is
  part of the download URL ("Whenever you try to download a dataset or file ... you must
  include your Auth-Key in the URL", https://urlhaus.abuse.ch/api/). The old key-less host
  file URL (`https://urlhaus.abuse.ch/downloads/hostfile/`) now answers HTTP 410 Gone.
- **What netwarden does:** it has no built-in feed URL any more. A bare `--update` prints how
  to get an Auth-Key (https://auth.abuse.ch/) and changes nothing; `--update "URL"` downloads
  the given list. The URL is treated as a secret: it is never printed or stored (the cache
  keeps only the host name), and HTTP 401 / 403 / 410 is explained as "this link needs your
  Auth-Key". The built-in starter list works without any download.
- **Terms:** https://abuse.ch/terms-of-use/ - URLhaus is free of charge under fair-use
  principles for authenticated users and not-for-profit purposes; commercial or for-profit
  use may need a paid Spamhaus subscription. The CC0 dedication in those terms covers other
  abuse.ch platforms (Feodo Tracker, SSL Blacklist, YARAify), not URLhaus. The terms ask no
  specific attribution for URLhaus; netwarden names abuse.ch URLhaus as the source wherever
  the feed is mentioned. They forbid using the data to train AI models: netwarden never sends
  the feed itself to a model (only a device's own matches may appear in an answer).
- **Bundled?** No. Nothing from URLhaus is in the repository or the images; each user
  downloads it with their own key, for their own use, under the terms above.
