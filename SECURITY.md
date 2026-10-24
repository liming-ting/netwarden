# Security policy

## Supported versions

netwarden is a young project. Only the latest release gets security fixes.

| Version | Supported |
|---|---|
| 0.1.x (latest) | yes |
| anything older | no |

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Report them privately through
GitHub's private vulnerability reporting:

https://github.com/liming-ting/netwarden/security/advisories/new

Include what you found, how to reproduce it (version, install method - Docker, Home
Assistant add-on, systemd, checkout - and the settings involved), and what an attacker could
achieve. Please never include real secrets, API keys or data from someone else's network.

What to expect: an acknowledgement within about a week, an assessment and, for a confirmed
issue, a fix in a new release with credit to you (unless you prefer not to be named). This is
a volunteer project, so timelines are best effort; we will keep you informed.

## Scope

In scope - things netwarden promises:

- the dashboard and its JSON API (`netwarden/web.py`): authentication and pairing in LAN mode,
  the admin / loopback-only boundary, Host and Origin checks, Home Assistant ingress handling;
- escaping of hostile text (device names, mDNS / SSDP / UPnP strings, owner and room names) in
  the dashboard, reports and CSV exports;
- secrets: API keys or passwords appearing in API responses, logs, backups or the UI -
  including notification channel tokens, webhook URLs and HMAC secrets;
- notification channels sending more than their privacy level allows (an address or a
  domain below "detailed"), following a redirect, or skipping TLS verification;
- anything that sends data off the machine that the docs say stays local, or that changes the
  network although netwarden is documented as read-only;
- AI redaction (`netwarden/redact.py`) leaking a name or address it is documented to hide;
- the container images, the add-on and `scripts/install_linux.sh` (privileges, file permissions).

Out of scope:

- weaknesses of AdGuard Home, Pi-hole, ntopng, Home Assistant, Ollama or other software
  netwarden talks to (report those upstream);
- attacks that need an already compromised host or root on the machine running netwarden;
- the opt-in features doing what they are documented to do (for example the port check
  connecting to devices on your LAN, or the cloud AI receiving the redacted snapshot);
- denial of service by a client that is already paired as admin.
