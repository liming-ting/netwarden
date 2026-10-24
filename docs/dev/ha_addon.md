# Home Assistant add-on: decisions and sources (round 6, stage H)

User guide: [../home_assistant.md](../home_assistant.md). Code: `netwarden/addon.py`,
`web.Handler._ingress_ok`, `ha-addon/`, `repository.yaml`, Dockerfile target `addon`,
`.github/workflows/docker.yml`. Tests: `tests/test_round6_h.py` + `tests/ingress_proxy.py`.

## Sources (read October 2026)

- Add-on developer docs, now at contributors.home-assistant.io/apps/ (configuration,
  presentation/ingress, communication, security, repositories); developers.home-assistant.io
  /docs/add-ons/* redirects there. Part of it could only be confirmed through search
  results and the source code below.
- Supervisor, `supervisor/store/data.py`: a repository is scanned with
  `path.glob("**/config.*")`, skipping path parts that start with "." or equal "rootfs";
  an invalid config is a warning, not a failure; `repository.{yaml,json}` names it.
- Supervisor, `supervisor/api/ingress.py`: forwards to
  `http://{addon ip}:{ingress_port}/{path}`, copies headers except hop-by-hop /
  websocket / remote-user ones (Host and Origin pass through), appends its peer to
  X-Forwarded-For, validates HA's `ingress_session` cookie first.
- Home Assistant core, `homeassistant/components/hassio/ingress.py`: route
  `/api/hassio_ingress/{token}/{path}`; sets `X-Ingress-Path: /api/hassio_ingress/{token}`,
  `X-Hass-Source: core.ingress`, X-Forwarded-For / -Host / -Proto; drops
  Accept-Encoding; responses without Content-Length are streamed.
- Home Assistant core, `hassio/http.py` `should_compress()`: never compresses
  `text/event-stream` - so /api/stream and the chat stream pass through unbuffered.
- The ingress proxy's address 172.30.32.2 is the one the HA docs tell add-ons to allow.

## Decisions

**One repository.** The Supervisor accepts an add-on in a sub-folder, so this repo is also
the add-on repository: `repository.yaml` at the root, the add-on in `ha-addon/` (no clash
with the `netwarden/` package; the folder name doesn't matter, the slug does). No other
`config.{json,yaml,yml}` may exist outside dot-folders (a test checks it).

**A second image target.** The Supervisor creates `/data` owned by root and has no option
to run an add-on as another user, while the default image runs as `netwarden` (uid 10001)
and could not write there. So the Dockerfile has a target `addon` (same runtime stage, no
`USER`, `CMD python3 -m netwarden.addon`) published as `ghcr.io/liming-ting/netwarden-addon`; its
start chowns `/data` (not `options.json`), then `setgroups([])/setgid/setuid` to the
`netwarden` user before anything reads network data (`addon.prepare_and_drop`). If that
fails it keeps running as root and logs it. The default image is unchanged and stays the
last stage. Version tag = `config.yaml` `version` (the Supervisor pulls
`<image>:<version>`); multi-arch manifest, no `{arch}` in the image name.

**Add-on mode** = `SUPERVISOR_TOKEN` set AND `/data/options.json` readable
(`addon.active`). The token is never read further or logged. `options.json` (64 KB cap,
must be an object) is mapped onto the environment variables netwarden already reads
(`addon.OPTION_ENV`, `BOOL_OPTIONS`), so the usual precedence holds: option > dashboard
setting > default. Plus fixed values: `NETWARDEN_HEADLESS=1`, `NETWARDEN_REQUIRE_AUTH=1`,
`NETWARDEN_HOST=127.0.0.1`, `NETWARDEN_PORT=8787`; `TZ` (passed in by the Supervisor) ->
`NETWARDEN_TZ` when no `timezone` option. The log lists option NAMES only.

**Ingress trust.** Only with `Handler.ingress_proxy` set (by `run` in add-on mode; tests
inject it; never a setting) and only when the socket peer IS that address: the request
counts as a signed-in HA administrator (`panel_admin: true`), `local = False`,
`admin = True`, no cookie of ours. `X-Ingress-Path` is read only then, validated
(`web.ingress_base`: plain path segments, no `.`/`..`, <= 8 x 128 chars) and escaped.
Host is HA's own name (any), so the Host check is skipped for that peer; a POST still
needs an `Origin` whose host:port equals X-Forwarded-Host or Host (CSRF through the HA
tab). Responses to the proxy may be framed by the same origin (`frame-ancestors 'self'`,
`X-Frame-Options: SAMEORIGIN`); everything else keeps DENY / `'none'`. Live-stream caps
count the browser (second-to-last X-Forwarded-For hop), not the proxy.

**Listening.** Loopback (needs a session: with `host_network` every other host-network
add-on shares our loopback) + the local address toward the proxy
(`addon.ingress_listen`: UDP-connect route lookup, fallback 172.30.32.1). LAN only with
the `lan_access` option (`NETWARDEN_LAN`), pairing as always. The headless "claim" admin
code is not printed in add-on mode (HA admins already are admins).

**Base path.** Pages get the prefix server-side (`__BASE__` in index.html, `base=` for
pairing / offline / weekly report, `<html data-base>`); app.js / pair.js / offline.js
prefix their own URLs (`url()`), app.css and the manifest use relative URLs, sw.js derives
everything from `registration.scope`. Redirects (`303 /pair`) carry the prefix. At `/`
the output is byte-for-byte what it was (base = "").

**config.yaml.** `init: true` (no s6 in the image; tini reaps ping/ip children),
`host_network: true` (ARP, ping sweep, mDNS/SSDP), not privileged, no extra
capabilities, `hassio_api` / `homeassistant_api` false, `backup: cold` (consistent SQLite
file), `panel_admin: true`, `ingress_port: 8787`. Secrets are `password?` types. No
`watchdog` (the `[PORT:...]` substitution with host networking could not be verified; a
wrong watchdog URL would restart the add-on in a loop). No AppArmor profile: one that is
wrong breaks discovery (raw sockets, `ip`, `ping`) in ways we can't test here; the default
container profile applies.

**Icons.** `scripts/make_icons.py --ha-addon` draws `icon.png` (128x128) and `logo.png`
(250x100, mark + stroked wordmark) with the stdlib, same design as icon.svg.

## Not verified locally (no Docker, no Home Assistant here)

- The add-on image build and its CI smoke test (fake SUPERVISOR_TOKEN + root-owned /data)
  run only in GitHub Actions.
- Installing from the repository URL in a real Supervisor, the real ingress iframe, the
  Supervisor's view of the multi-arch image, `TZ` passing, `backup: cold`.
- Ingress was tested with `tests/ingress_proxy.py`, which mimics the header behaviour
  described above (connecting from 127.0.0.2 as the trusted peer), and in Chrome through
  that proxy at /api/hassio_ingress/TESTTOKEN/.
- armv7: Home Assistant has announced the end of 32-bit support; it stays in the list as
  long as the release job builds it.
