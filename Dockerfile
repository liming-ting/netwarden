# netwarden - container image (headless: no browser in here; claim it from your LAN).
#
#   docker build -t netwarden .
#   docker run -d --name netwarden --network host \
#     -e NETWARDEN_HOST=127.0.0.1 -e NETWARDEN_LAN=1 -v netwarden-data:/data netwarden
#   docker logs netwarden          # the one-time admin code of a fresh install
#
# With host networking ALWAYS pass NETWARDEN_HOST=127.0.0.1 + NETWARDEN_LAN=1 (loopback +
# the detected LAN address): the default 0.0.0.0 below is for bridge networking, where it
# means the container's own interface; on the host network it would be every host
# interface (VPN, public ones too).
#
# Zero runtime dependencies: the official Python image + the two OS tools the code
# shells out to (`ip` for routes / the ARP table, `ping` for discovery and the gateway
# probe). No compiler, no build step. See docs/install.md (and deploy/ for compose).
#
# Two images from this one file (both built by .github/workflows/docker.yml):
#   default (the last stage)   ghcr.io/liming-ting/netwarden         docker / compose / k8s
#   --target addon             ghcr.io/liming-ting/netwarden-addon   the Home Assistant add-on
#                              (ha-addon/config.yaml; docs/dev/ha_addon.md says why it differs)
FROM python:3.12-slim-bookworm AS runtime

ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="netwarden" \
      org.opencontainers.image.description="AI home-network manager: see your devices, watch who they talk to, explain it in plain language." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/liming-ting/netwarden" \
      org.opencontainers.image.url="https://github.com/liming-ting/netwarden" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# iproute2: `ip route` / `ip neigh` / `ip -o addr` (discovery, LAN address, UPnP gateway)
# iputils-ping: `ping` (sweep + gateway probe; without CAP_NET_RAW it falls back to TCP)
# tzdata + ca-certificates: local time zones (zoneinfo) and HTTPS to the configured LLM
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# A fixed, unprivileged user; /data is its only writable place.
RUN groupadd --system --gid 10001 netwarden \
 && useradd --system --uid 10001 --gid netwarden --home-dir /data --no-create-home \
            --shell /usr/sbin/nologin netwarden \
 && mkdir -p /data && chown netwarden:netwarden /data && chmod 0750 /data

WORKDIR /opt/netwarden
# LICENSE + THIRD_PARTY_NOTICES.md: pyproject `license-files` (the build needs them) and they
# stay in /opt/netwarden, so every image carries the license text and the notices.
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY netwarden ./netwarden
RUN pip install --no-cache-dir --no-compile . \
 && rm -rf /opt/netwarden/netwarden /root/.cache

# Every setting can still come from env vars or an env_file (ADGUARD_URL, PIHOLE_URL,
# NETWARDEN_LANG, ANTHROPIC_API_KEY, ...).
#   NETWARDEN_HEADLESS=1    logs to stderr; prints ONE admin code until claimed
ENV NETWARDEN_DB=/data/netwarden.db \
    NETWARDEN_PORT=8787 \
    NETWARDEN_HEADLESS=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/data

WORKDIR /data
EXPOSE 8787

# /healthz: public, constant, no database (web.HEALTHZ_PATH). Loopback is always bound.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python3", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('NETWARDEN_PORT', '8787'), timeout=4)"]

# SIGTERM (docker stop) shuts down like Ctrl+C, also as PID 1; `init: true` adds tini.
STOPSIGNAL SIGTERM


# --- Home Assistant add-on: docker build --target addon ---------------------------------
# The Supervisor creates the add-on's /data owned by root and can't be told to run us as
# another user, so this image starts as root ONLY to hand /data to the `netwarden` user
# and then drops to it for good (netwarden/addon.py prepare_and_drop) before reading any
# network data. It reads /data/options.json (the add-on options) and listens for the
# Supervisor's ingress proxy. Not meant for plain `docker run` (it refuses to start
# without SUPERVISOR_TOKEN + /data/options.json).
FROM runtime AS addon
ARG VERSION=0.1.0
LABEL io.hass.type="addon" \
      io.hass.name="netwarden" \
      io.hass.version="${VERSION}" \
      io.hass.description="AI home-network manager: your devices, who they talk to, in plain language."
CMD ["python3", "-m", "netwarden.addon"]


# --- the default image (last stage: plain `docker build .`) --------------------------------
FROM runtime
# Container mode (netwarden/headless.py):
#   NETWARDEN_HOST=0.0.0.0  LAN mode on every interface: other devices need pairing
#   (bridge networking; on --network host override it, see the header)
ENV NETWARDEN_HOST=0.0.0.0
USER netwarden
VOLUME ["/data"]
ENTRYPOINT ["netwarden"]
CMD ["run"]
