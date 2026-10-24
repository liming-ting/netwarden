#!/usr/bin/env python3
"""
netwarden - routine.py: is this lookup just normal background traffic?

Every device on a home network constantly looks up a handful of domains nobody ever
typed: "am I online?" checks, the clock, software / firmware updates, certificate
checks and the big CDN / cloud hosts that serve almost everything. To a non-expert a
list of raw domains like connectivitycheck.gstatic.com or a1234.dscb.akamaiedge.net
looks suspicious; this module names them calmly.

    lookup("captive.apple.com")  -> "connectivity"
    explain("connectivity", lang) -> "Connectivity check: the device asks 'am I online?' ..."

Kinds (stable keys; text is routine.name.<kind> / routine.text.<kind> in the locales):
    connectivity   online / captive-portal checks
    time           clock synchronisation (NTP)
    updates        operating-system, app-store and firmware updates
    certs          certificate validity checks (OCSP / CRL)
    cdn            content-delivery networks that serve images, video, app files
    cloud          general cloud hosting (the servers behind many apps)

Matching works like services.py / privacy.py: a domain matches an entry when it
equals it or ends with "." + entry; the LONGEST entry wins. Only domains whose
purpose is well documented are listed - a routine flag is a reassurance, so it must
never be wrong. Deterministic, local, no network.
"""
from __future__ import annotations

from functools import lru_cache

from netwarden import i18n

KINDS = ("connectivity", "time", "updates", "certs", "cdn", "cloud")

# domain suffix -> kind
ROUTINE = {
    # --- connectivity / captive-portal checks ---
    "connectivitycheck.gstatic.com": "connectivity",
    "connectivitycheck.android.com": "connectivity",
    "clients3.google.com": "connectivity",
    "clients1.google.com": "connectivity",
    "captive.apple.com": "connectivity",
    "msftconnecttest.com": "connectivity",
    "msftncsi.com": "connectivity",
    "detectportal.firefox.com": "connectivity",
    "nmcheck.gnome.org": "connectivity",
    "connectivity-check.ubuntu.com": "connectivity",
    "network-test.debian.org": "connectivity",
    "connect.rom.miui.com": "connectivity",
    "connectivitycheck.platform.hicloud.com": "connectivity",
    "wifi.vivo.com.cn": "connectivity",

    # --- time sync (NTP) ---
    "ntp.org": "time",
    "time.apple.com": "time",
    "time-ios.apple.com": "time",
    "time-macos.apple.com": "time",
    "time.windows.com": "time",
    "time.google.com": "time",
    "time.android.com": "time",
    "time.cloudflare.com": "time",
    "time.facebook.com": "time",
    "time.nist.gov": "time",
    "ntp.ubuntu.com": "time",
    "time.stdtime.gov.tw": "time",
    "tock.stdtime.gov.tw": "time",
    "tick.stdtime.gov.tw": "time",
    "ntp.aliyun.com": "time",
    "ntp.tencent.com": "time",

    # --- OS / app / firmware updates ---
    "update.microsoft.com": "updates",
    "windowsupdate.com": "updates",
    "delivery.mp.microsoft.com": "updates",
    "swscan.apple.com": "updates",
    "swcdn.apple.com": "updates",
    "swdist.apple.com": "updates",
    "mesu.apple.com": "updates",
    "updates.cdn-apple.com": "updates",
    "gdmf.apple.com": "updates",
    "update.googleapis.com": "updates",
    "gvt1.com": "updates",
    "gvt2.com": "updates",
    "dl.google.com": "updates",
    "archive.ubuntu.com": "updates",
    "security.ubuntu.com": "updates",
    "ports.ubuntu.com": "updates",
    "deb.debian.org": "updates",
    "security.debian.org": "updates",
    "raspbian.raspberrypi.org": "updates",
    "archive.raspberrypi.org": "updates",
    "update.playstation.net": "updates",
    "ospserver.net": "updates",
    "update.miui.com": "updates",
    "update.intl.miui.com": "updates",
    "download.mozilla.org": "updates",
    "aus5.mozilla.org": "updates",
    "officecdn.microsoft.com": "updates",
    "steamcontent.com": "updates",

    # --- certificate checks (OCSP / CRL) ---
    "ocsp.apple.com": "certs",
    "ocsp2.apple.com": "certs",
    "crl.apple.com": "certs",
    "valid.apple.com": "certs",
    "pki.goog": "certs",
    "ocsp.digicert.com": "certs",
    "crl3.digicert.com": "certs",
    "crl4.digicert.com": "certs",
    "ocsp.sectigo.com": "certs",
    "ocsp.usertrust.com": "certs",
    "ocsp.comodoca.com": "certs",
    "lencr.org": "certs",
    "ocsp.globalsign.com": "certs",
    "ocsp.entrust.net": "certs",
    "ocsp.godaddy.com": "certs",
    "ocsp.msocsp.com": "certs",
    "oneocsp.microsoft.com": "certs",

    # --- content-delivery networks ---
    "akamaized.net": "cdn",
    "akamaiedge.net": "cdn",
    "akamai.net": "cdn",
    "akamaihd.net": "cdn",
    "edgekey.net": "cdn",
    "edgesuite.net": "cdn",
    "cloudfront.net": "cdn",
    "fastly.net": "cdn",
    "fastlylb.net": "cdn",
    "cdn.cloudflare.net": "cdn",
    "cdnjs.cloudflare.com": "cdn",
    "jsdelivr.net": "cdn",
    "llnwd.net": "cdn",
    "azureedge.net": "cdn",
    "edgecastcdn.net": "cdn",
    "b-cdn.net": "cdn",
    "cdn77.org": "cdn",
    "alicdn.com": "cdn",

    # --- general cloud hosting / infrastructure ---
    "amazonaws.com": "cloud",
    "googleusercontent.com": "cloud",
    "1e100.net": "cloud",
    "cloudapp.azure.com": "cloud",
    "trafficmanager.net": "cloud",
    "windows.net": "cloud",
    "akadns.net": "cloud",
    "aliyuncs.com": "cloud",
    "myqcloud.com": "cloud",
    "digitaloceanspaces.com": "cloud",
}


@lru_cache(maxsize=65536)
def lookup(domain: str) -> str | None:
    """The routine kind of `domain`, or None. Longest matching entry wins."""
    d = (domain or "").lower().strip().strip(".")
    labels = d.split(".")
    for i in range(len(labels)):
        kind = ROUTINE.get(".".join(labels[i:]))
        if kind:
            return kind
    return None


def is_routine(domain: str) -> bool:
    return lookup(domain) is not None


def name(kind: str, lang: str) -> str:
    """Short label, e.g. "Connectivity check"."""
    return i18n.t("routine.name." + kind, lang)


def explain(kind: str, lang: str) -> str:
    """One calm sentence: what it is and why it is normal."""
    return i18n.t("routine.text." + kind, lang)


def info(domain: str, lang: str) -> dict | None:
    """{kind, name, text} for a routine domain (the API shape), else None."""
    kind = lookup(domain)
    if not kind:
        return None
    return {"kind": kind, "name": name(kind, lang), "text": explain(kind, lang)}


# The short English phrase the LLM snapshot carries next to a routine domain.
LLM_TEXT = {
    "connectivity": "routine: connectivity check",
    "time": "routine: clock sync",
    "updates": "routine: software/firmware updates",
    "certs": "routine: certificate check",
    "cdn": "routine: content-delivery network",
    "cloud": "routine: cloud hosting",
}
