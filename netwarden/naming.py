"""
netwarden - naming.py: one display name per device, the same everywhere.

The dashboard names a device label > hostname > the name it announced on the LAN
(mDNS / SSDP) > vendor > "Type · owner" > "Private device" / "Unknown device"
(app.js dname()). Server-written text - the DNS-visibility findings, alerts, the
offline AI answer, the digest, the exports - used to stop at the MAC instead, so a
nameless private-address phone read "a2:4f:..." in one place and "Phone · Mom" in
another. display_names() is that same rule on the server, localized:

    display_names(db, lang)   -> {mac: name}  for every known device
    relabel(obj, names)       -> a copy of obj where every {"mac": m, "name": m}
                                 (or "device": m) gets the display name instead

store.device_names() stays the canonical, language-free map (MAC as the last resort):
it is what the LLM redaction and the canonical English snapshot use.
"""
from __future__ import annotations

from netwarden import devicetype, i18n, store

NAME_FIELDS = ("name", "device")   # alert / finding fields that carry a device name


def display_names(db, lang: str) -> dict:
    """mac -> the name the dashboard shows for it, in `lang` (never a bare MAC)."""
    lang = i18n.normalize(lang)
    base = store.device_names(db)
    rows = {r["mac"]: bool(r["randomized"])
            for r in db.execute("SELECT mac, randomized FROM devices")}
    nameless = [mac for mac, name in base.items() if name == mac]
    if not nameless:
        return base
    types = devicetype.classify_all(db)
    profiles = store.get_profiles(db)
    out = dict(base)
    for mac in nameless:
        typ = (types.get(mac) or {}).get("type")
        owner = (profiles.get(mac) or {}).get("owner")
        if typ and typ != "unknown" and owner:
            out[mac] = devicetype.type_name(typ, lang) + " · " + owner
        else:
            out[mac] = i18n.t("app.d.private_device" if rows.get(mac) else "ui.unknown_device", lang)
    return out


def relabel(obj, names: dict):
    """A copy of `obj` (dicts / lists, any depth) in which an item naming a device by its
    bare MAC - {"mac": m, "name": m} or {"mac": m, "device": m} - gets names[m]."""
    if isinstance(obj, list):
        return [relabel(x, names) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {k: relabel(v, names) for k, v in obj.items()}
    mac = obj.get("mac")
    if isinstance(mac, str) and mac in names:
        for f in NAME_FIELDS:
            if out.get(f) == mac:
                out[f] = names[mac]
    return out
