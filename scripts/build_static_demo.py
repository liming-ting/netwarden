#!/usr/bin/env python3
"""
netwarden - build the static live demo (round 9 W).

    python3 scripts/build_static_demo.py --out /tmp/nw_demo_site
    python3 scripts/build_static_demo.py --out DIR --langs en,zh-Hant --quick   # a small build

Writes DIR: the real dashboard (index.html + static/) on a made-up home, plus every GET
answer the page needs under DIR/demo-data/ - so it works from plain files under any
sub-path (GitHub Pages: https://liming-ting.github.io/netwarden/). Nothing is forked:
  - the home is the demo seeder's (netwarden/demo.py), built fresh in a temp dir (never
    data/demo.db or data/netwarden.db);
  - every answer comes from the REAL server (web.make_server on an ephemeral 127.0.0.1
    port inside this process, AI forced offline), saved byte for byte;
  - the page is netwarden/static/app.js itself: index.html gets data-static-demo="1" and
    static/demo.js, which maps a request to its file (static_name() below is the same
    function in Python; tests/fixtures/static_demo_names.json pins both).
What is saved: the Overview bundle and every page's own data, every device drawer, the
service / domain drawers the pages link to (crawled from the answers themselves, up to
MAX_LOOKUPS), the people pages, the report at its shareable and minimal levels, the
exports, the weekly family report - in every language - and the offline assistant's
answers to the suggested questions. Writes, live updates, search, "since your last
visit" and the full report level are not part of a static copy: the page says so.

No network beyond that loopback server; no LLM (NETWARDEN_OFFLINE_AI=1); the output is
scanned for the build machine's paths and addresses before it is written (privacy_scan());
the one answer that describes the host itself (pairing's LAN URL) gets the demo's.
"""
from __future__ import annotations

import argparse
import contextlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import netwarden  # noqa: E402
from netwarden import activity, brain, cache, demo, dns_ingest, i18n, pairing, web  # noqa: E402

DATA_DIR = "demo-data/"
DEFAULT_SITE = "https://liming-ting.github.io/netwarden/"
DEMO_TZ = "Asia/Taipei"        # the demo home's zone (its evenings and school nights)
OG_IMAGE = ROOT / "docs" / "images" / "social-preview.png"   # 1280x640, also GitHub's social preview
OG_LANG = "en"                 # link previews: the launch is international
# static/ files the demo page uses (sw.js / offline.js / pair.js: server-only features)
STATIC_FILES = ("app.css", "app.js", "map.js", "demo.js", "report.css", "report.js",
                "icon.svg", "icon-192.png", "icon-512.png", "apple-touch-icon.png",
                "manifest.webmanifest")
# GETs that take no argument (lang aside); the page fetches each of them somewhere
PAGES = ("/api/locale", "/api/overview", "/api/hygiene", "/api/tuning", "/api/types",
         "/api/people", "/api/rooms", "/api/screentime?days=7", "/api/weekly", "/api/bedtime",
         "/api/pair/sessions", "/api/ai/usage", "/api/settings", "/api/setup",
         "/api/ai/questions", "/api/export/devices.csv", "/api/export/report.md",
         "/report/weekly", "/api/channels")
DEVICE_GETS = ("/api/device?mac={m}", "/api/activity?mac={m}", "/api/timeline?mac={m}",
               "/api/screentime?days=7&device={m}")
REPORT_PERIODS, REPORT_FORMATS = ("7", "30"), ("html", "md")
MAX_LOOKUPS = 400              # service + domain drawers (the demo home has far fewer)
MAX_ANSWERS = 14               # pre-computed assistant answers per language
SUGGESTED = ("app.ai.s1", "app.ai.s2", "app.ai.s3")   # the chat's own standing questions

# --- the request -> file map (static/demo.js has the same function) ----------------------
LANG_FREE = ("/api/meta",)
DROP = ("lang", "accept", "inline")
LANG_RE = re.compile(r"[A-Za-z]{2,3}(-[A-Za-z0-9]{2,4})?")


def fnv(text: str) -> str:
    """FNV-1a 32 over UTF-8, as 8 hex digits (NWDemo.fnv)."""
    h = 0x811C9DC5
    for b in str(text).encode("utf-8"):
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return f"{h:08x}"


def _lang_of(value, fallback=None) -> str:
    if value and LANG_RE.fullmatch(value):
        return value
    return fallback if fallback and LANG_RE.fullmatch(fallback) else i18n.DEFAULT


def static_name(request: str, fallback_lang: str | None = None) -> str:
    """'/api/device?mac=..&lang=en' -> 'demo-data/en/api/device.q<hash>.json' (NWDemo.file)."""
    path, _, qs = str(request).partition("?")
    pairs = parse_qsl(qs, keep_blank_values=True)
    q = dict(pairs)
    lang = _lang_of(q.get("lang"), fallback_lang)
    ext = "" if re.search(r"\.(csv|md)$", path) else ".html" if path == "/report/weekly" else ".json"
    if path == "/api/report":
        if q.get("privacy") != "shareable":
            pairs = [p for p in pairs if p[0] not in ("names", "people")]
        ext = ".txt" if q.get("format") == "md" else ".html"
    canon = "&".join(f"{k}={v}" for k, v in sorted(p for p in pairs if p[0] not in DROP))
    return (DATA_DIR + ("" if path in LANG_FREE else lang + "/") + path.lstrip("/")
            + (".q" + fnv(canon) if canon else "") + ext)


def chat_name(mode: str, question: str, lang: str) -> str:
    """NWDemo.chatFile: one pre-computed answer (the raw SSE stream)."""
    return f"{DATA_DIR}{_lang_of(lang)}/chat/{fnv(mode + chr(10) + str(question or '').strip())}.txt"


def chat_index(lang: str) -> str:
    return f"{DATA_DIR}{_lang_of(lang)}/chat/index.json"


def with_lang(request: str, lang: str) -> str:
    return request + ("&" if "?" in request else "?") + "lang=" + quote(lang)


def report_requests() -> list[str]:
    """Every report the page can ask for in the demo: shareable (names x people) and
    minimal, both periods and formats (a download and its Preview are the same file)."""
    out = []
    for period in REPORT_PERIODS:
        for fmt in REPORT_FORMATS:
            combos = [("shareable", n, p) for n in ("type", "keep") for p in ("roles", "keep")]
            combos.append(("minimal", "type", "roles"))
            for privacy, names, people in combos:
                out.append("/api/report?" + urlencode({"period": period, "privacy": privacy, "names": names,
                                                       "people": people, "format": fmt}))
    return out


# --- the crawl: links the answers themselves contain --------------------------------------
MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
DOMAIN_RE = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")
SERVICE_RE = re.compile(r"[^\x00-\x1f]{1,120}")   # "YouTube", "svc.ads|Google", ...


def links(obj, found: dict) -> None:
    """Device MACs, domains and service ids an answer can link to (#/device/<mac>,
    #/domain/<d>, #/service/<id>), by the field names the page reads them from."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                if k == "mac" and MAC_RE.fullmatch(v):
                    found["mac"].add(v)
                elif k in ("domain", "entry") and DOMAIN_RE.fullmatch(v):
                    found["domain"].add(v)
                elif k == "service_id" and SERVICE_RE.fullmatch(v):
                    found["service"].add(v)
            elif k == "services" and isinstance(v, list):
                for s in v:
                    if isinstance(s, dict) and isinstance(s.get("id"), str) and SERVICE_RE.fullmatch(s["id"]):
                        found["service"].add(s["id"])
            elif k == "domains" and isinstance(v, list):
                for d in v:
                    if isinstance(d, str) and DOMAIN_RE.fullmatch(d):
                        found["domain"].add(d)
            links(v, found)
    elif isinstance(obj, list):
        for v in obj:
            links(v, found)


# --- the build ----------------------------------------------------------------------------
class BuildError(RuntimeError):
    pass


@contextlib.contextmanager
def pinned_tz(name: str):
    """The demo home's zone for the seeder and the server (NETWARDEN_TZ + TZ), restored after."""
    keys = ("TZ", "NETWARDEN_TZ")
    old = {k: os.environ.get(k) for k in keys}
    old_setting = activity.SETTING_TZ
    try:
        for k in keys:
            os.environ[k] = name
        activity.SETTING_TZ = None
        if hasattr(time, "tzset"):
            time.tzset()
        cache.clear()
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        activity.SETTING_TZ = old_setting
        if hasattr(time, "tzset"):
            time.tzset()
        cache.clear()


class Site:
    """The output being written: files by relative path, with byte counts."""

    def __init__(self):
        self.files: dict[str, bytes] = {}

    def put(self, name: str, body: bytes) -> None:
        self.files[name] = body

    def size(self) -> int:
        return sum(len(b) for b in self.files.values())


def _client(port: int):
    local = threading.local()

    def request(method: str, path: str, body: dict | None = None):
        c = getattr(local, "c", None)
        if c is None:
            c = local.c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"content-type": "application/json"} if data is not None else {}
        try:
            c.request(method, path, body=data, headers=headers)
            r = c.getresponse()
            out = r.status, r.getheader("content-type") or "", r.read()
        except (http.client.HTTPException, OSError):
            local.c = None
            c.close()
            raise
        if r.will_close:
            local.c = None
            c.close()
        return out
    return request


ROOT_LINK_RE = re.compile(rb'(\s(?:src|href)=")/(?!/)')


def relative_static(body: bytes, name: str) -> bytes:
    """An HTML answer under demo-data/<lang>/...: its root-absolute links (/static/...,
    the weekly report's "back to the dashboard" /#/family) made relative to the site."""
    up = ("../" * name.count("/")).encode()
    return ROOT_LINK_RE.sub(lambda m: m.group(1) + up, body)


def build(out: Path, now: datetime | None = None, langs=None, quick: bool = False,
          site_url: str = DEFAULT_SITE, log=print) -> dict:
    """Build the static demo into `out` (replaced). -> stats {files, bytes, requests, ...}."""
    started = time.monotonic()
    langs = list(langs or [c for c, _n, _l in i18n.LANGS])
    for code in langs:
        if i18n.match(code) != code:
            raise BuildError(f"unknown language {code!r}")
    if not site_url.endswith("/"):
        site_url += "/"
    now = now or datetime.now(timezone.utc).replace(second=0, microsecond=0)
    site = Site()
    with tempfile.TemporaryDirectory(prefix="nw_static_demo_") as tmp, pinned_tz(DEMO_TZ):
        db_path = Path(tmp) / "demo.db"
        demo.build(db_path, now=now)
        srv = web.make_server(db_path, 0, {brain.OFFLINE_ENV: "1", "NETWARDEN_TZ": DEMO_TZ},
                              i18n.DEFAULT)
        threading.Thread(target=srv.serve_forever, name="static-demo", daemon=True).start()
        try:
            stats = _crawl(site, _client(srv.server_address[1]), langs, quick, now, log)
        finally:
            srv.shutdown()
            web.close_server(srv)
        _page(site, site_url)
        privacy_scan(site, [tmp, str(db_path)])
    _write(site, Path(out))
    stats.update(files=len(site.files), bytes=site.size(), seconds=round(time.monotonic() - started, 1),
                 langs=langs, built_at=now.isoformat())
    return stats


def _crawl(site: Site, request, langs, quick: bool, now: datetime, log) -> dict:
    count = {"requests": 0}

    def get(path: str, lang: str | None = None):
        full = with_lang(path, lang) if lang else path
        status, ctype, body = request("GET", full)
        count["requests"] += 1
        if status != 200:
            raise BuildError(f"GET {full} -> {status}: {body[:200]!r}")
        name = static_name(full)
        if name.endswith(".html"):
            body = relative_static(body, name)
        site.put(name, body)
        return json.loads(body) if "json" in ctype else None

    def get_all(paths, lang):
        with ThreadPoolExecutor(4) as pool:
            return list(pool.map(lambda p: get(p, lang), paths))

    # /api/meta: the server's own answer + what only the static copy knows
    meta = get("/api/meta")
    meta.update(db_id="static-demo", browser_lang=None, static_demo={
        "built_at": now.isoformat().replace("+00:00", "Z"),
        "install_url": netwarden.SOURCE_URL + "/blob/main/docs/install.md",
        "install_url_zh": netwarden.SOURCE_URL + "/blob/main/docs/install.zh-TW.md",
        "source_url": netwarden.SOURCE_URL})
    if not meta.get("demo") or meta.get("ai_mode") != "offline":
        raise BuildError("the build server must serve the demo home with the AI offline")
    site.put(static_name("/api/meta"), json.dumps(meta, ensure_ascii=False).encode("utf-8"))

    # what to fetch in every language: crawled once (the links are the same in each)
    first = langs[0]
    found = {"mac": set(), "domain": set(), "service": set()}
    for ans in get_all(PAGES, first):
        if ans is not None:
            links(ans, found)
    people = [p["id"] for p in json.loads(site.files[static_name(with_lang("/api/people", first))])
              .get("people", []) if isinstance(p.get("id"), int)]
    person_gets = [f"/api/person?id={i}" for i in people]
    for ans in get_all(person_gets, first):
        links(ans, found)
    # each demo channel's "Delivery log" (the seeded, synthetic history)
    channel_ids = [c["id"] for c in json.loads(site.files[static_name(with_lang("/api/channels", first))])
                   .get("channels", []) if isinstance(c.get("id"), int)]
    channel_gets = [f"/api/channels/log?id={i}" for i in channel_ids]
    get_all(channel_gets, first)
    macs = sorted(found["mac"])
    device_gets = [g.format(m=quote(m, safe="")) for m in macs for g in DEVICE_GETS]
    if quick:
        device_gets = device_gets[:4 * 3]
    for ans in get_all(device_gets, first):
        links(ans, found)
    # service / domain drawers link to each other: follow until nothing new (capped)
    cap, lookups = (12 if quick else MAX_LOOKUPS), []

    def pending():
        return sorted(({f"/api/service?name={quote(s, safe='')}" for s in found["service"]} |
                       {f"/api/domain?d={quote(d, safe='')}" for d in found["domain"]}) - set(lookups))
    while len(lookups) < cap and pending():
        todo = pending()[:cap - len(lookups)]
        lookups += todo
        for ans in get_all(todo, first):
            links(ans, found)
    capped = bool(pending())
    reports = report_requests()[:2] if quick else report_requests()
    everything = list(PAGES) + person_gets + channel_gets + device_gets + lookups + reports
    for lang in langs[1:]:
        get_all(everything, lang)
    get_all(reports, first)
    for lang in langs:
        _neutral_pairing(site, lang)
    answers = {lang: _answers(site, request, lang, count, quick) for lang in langs}
    log(f"crawled {len(macs)} devices, {len(lookups)} service/domain drawers"
        f"{' (capped)' if capped else ''}, {len(people)} people, {sum(answers.values())} answers")
    return {"requests": count["requests"], "devices": len(macs), "lookups": len(lookups),
            "people": len(people), "answers": sum(answers.values()), "capped": capped}


DEMO_LAN_URL = "http://192.168.1.20:8787/"   # the demo home's netwarden box (docs' example)


def _neutral_pairing(site: Site, lang: str) -> None:
    """/api/pair/sessions describes the machine it runs on (its LAN address, a WSL firewall
    rule for its subnet): the build machine's, never the demo home's. Swap in the demo's."""
    name = static_name(with_lang("/api/pair/sessions", lang))
    ans = json.loads(site.files[name])
    ans.update(url=DEMO_LAN_URL, wsl_firewall=None)
    site.put(name, json.dumps(ans, ensure_ascii=False).encode("utf-8"))


def demo_hint(sse: bytes, lang: str) -> bytes:
    """An offline answer ends with how to turn the real AI on (.env, restart without
    --offline-ai): meaningless to someone trying the demo in a browser. That line (one
    chunk: offline_ai.chunks streams line by line) becomes the demo's own note."""
    hint = i18n.t("offline.enable_hint", lang).strip()
    note = "💡 " + i18n.t("app.demo.chat_only", lang)
    frames = sse.decode("utf-8").split("\n\n")
    for i, frame in enumerate(frames):
        if not frame.startswith("data: "):
            continue
        data = json.loads(frame[len("data: "):])
        if isinstance(data, dict) and isinstance(data.get("t"), str) and data["t"].strip() == hint:
            data["t"] = data["t"].replace(hint, note)
            frames[i] = "data: " + json.dumps(data, ensure_ascii=False)
    return "\n\n".join(frames).encode("utf-8")


def _answers(site: Site, request, lang: str, count: dict, quick: bool) -> int:
    """The offline assistant's answers to the suggested questions (and to the follow-up
    questions those answers suggest, up to MAX_ANSWERS), plus "Insight", as the raw SSE
    streams the page reads; index.json lists what has an answer."""
    qs = json.loads(site.files[static_name(with_lang("/api/ai/questions", lang))])
    suggested = [q["text"] for q in qs.get("questions", []) if isinstance(q.get("text"), str)]
    suggested += [i18n.t(k, lang) for k in SUGGESTED]
    suggested = list(dict.fromkeys(t.strip() for t in suggested if t.strip()))
    limit = 3 if quick else MAX_ANSWERS
    todo, answered = [("insight", "")] + [("chat", q) for q in suggested], []
    while todo and len(answered) < limit + 1:
        mode, q = todo.pop(0)
        if (mode, q) in answered:
            continue
        body = {"mode": mode, "messages": [{"role": "user", "content": q}] if q else [],
                "mac": None, "lang": lang}
        status, _ctype, sse = request("POST", "/api/chat/stream", body)
        count["requests"] += 1
        if status != 200 or b"event: done" not in sse:
            raise BuildError(f"chat answer ({lang}, {mode}) -> {status}: {sse[:200]!r}")
        sse = demo_hint(sse, lang)
        site.put(chat_name(mode, q, lang), sse)
        answered.append((mode, q))
        for frame in sse.decode("utf-8").split("\n\n"):
            if frame.startswith("event: suggest"):
                data = json.loads(frame.split("data:", 1)[1])
                todo += [("chat", t.strip()) for t in data.get("questions", [])
                         if isinstance(t, str) and t.strip()]
    texts = [q for m, q in answered if m == "chat"]
    site.put(chat_index(lang), json.dumps(
        {"suggested": [q for q in suggested if q in texts], "answers": texts,
         "insight": ("insight", "") in answered}, ensure_ascii=False).encode("utf-8"))
    return len(answered)


def _page(site: Site, site_url: str) -> None:
    """index.html (the real shell, flagged as the static demo) + static/ + link previews."""
    html = web.index_html("").decode("utf-8")
    html = html.replace('="/static/', '="static/')
    if 'data-base=""' not in html or "static/app.js" not in html:
        raise BuildError("index.html changed shape: update _page()")
    e = lambda s: escape(s, quote=True)   # noqa: E731
    title, desc = i18n.t("demo.og_title", OG_LANG), i18n.t("demo.og_description", OG_LANG)
    head = "\n".join((
        # no server headers on a static host: the same policy as a <meta> (minus what a
        # <meta> cannot carry, e.g. frame-ancestors)
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; '
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "manifest-src 'self'; base-uri 'none'; form-action 'none'\">",
        f'<meta name="description" content="{e(desc)}">',
        '<meta property="og:type" content="website">',
        f'<meta property="og:title" content="{e(title)}">',
        f'<meta property="og:description" content="{e(desc)}">',
        f'<meta property="og:url" content="{e(site_url)}">',
        f'<meta property="og:image" content="{e(site_url)}og-image.png">',
        f'<meta property="og:image:alt" content="{e(i18n.t("demo.og_image_alt", OG_LANG))}">',
        '<meta name="twitter:card" content="summary_large_image">',
        '<script src="static/demo.js?v=' + web.asset_version() + '" defer></script>'))
    html = html.replace('<html lang="zh-Hant" data-base=""',
                        '<html lang="zh-Hant" data-base="" data-static-demo="1"', 1)
    html = html.replace('<script src="static/map.js', head + '\n<script src="static/map.js', 1)
    if 'data-static-demo="1"' not in html or "demo.js" not in html:
        raise BuildError("could not flag index.html as the static demo")
    site.put("index.html", html.encode("utf-8"))
    for name in STATIC_FILES:
        found = web.static_file(name)
        if not found:
            raise BuildError(f"static/{name} is missing")
        site.put("static/" + name, found[0])
    site.put("og-image.png", OG_IMAGE.read_bytes())
    site.put(".nojekyll", b"")   # GitHub Pages: serve the files as they are (no Jekyll)


# a home directory, a Windows user folder, a WSL mount of one
HOME_RE = re.compile(rb"(/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|[A-Za-z]:\\\\?Users\\\\?|/mnt/[a-z]/)")


DEMO_NET = ipaddress.ip_network("192.168.1.0/24")   # the demo home's own (made-up) LAN


def machine_addresses() -> set[str]:
    """The build machine's own addresses (minus loopback and the demo's range, where any
    match is the made-up home's by design)."""
    out = set()
    for a in dns_ingest.local_addresses() | {pairing.lan_address() or ""}:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_unspecified and ip not in DEMO_NET:
            out.add(str(ip))
    return out


def privacy_scan(site: Site, extra=(), addresses=None) -> None:
    """Nothing from the build machine may end up in the output: the temp dir and DB path,
    this user's home, any home-directory-looking path, the machine's own IP addresses.
    Raises BuildError naming the file (and line) and the category - never the value."""
    needles = [(s.encode(), "build path") for s in extra if s]
    home = os.path.expanduser("~")
    if home and home not in ("/", "~"):
        needles.append((home.encode(), "home path"))
    addrs = machine_addresses() if addresses is None else set(addresses)
    addr_re = re.compile(rb"(?<![\w.:])(" + b"|".join(re.escape(a.encode()) for a in sorted(addrs)) +
                         rb")(?![\w.])") if addrs else None   # "a:port" still counts

    def fail(name, body, start, what):
        line = body[:start].count(b"\n") + 1
        raise BuildError(f"{name}:{line}: contains a {what}")
    for name, body in site.files.items():
        if name.endswith(".png"):
            continue
        for needle, what in needles:
            i = body.find(needle)
            if i >= 0:
                fail(name, body, i, what)
        m = HOME_RE.search(body)
        if m:
            fail(name, body, m.start(), "home-directory path")
        m = addr_re.search(body) if addr_re else None
        if m:
            fail(name, body, m.start(), "build machine address")


def _write(site: Site, out: Path) -> None:
    out = out.resolve()
    if out in (ROOT, ROOT / "data", Path.home().resolve(), Path("/")):
        raise BuildError(f"refusing to replace {out}")
    if out.exists():
        if not (out / "index.html").exists() and any(out.iterdir()):
            raise BuildError(f"{out} is not empty and is not an earlier demo build")
        shutil.rmtree(out)
    for name, body in sorted(site.files.items()):
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build netwarden's static live demo (GitHub Pages).")
    ap.add_argument("--out", required=True, help="output directory (replaced)")
    ap.add_argument("--langs", default="", help="comma-separated language codes (default: all 12)")
    ap.add_argument("--quick", action="store_true", help="a small build (tests, a quick look)")
    ap.add_argument("--site-url", default=DEFAULT_SITE, help="where it is published (link previews)")
    args = ap.parse_args(argv)
    langs = [c.strip() for c in args.langs.split(",") if c.strip()] or None
    try:
        stats = build(Path(args.out), langs=langs, quick=args.quick, site_url=args.site_url)
    except (BuildError, demo.NotADemoDB) as e:
        print(f"build_static_demo: {e}", file=sys.stderr)
        return 1
    print(f"wrote {stats['files']} files, {stats['bytes'] / 1e6:.1f} MB, {stats['requests']} requests "
          f"in {stats['seconds']} s -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
