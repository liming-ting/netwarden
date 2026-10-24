"""
Stage L: private AI - the settings registry, the OpenAI-compatible provider (Ollama,
LM Studio, llama.cpp, vLLM), where AI data goes, redaction before cloud calls, the
"preview what will be sent" and "test connection" endpoints.

Every model server here is a FAKE on an ephemeral 127.0.0.1 port; nothing ever talks to
Anthropic or any other real host.
"""
import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from netwarden import (activity, brain, demo, health, i18n, localai, redact, settings, store,
                       web)

AI_KEY = "nw-local-secret-0123456789"
ANT_KEY = "sk-ant-test-0123456789abcdef"


# --- a fake OpenAI-compatible server ---------------------------------------------------

def _chunk(text):
    return "data: " + json.dumps({"choices": [{"index": 0, "delta": {"content": text}}]}) + "\n\n"


class FakeOpenAI(BaseHTTPRequestHandler):
    """Plays /v1/chat/completions + /v1/models. `mode` picks the behaviour; every request
    is recorded (path, auth header, body)."""
    mode = "ok"
    seen = []
    reply = ["Hello ", "from ", "[D2]", " and [M", "2] at [IP", "2]."]
    models = ["llama3.2:latest", "qwen2.5:7b"]

    def _json(self, code, obj):
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        FakeOpenAI.seen.append({"path": self.path, "auth": self.headers.get("authorization")})
        if self.path.endswith("/models"):
            self._json(200, {"object": "list", "data": [{"id": m} for m in self.models]})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        raw = json.dumps(body, ensure_ascii=False)
        FakeOpenAI.seen.append({"path": self.path, "auth": self.headers.get("authorization"),
                                "body": body, "raw": raw})
        mode = FakeOpenAI.mode
        if mode == "slow":
            time.sleep(1.5)
        if mode == "no_model":
            self._json(404, {"error": {"message": f"model \"{body['model']}\" not found, try pulling it first"}})
            return
        if mode == "auth":
            self._json(401, {"error": {"message": "invalid api key"}})
            return
        if mode == "boom":
            self._json(500, {"error": {"message": "out of memory"}})
            return
        text = "".join(self.reply)
        if not body.get("stream") or mode == "json_only":
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant",
                                                                  "content": text}}]})
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        for part in self.reply:
            self.wfile.write(_chunk(part).encode())
            self.wfile.flush()
        if mode == "stream_error":
            self.wfile.write(b'data: {"error": {"message": "model crashed"}}\n\n')
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.write(_chunk("AFTER-DONE").encode())

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- settings registry -----------------------------------------------------------------

class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def test_defaults_env_db_precedence(self):
        self.assertEqual(settings.get(self.db, {}, "ai.provider"), "auto")
        settings.update(self.db, {}, {"ai.provider": "offline", "data.retention_days": 30})
        self.assertEqual(settings.get(self.db, {}, "ai.provider"), "offline")
        self.assertEqual(settings.get(self.db, {}, "data.retention_days"), 30)
        env = {"NETWARDEN_AI_PROVIDER": "anthropic"}
        self.assertEqual(settings.get(self.db, env, "ai.provider"), "anthropic")   # env wins
        item = {i["key"]: i for i in settings.describe(self.db, env, "en")["items"]}
        self.assertEqual(item["ai.provider"]["source"], "env")
        self.assertFalse(item["ai.provider"]["editable"])
        self.assertEqual(item["data.retention_days"]["source"], "db")
        self.assertEqual(item["ai.redact"]["source"], "default")
        # reset to default with "" / None
        settings.update(self.db, {}, {"ai.provider": ""})
        self.assertEqual(settings.get(self.db, {}, "ai.provider"), "auto")

    def test_validation_is_all_or_nothing(self):
        for changes, code in (({"ai.provider": "gpt"}, "setting_invalid"),
                              ({"data.retention_days": 3}, "setting_range"),
                              ({"data.retention_days": True}, "setting_invalid"),
                              ({"ai.base_url": "ftp://x"}, "setting_url"),
                              ({"ai.base_url": "http://u:p@192.168.1.5:11434/v1"}, "setting_url"),
                              ({"ai.base_url": "http://h/v1?k=1"}, "setting_url"),
                              ({"ai.model": "bad model;rm"}, "setting_invalid"),
                              ({"ai.key": "abc"}, "setting_secret"),
                              ({"nope": 1}, "setting_unknown"),
                              ({"time.timezone": "Mars/Base"}, "setting_invalid"),
                              ({"ui.language": "xx"}, "setting_invalid"),
                              ({"ai.model": 5}, "setting_invalid")):
            with self.subTest(changes=changes):
                with self.assertRaises(settings.SettingError) as cm:
                    settings.update(self.db, {}, {"ai.redact": "on", **changes})
                self.assertEqual(cm.exception.code, code)
        self.assertEqual(store.get_settings(self.db), {})          # nothing half-written
        with self.assertRaises(settings.SettingError) as cm:
            settings.update(self.db, {"NETWARDEN_AI_MODEL": "x"}, {"ai.model": "y"})
        self.assertEqual(cm.exception.code, "setting_env")

    def test_normalization(self):
        settings.update(self.db, {}, {"ai.base_url": "HTTP://LocalHost:11434/",
                                      "ui.language": "zh-tw", "time.timezone": "Asia/Taipei"})
        v = settings.values(self.db, {})
        self.assertEqual(v["ai.base_url"], "http://localhost:11434/v1")
        self.assertEqual(v["ui.language"], "zh-Hant")
        self.assertEqual(settings.get(self.db, {"NETWARDEN_LANG": "繁體中文"}, "ui.language"), "zh-Hant")

    def test_env_quirks_kept(self):
        # RETENTION_DAYS below the minimum has always meant the minimum; junk -> default
        self.assertEqual(settings.get(None, {"NETWARDEN_RETENTION_DAYS": "3"}, "data.retention_days"), 8)
        self.assertEqual(settings.get(None, {"NETWARDEN_RETENTION_DAYS": "x"}, "data.retention_days"), 90)
        # a URL with credentials in the environment is ignored, never used
        self.assertEqual(settings.get(None, {"NETWARDEN_AI_BASE_URL": "http://a:b@h/v1"}, "ai.base_url"), "")

    def test_secrets_never_stored_or_returned(self):
        env = {"NETWARDEN_AI_KEY": AI_KEY, "ANTHROPIC_API_KEY": ANT_KEY}
        d = settings.describe(self.db, env, "zh-Hant")
        text = json.dumps(d, ensure_ascii=False)
        self.assertNotIn(AI_KEY, text)
        self.assertNotIn(ANT_KEY, text)
        item = {i["key"]: i for i in d["items"]}
        self.assertTrue(item["ai.key"]["configured"])
        self.assertNotIn("value", item["ai.key"])
        self.assertFalse(settings.describe(self.db, {}, "en")["items"][-1]["configured"])
        self.assertEqual(item["ai.provider"]["label"], i18n.t("settings.ai.provider", "zh-Hant"))

    def test_env_keys_are_loaded_from_environment(self):
        for k in ("NETWARDEN_AI_PROVIDER", "NETWARDEN_AI_BASE_URL", "NETWARDEN_AI_MODEL",
                  "NETWARDEN_AI_REDACT", "NETWARDEN_AI_KEY"):
            self.assertIn(k, brain.ENV_KEYS)

    def test_timezone_setting_reaches_activity(self):
        settings.update(self.db, {}, {"time.timezone": "Asia/Tokyo"})
        try:
            settings.apply(self.db, {})
            self.assertEqual(activity.SETTING_TZ, "Asia/Tokyo")
        finally:
            activity.SETTING_TZ = None

    def test_destination(self):
        cases = {None: "none", "": "none", "http://127.0.0.1:11434/v1": "local",
                 "http://localhost:1234/v1": "local", "http://[::1]:8080/v1": "local",
                 "http://192.168.1.20:11434/v1": "lan", "http://192.168.0.5/v1": "lan",
                 "http://ollama.local:11434/v1": "lan", "http://gpu-box:8000/v1": "lan",
                 "http://169.254.1.1/v1": "lan", "https://api.openai.com/v1": "cloud",
                 "http://8.8.8.8/v1": "cloud", "https://127.0.0.1.nip.io/v1": "cloud"}
        for url, want in cases.items():
            self.assertEqual(settings.destination(url), want, url)


# --- which AI answers ---------------------------------------------------------------------

class AiConfigTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def test_auto_keeps_todays_behaviour(self):
        cfg = brain.ai_config({"ANTHROPIC_API_KEY": ANT_KEY}, self.db)
        self.assertEqual((cfg["mode"], cfg["destination"], cfg["redact"]), ("anthropic", "cloud", True))
        self.assertEqual(brain.ai_config({}, self.db)["reason"], "no_key")
        # a base URL alone -> the local server; the key still wins in auto mode
        settings.update(self.db, {}, {"ai.base_url": "http://127.0.0.1:11434/v1", "ai.model": "llama3.2"})
        cfg = brain.ai_config({}, self.db)
        self.assertEqual((cfg["mode"], cfg["destination"], cfg["redact"], cfg["provider"]),
                         ("openai_compat", "local", False, "Ollama"))
        self.assertEqual(brain.ai_mode({"ANTHROPIC_API_KEY": ANT_KEY}, self.db), "anthropic")

    def test_explicit_choices(self):
        settings.update(self.db, {}, {"ai.provider": "openai_compat"})
        cfg = brain.ai_config({"ANTHROPIC_API_KEY": ANT_KEY}, self.db)
        self.assertEqual((cfg["mode"], cfg["base_url"]), ("openai_compat", localai.OLLAMA_BASE))
        settings.update(self.db, {}, {"ai.provider": "offline"})
        self.assertEqual(brain.offline_reason({"ANTHROPIC_API_KEY": ANT_KEY}, self.db), "chosen")
        self.assertEqual(brain.offline_reason({brain.OFFLINE_ENV: "1"}, self.db), "forced")
        settings.update(self.db, {}, {"ai.provider": "anthropic"})
        self.assertEqual(brain.offline_reason({}, self.db), "no_key")
        self.assertIsInstance(brain.provider_from_env({}, self.db), brain.offline_ai.OfflineProvider)

    def test_redact_setting(self):
        settings.update(self.db, {}, {"ai.provider": "openai_compat",
                                      "ai.base_url": "https://llm.example.com/v1"})
        self.assertTrue(brain.ai_config({}, self.db)["redact"])        # cloud -> on
        settings.update(self.db, {}, {"ai.redact": "off"})
        self.assertFalse(brain.ai_config({}, self.db)["redact"])
        settings.update(self.db, {}, {"ai.redact": "on", "ai.base_url": "http://192.168.1.9:8000/v1"})
        self.assertTrue(brain.ai_config({}, self.db)["redact"])        # forced on for LAN
        p = brain.provider_from_env({"NETWARDEN_AI_KEY": AI_KEY}, self.db)
        self.assertIsInstance(p, localai.OpenAICompatibleProvider)
        self.assertTrue(p.redact)
        self.assertEqual(p.destination, "lan")

    def test_describe_never_leaks(self):
        settings.update(self.db, {}, {"ai.base_url": "http://192.168.1.9:8000/v1", "ai.model": "m"})
        d = brain.describe_provider({"NETWARDEN_AI_KEY": AI_KEY}, self.db)
        self.assertEqual(d, {"provider": "192.168.1.9:8000", "model": "m", "ai_mode": "openai_compat",
                             "ai_destination": "lan", "ai_redact": False})
        self.assertNotIn("http", json.dumps(d))

    def test_health_line_names_destination(self):
        st = {"mode": "openai_compat", "model": "llama3.2", "destination": "local",
              "provider": "Ollama", "redact": False}
        line = health.ai_line(st, "en")
        self.assertIn("llama3.2", line)
        self.assertIn(i18n.t("ai.dest.local", "en"), line)
        cloud = health.ai_line({**st, "destination": "cloud", "redact": True}, "zh-Hant")
        self.assertIn(i18n.t("ai.redact_on", "zh-Hant"), cloud)
        self.assertIn(i18n.t("status.ai.offline_chosen", "en"),
                      health.ai_line({"mode": "offline", "model": "offline", "reason": "chosen"}, "en"))


# --- the OpenAI-compatible provider ---------------------------------------------------------

class OpenAICompatibleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _serve(FakeOpenAI)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeOpenAI.mode, FakeOpenAI.seen = "ok", []
        self.p = localai.OpenAICompatibleProvider(self.base, "llama3.2", api_key=AI_KEY, timeout=5)

    def test_stream(self):
        out = list(self.p.stream("SYS", "USER", max_tokens=99))
        self.assertEqual("".join(out), "".join(FakeOpenAI.reply))   # stops at [DONE]
        req = FakeOpenAI.seen[0]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["auth"], f"Bearer {AI_KEY}")
        self.assertEqual(req["body"]["messages"], [{"role": "system", "content": "SYS"},
                                                   {"role": "user", "content": "USER"}])
        self.assertTrue(req["body"]["stream"])
        self.assertEqual(req["body"]["max_tokens"], 99)

    def test_complete_and_non_streaming_fallback(self):
        self.assertEqual(self.p.complete("s", "u"), "".join(FakeOpenAI.reply).strip())
        self.assertFalse(FakeOpenAI.seen[0]["body"]["stream"])
        FakeOpenAI.mode = "json_only"        # a server that ignores "stream": true
        self.assertEqual("".join(self.p.stream("s", "u")), "".join(FakeOpenAI.reply).strip())

    def test_models(self):
        self.assertEqual(self.p.models(), sorted(FakeOpenAI.models))
        self.assertEqual(FakeOpenAI.seen[0]["path"], "/v1/models")

    def test_typed_errors(self):
        for mode, kind in (("no_model", "model_not_found"), ("auth", "auth"), ("boom", "http")):
            FakeOpenAI.mode = mode
            with self.subTest(mode=mode), self.assertRaises(brain.LLMError) as cm:
                list(self.p.stream("s", "u"))
            self.assertEqual(cm.exception.kind, kind)
        FakeOpenAI.mode = "stream_error"
        with self.assertRaises(brain.LLMError) as cm:
            list(self.p.stream("s", "u"))
        self.assertIn("model crashed", str(cm.exception))
        with self.assertRaises(brain.LLMError) as cm:
            localai.OpenAICompatibleProvider(self.base, "").complete("s", "u")
        self.assertEqual(cm.exception.kind, "no_model")

    def test_connection_refused_is_local_unreachable(self):
        p = localai.OpenAICompatibleProvider(f"http://127.0.0.1:{_free_port()}/v1", "m", timeout=3)
        with self.assertRaises(brain.LLMError) as cm:
            p.complete("s", "u")
        self.assertEqual(cm.exception.kind, "local_unreachable")
        text = brain.llm_error_text(cm.exception, "en")
        self.assertIn("Ollama", text)

    def test_connect_that_hangs_is_unreachable_not_timeout(self):
        # WSL's mirrored loopback drops instead of refusing: the connect times out.
        # That must fail fast as "unreachable", with the short connect timeout, while
        # the read timeout (for a slow model) stays long.
        seen = []

        def hang(address, timeout=None, *a, **kw):
            seen.append(timeout)
            raise socket.timeout("timed out")
        p = localai.OpenAICompatibleProvider("http://127.0.0.1:9/v1", "m", timeout=120)
        orig = socket.create_connection
        socket.create_connection = hang
        try:
            with self.assertRaises(brain.LLMError) as cm:
                p.complete("s", "u")
        finally:
            socket.create_connection = orig
        self.assertEqual(cm.exception.kind, "local_unreachable")
        self.assertEqual(seen, [localai.CONNECT_TIMEOUT])

    def test_slow_answer_keeps_read_timeout(self):
        # connecting is instant, the answer takes longer than CONNECT_TIMEOUT
        old, localai.CONNECT_TIMEOUT = localai.CONNECT_TIMEOUT, 0.2
        FakeOpenAI.mode = "slow"             # answers after 1.5 s
        try:
            self.assertEqual(self.p.complete("s", "u"), "".join(FakeOpenAI.reply).strip())
        finally:
            localai.CONNECT_TIMEOUT = old

    def test_timeout(self):
        FakeOpenAI.mode = "slow"
        p = localai.OpenAICompatibleProvider(self.base, "m", timeout=0.3)
        with self.assertRaises(brain.LLMError) as cm:
            p.complete("s", "u")
        self.assertEqual(cm.exception.kind, "timeout")

    def test_check_connection(self):
        res = localai.check_connection(self.p, [AI_KEY])
        self.assertTrue(res["ok"])
        self.assertEqual(res["models"], sorted(FakeOpenAI.models))
        self.assertTrue(res["model_found"])            # "llama3.2" ~ "llama3.2:latest"
        self.assertTrue(res["reply"])
        FakeOpenAI.mode = "no_model"
        res = localai.check_connection(self.p, [AI_KEY])
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "model_not_found")
        down = localai.OpenAICompatibleProvider(f"http://127.0.0.1:{_free_port()}/v1", "m")
        res = localai.check_connection(down)
        self.assertEqual(res["error_kind"], "local_unreachable")

    def test_server_label(self):
        self.assertEqual(localai.server_label("http://127.0.0.1:11434/v1"), "Ollama")
        self.assertEqual(localai.server_label("http://127.0.0.1:1234/v1"), "LM Studio")
        self.assertEqual(localai.server_label("http://gpu:8000/v1"), "gpu:8000")


# --- redaction ------------------------------------------------------------------------------

class RedactorTests(unittest.TestCase):
    def test_trie_matches_flat_alternation(self):
        # the prefix-tree regex must find exactly what "longest name first" would
        import re
        names = ["TV", "TVBox", "tv-2", "Tablet", "tab", "爸爸", "爸爸的手機", "Mom's iPad",
                 "iPad", "a.b", "-x-", "ps5", "PS5 Pro"]

        def flat(text):
            alts = []
            for f in sorted({n.lower() for n in names}, key=lambda f: (-len(f), f)):
                p = re.escape(f)
                if f[0].isascii() and f[0].isalnum():
                    p = r"(?<![A-Za-z0-9])" + p
                if f[-1].isascii() and f[-1].isalnum():
                    p += r"(?![A-Za-z0-9])"
                alts.append(p)
            return [m.group(0) for m in re.finditer("|".join(alts), text, re.I)]
        rx = re.compile(redact._trie({n.lower() for n in names}), re.I)
        for text in ("the tv and TVBox, tv-2 and tvs; Tablet tab tabs 爸爸的手機 爸爸",
                     "Mom's iPad / iPads / xiPad", "a.b a.bc -x-y PS5 Pro ps5pro ps5,PS5 Prox"):
            with self.subTest(text=text):
                self.assertEqual([m.group(0) for m in rx.finditer(text)], flat(text))

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)
        store.set_label(cls.db, "a6:71:0c:9d:4e:f2", '爸爸的 "iPhone"', "")
        cls.snap = brain.snapshot(cls.db, hours=100000)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def setUp(self):
        self.r = redact.Redactor.build(self.db, self.snap)

    def test_round_trip(self):
        text = ('爸爸的 "iPhone" (a6:71:0c:9d:4e:f2, 192.168.1.21?) and DESKTOP-7Q2K9LM in 書房; '
                '小孩 uses TikTok; also AA-BB-CC-DD-EE-FF and 192.168.9.9 but 8.8.8.8 stays.')
        red = self.r.redact(text)
        for real in ('爸爸的 "iPhone"', "a6:71:0c:9d:4e:f2", "DESKTOP-7Q2K9LM", "書房", "小孩",
                     "AA-BB-CC-DD-EE-FF", "192.168.9.9"):
            self.assertNotIn(real, red)
        self.assertIn("TikTok", red)
        self.assertIn("8.8.8.8", red)
        self.assertEqual(self.r.unredact(red).replace("爸爸的 \"iPhone\"", "X"),
                         text.replace("爸爸的 \"iPhone\"", "X"))
        self.assertTrue(self.r.legend())

    def test_stable_and_json_escaped(self):
        a = self.r.redact("DESKTOP-7Q2K9LM")
        self.assertEqual(redact.Redactor.build(self.db, self.snap).redact("desktop-7q2k9lm"), a)
        self.assertNotIn("iPhone", self.r.redact(json.dumps('爸爸的 "iPhone"', ensure_ascii=False)))

    def test_word_boundaries(self):
        r = redact.Redactor()
        r.add("[D1]", "TV", "TV")
        self.assertEqual(r.redact("TV and TVBox and myTV"), "[D1] and TVBox and myTV")
        r.add("[D2]", "x", "x")               # single characters are never names
        self.assertEqual(r.redact("x"), "x")

    def test_split_stream_chunks(self):
        r = redact.Redactor()
        r.add("[D3]", "小孩的平板", "小孩的平板")
        r.add("[IP12]", "192.168.1.42", "192.168.1.42")
        text = "Look at [D3] - it is [IP12]; [link](x) and [D99] stay, [ alone too ["
        want = r.unredact(text)
        self.assertIn("小孩的平板", want)
        self.assertIn("[D99]", want)
        for size in range(1, len(text) + 1):        # every chunk size, every split point
            chunks = [text[i:i + size] for i in range(0, len(text), size)]
            self.assertEqual("".join(r.unredact_stream(chunks)), want, size)
        self.assertEqual("".join(r.unredact_stream(["[D", "3", "]!"])), "小孩的平板!")


class FakeCloudTests(unittest.TestCase):
    """The acceptance test: with redaction on, NOTHING household-identifying reaches the
    (fake) cloud model, and the reply comes back with the real names."""

    @classmethod
    def setUpClass(cls):
        cls.srv = _serve(FakeOpenAI)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)
        store.set_label(cls.db, "9e:88:44:21:af:30", "小明的平板", "")
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.db.close()
        cls.tmp.cleanup()

    def setUp(self):
        FakeOpenAI.mode, FakeOpenAI.seen = "ok", []

    def _identifiers(self):
        out = set()
        for r in self.db.execute("SELECT mac, ip, hostname FROM devices"):
            out |= {r["mac"], r["ip"], r["hostname"]}
        for p in store.get_profiles(self.db).values():
            out |= {p["owner"], p["room"]}
        out |= {v["label"] for v in store.get_labels(self.db).values()}
        return {x for x in out if x}

    def _cloud(self):
        p = localai.OpenAICompatibleProvider(self.base, "cloud-model", destination="cloud")
        p.redact = True
        return p

    def test_stream_chat_sends_no_identifiers(self):
        msgs = [{"role": "user", "content": "小明的平板 (9e:88:44:21:af:30) 半夜在做什麼?爸爸的電腦呢?"},
                {"role": "assistant", "content": "DESKTOP-7Q2K9LM 在書房很安靜。"},
                {"role": "user", "content": "那 192.168.1.13 呢?"}]
        out = "".join(brain.stream_reply(self.db, self._cloud(), "chat", msgs, hours=100000,
                                         lang="zh-Hant", mac="9e:88:44:21:af:30"))
        raw = FakeOpenAI.seen[0]["raw"]
        leaked = [x for x in self._identifiers() if x.lower() in raw.lower()
                  and x not in ("tplinkwifi.net",)]       # (also a looked-up domain: redacted too)
        self.assertEqual(leaked, [])
        self.assertNotIn("tplinkwifi.net", raw)
        self.assertIn("[D", raw)
        self.assertIn("[P", raw)
        self.assertIn("TikTok", raw)                         # services stay useful
        self.assertNotIn("[D2]", out)                        # mapped back ...
        self.assertNotIn("[M", out)
        r = redact.Redactor.build(self.db, brain.snapshot(self.db, hours=100000))
        self.assertIn(r.real["[D2]"], out)                    # ... to the real name
        self.assertIn(r.real["[M2]"], out)                    # (split across chunks: "[M" + "2]")

    def test_insight_and_complete_paths(self):
        brain.insights(self.db, self._cloud(), hours=100000, lang="en")
        brain.ask(self.db, self._cloud(), "What does 小明的平板 do?", hours=100000, lang="en")
        for req in FakeOpenAI.seen:
            for x in self._identifiers():
                self.assertNotIn(x.lower(), req["raw"].lower(), x)

    def test_local_destination_is_not_redacted(self):
        p = localai.OpenAICompatibleProvider(self.base, "m")
        p.redact = False
        list(brain.stream_reply(self.db, p, "chat", [{"role": "user", "content": "小明的平板?"}],
                                hours=100000, lang="en"))
        self.assertIn("小明的平板", FakeOpenAI.seen[0]["raw"])

    def test_preview_matches_what_is_sent(self):
        env = {"NETWARDEN_AI_PROVIDER": "openai_compat", "NETWARDEN_AI_BASE_URL": self.base,
               "NETWARDEN_AI_MODEL": "m", "NETWARDEN_AI_REDACT": "on"}
        msgs = [{"role": "user", "content": "小明的平板?"}]
        prev = brain.preview(self.db, env, "chat", msgs, hours=100000, lang="en")
        self.assertEqual(FakeOpenAI.seen, [])                 # the preview calls no model
        self.assertTrue(prev["sends"] and prev["redact"])
        self.assertNotIn("小明的平板", prev["user"])
        self.assertIn({"token": next(l["token"] for l in prev["legend"] if l["real"] == "小明的平板"),
                       "real": "小明的平板"}, prev["legend"])
        p = brain.provider_from_env(env, self.db)
        list(brain.stream_reply(self.db, p, "chat", msgs, hours=100000, lang="en"))
        sent = FakeOpenAI.seen[0]["body"]["messages"]
        self.assertEqual(sent[1]["content"], prev["user"])
        self.assertEqual(sent[0]["content"], prev["system"])
        off = brain.preview(self.db, {brain.OFFLINE_ENV: "1"}, "insight", hours=100000)
        self.assertFalse(off["sends"])
        self.assertEqual(off["user"], "")


# --- the web endpoints ---------------------------------------------------------------------

class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai = _serve(FakeOpenAI)
        cls.base = f"http://127.0.0.1:{cls.ai.server_address[1]}/v1"
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.srv = web.make_server(cls.path, 0, {"NETWARDEN_AI_KEY": AI_KEY}, None, 100000)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.ai.shutdown()
        cls.ai.server_close()
        cls.tmp.cleanup()
        activity.SETTING_TZ = None

    def setUp(self):
        FakeOpenAI.mode, FakeOpenAI.seen = "ok", []
        web.Handler.env = {"NETWARDEN_AI_KEY": AI_KEY}
        db = store.connect(self.path)
        store.put_settings(db, {k: None for k in settings.REGISTRY if not settings.REGISTRY[k].secret})
        db.close()

    def _req(self, method, path, obj=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"content-type": "application/json", **(headers or {})}
        c.request(method, path, json.dumps(obj) if obj is not None else None, h)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, (json.loads(body) if body else None)

    def _set(self, values):
        return self._req("POST", "/api/settings", {"values": values, "lang": "en"})

    def test_get_settings_and_meta(self):
        code, s = self._req("GET", "/api/settings?lang=zh-Hant")
        self.assertEqual(code, 200)
        self.assertNotIn(AI_KEY, json.dumps(s))
        keys = {i["key"] for i in s["items"]}
        self.assertTrue({"ui.language", "time.timezone", "data.retention_days", "ai.provider",
                         "ai.base_url", "ai.model", "ai.redact", "ai.key"} <= keys)
        self.assertEqual(s["ai"]["ai_mode"], "offline")
        _, meta = self._req("GET", "/api/meta")
        self.assertEqual(meta["ai_destination"], "none")

    def test_post_settings_switches_ai_live(self):
        code, s = self._set({"ai.base_url": self.base, "ai.model": "llama3.2"})
        self.assertEqual(code, 200, s)
        self.assertEqual(s["ai"]["ai_mode"], "openai_compat")
        self.assertEqual(s["ai"]["ai_destination"], "local")
        _, meta = self._req("GET", "/api/meta")
        self.assertEqual((meta["ai_mode"], meta["ai_redact"]), ("openai_compat", False))
        self.assertNotIn(str(self.ai.server_address[1]) + "/v1", json.dumps(meta))
        # the chat now streams from the local server
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/chat/stream", json.dumps({"mode": "chat", "lang": "en",
                  "messages": [{"role": "user", "content": "hi"}]}), {"content-type": "application/json"})
        text = c.getresponse().read().decode()
        self.assertIn("event: done", text)
        self.assertEqual(FakeOpenAI.seen[0]["path"], "/v1/chat/completions")
        self.assertEqual(FakeOpenAI.seen[0]["auth"], f"Bearer {AI_KEY}")

    def test_post_settings_errors(self):
        code, j = self._set({"ai.provider": "skynet"})
        self.assertEqual((code, j["key"]), (400, "ai.provider"))
        self.assertEqual(j["error"], i18n.t("err.setting_invalid", "en"))
        self.assertEqual(self._set({"ai.key": "x"})[0], 400)
        self.assertEqual(self._set({})[0], 400)
        self.assertEqual(self._req("POST", "/api/settings", {"values": "x"})[0], 400)
        web.Handler.env = {"NETWARDEN_AI_MODEL": "pinned"}
        code, j = self._set({"ai.model": "other"})
        self.assertEqual((code, j["error"]), (400, i18n.t("err.setting_env", "en")))
        code, _ = self._req("POST", "/api/settings", {"values": {"ai.redact": "on"}},
                            {"origin": "http://evil.example"})
        self.assertEqual(code, 403)
        code, _ = self._req("POST", "/api/settings", {"values": {"ai.redact": "on"}},
                            {"content-type": "text/plain"})
        self.assertEqual(code, 415)

    def test_language_setting_changes_server_default(self):
        web.Handler.lang_pinned = False
        try:
            self._set({"ui.language": "ja"})
            _, meta = self._req("GET", "/api/meta")
            self.assertEqual(meta["default_lang"], "ja")
        finally:
            self._set({"ui.language": None})
            web.Handler.lang = "zh-Hant"

    def test_preview_endpoint(self):
        code, p = self._req("POST", "/api/chat/preview", {"mode": "insight", "lang": "en"})
        self.assertEqual((code, p["sends"]), (200, False))      # offline: nothing is sent
        self._set({"ai.provider": "openai_compat", "ai.base_url": self.base, "ai.model": "m",
                   "ai.redact": "on"})
        code, p = self._req("POST", "/api/chat/preview",
                            {"mode": "chat", "messages": [{"role": "user", "content": "DESKTOP-7Q2K9LM?"}]})
        self.assertEqual(code, 200)
        self.assertTrue(p["redact"])
        self.assertNotIn("DESKTOP-7Q2K9LM", p["user"])
        self.assertIn("DESKTOP-7Q2K9LM", [l["real"] for l in p["legend"]])
        self.assertEqual(FakeOpenAI.seen, [])
        self.assertEqual(self._req("POST", "/api/chat/preview", {"mode": "chat", "messages": []})[0], 400)
        self.assertEqual(self._req("POST", "/api/chat/preview", {"mode": "x"})[0], 400)

    def test_ai_test_endpoint(self):
        code, j = self._req("POST", "/api/ai/test", {})
        self.assertEqual(code, 409)                               # offline: nothing to test
        self._set({"ai.provider": "openai_compat", "ai.base_url": "https://llm.example.com/v1"})
        code, j = self._req("POST", "/api/ai/test", {"lang": "en"})
        self.assertEqual((code, j["error"]), (409, i18n.t("err.ai_test_cloud", "en")))
        self._set({"ai.base_url": self.base, "ai.model": "llama3.2"})
        code, j = self._req("POST", "/api/ai/test", {})
        self.assertEqual(code, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["models"], sorted(FakeOpenAI.models))
        self.assertEqual(j["destination"], "local")
        FakeOpenAI.mode = "no_model"
        code, j = self._req("POST", "/api/ai/test", {"lang": "en"})
        self.assertEqual((j["ok"], j["error_kind"]), (False, "model_not_found"))
        self.assertEqual(j["error_text"], i18n.t("err.llm_model_not_found", "en"))
        self.assertNotIn(AI_KEY, json.dumps(j))

    def test_chat_error_is_localized(self):
        self._set({"ai.provider": "openai_compat", "ai.base_url": f"http://127.0.0.1:{_free_port()}/v1",
                   "ai.model": "m"})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/chat/stream", json.dumps({"mode": "chat", "lang": "zh-Hant",
                  "messages": [{"role": "user", "content": "hi"}]}), {"content-type": "application/json"})
        text = c.getresponse().read().decode()
        self.assertIn("event: error", text)
        self.assertIn("Ollama", json.loads(text.split("event: error\ndata: ")[1].split("\n")[0])["error"])

    def test_status_reports_destination(self):
        self._set({"ai.base_url": self.base, "ai.model": "m", "data.retention_days": 45})
        _, st = self._req("GET", "/api/status?lang=en")
        self.assertEqual(st["ai"]["destination"], "local")
        self.assertEqual(st["db"]["retention_days"], 45)


if __name__ == "__main__":
    unittest.main()
