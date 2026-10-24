"""
netwarden - localai.py: AI that runs on hardware you own.

OpenAICompatibleProvider speaks the OpenAI-style HTTP API that local model servers
share - Ollama (http://127.0.0.1:11434/v1), LM Studio (:1234/v1), the llama.cpp server
(:8080/v1) and vLLM (:8000/v1) - over plain stdlib urllib:

    POST <base>/chat/completions   streaming (server-sent events) or one JSON answer
    GET  <base>/models             the models the server offers ("Test connection")

It has the same .complete(system, user) / .stream(system, user) interface as
brain.AnthropicProvider, so the chat UI and the streaming endpoint need no changes.
Failures become brain.LLMError with a kind the UI localizes: "local_unreachable" (is
Ollama running?), "model_not_found", "no_model", "timeout", "auth", "http", ...

For a local or LAN server the requests bypass any HTTP proxy from the environment (the
data must not take a detour) and redirects are only followed to the same origin (an
optional NETWARDEN_AI_KEY bearer token must not travel anywhere else).
"""
from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from netwarden import health, settings

OLLAMA_BASE = "http://127.0.0.1:11434/v1"

# well-known ports of local model servers -> the name we show next to the model
KNOWN_PORTS = {11434: "Ollama", 1234: "LM Studio"}


def _err(message: str, kind: str):
    from netwarden import brain   # brain imports us
    return brain.LLMError(message, kind)


def server_label(base_url: str) -> str:
    """"Ollama" / "LM Studio" for their default ports, else host:port. Never the path
    or anything that could carry credentials (clean_base_url refuses userinfo anyway)."""
    u = urllib.parse.urlsplit(base_url)
    if u.port in KNOWN_PORTS:
        return KNOWN_PORTS[u.port]
    host = u.hostname or "?"
    host = f"[{host}]" if ":" in host else host
    return f"{host}:{u.port}" if u.port else host


def _is_timeout(e) -> bool:
    return isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in str(e).lower()


CONNECT_TIMEOUT = 5.0   # reaching the server; the answer itself may take much longer


class ConnectFailed(OSError):
    """The TCP connection to the AI server could not be opened (refused, no route, or
    no answer within CONNECT_TIMEOUT - e.g. WSL's mirrored loopback drops instead of
    refusing a closed port)."""


def _fast_connect(conn_cls):
    """An http.client connection class that gives up connecting after CONNECT_TIMEOUT
    but keeps the (long) read timeout for the answer: a local model may need a minute
    to load, a server that is not running should fail in seconds."""
    class Conn(conn_cls):
        def connect(self):
            read = self.timeout
            if isinstance(read, (int, float)):
                self.timeout = min(read, CONNECT_TIMEOUT)
            try:
                super().connect()
            except OSError as e:
                raise ConnectFailed(str(e) or type(e).__name__) from None
            finally:
                self.timeout = read
            self.sock.settimeout(read)
    return Conn


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_fast_connect(http.client.HTTPConnection), req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_fast_connect(http.client.HTTPSConnection), req,
                            context=self._context)


class OpenAICompatibleProvider:
    """/v1/chat/completions + /v1/models over urllib (no SDK dependency).

    Usage (round 7 C): a streaming request asks for the token counts with
    stream_options.include_usage (the final chunk carries `usage`); a server that refuses
    that field gets the request again without it, remembered per server, and then the
    answer is counted with brain's local estimate."""
    prompt_cache = False    # no cache hints: servers with prefix caching do it themselves
    meter = None            # a usage.Meter brain sets per answer: we report into it
    _NO_USAGE_OPTION: set = set()   # base URLs that refused stream_options

    def __init__(self, base_url: str, model: str, api_key: str | None = None,
                 timeout: float = 120, destination: str | None = None):
        self.base_url = settings.clean_base_url(base_url or OLLAMA_BASE)
        self.model = model
        self.api_key = api_key or None
        self.timeout = timeout
        self.destination = destination or settings.destination(self.base_url)
        self.name = server_label(self.base_url)
        handlers = [health._SameOriginRedirect(), _HTTPHandler(), _HTTPSHandler()]
        if self.destination in ("local", "lan"):
            handlers.append(urllib.request.ProxyHandler({}))   # never via a proxy
        self._opener = urllib.request.build_opener(*handlers)

    # --- plumbing ---------------------------------------------------------------

    def _where(self) -> str:
        return server_label(self.base_url)

    def _open(self, path: str, body: dict | None = None, timeout: float | None = None,
              stream: bool = False):
        url = self.base_url + path
        tools = bool(body and body.get("tools"))
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
        if data:
            req.add_header("content-type", "application/json")
        req.add_header("accept", "text/event-stream" if stream else "application/json")
        if self.api_key:
            req.add_header("authorization", f"Bearer {self.api_key}")
        try:
            return self._opener.open(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as e:
            raise self._http_error(e, tools) from None
        except urllib.error.URLError as e:
            reason = e.reason
            if _is_timeout(reason) and not isinstance(reason, ConnectFailed):
                raise _err(f"AI server {self._where()} timed out", "timeout") from None
            kind = "local_unreachable" if self.destination in ("local", "lan") else "unreachable"
            raise _err(f"Can't reach AI server {self._where()}: {reason}", kind) from None
        except OSError as e:
            if _is_timeout(e) and not isinstance(e, ConnectFailed):
                raise _err(f"AI server {self._where()} timed out", "timeout") from None
            kind = "local_unreachable" if self.destination in ("local", "lan") else "unreachable"
            raise _err(f"Can't reach AI server {self._where()}: {e}", kind) from None

    def _http_error(self, e: urllib.error.HTTPError, tools: bool = False):
        try:
            raw = e.read(4096).decode("utf-8", "ignore")
        except OSError:
            raw = ""
        detail = raw
        try:
            j = json.loads(raw)
            err = j.get("error")
            detail = (err.get("message") if isinstance(err, dict) else err) or j.get("message") or raw
        except (ValueError, AttributeError):
            pass
        detail = str(detail)[:300]
        from netwarden import brain   # brain imports us
        if tools and brain.tools_refused(e.code, detail):
            # e.g. Ollama: "registry.ollama.ai/library/gemma:2b does not support tools"
            return brain.ToolsUnsupported(f"AI server {e.code}: {detail}")
        if e.code in (401, 403):
            return _err(f"AI server {e.code}: {detail}", "auth")
        if e.code == 404 and "model" in detail.lower():
            return _err(f"model {self.model!r} not found: {detail}", "model_not_found")
        return _err(f"AI server {e.code}: {detail}", "http")

    def _body(self, system: str, user: str, max_tokens: int, stream: bool) -> dict:
        if not self.model:
            raise _err("no model chosen (ai.model)", "no_model")
        return {"model": self.model, "max_tokens": max_tokens, "stream": stream,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}

    def _chat(self, body: dict, stream: bool):
        """POST /chat/completions; a stream asks for usage unless this server refused it."""
        if stream and self.base_url not in self._NO_USAGE_OPTION:
            body = {**body, "stream_options": {"include_usage": True}}
        try:
            return self._open("/chat/completions", body, stream=stream)
        except Exception as e:   # noqa: BLE001 - only a refusal of the usage field is retried
            if "stream_options" not in body or getattr(e, "kind", None) != "http" \
                    or "stream_options" not in str(e):
                raise
            self._NO_USAGE_OPTION.add(self.base_url)
            body = {k: v for k, v in body.items() if k != "stream_options"}
            return self._open("/chat/completions", body, stream=stream)

    def _report(self, usage) -> None:
        """OpenAI-style usage -> the meter. prompt_tokens includes the cached ones."""
        if self.meter is None or not isinstance(usage, dict):
            return
        def n(v):
            return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0
        details = usage.get("prompt_tokens_details")
        cached = n(details.get("cached_tokens")) if isinstance(details, dict) else 0
        prompt = n(usage.get("prompt_tokens"))
        self.meter.report(input_tokens=max(0, prompt - cached),
                          output_tokens=n(usage.get("completion_tokens")), cache_read=cached)

    @staticmethod
    def _text(data: dict) -> str:
        """The answer text of a non-streaming chat completion."""
        choices = data.get("choices") or []
        msg = (choices[0].get("message") or {}) if choices and isinstance(choices[0], dict) else {}
        return (msg.get("content") or "").strip()

    # --- the provider interface ----------------------------------------------------

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        with self._chat(self._body(system, user, max_tokens, False), stream=False) as resp:
            try:
                data = json.load(resp)
                self._report(data.get("usage") if isinstance(data, dict) else None)
                return self._text(data)
            except (ValueError, OSError) as e:
                if _is_timeout(e):
                    raise _err(f"AI server {self._where()} timed out", "timeout") from None
                raise _err(f"AI server {self._where()}: unreadable answer", "http") from None

    def stream(self, system: str, user: str, max_tokens: int = 1200):
        """Yield the answer as it is generated. A server that ignores "stream": true and
        answers with one JSON document still works (non-streaming fallback). Closing
        the generator closes the HTTP connection, which stops the generation."""
        from netwarden.brain import sse_events
        with self._chat(self._body(system, user, max_tokens, True), stream=True) as resp:
            ctype = (resp.headers.get("content-type") or "").lower()
            try:
                if "text/event-stream" not in ctype:
                    data = json.load(resp)
                    self._report(data.get("usage") if isinstance(data, dict) else None)
                    text = self._text(data)
                    if text:
                        yield text
                    return
                for _event, data in sse_events(resp):
                    if data.get("raw") == "[DONE]":
                        return
                    if data.get("error"):
                        err = data["error"]
                        msg = err.get("message") if isinstance(err, dict) else str(err)
                        raise _err(f"AI server: {msg}", "http")
                    self._report(data.get("usage"))
                    for ch in data.get("choices") or []:
                        delta = (ch.get("delta") or {}) if isinstance(ch, dict) else {}
                        if delta.get("content"):
                            yield delta["content"]
            except ValueError:
                raise _err(f"AI server {self._where()}: unreadable answer", "http") from None
            except OSError as e:
                if _is_timeout(e):
                    raise _err(f"AI server {self._where()} timed out", "timeout") from None
                raise _err(f"AI server stream interrupted: {e}", "interrupted") from None

    # --- Stage A: function calling ------------------------------------------------------

    @staticmethod
    def wire(system: str, conv: list) -> list:
        """brain's provider-neutral conversation -> chat-completions messages: tool calls
        ride on the assistant message, each result is its own "tool" message."""
        out = [{"role": "system", "content": system}]
        for m in conv:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                text = m.get("text") or ""
                out.append({"role": "assistant", "content": text if text.strip() else "",
                            "tool_calls": [{"id": c["id"], "type": "function",
                                            "function": {"name": c["name"],
                                                         "arguments": json.dumps(c.get("args") or {},
                                                                                 ensure_ascii=False)}}
                                           for c in m.get("calls") or []]})
            elif m["role"] == "tool":
                out += [{"role": "tool", "tool_call_id": r["id"], "name": r["name"],
                         "content": r["content"]} for r in m["results"]]
        return out

    def stream_turn(self, system: str, conv: list, tools: list, max_tokens: int = 1200,
                    allow_tools: bool = True):
        """One model turn with function calling: yields ("text", chunk) while it streams
        and, at the end, ("call", {id, name, args, ok}) per tool call - assembled from
        the streamed tool_calls deltas (by index; arguments arrive as JSON pieces), or
        taken whole from a server that answers with one JSON document. allow_tools=False
        sends tool_choice "none" (the round cap). A server / model that refuses tools
        raises brain.ToolsUnsupported (brain then answers without them)."""
        from netwarden.brain import parse_args, sse_events
        if not self.model:
            raise _err("no model chosen (ai.model)", "no_model")
        body = {"model": self.model, "max_tokens": max_tokens, "stream": True,
                "messages": self.wire(system, conv),
                "tools": [{"type": "function", "function": {
                    "name": t["name"], "description": t["description"],
                    "parameters": t["parameters"]}} for t in tools]}
        if not allow_tools:
            body["tool_choice"] = "none"
        calls: dict = {}

        def take(tool_calls, whole=False):
            for pos, tc in enumerate(tool_calls or []):
                if not isinstance(tc, dict):
                    continue
                # The stream's `index` says which call a piece belongs to. Without one (some
                # servers): a new id is a new call, a piece without an id continues the
                # latest call - never merge two calls into one with broken arguments. A
                # whole (non-streamed) message lists each call once.
                if tc.get("index") is not None:
                    idx = ("i", tc["index"])
                elif whole:
                    idx = ("i", pos)
                elif tc.get("id"):
                    idx = ("id", str(tc["id"]))
                elif calls:
                    idx = next(reversed(calls))
                else:
                    idx = ("i", pos)
                c = calls.setdefault(idx, {"id": None, "name": "", "args": []})
                if tc.get("id"):
                    c["id"] = str(tc["id"])
                fn = tc.get("function") or {}
                if fn.get("name") and not c["name"]:
                    c["name"] = str(fn["name"])
                a = fn.get("arguments")
                if isinstance(a, dict):        # some servers send the object itself
                    c["args"] = [json.dumps(a)]
                elif isinstance(a, str):
                    c["args"].append(a)

        with self._chat(body, stream=True) as resp:
            ctype = (resp.headers.get("content-type") or "").lower()
            try:
                if "text/event-stream" not in ctype:
                    data = json.load(resp)
                    self._report(data.get("usage") if isinstance(data, dict) else None)
                    choices = data.get("choices") or []
                    msg = (choices[0].get("message") or {}) if choices and isinstance(choices[0], dict) else {}
                    if msg.get("content"):
                        yield "text", msg["content"]
                    take(msg.get("tool_calls"), whole=True)
                else:
                    for _event, data in sse_events(resp):
                        if data.get("raw") == "[DONE]":
                            break
                        if data.get("error"):
                            err = data["error"]
                            msg = err.get("message") if isinstance(err, dict) else str(err)
                            raise _err(f"AI server: {msg}", "http")
                        self._report(data.get("usage"))
                        for ch in data.get("choices") or []:
                            delta = (ch.get("delta") or {}) if isinstance(ch, dict) else {}
                            if delta.get("content"):
                                yield "text", delta["content"]
                            take(delta.get("tool_calls"))
            except ValueError:
                raise _err(f"AI server {self._where()}: unreadable answer", "http") from None
            except OSError as e:
                if _is_timeout(e):
                    raise _err(f"AI server {self._where()} timed out", "timeout") from None
                raise _err(f"AI server stream interrupted: {e}", "interrupted") from None
        for n, c in enumerate(calls.values()):     # in the order the calls began
            args, ok = parse_args("".join(c["args"]))
            yield "call", {"id": c["id"] or f"call_{n}", "name": c["name"], "args": args, "ok": ok}

    def models(self, timeout: float = 5) -> list:
        """Model ids the server offers (GET /models), sorted."""
        with self._open("/models", timeout=timeout) as resp:
            try:
                data = json.load(resp)
            except ValueError:
                raise _err(f"AI server {self._where()}: unreadable model list", "http") from None
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            rows = data.get("models", []) if isinstance(data, dict) else []
        ids = {str(r.get("id") or r.get("name") or "") for r in rows if isinstance(r, dict)}
        return sorted(i for i in ids if i)[:200]


def check_connection(provider: OpenAICompatibleProvider, secrets=()) -> dict:
    """"Test connection" (explicit click only, local / LAN servers only): list the
    models, then - if a model is chosen - ask for a one-word reply. Never raises;
    returns {ok, models, model, model_found, reply, latency_ms, error_kind, error}."""
    out = {"ok": False, "server": provider.name, "model": provider.model, "models": [],
           "model_found": None, "reply": None, "latency_ms": None,
           "error_kind": None, "error": None}
    t0 = time.monotonic()
    try:
        out["models"] = provider.models()
        if provider.model:
            out["model_found"] = (not out["models"]) or provider.model in out["models"] or \
                any(m.split(":")[0] == provider.model for m in out["models"])
            reply = provider.complete("You are a connection test. Reply with one word.",
                                      "Say OK.", max_tokens=8)
            out["reply"] = " ".join(reply.split())[:80]
        out["ok"] = True
    except Exception as e:   # noqa: BLE001 - the user sees the localized kind + detail
        out["error_kind"] = getattr(e, "kind", "http")
        out["error"] = health.sanitize_error(str(e), [s for s in secrets if s])
    out["latency_ms"] = int((time.monotonic() - t0) * 1000)
    return out
