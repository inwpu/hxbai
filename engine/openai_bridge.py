from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_BRIDGES: dict[str, tuple[ThreadingHTTPServer, int]] = {}
_BRIDGES_LOCK = threading.Lock()

_STOP_MAP = {"tool_calls": "tool_use", "length": "max_tokens", "stop": "end_turn",
             "content_filter": "end_turn"}


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if isinstance(b, dict):
            if b.get("type") == "text":
                out.append(b.get("text", ""))
            elif b.get("type") == "tool_result":
                out.append(_content_text(b.get("content")))
    return "\n".join(x for x in out if x)


def anthropic_to_openai(req: dict) -> dict:
    oai: dict = {"model": req.get("model", ""), "max_tokens": req.get("max_tokens", 4096)}
    if "temperature" in req:
        oai["temperature"] = req["temperature"]
    if "top_p" in req:
        oai["top_p"] = req["top_p"]
    if req.get("stop_sequences"):
        oai["stop"] = req["stop_sequences"]
    if req.get("stream"):
        oai["stream"] = True
        oai["stream_options"] = {"include_usage": True}
    msgs: list[dict] = []
    if req.get("system"):
        msgs.append({"role": "system", "content": _content_text(req["system"])})
    for m in req.get("messages") or []:
        role = m.get("role", "user")
        content = m.get("content")
        if isinstance(content, str):
            msgs.append({"role": role, "content": content})
            continue
        tool_calls, parts, tool_results = [], [], []
        for b in content or []:
            bt = b.get("type")
            if bt == "text":
                parts.append({"type": "text", "text": b.get("text", "")})
            elif bt == "thinking":
                continue
            elif bt == "image":
                src = b.get("source") or {}
                if src.get("type") == "base64":
                    parts.append({"type": "image_url", "image_url":
                                 {"url": f"data:{src.get('media_type', 'image/png')};base64,{src.get('data', '')}"}})
            elif bt == "tool_use":
                tool_calls.append({"id": b.get("id", ""), "type": "function",
                                   "function": {"name": b.get("name", ""),
                                                "arguments": json.dumps(b.get("input") or {}, ensure_ascii=False)}})
            elif bt == "tool_result":
                tool_results.append({"role": "tool", "tool_call_id": b.get("tool_use_id", ""),
                                     "content": _content_text(b.get("content")) or "(empty)"})
        msgs.extend(tool_results)
        if role == "assistant":
            if tool_calls or parts:
                msgs.append({"role": "assistant",
                             "content": ("".join(p.get("text", "") for p in parts) or None),
                             **({"tool_calls": tool_calls} if tool_calls else {})})
        else:
            if parts:
                msgs.append({"role": role, "content": parts})
            elif not tool_results:
                msgs.append({"role": role, "content": "(empty)"})
    oai["messages"] = msgs
    if req.get("tools"):
        oai["tools"] = [{"type": "function",
                         "function": {"name": t.get("name", ""),
                                      "description": t.get("description", ""),
                                      "parameters": t.get("input_schema") or {"type": "object"}}}
                        for t in req["tools"]]
    return oai


def openai_response_to_anthropic(model: str, resp: dict) -> dict:
    ch = (resp.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    blocks: list[dict] = []
    rc = msg.get("reasoning_content") or ""
    if rc:
        blocks.append({"type": "thinking", "thinking": rc})
    txt = msg.get("content")
    if txt:
        blocks.append({"type": "text", "text": txt})
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {"_raw": fn.get("arguments", "")}
        blocks.append({"type": "tool_use", "id": tc.get("id", ""), "name": fn.get("name", ""), "input": args})
    if not blocks:
        blocks.append({"type": "text", "text": ""})
    u = resp.get("usage") or {}
    return {"id": resp.get("id", ""), "type": "message", "role": "assistant", "model": model,
            "content": blocks,
            "stop_reason": _STOP_MAP.get(ch.get("finish_reason") or "", "end_turn"),
            "stop_sequence": None,
            "usage": {"input_tokens": u.get("prompt_tokens", 0), "output_tokens": u.get("completion_tokens", 0)}}


class _StreamState:

    def __init__(self, model: str):
        self.model = model
        self.events: list[str] = []
        self.open_block: int | None = None
        self.open_kind: str = ""
        self._next = 0
        self.tools: dict[int, dict] = {}
        self.finish = None
        self.usage = {}
        self.started = False

    def _emit(self, ev: dict) -> None:
        self.events.append("event: " + ev["type"] + "\ndata: "
                           + json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n\n")

    def start(self) -> None:
        import uuid
        self._emit({"type": "message_start", "message": {
            "id": "msg_bridge_" + uuid.uuid4().hex[:24], "type": "message",
            "role": "assistant", "model": self.model,
            "content": [], "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0}}})
        self.started = True

    def _close_open(self) -> None:
        if self.open_block is not None:
            self._emit({"type": "content_block_stop", "index": self.open_block})
            for t in self.tools.values():
                if t.get("block") == self.open_block:
                    t["open"] = False
            self.open_block, self.open_kind = None, ""

    def _open_block_as(self, kind: str, block: dict) -> int:
        self._close_open()
        idx = self._next
        self._next += 1
        self.open_block, self.open_kind = idx, kind
        self._emit({"type": "content_block_start", "index": idx, "content_block": block})
        return idx

    def text_delta(self, s: str) -> None:
        if self.open_kind != "text":
            self._open_block_as("text", {"type": "text", "text": ""})
        self._emit({"type": "content_block_delta", "index": self.open_block,
                    "delta": {"type": "text_delta", "text": s}})

    def thinking_delta(self, s: str) -> None:
        if self.open_kind != "thinking":
            self._open_block_as("thinking", {"type": "thinking", "thinking": ""})
        self._emit({"type": "content_block_delta", "index": self.open_block,
                    "delta": {"type": "thinking_delta", "thinking": s}})

    def tool_delta(self, idx: int, tc: dict) -> None:
        t = self.tools.setdefault(idx, {})
        fn = tc.get("function") or {}
        if tc.get("id"):
            t["id"] = tc["id"]
        if fn.get("name"):
            t["name"] = fn["name"]
        if not t.get("open"):
            t["open"] = True
            t["block"] = self._open_block_as(
                "tool", {"type": "tool_use", "id": t.get("id", ""), "name": t.get("name", ""), "input": {}})
        if fn.get("arguments"):
            self._emit({"type": "content_block_delta", "index": t["block"],
                        "delta": {"type": "input_json_delta", "partial_json": fn["arguments"]}})

    def finish_with(self, finish: str | None, usage: dict | None) -> list[str]:
        self._close_open()
        for t in self.tools.values():
            if t.get("open"):
                t["open"] = False
                self._emit({"type": "content_block_stop", "index": t["block"]})
        u = usage or {}
        self._emit({"type": "message_delta",
                    "delta": {"stop_reason": _STOP_MAP.get(finish or "", "end_turn"), "stop_sequence": None},
                    "usage": {"input_tokens": u.get("prompt_tokens", 0),
                              "output_tokens": u.get("completion_tokens", 0)}})
        self._emit({"type": "message_stop"})
        return self.events


def openai_stream_to_anthropic_sse(model: str, upstream_lines) -> list[str]:
    st = _StreamState(model)
    st.start()
    for raw in upstream_lines:
        line = raw.decode("utf-8", "replace").strip() if isinstance(raw, bytes) else raw.strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue
        if chunk.get("usage"):
            st.usage = chunk["usage"]
        for ch in chunk.get("choices") or []:
            delta = ch.get("delta") or {}
            if delta.get("reasoning_content"):
                st.thinking_delta(delta["reasoning_content"])
            if delta.get("content"):
                st.text_delta(delta["content"])
            for tc in delta.get("tool_calls") or []:
                st.tool_delta(tc.get("index", 0), tc)
            if ch.get("finish_reason"):
                st.finish = ch["finish_reason"]
    return st.finish_with(st.finish, st.usage)


class _Handler(BaseHTTPRequestHandler):
    upstream = ""

    def log_message(self, *a):
        pass

    def do_POST(self):
        from urllib.parse import urlsplit
        path = urlsplit(self.path).path.rstrip("/")
        if not path.endswith("/v1/messages"):
            self.send_error(404, f"bridge only serves /v1/messages (got {self.path})")
            return
        try:
            n = int(self.headers.get("content-length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "bad json")
            return
        key = (self.headers.get("x-api-key")
               or (self.headers.get("authorization") or "").removeprefix("Bearer ").strip())
        oai = anthropic_to_openai(req)
        want_stream = bool(oai.get("stream"))
        body, status, ctype = self._forward(oai, key, want_stream)
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, oai: dict, key: str, want_stream: bool) -> tuple[bytes, int, str]:
        import urllib.error
        import urllib.request
        url = self.upstream.rstrip("/") + "/chat/completions"
        r = urllib.request.Request(url, data=json.dumps(oai, ensure_ascii=False).encode("utf-8"),
                                   method="POST",
                                   headers={"content-type": "application/json",
                                            "authorization": "Bearer " + key})
        try:
            resp = urllib.request.urlopen(r, timeout=1800)
        except urllib.error.HTTPError as e:
            detail = e.read()[:2000]
            return (json.dumps({"type": "error", "error": {"type": "upstream_error",
                    "message": f"HTTP {e.code}: {detail.decode('utf-8', 'replace')}"}}).encode(),
                    e.code, "application/json")
        except Exception as e:
            return (json.dumps({"type": "error", "error": {"type": "api_error",
                    "message": f"bridge upstream failure: {e.__class__.__name__}"}}).encode(),
                    502, "application/json")
        with resp:
            if not want_stream:
                data = json.loads(resp.read().decode("utf-8", "replace"))
                out = openai_response_to_anthropic(oai["model"], data)
                return (json.dumps(out, ensure_ascii=False).encode(), 200, "application/json")
            lines = [ln for ln in resp]
            events = openai_stream_to_anthropic_sse(oai["model"], lines)
            return ("".join(events).encode("utf-8"), 200, "text/event-stream")


def bridge_base_url(upstream: str) -> str:
    with _BRIDGES_LOCK:
        got = _BRIDGES.get(upstream)
        if got:
            return f"http://127.0.0.1:{got[1]}"
        h = type("BridgeHandler", (_Handler,), {"upstream": upstream})

        class _Srv(ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 128

        srv = _Srv(("127.0.0.1", 0), h)
        threading.Thread(target=srv.serve_forever, daemon=True,
                         name=f"openai-bridge-{srv.server_address[1]}").start()
        port = srv.server_address[1]
        _BRIDGES[upstream] = (srv, port)
        return f"http://127.0.0.1:{port}"
