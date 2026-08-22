from __future__ import annotations

import json
import os
import threading
import time

EVENT_TYPES = {
    "run_start", "run_end", "challenge_start", "challenge_end",
    "plan", "tool_call", "tool_result",
    "claim_new", "gate_pass", "gate_fail", "claim_verdict",
    "submit", "score", "budget", "model_call", "observer_note", "error", "info",
    "handoff_llm_empty",
    "slot_rebank", "stuck_benched", "keepalive_miss",
    "handoff_degraded",
    "cred_pooled",
    "spray_cap_hit",
    "flag_paraphrase_held",
}

_MAX_INLINE = 8000
_HEAD_KEEP = 2000


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fh = None
        self._run_id: str | None = None
        self._blob_dir: str | None = None
        self._seq = 0
        self._tl = threading.local()

    def configure(self, path: str, run_id: str | None = None) -> "EventBus":
        with self._lock:
            ap = os.path.abspath(path)
            os.makedirs(os.path.dirname(ap) or ".", exist_ok=True)
            self._fh = open(ap, "a", encoding="utf-8")
            self._run_id = run_id or os.path.splitext(os.path.basename(ap))[0]
            self._blob_dir = os.path.join(os.path.dirname(ap), "blobs")
            os.makedirs(self._blob_dir, exist_ok=True)
        return self

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.flush()
                self._fh.close()
                self._fh = None

    def context(self, challenge_id: str | None = None, attempt_id: str | None = None) -> None:
        if challenge_id is not None:
            self._tl.challenge_id = challenge_id
        if attempt_id is not None:
            self._tl.attempt_id = attempt_id

    def clear_context(self) -> None:
        self._tl.challenge_id = None
        self._tl.attempt_id = None

    def emit(self, type: str, *, actor: str = "agent", layer: str = "",
             payload=None, evidence=None) -> dict:
        payload, spill = self._spill_if_big(payload)
        ev = {
            "ts": _now(),
            "run_id": self._run_id,
            "challenge_id": getattr(self._tl, "challenge_id", None),
            "attempt_id": getattr(self._tl, "attempt_id", None),
            "layer": layer,
            "type": type if type in EVENT_TYPES else f"info:{type}",
            "actor": actor,
            "payload": payload,
            "evidence": evidence,
        }
        if spill:
            ev["spill"] = spill
        line = json.dumps(ev, ensure_ascii=False, default=str)
        with self._lock:
            self._seq += 1
            ev["seq"] = self._seq
            line = json.dumps(ev, ensure_ascii=False, default=str)
            if self._fh:
                self._fh.write(line + "\n")
                self._fh.flush()
        return ev

    def _spill_if_big(self, payload):
        if payload is None:
            return None, None
        try:
            s = json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            s = str(payload)
        if len(s) <= _MAX_INLINE:
            return payload, None
        ref = self._write_blob(s)
        return {"_truncated": True, "head": s[:_HEAD_KEEP], "len": len(s)}, ref

    def _write_blob(self, text: str) -> str | None:
        with self._lock:
            self._seq += 1
            n = self._seq
            bd = self._blob_dir
        if not bd:
            return None
        p = os.path.join(bd, f"{n}.txt")
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            return p
        except OSError:
            return None


def _now() -> float:
    try:
        return time.time()
    except Exception:
        return 0.0


BUS = EventBus()


def configure(path: str, run_id: str | None = None) -> EventBus:
    return BUS.configure(path, run_id)


def context(challenge_id: str | None = None, attempt_id: str | None = None) -> None:
    BUS.context(challenge_id, attempt_id)


def emit(type: str, *, actor: str = "agent", layer: str = "", payload=None, evidence=None) -> dict:
    return BUS.emit(type, actor=actor, layer=layer, payload=payload, evidence=evidence)


def load(path: str) -> list[dict]:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except OSError:
        return out
    out.sort(key=lambda e: e.get("seq", 0))
    return out
