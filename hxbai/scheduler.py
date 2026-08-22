from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import observability as obs


@dataclass
class _Item:
    key: str
    payload: object
    best_of: int
    done: threading.Event = field(default_factory=threading.Event)
    result: object = None
    winning_attempt: int = -1
    attempts_run: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


def run_fleet(items, solve_fn, *, is_success, max_concurrent: int = 3, best_of: int = 1,
              variant_fn=None, best_of_fn=None) -> dict:
    best_of = max(1, int(best_of))
    max_concurrent = max(1, int(max_concurrent))
    wrapped = [
        _Item(key=_key(it, i), payload=it,
              best_of=max(1, int(best_of_fn(it))) if best_of_fn else best_of)
        for i, it in enumerate(items)
    ]
    by_key = {w.key: w for w in wrapped}

    tasks = []
    for a in range(max((w.best_of for w in wrapped), default=best_of)):
        for w in wrapped:
            if a < w.best_of:
                tasks.append((w, a))

    def _work(w: _Item, attempt_idx: int):
        if w.done.is_set():
            return
        variant = variant_fn(w.key, attempt_idx) if variant_fn else {}
        obs.emit("info", layer="scheduler", actor="scheduler",
                 payload={"event": "attempt_start", "item": w.key, "attempt": attempt_idx, "variant": variant})
        try:
            res = solve_fn(w.payload, attempt_idx, variant)
        except Exception as e:
            obs.emit("error", layer="scheduler", payload={"item": w.key, "attempt": attempt_idx, "err": str(e)[:200]})
            res = None
        with w.lock:
            w.attempts_run += 1
            ok = False
            try:
                ok = bool(res is not None and is_success(res))
            except Exception:
                ok = False
            if ok and not w.done.is_set():
                w.result, w.winning_attempt = res, attempt_idx
                w.done.set()
            elif w.result is None and res is not None:
                w.result = res
        obs.emit("info", layer="scheduler", actor="scheduler",
                 payload={"event": "attempt_end", "item": w.key, "attempt": attempt_idx, "success": ok})

    with ThreadPoolExecutor(max_workers=max_concurrent) as pool:
        futures = [pool.submit(_work, w, a) for (w, a) in tasks]
        for f in futures:
            f.result()

    out = {}
    for w in wrapped:
        out[w.key] = {"result": w.result, "success": w.done.is_set(),
                      "attempts": w.attempts_run, "winning_attempt": w.winning_attempt}
    obs.emit("info", layer="scheduler", actor="scheduler",
             payload={"event": "fleet_done", "solved": sum(1 for v in out.values() if v["success"]),
                      "total": len(out)})
    return out


def best_of_for(difficulty: str, base_best_of: int = 1) -> int:
    b = max(1, int(base_best_of))
    d = (difficulty or "").lower()
    if d == "easy":
        return max(1, round(b * 0.4))
    if d == "hard":
        return max(1, round(b * 0.6))
    return b


def diversified_variant(attempt_idx: int, best_of: int = 1, base_temp: float = 0.6) -> dict:
    temp = round(min(1.0, base_temp + 0.15 * max(0, int(attempt_idx))), 3)
    return {"temperature": temp, "nonce": int(attempt_idx)}


def _key(item, idx: int) -> str:
    for attr in ("key", "unique_code", "id", "name"):
        v = getattr(item, attr, None) if not isinstance(item, dict) else item.get(attr)
        if v:
            return str(v)
    return f"item-{idx}"
