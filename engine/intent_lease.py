from __future__ import annotations

import re
import threading
import time

_ACTION_WORDS = frozenset("""exploit attack try attempt test check probe scan brute bruteforce
crack pivot enumerate investigate explore verify mine harvest dump read fetch get find search""".split())
_FILLER_WORDS = frozenset("""the a an this that on at against for of to via using with from
host server service box node machine target""".split())


def direction_key(subgoal: str) -> str:
    s = (subgoal or "").strip().lower()
    toks = sorted({t for t in re.split(r"[^a-z0-9.]+", s) if t}
                  - _ACTION_WORDS - _FILLER_WORDS)
    return " ".join(toks)


class WorkClaimTable:

    def __init__(self, ttl_s: float = 1800.0):
        self._claims: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_s
        self._conflicts = 0

    def claim(self, subgoal: str, worker_id: str) -> bool:
        key = direction_key(subgoal)
        with self._lock:
            self._evict_expired()
            existing = self._claims.get(key)
            if existing:
                if existing["worker_id"] == worker_id:
                    existing["expires_at"] = time.time() + self._ttl
                    return True
                self._conflicts += 1
                return False
            self._claims[key] = {
                "worker_id": worker_id,
                "claimed_at": time.time(),
                "expires_at": time.time() + self._ttl,
            }
            return True

    def release(self, subgoal: str, worker_id: str) -> bool:
        key = direction_key(subgoal)
        with self._lock:
            existing = self._claims.get(key)
            if existing and existing["worker_id"] == worker_id:
                del self._claims[key]
                return True
            return False

    def active(self) -> dict:
        with self._lock:
            self._evict_expired()
            return {k: dict(v) for k, v in self._claims.items()}

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [k for k, v in self._claims.items() if v["expires_at"] < now]
        for k in expired:
            del self._claims[k]

    def stats(self) -> dict:
        with self._lock:
            self._evict_expired()
            return {"active_claims": len(self._claims),
                    "conflicts": self._conflicts,
                    "directions": sorted(self._claims.keys())}
