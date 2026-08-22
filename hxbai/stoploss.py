from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class _State:
    started: float = 0.0
    active: float = 0.0
    sessions: int = 0
    dry_streak: int = 0
    unreachable_streak: int = 0
    total_new_facts: int = 0
    stopped_reason: str = ""
    multi_flag: bool = False
    flags_captured: int = 0
    active_at_last_flag: float = 0.0
    lifetime_sessions: int = 0


class StopLoss:
    def __init__(self, *, per_challenge_seconds: int, max_sessions: int, dry_cutoff: int,
                 unreachable_cutoff: int = 2, min_session_seconds: int = 45,
                 multi_flag_max_mult: float = 4.0, lifetime_sessions_cap: int = 0, clock=time.monotonic):
        self.per_challenge_seconds = max(1, int(per_challenge_seconds))
        self.max_sessions = max(1, int(max_sessions))
        self.lifetime_sessions_cap = int(lifetime_sessions_cap) if lifetime_sessions_cap else self.max_sessions * 2
        self.dry_cutoff = max(1, int(dry_cutoff))
        self.unreachable_cutoff = max(1, int(unreachable_cutoff))
        self.multi_flag_max_mult = max(1.0, float(multi_flag_max_mult))
        self.min_session_seconds = max(1, int(min_session_seconds))
        self._clock = clock
        self._by: dict[str, _State] = {}
        self._lock = threading.Lock()

    def start(self, code: str, *, multi_flag: bool = False) -> None:
        with self._lock:
            st = self._by.get(code)
            if st is None:
                st = self._by[code] = _State(started=self._clock())
            if multi_flag:
                st.multi_flag = True

    def note_flag(self, code: str) -> None:
        with self._lock:
            st = self._by.setdefault(code, _State(started=self._clock()))
            st.flags_captured += 1
            st.active_at_last_flag = st.active
            st.dry_streak = 0
            st.unreachable_streak = 0

    def should_stop(self, code: str) -> tuple[bool, str]:
        with self._lock:
            st = self._by.get(code) or _State(started=self._clock())
            self._by.setdefault(code, st)
            if st.stopped_reason:
                return True, st.stopped_reason
            near_done = st.multi_flag and st.flags_captured >= 1
            if st.sessions >= self.max_sessions and not near_done:
                st.stopped_reason = f"session cap reached ({st.sessions}/{self.max_sessions})"
                return True, st.stopped_reason
            if st.lifetime_sessions >= self.lifetime_sessions_cap and not near_done:
                st.stopped_reason = f"lifetime session cap ({st.lifetime_sessions}/{self.lifetime_sessions_cap})"
                return True, st.stopped_reason
            margin = self.per_challenge_seconds - self.min_session_seconds
            if st.multi_flag and st.flags_captured >= 1:
                since_flag = st.active - st.active_at_last_flag
                ceiling = self.per_challenge_seconds * self.multi_flag_max_mult
                if st.active >= ceiling - self.min_session_seconds:
                    st.stopped_reason = (f"multi-flag ceiling ({int(st.active)}s/"
                                         f"{int(ceiling)}s, {st.flags_captured} flags)")
                    return True, st.stopped_reason
                if since_flag >= margin:
                    return True, (f"stuck: no new flag in {int(since_flag)}s "
                                  f"({st.flags_captured} flags banked) — bench, keep instance")
            elif st.active >= margin:
                st.stopped_reason = f"time budget spent ({int(st.active)}s/{self.per_challenge_seconds}s active)"
                return True, st.stopped_reason
            if st.dry_streak >= self.dry_cutoff and not near_done:
                st.stopped_reason = f"diminishing returns ({st.dry_streak} dry sessions, no new facts)"
                return True, st.stopped_reason
            if st.unreachable_streak >= self.unreachable_cutoff:
                st.stopped_reason = f"target unreachable {st.unreachable_streak} visits (instance dead/expired)"
                return True, st.stopped_reason
            return False, ""

    def remaining_seconds(self, code: str) -> int:
        with self._lock:
            st = self._by.get(code)
            if st is None:
                return self.per_challenge_seconds
            if st.multi_flag and st.flags_captured >= 1:
                return max(1, int(self.per_challenge_seconds * self.multi_flag_max_mult - st.active))
            return max(1, int(self.per_challenge_seconds - st.active))

    def rearm_dry_window(self, code: str) -> None:
        with self._lock:
            st = self._by.get(code)
            if st:
                st.active_at_last_flag = st.active

    def sessions_for(self, code: str) -> int:
        with self._lock:
            st = self._by.get(code)
            return st.sessions if st else 0

    def record_session(self, code: str, *, new_facts: int, active_seconds: float = 0.0,
                       unreachable: bool = False) -> None:
        with self._lock:
            st = self._by.setdefault(code, _State(started=self._clock()))
            st.sessions += 1
            st.lifetime_sessions += 1
            st.active += max(0.0, float(active_seconds))
            st.total_new_facts += max(0, int(new_facts))
            if new_facts > 0:
                st.dry_streak = 0
            else:
                st.dry_streak += 1
            if unreachable:
                st.unreachable_streak += 1
            else:
                st.unreachable_streak = 0

    def reset(self, code: str) -> None:
        with self._lock:
            prev = self._by.get(code)
            carry = prev.lifetime_sessions if prev else 0
            self._by[code] = _State(started=self._clock(), lifetime_sessions=carry)

    def flags_banked(self, code: str) -> int:
        with self._lock:
            st = self._by.get(code)
            return st.flags_captured if st else 0

    def stats(self, code: str) -> dict:
        with self._lock:
            st = self._by.get(code)
            if st is None:
                return {"sessions": 0, "dry_streak": 0, "new_facts": 0}
            return {"sessions": st.sessions, "dry_streak": st.dry_streak,
                    "new_facts": st.total_new_facts, "stopped": st.stopped_reason}
