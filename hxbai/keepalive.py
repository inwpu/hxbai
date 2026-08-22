from __future__ import annotations

import time
from typing import Callable, Optional


class KeepAliveRegistry:
    def __init__(self, *, close_fn: Callable[[str], None], probe_fn: Callable[[str], bool],
                 clock: Callable[[], float], emit: Optional[Callable[[str, dict], None]] = None,
                 max_held: int = 3, window_s: int = 7200, phase_pending: int = 4,
                 tail_s: int = 1800, preempt_cooldown_s: int = 1800,
                 reaped_cooldown_s: int = 1800, probe_retries: int = 2,
                 probe_retry_delay_s: float = 4.0, sleep_fn: Optional[Callable[[float], None]] = None,
                 total_run_s: float = 0.0):
        self._close = close_fn
        self._probe = probe_fn
        self._clock = clock
        self._emit = emit or (lambda ev, payload: None)
        self.max_held = max(0, int(max_held))
        self.window_s = int(window_s)
        self.total_run_s = float(total_run_s)
        self.phase_pending = int(phase_pending)
        self.tail_s = int(tail_s)
        self.preempt_cooldown_s = int(preempt_cooldown_s)
        self.reaped_cooldown_s = int(reaped_cooldown_s)
        self.probe_retries = max(0, int(probe_retries))
        self.probe_retry_delay_s = float(probe_retry_delay_s)
        self._sleep = sleep_fn or time.sleep
        self._held: dict[str, tuple] = {}
        self._reaped_until = 0.0
        self._reaped_streak = 0
        self._preempt_until = 0.0

    def held_count(self) -> int:
        return len(self._held)

    def is_held(self, code: str) -> bool:
        return code in self._held

    def effective_concurrency(self, max_concurrency: int, roster_codes=None) -> int:
        if roster_codes is None:
            held_out = self.held_count()
        else:
            rs = set(roster_codes)
            held_out = sum(1 for c in self._held if c not in rs)
        return max(1, int(max_concurrency) - held_out)

    def _active(self) -> bool:
        return (self.max_held > 0 and self._clock() >= self._preempt_until
                and self._clock() >= self._reaped_until)

    def should_hold(self, code: str, *, has_state: bool, is_pending: bool,
                    remaining_s: float, round_idx: int, pending_count: int,
                    high_value: bool = False) -> bool:
        if not self._active() or self.is_held(code):
            return False
        if self.held_count() >= self.max_held:
            return False
        if not (has_state and is_pending):
            return False
        _gate4 = self.window_s * 2
        if self.total_run_s > 0:
            _gate4 = min(self.window_s * 2, self.total_run_s * 0.5)
        if remaining_s <= _gate4:
            return False
        if not (high_value or pending_count <= self.phase_pending or round_idx >= 1):
            return False
        return True

    def grant(self, code: str, addr) -> bool:
        if not self._active() or self.held_count() >= self.max_held or self.is_held(code):
            return False
        self._held[code] = (addr, self._clock())
        self._emit("keepalive_grant", {"code": code, "held": self.held_count()})
        return True

    def renew(self, code: str) -> None:
        if code in self._held:
            addr, _ = self._held[code]
            self._held[code] = (addr, self._clock())

    def release(self, code: str, reason: str = "release") -> None:
        if code not in self._held:
            return
        self._held.pop(code, None)
        try:
            self._close(code)
        except Exception:
            pass
        self._emit("keepalive_release", {"code": code, "reason": reason})

    def release_all(self, reason: str = "release") -> None:
        for code in list(self._held.keys()):
            self.release(code, reason)
        if reason == "preempt":
            self._emit("keepalive_preempt", {"cooldown_s": self.preempt_cooldown_s})
            self._preempt_until = self._clock() + self.preempt_cooldown_s

    def probe_and_resume(self, code: str):
        if code not in self._held:
            return None
        addr, _ = self._held[code]
        if self._probe_with_retry(addr):
            self._reaped_streak = 0
            return addr
        self.release(code, "reaped")
        self._reaped_until = self._clock() + self.reaped_cooldown_s
        self._reaped_streak += 1
        derated = False
        if self._reaped_streak >= 2 and self.max_held > 1:
            self.max_held = 1
            derated = True
        self._emit("keepalive_reaped", {"code": code, "streak": self._reaped_streak,
                                        "cooldown_s": self.reaped_cooldown_s, "derated": derated})
        return None

    def _probe_with_retry(self, addr) -> bool:
        for attempt in range(1 + self.probe_retries):
            try:
                if self._probe(addr):
                    return True
            except Exception:
                pass
            if attempt < self.probe_retries:
                try:
                    self._sleep(self.probe_retry_delay_s)
                except Exception:
                    pass
        return False

    def sweep_expired(self, pending_codes=None) -> None:
        now = self._clock()
        pend = set(pending_codes) if pending_codes is not None else set()
        for code, (addr, granted) in list(self._held.items()):
            if now - granted < self.window_s:
                continue
            if code in pend and self._probe_with_retry(addr):
                self.renew(code)
                self._emit("keepalive_renew", {"code": code})
                continue
            self.release(code, "window_expired")

    def tail_release(self, remaining_s: float) -> None:
        if remaining_s < self.tail_s:
            self.release_all("tail")
