from __future__ import annotations

import time

_ANCHOR_SESSION_S = 6 * 3600
_ANCHOR_NTASKS = 63
_LADDER = (6 * 3600, 8 * 3600, 10 * 3600)


class _Pacing:

    def __init__(self) -> None:
        self._endgame_latched: bool = False
        self.n_tasks: int = _ANCHOR_NTASKS
        self._len_idx: int = 0
        self._t0: float | None = None

    def start(self, n_tasks: int) -> None:
        if n_tasks and n_tasks >= 20:
            self.n_tasks = int(n_tasks)
        if self._t0 is None:
            self._t0 = time.time()

    def session_len_s(self) -> int:
        if self._t0 is not None:
            elapsed = time.time() - self._t0
            while (self._len_idx < len(_LADDER) - 1
                   and elapsed >= _LADDER[self._len_idx]):
                self._len_idx += 1
        return _LADDER[self._len_idx]

    def elapsed_s(self) -> float:
        return (time.time() - self._t0) if self._t0 is not None else 0.0

    def scale(self) -> float:
        s = (self.session_len_s() / _ANCHOR_SESSION_S) * (_ANCHOR_NTASKS / max(self.n_tasks, 1))
        return max(0.25, min(3.0, s))

    def in_endgame(self) -> bool:
        if not self._endgame_latched:
            if (self.session_len_s() - self.elapsed_s()) <= self.endgame_window_s():
                self._endgame_latched = True
        return self._endgame_latched

    def endgame_window_s(self) -> int:
        return max(int(0.1 * self.session_len_s()), 45 * 60)


PACING = _Pacing()


def hard_total_cap_s() -> int:
    return int(150 * 60 * PACING.scale())


def hungry_cap_s() -> int:
    return int(min(max(30 * 60 * PACING.scale(), 15 * 60), 35 * 60))


def golden_park_wall_s() -> int:
    return int(20 * 60 * PACING.scale())


def hint_floor_s() -> int:
    return int(25 * 60 * PACING.scale())


def max_attempt_cap_s() -> int:
    return int(45 * 60 * PACING.scale())


def hi_window_floor_s() -> int:
    return int(40 * 60 * PACING.scale())


def drought_work_s() -> int:
    return int(35 * 60 * PACING.scale())


def hint_wall_fuse_s() -> int:
    return int(10 * 60 * PACING.scale())
