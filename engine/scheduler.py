from __future__ import annotations

import time
from typing import Any, Callable, NamedTuple

from engine import pacing

BASE_ATTEMPT_CAP_S = 12 * 60
MIN_ATTEMPT_CAP_S = 5 * 60
MAX_ATTEMPT_CAP_S = 45 * 60
HI_WEIGHT = 2.0
TOTAL_BUDGET_S = 6 * 3600
HI_STALL_PASSES = 2
MIN_PASSES = 2
MAX_PASSES = 8
BASE_WAVES = 4
GOLDEN_PARK_WALL_S = 20 * 60
GOLDEN_PARK_MIN_PASSES = 3
HI_WINDOW_FLOOR_S = 40 * 60
HI_BASE_WAVES = 12
MIN_WAVES = 2
ABANDON_GRACE_S = 90
RECONCILE_RETRY_S = 90
EXECUTOR_RETRY_LIMIT = 2
HINT_FLOOR_S = 25 * 60
HINT_BUDGET_FACTOR = 1.0 / 3
HARD_TOTAL_CAP_S = 150 * 60
ZERO_FLAG_HUNGRY_CAP_S = 30 * 60
ZERO_FLAG_CAP_S = 60 * 60
WEAK_PROGRESS_PATIENCE = 1
CORRECT_STUCK_PATIENCE = 2
STUCK_TIME_BUDGET_MULT = 2.0


class Attempt(NamedTuple):
    solved: bool
    progress: dict
    status: str = ""
    deferred: bool = False
    executor_failed: bool = False


class Budget(NamedTuple):
    deadline: float
    max_waves: int


_MILESTONE_KEYS = ("capabilities_verified", "findings_verified", "correct")


def _milestone_progressed(best: dict, cur: dict) -> bool:
    cur = cur or {}
    best = best or {}
    return any(cur.get(k, 0) > best.get(k, 0) for k in _MILESTONE_KEYS)


def _progressed(best: dict, cur: dict) -> bool:
    cur = cur or {}
    best = best or {}
    return any(cur.get(k, 0) > best.get(k, 0) for k in cur)


def _merge_best(best: dict, cur: dict) -> dict:
    out = dict(best or {})
    for k, v in (cur or {}).items():
        if v > out.get(k, 0):
            out[k] = v
    return out


def _queue_starved(ready: list, by_key: dict, passes: dict, free_slots: int, is_high_cost) -> bool:
    if not ready:
        return False
    _n_never = sum(1 for k in ready if passes.get(k, 0) == 0)
    return _n_never > free_slots


def _revive_policy(passes: int, min_passes: int, max_passes: int, *,
                   milestone: bool, weak: bool, correct: int,
                   weak_only: int, weak_patience: int, correct_patience: int = 2,
                   time_stuck: float = 0.0, stuck_budget: float = float("inf"),
                   need: int | None = None, breadth_starved: bool = False,
                   total_elapsed: float = 0.0, flag_stuck: float = 0.0,
                   hint_elapsed: float | None = None) -> tuple[str, int, str]:
    if passes >= max_passes:
        return "drop", weak_only, f"max {passes} passes reached"
    if (correct > 0 and hint_elapsed is not None
            and hint_elapsed >= max(stuck_budget * HINT_BUDGET_FACTOR, pacing.hint_floor_s())
            and passes >= min_passes):
        return "drop", weak_only, (f"hint budget exhausted ({hint_elapsed:.0f}s since hint ≥ "
                                  f"{stuck_budget * HINT_BUDGET_FACTOR:.0f}s (1/3 budget); yield slot)")
    _hard_s = max(pacing.hard_total_cap_s(), ZERO_FLAG_CAP_S + 15 * 60)
    if correct > 0 and passes >= min_passes and total_elapsed >= _hard_s:
        return "drop", weak_only, (f"partial deepchain hard cap ({total_elapsed:.0f}s total ≥ "
                                  f"{pacing.hard_total_cap_s():.0f}s; absolute yield regardless of hint/milestone resets)")
    _hungry_s = min(pacing.hungry_cap_s(), ZERO_FLAG_CAP_S - 5 * 60)
    if correct == 0 and breadth_starved and passes >= 1 and total_elapsed >= _hungry_s:
        return "requeue", weak_only, (f"zero-flag hungry yield ({total_elapsed:.0f}s, 0 flags, unopened challenges "
                                      f"waiting; opportunity cost — releases slot+instance, rejoins queue tail at "
                                      f"{_hungry_s//60}min)")
    if correct == 0 and passes >= 1 and total_elapsed >= ZERO_FLAG_CAP_S:
        return "drop", weak_only, (f"zero-flag absolute cap ({total_elapsed:.0f}s total wall-clock, 0 flags ever; "
                                  f"releases slot — no foothold after a full hour is dead-value grinding)")
    if correct == 0 and breadth_starved and passes >= min_passes and total_elapsed >= stuck_budget:
        return "drop", weak_only, (f"zero-delivery churn ({total_elapsed:.0f}s total wall-clock ≥ budget "
                                  f"{stuck_budget:.0f}s, correct==0, fresh breadth starved; milestone-inflation-proof yield)")
    if correct > 0 and breadth_starved and passes >= min_passes and flag_stuck >= stuck_budget:
        return "drop", weak_only, (f"partial deepchain flag-stall ({flag_stuck:.0f}s since last flag ≥ budget "
                                  f"{stuck_budget:.0f}s, 0<correct<need, breadth starved; milestone-creep-immune yield slot)")
    if milestone:
        return "revive", 0, "milestone progress"
    if passes < min_passes:
        return "revive", weak_only, "min-passes floor"
    if need is not None and 0 < correct < need and weak and not (breadth_starved and time_stuck >= stuck_budget):
        return "revive", 0, "partial multi-flag delivery progress (bursty; revives before wall-clock kill — golden order, phase-gated concurrency frees b-01/b-03 instead)"
    if time_stuck >= stuck_budget:
        return "drop", weak_only, (f"α≈0 stuck ({time_stuck:.0f}s wall-clock ≥ budget {stuck_budget:.0f}s "
                                  "since last milestone; cost-aware, releases slot; "
                                  f"{'breadth-starved partial deepchain evicted' if correct > 0 else 'correct==0 zero-delivery'})")
    patience = correct_patience if correct > 0 else weak_patience
    if (correct > 0 or weak) and weak_only < patience:
        return "revive", weak_only + 1, ("partial deliverable, no milestone (bounded)"
                                     if correct > 0 else "bounded recon progress")
    return "drop", weak_only, ("α≈0 stuck (partial held, patience spent)" if correct > 0
                              else ("α≈0, no milestone (recon-only)" if weak else "α≈0, no progress"))


class Scheduler:
    def __init__(self, *, concurrency: int = 3, total_budget_s: float | None = None,
                 per_attempt_cap_s: float = BASE_ATTEMPT_CAP_S, min_passes: int = MIN_PASSES,
                 max_passes: int = MAX_PASSES, base_waves: int = BASE_WAVES, min_waves: int = MIN_WAVES,
                 is_high_cost: Callable[[Any], bool] | None = None, max_high_cost: int = 1,
                 is_breadth: Callable[[Any], bool] | None = None,
                 abandon_grace_s: float = ABANDON_GRACE_S, hi_base_waves: int = HI_BASE_WAVES,
                 min_attempt_cap_s: float = MIN_ATTEMPT_CAP_S, max_attempt_cap_s: float | None = None,
                 value_weight: Callable[[Any], float] | None = None, hi_weight: float = HI_WEIGHT,
                 on_abandon: Callable[[Any], None] | None = None, max_deferrals: int = 40,
                 can_start: Callable[..., bool] | None = None,
                 hi_open: Callable[[], int] | None = None,
                 on_wedge: Callable[[], int] | None = None,
                 on_dispatch: Callable[[Any], None] | None = None,
                 worth_backfill: Callable[[Any], bool] | None = None,
                 executor_retry_limit: int = EXECUTOR_RETRY_LIMIT,
                 reconcile_retry_s: float = RECONCILE_RETRY_S,
                 weak_progress_patience: int = WEAK_PROGRESS_PATIENCE,
                 correct_stuck_patience: int = CORRECT_STUCK_PATIENCE,
                 stuck_time_budget_mult: float = STUCK_TIME_BUDGET_MULT,
                 clock: Callable[[], float] = time.time, log: Callable[[str], None] = lambda m: None):
        self.concurrency = max(1, concurrency)
        self.executor_retry_limit = max(0, executor_retry_limit)
        self.reconcile_retry_s = max(0.0, reconcile_retry_s)
        self.weak_progress_patience = max(0, weak_progress_patience)
        self.correct_stuck_patience = max(0, correct_stuck_patience)
        self.stuck_time_budget_mult = max(0.0, stuck_time_budget_mult)
        self.max_deferrals = max(1, max_deferrals)
        self.per_attempt_cap_s = per_attempt_cap_s
        self._cap_pinned = max_attempt_cap_s is not None
        self.max_attempt_cap_s = max_attempt_cap_s if self._cap_pinned else None
        self.min_attempt_cap_s = max(0.0, min_attempt_cap_s)
        self.hi_weight = max(1.0, hi_weight)
        self.hi_base_waves = max(base_waves, hi_base_waves)
        self.abandon_grace_s = max(0.0, abandon_grace_s)
        self.min_passes = max(1, min_passes)
        self.max_passes = max(self.min_passes, max_passes)
        self.base_waves = base_waves
        self.min_waves = min_waves
        self.is_high_cost = is_high_cost or (lambda _t: False)
        self.max_high_cost = max(1, max_high_cost)
        self.is_breadth = is_breadth or (lambda _t: not self.is_high_cost(_t))
        self.can_start = can_start or (lambda _t, _fresh=True: True)
        try:
            import inspect as _inspect
            self._can_start_takes_stall = len([p for p in _inspect.signature(self.can_start).parameters.values()
                                               if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]) >= 3
        except (TypeError, ValueError):
            self._can_start_takes_stall = False
        self.hi_open = hi_open
        self.on_dispatch = on_dispatch
        self.worth_backfill = worth_backfill
        self.value_weight = value_weight or (lambda t: self.hi_weight if self.is_high_cost(t) else 1.0)
        self.on_abandon = on_abandon
        self.on_wedge = on_wedge
        self.clock = clock
        self.log = log
        self.start = clock()
        self.total_budget_s = total_budget_s
        self.deadline = (self.start + total_budget_s) if total_budget_s is not None else None

    def time_left(self) -> float:
        return float("inf") if self.deadline is None else self.deadline - self.clock()

    def _safe_on_abandon(self, task) -> None:
        if self.on_abandon is None:
            return
        try:
            self.on_abandon(task)
        except Exception as e:
            self.log(f"[sched] on_abandon error: {e!r}")

    def _attempt_cap(self, task) -> float:
        from engine import pacing as _pc
        _sc = _pc.PACING.scale()
        base_eff = self.per_attempt_cap_s * min(1.0, _sc)
        floor = min(self.min_attempt_cap_s, self.per_attempt_cap_s)
        cap = base_eff * max(1.0, self.value_weight(task))
        _live_max = max(self.per_attempt_cap_s,
                        self.max_attempt_cap_s if self._cap_pinned else _pc.max_attempt_cap_s())
        cap = max(floor, min(_live_max, cap))
        _hwf = _pc.hi_window_floor_s()
        if self.is_high_cost(task) and _live_max > _hwf:
            cap = max(cap, _hwf)
        return cap

    def _waves_for(self, remaining_tasks: int, base: int | None = None) -> int:
        base = self.base_waves if base is None else base
        need = remaining_tasks * self.per_attempt_cap_s / self.concurrency
        return self.min_waves if self.time_left() < need else base

    def run(self, tasks: list, attempt_fn: Callable[[Any, Budget], Attempt]) -> list:
        import queue as _queue
        import threading as _threading

        by_key = {id(t): t for t in tasks}
        ready = [id(t) for t in tasks]
        revive: list = []
        passes: dict = {}
        deferrals: dict = {}
        exec_failures: dict = {}
        weak_only: dict = {}
        time_stuck: dict = {}
        total_elapsed: dict = {}
        noprog_passes: dict = {}
        hint_elapsed: dict = {}
        flag_stuck: dict = {}
        best_prog: dict = {}
        results: dict = {}
        inflight: dict = {}
        done_q: "_queue.Queue" = _queue.Queue()
        abandoned: set = set()
        lease_seq = 0
        _last_reconcile_at = float("-inf")

        def _pick():
            _fresh = any(self.is_breadth(by_key[k]) for k in ready)
            _active_hi = set(inflight) | set(revive)
            _hi_stalled = any(self.is_high_cost(by_key[k]) and noprog_passes.get(k, 0) >= HI_STALL_PASSES
                              for k in _active_hi if k in by_key)
            for src in (revive, ready):
                for i, k in enumerate(src):
                    ok = (self.can_start(by_key[k], _fresh, _hi_stalled) if self._can_start_takes_stall
                          else self.can_start(by_key[k], _fresh))
                    if ok:
                        return src.pop(i), self.is_high_cost(by_key[k])
            return None, False

        def _worker(k, task, budget, lease):
            try:
                oc = attempt_fn(task, budget)
                oc = oc if isinstance(oc, Attempt) else Attempt(bool(oc), {}, "")
            except Exception as e:
                import traceback as _tb
                _code = getattr(task, "unique_code", str(task))[:32]
                self.log(f"[sched] attempt error on {_code}: {e!r}\n" + _tb.format_exc(limit=8))
                oc = Attempt(False, {}, f"error:{e!r}"[:80])
            done_q.put((k, oc, lease))

        def _account(k, oc, *, abandoned_timeout: bool = False, elapsed: float = 0.0):
            code = getattr(by_key[k], "unique_code", by_key[k])
            if abandoned_timeout or getattr(oc, "executor_failed", False):
                symptom = "hang/timeout" if abandoned_timeout else "no-output"
                exec_failures[k] = exec_failures.get(k, 0) + 1
                if exec_failures[k] <= self.executor_retry_limit and self.time_left() > 0:
                    self.log(f"[sched] executor failure #{exec_failures[k]} ({symptom}; executor health, not task α); "
                             f"requeue: {code!r}")
                    revive.append(k)
                else:
                    results[k] = oc
                    self.log(f"[sched] executor quarantined after {exec_failures[k]} failure(s) ({symptom}): {code!r}")
                    if not abandoned_timeout and self.on_abandon is not None:
                        _threading.Thread(target=self._safe_on_abandon, args=(by_key[k],), daemon=True).start()
                return
            results[k] = oc
            passes[k] = passes.get(k, 0) + 1
            exec_failures[k] = 0
            if oc.solved:
                return
            milestone = _milestone_progressed(best_prog.get(k), oc.progress)
            weak = _progressed(best_prog.get(k), oc.progress)
            _flag_new = (oc.progress or {}).get("correct", 0) > (best_prog.get(k) or {}).get("correct", 0)
            best_prog[k] = _merge_best(best_prog.get(k), oc.progress)
            time_stuck[k] = 0.0 if milestone else (time_stuck.get(k, 0.0) + max(0.0, elapsed))
            total_elapsed[k] = total_elapsed.get(k, 0.0) + max(0.0, elapsed)
            noprog_passes[k] = 0 if milestone else noprog_passes.get(k, 0) + 1
            flag_stuck[k] = 0.0 if _flag_new else (flag_stuck.get(k, 0.0) + max(0.0, elapsed))
            if (oc.progress or {}).get('info_gain'):
                hint_elapsed[k] = 0.0
            elif hint_elapsed.get(k) is not None:
                hint_elapsed[k] += max(0.0, elapsed)
            if self.time_left() <= 0:
                return
            _free_slots = self.concurrency - len(inflight)
            _breadth_starved = _queue_starved(ready, by_key, passes, _free_slots, self.is_high_cost)
            action, weak_only[k], why = _revive_policy(
                passes[k], self.min_passes, self.max_passes,
                milestone=milestone, weak=weak,
                correct=(oc.progress or {}).get("correct", 0),
                weak_only=weak_only.get(k, 0), weak_patience=self.weak_progress_patience,
                correct_patience=self.correct_stuck_patience,
                time_stuck=time_stuck.get(k, 0.0),
                stuck_budget=self.stuck_time_budget_mult * self._attempt_cap(by_key[k]),
                need=(oc.progress or {}).get("need"),
                breadth_starved=_breadth_starved,
                total_elapsed=total_elapsed.get(k, 0.0),
                flag_stuck=flag_stuck.get(k, 0.0),
                hint_elapsed=hint_elapsed.get(k))
            _g_correct = (oc.progress or {}).get("correct", 0)
            _g_need = (oc.progress or {}).get("need") or 1
            if (action == "revive" and _g_correct > 0 and _g_correct < _g_need
                    and flag_stuck.get(k, 0.0) >= pacing.golden_park_wall_s()
                    and passes[k] >= GOLDEN_PARK_MIN_PASSES):
                action = "drop"
                why = f"golden-parked ({_g_correct}/{_g_need} flags, {flag_stuck[k]:.0f}s no new flag, {passes[k]} passes)"
            if action == "requeue":
                ready.append(k)
                if self.on_abandon is not None:
                    _threading.Thread(target=self._safe_on_abandon, args=(by_key[k],),
                                      daemon=True).start()
            elif action == "revive":
                revive.append(k)
            else:
                self.log(f"[sched] drop ({why} after {passes[k]} passes): {code!r}")
                if self.on_abandon is not None:
                    _threading.Thread(target=self._safe_on_abandon, args=(by_key[k],), daemon=True).start()

        _STATUS_HEARTBEAT_S = 300
        _status_prev = [None]
        _status_ts = [0.0]

        def _scode(k) -> str:
            t = by_key.get(k, k)
            return str(getattr(t, "unique_code", t))

        def _scodes(seq, n: int = 10) -> str:
            cs = [f"{_scode(k)}{'·hi' if self.is_high_cost(by_key.get(k)) else ''}" for k in seq]
            return (", ".join(cs[:n]) + (f" +{len(cs) - n}" if len(cs) > n else "")) if cs else "无"

        def _idle_reason() -> str:
            q = list(revive) + list(ready)
            if not q:
                return "无等待题(队列真空,正常收尾)"
            startable = [k for k in q if self.can_start(by_key.get(k), bool(ready))]
            if inflight and not startable:
                if len(inflight) < self.concurrency:
                    _hi_wait = sum(1 for k in q if self.is_high_cost(by_key.get(k)))
                    return (f"准入门全拦(本地 {len(inflight)}/{self.concurrency} 在做<上限 → 非本地满:"
                            f"待开 {_hi_wait} 道全 hi 被名额/相位门拦;平台侧若真满=幽灵,由 on_wedge 对账区分)")
                return "平台 max-active 满:等在跑题关实例腾槽(持续=疑幽灵/solved-占槽,待 on_wedge 对账回收)"
            lo = [k for k in startable if not self.is_high_cost(by_key.get(k))]
            hi = [k for k in startable if self.is_high_cost(by_key.get(k))]
            _hc = self.hi_open() if self.hi_open is not None else 0
            if lo:
                return f"低成本可派却空槽(异常待查): {_scodes(lo)}"
            if hi and _hc >= self.max_high_cost:
                return f"高成本名额满(≤{self.max_high_cost});{len(hi)}题轮候: {_scodes(hi)}"
            return "调度约束(准入门)"

        def _emit_status():
            now = self.clock()
            infl = frozenset(inflight)
            idle = self.concurrency - len(inflight)
            if not (infl != _status_prev[0] or (idle > 0 and (ready or revive)
                                                and now - _status_ts[0] >= _STATUS_HEARTBEAT_S)):
                return
            doing = _scodes(sorted(inflight, key=_scode)) if inflight else "(空)"
            msg = (f"[status] 并发 {len(inflight)}/{self.concurrency} 在做: {doing}"
                   f" | 待开: {_scodes(ready)} | 待复活: {_scodes(revive)}")
            if idle > 0 and (ready or revive):
                msg += f" | ⚠ {idle}槽空闲原因: {_idle_reason()}"
            self.log(msg)
            _status_prev[0] = infl
            _status_ts[0] = now

        while ready or revive or inflight:
            if self.time_left() <= 0 and inflight:
                self.log(f"[sched] deadline hit; abandoning {len(inflight)} in-flight straggler(s)")
                break
            _dispatched = 0
            while len(inflight) < self.concurrency and self.time_left() > 0:
                k, counted_hi = _pick()
                if k is None:
                    break
                cap = self._attempt_cap(by_key[k])
                base_w = self.hi_base_waves if counted_hi else self.base_waves
                mw = self._waves_for(len(ready) + len(revive) + len(inflight) + 1, base_w)
                now = self.clock()
                hard = self.deadline if self.deadline is not None else float("inf")
                dl = min(hard, now + cap)
                abandon_at = dl + self.abandon_grace_s
                lease_seq += 1
                inflight[k] = {"counted_hi": counted_hi, "abandon_at": abandon_at, "lease": lease_seq,
                               "start": now}
                if self.on_dispatch is not None:
                    self.on_dispatch(by_key[k])
                _threading.Thread(target=_worker, args=(k, by_key[k], Budget(deadline=dl, max_waves=mw), lease_seq),
                                  daemon=True, name=f"sched-worker-{k}").start()
                _dispatched += 1
            if _dispatched:
                _last_reconcile_at = float("-inf")
            if len(inflight) < self.concurrency and not ready and self.time_left() > 0:
                _free = self.concurrency - len(inflight)
                for _bk in [k for k, oc in results.items()
                            if (not oc.solved)
                            and passes.get(k, 0) < self.max_passes
                            and (self.worth_backfill is None or self.worth_backfill(by_key[k]))]:
                    del results[_bk]
                    revive.append(_bk)
                    if len(revive) >= _free:
                        break
            _emit_status()
            _wnow = self.clock()
            if (self.on_wedge is not None and (_wnow - _last_reconcile_at) >= self.reconcile_retry_s
                    and self.time_left() > 0
                    and len(inflight) < self.concurrency and (ready or revive)):
                try:
                    _freed = self.on_wedge() or 0
                except Exception as e:
                    _freed = 0
                    self.log(f"[sched] on_wedge 对账异常(忽略): {e!r}")
                _last_reconcile_at = _wnow
                if _freed:
                    self.log(f"[sched] 准入 wedge → 平台真值对账回收 {_freed} 幽灵槽,重试填槽")
                    continue
            if not inflight:
                if self.time_left() <= 0:
                    self.log(f"[sched] deadline reached; {len(ready) + len(revive)} unfinished")
                break
            now = self.clock()
            wakes = [v["abandon_at"] for v in inflight.values()]
            if self.deadline is not None:
                wakes.append(self.deadline)
            if (self.on_wedge is not None and len(inflight) < self.concurrency and (ready or revive)):
                wakes.append(_last_reconcile_at + self.reconcile_retry_s if _last_reconcile_at != float("-inf")
                             else now)
            wake = min(wakes)
            try:
                item = done_q.get(timeout=max(0.05, wake - now))
            except _queue.Empty:
                item = None
            while item is not None:
                k, oc, lease = item
                meta = inflight.get(k)
                if meta is not None and meta["lease"] == lease:
                    inflight.pop(k)
                    _last_reconcile_at = float("-inf")
                    _never_ran = passes.get(k, 0) == 0
                    if getattr(oc, "deferred", False) and self.time_left() > 0 and (
                            (_never_ran and inflight) or deferrals.get(k, 0) < self.max_deferrals):
                        deferrals[k] = deferrals.get(k, 0) + 1
                        revive.append(k)
                    elif getattr(oc, "deferred", False):
                        results[k] = Attempt(False, best_prog.get(k, {}), "starved")
                        self.log(f"[sched] starved (deferral budget spent, no other task running to free a slot): "
                                 f"{getattr(by_key[k], 'unique_code', by_key[k])!r}")
                    else:
                        _account(k, oc, elapsed=self.clock() - meta.get("start", self.clock()))
                else:
                    abandoned.discard(k)
                try:
                    item = done_q.get_nowait()
                except _queue.Empty:
                    item = None
            now = self.clock()
            for k in list(inflight):
                if now >= inflight[k]["abandon_at"] or self.time_left() <= 0:
                    meta = inflight.pop(k)
                    abandoned.add(k)
                    if self.time_left() > 0:
                        _account(k, Attempt(False, best_prog.get(k, {}), "abandoned:timeout"),
                                 abandoned_timeout=True)
                        if k not in revive and self.on_abandon is not None:
                            _threading.Thread(target=self._safe_on_abandon, args=(by_key[k],),
                                              daemon=True).start()
        return [(by_key[k], oc) for k, oc in results.items()]
