from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    ap = argparse.ArgumentParser(prog="run-koh", description="KOH attack-and-hold engagement")
    ap.add_argument("--target", action="append", default=[], help="据点 URL(可多次=多据点)")
    ap.add_argument("--task", default="Capture root on every box and HOLD it against opponents: entrench "
                                      "stealthy persistence, clear opponent footholds, lock public entry, "
                                      "and re-capture anything you lose.")
    try:
        from engine.pacing import PACING as _PACING
        _dflt_budget = _PACING.session_len_s()
    except Exception:
        _dflt_budget = 4 * 3600
    ap.add_argument("--budget", type=int, default=_dflt_budget)
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--model", default="deepseek-flash")
    args = ap.parse_args()
    if not args.target:
        sys.exit("--target 至少一个(据点 URL)")
    if not os.environ.get("SOLVER_API_KEY"):
        sys.exit("SOLVER_API_KEY 未设置(模型 key)")

    from engine.profile import make_koh_profile
    from engine.run_finding import LOG_ROOT as _FR
    from engine.loop import solve_challenge
    from engine.tsg.store import TSG
    import time

    targets = args.target
    prof = make_koh_profile()
    for tgt in targets:
        safe = "".join(c if c.isalnum() else "_" for c in tgt.split("//")[-1])[:60]
        db = str(Path(_FR) / safe / "koh.tsg.db")
        Path(db).parent.mkdir(parents=True, exist_ok=True)
        print(f"[koh] engaging {tgt} (TSG {db})", flush=True)
        try:
            outcome, tsg = solve_challenge(
                tgt, args.task, provider=args.provider, model=args.model, db_path=db,
                max_waves=64, deadline=time.time() + args.budget, profile=prof)
            print(f"[koh] {tgt} -> status={outcome.status} waves={outcome.waves_used} "
                  f"captured={len(outcome.captured)}", flush=True)
        except Exception as e:
            print(f"[koh] {tgt} engine error: {e!r}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
