import argparse
import json
import os
import shutil
import sys
import threading
import time
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hxbai import (SolverConfig, ControllerConfig, AgentTask, Verifier, Claim,
                   build_verifier_config, solve_with_claude_code, build_task_prompt, StopLoss)
from hxbai.blackboard import Blackboard
from hxbai.taskprompt import write_claude_md, write_memory
from hxbai.knowledge.store import KnowledgeStore
from hxbai.llm import LLMClient
from hxbai import observability as obs
from benchmark_driver import schedule_rounds

log_lock = threading.Lock()


def _log(msg):
    with log_lock:
        print(msg, flush=True)


def _safe(name):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:64]


class _Ch:
    def __init__(self, spec):
        self.spec = spec
        self.unique_code = spec["name"]
        self.difficulty = spec.get("difficulty", "easy")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--workroot", default=None)
    args = ap.parse_args()

    manifest = json.load(open(args.manifest))
    solver = SolverConfig.from_env()
    ctrl = ControllerConfig.from_env()
    if args.workroot:
        ctrl.workdir = args.workroot
    os.makedirs(ctrl.workdir, exist_ok=True)
    obs.configure(os.path.join(ctrl.workdir, "_events.jsonl"), run_id=f"batch-{solver.provider}")

    vcfg = build_verifier_config(solver)
    llm = LLMClient(vcfg) if vcfg.is_usable() else None
    verifier = Verifier(llm, skeptic_votes=ctrl.skeptic_votes)
    knowledge = KnowledgeStore()
    stoploss = StopLoss(per_challenge_seconds=ctrl.per_challenge_seconds,
                        max_sessions=ctrl.max_sessions_per_challenge, dry_cutoff=ctrl.dry_facts_cutoff)

    boards: dict = {}
    boards_lock = threading.Lock()
    populated: set = set()
    results: dict = {}
    res_lock = threading.Lock()

    challenges = [_Ch(s) for s in manifest]
    _log(f"[batch] {len(challenges)} challenges | provider={solver.provider} model={solver.model} "
         f"concurrency={ctrl.max_concurrency} rounds={ctrl.round_timeboxes}")

    def shared_board(code, workdir):
        with boards_lock:
            b = boards.get(code)
            if b is None:
                b = Blackboard(os.path.join(workdir, "_blackboard.json"))
                boards[code] = b
            return b

    def visit(ch, visit_seconds, rnd):
        spec = ch.spec
        code = ch.unique_code
        stop, why = stoploss.should_stop(code)
        if stop:
            return {"solved": False, "outcome": "dropped", "reason": why}
        workdir = os.path.join(ctrl.workdir, _safe(code))
        os.makedirs(workdir, exist_ok=True)
        with boards_lock:
            first = code not in populated
            populated.add(code)
        if first and spec.get("files_dir") and os.path.isdir(spec["files_dir"]):
            for item in os.listdir(spec["files_dir"]):
                src = os.path.join(spec["files_dir"], item)
                dst = os.path.join(workdir, item)
                try:
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                except Exception as e:
                    _log(f"[batch] {code}: file copy warn: {e}")
        write_claude_md(workdir)
        task = AgentTask(objective=spec["objective"], targets=[spec["target"]] if spec.get("target") else [],
                         flag_format=spec.get("flag_format", "HTB{...}"), workdir=workdir, unique_code=code)
        board = shared_board(code, workdir)
        board.objective = task.objective
        board.seed_goals()
        stoploss.start(code)
        answer = (spec.get("answer") or "").strip()
        solved = False
        visit_deadline = time.monotonic() + max(60, int(visit_seconds))
        _log(f"[batch] round {rnd+1} visit {code} (visit<={int(visit_seconds)}s, target={task.target_str()[:40]})")

        s = 0
        while time.monotonic() < visit_deadline:
            stop, why = stoploss.should_stop(code)
            if stop:
                _log(f"[batch]   {code} stop-loss: {why}")
                break
            prior = os.path.join(workdir, "MEMORY.md")
            prompt = build_task_prompt(task, board, knowledge=knowledge,
                                       prior_memory_path=prior if os.path.isfile(prior) else None, session_idx=s)
            sess_secs = min(solver.session_seconds, int(visit_deadline - time.monotonic()),
                            stoploss.remaining_seconds(code))
            if sess_secs < 45:
                break
            solver_this = replace(solver, session_seconds=max(45, sess_secs))
            nf = [0]

            def _on_fact(t, a, o, _s=s, _nf=nf):
                _nf[0] += board.observe(t, a or {}, o or "", iter=_s)

            t0 = time.monotonic()
            r = solve_with_claude_code(prompt, workdir, solver_this, flag_format=task.flag_format, on_fact=_on_fact)
            write_memory(workdir, board)
            stoploss.record_session(code, new_facts=nf[0], active_seconds=time.monotonic() - t0)
            _log(f"[batch]   {code} s{s+1}: turns={r.num_turns} facts+={nf[0]} flags={r.flags[:3]} err={r.error or '-'}")
            s += 1

            for flag in r.flags:
                claim = Claim(kind="flag", value=flag, statement=(r.final_answer or "")[:200],
                              observed_output=r.evidence_for(flag), flag_format=task.flag_format)
                ok, gwhy = verifier.grounding_ok(claim)
                if not ok:
                    continue
                verifier.verify(claim)
                correct = bool(answer and (flag.strip() == answer or answer in flag))
                _log(f"[batch]   {code} GROUNDED {flag}  correct={correct}")
                if correct:
                    solved = True
                    break
            if solved:
                break
        with res_lock:
            results[code] = {"solved": solved, "answer": answer}
        return {"solved": solved, "outcome": "done"}

    t0 = time.monotonic()
    solved_codes, dropped_codes = schedule_rounds(
        challenges, visit, timeboxes=ctrl.round_timeboxes,
        should_drop=lambda c: stoploss.should_stop(c)[0],
        max_concurrent=ctrl.max_concurrency, total_seconds=ctrl.total_seconds,
        stop_event=threading.Event(),
    )
    obs.emit("run_end", layer="batch")
    _log("\n================= BATCH RESULT =================")
    for ch in challenges:
        code = ch.unique_code
        st = "SOLVED " if code in solved_codes else ("dropped" if code in dropped_codes else "unsolved")
        _log(f"  [{st}] {code}")
    _log(f"solved {len(solved_codes)}/{len(challenges)} in {int(time.monotonic()-t0)}s "
         f"(dropped {len(dropped_codes)})")
    _log("===============================================")
    sys.exit(0)


if __name__ == "__main__":
    main()
