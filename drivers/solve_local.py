import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hxbai import (SolverConfig, ControllerConfig, AgentTask, Verifier, Claim,
                   build_verifier_config, solve_with_claude_code, build_task_prompt, StopLoss)
from hxbai.blackboard import Blackboard
from hxbai.taskprompt import write_claude_md, write_memory
from hxbai.knowledge.store import KnowledgeStore
from hxbai.llm import LLMClient


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="reachable target, e.g. http://localhost:1337 or host:port")
    ap.add_argument("--objective", default="Find and extract the flag from the target.")
    ap.add_argument("--flag-format", default="flag{...}")
    ap.add_argument("--flag-count", type=int, default=1)
    ap.add_argument("--hint", default=None)
    ap.add_argument("--category", default=None)
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--max-sessions", type=int, default=None)
    args = ap.parse_args()

    solver = SolverConfig.from_env()
    ctrl = ControllerConfig.from_env()
    if not solver.api_key:
        print("ERROR: set SOLVER_API_KEY (and HXBAI_PROVIDER=deepseek|glm) so Claude Code can auth.", file=sys.stderr)
        sys.exit(2)
    max_sessions = args.max_sessions or ctrl.max_sessions_per_challenge

    code = "local"
    workdir = args.workdir or os.path.join(ctrl.workdir, code)
    os.makedirs(workdir, exist_ok=True)
    write_claude_md(workdir)

    task = AgentTask(objective=args.objective, targets=[args.target], flag_count=args.flag_count,
                     flag_format=args.flag_format, workdir=workdir, category=args.category, unique_code=code)
    board = Blackboard(os.path.join(workdir, "_blackboard.json"))
    board.objective = task.objective
    board.seed_goals()

    verifier_cfg = build_verifier_config(solver)
    llm = LLMClient(verifier_cfg) if verifier_cfg.is_usable() else None
    verifier = Verifier(llm, skeptic_votes=ctrl.skeptic_votes)
    knowledge = KnowledgeStore()
    stoploss = StopLoss(per_challenge_seconds=ctrl.per_challenge_seconds,
                        max_sessions=max_sessions, dry_cutoff=ctrl.dry_facts_cutoff)
    stoploss.start(code)

    print(f"[solve_local] provider={solver.provider} model={solver.model} target={args.target}")
    print(f"[solve_local] workdir={workdir} max_sessions={max_sessions} per_challenge={ctrl.per_challenge_seconds}s")

    confirmed: list = []
    for s in range(max_sessions):
        stop, why = stoploss.should_stop(code)
        if stop:
            print(f"[solve_local] stop-loss: {why}")
            break
        prior = os.path.join(workdir, "MEMORY.md")
        prompt = build_task_prompt(task, board, knowledge=knowledge, hint=args.hint,
                                   prior_memory_path=prior if os.path.isfile(prior) else None, session_idx=s)
        from dataclasses import replace
        sess_secs = min(solver.session_seconds, stoploss.remaining_seconds(code))
        solver_this = replace(solver, session_seconds=max(60, sess_secs))

        new_facts = [0]

        def _on_fact(tool, a, o, _s=s, _nf=new_facts):
            _nf[0] += board.observe(tool, a or {}, o or "", iter=_s)

        print(f"\n[solve_local] === session {s+1}/{max_sessions} (<= {solver_this.session_seconds}s) ===")
        res = solve_with_claude_code(prompt, workdir, solver_this, flag_format=task.flag_format, on_fact=_on_fact)
        write_memory(workdir, board)
        stoploss.record_session(code, new_facts=new_facts[0])
        print(f"[solve_local] session done: turns={res.num_turns} new_facts={new_facts[0]} "
              f"candidate_flags={res.flags} err={res.error or '-'}")

        for flag in res.flags:
            claim = Claim(kind="flag", value=flag, statement=(res.final_answer or "")[:300],
                          observed_output=res.evidence_for(flag), flag_format=task.flag_format)
            ok, why = verifier.grounding_ok(claim)
            if not ok:
                print(f"  [REJECTED] {flag}  ({why})")
                continue
            gated = verifier.verify(claim)
            print(f"  [GROUNDED] {flag}  (verdict={gated.verdict})")
            if flag not in confirmed:
                confirmed.append(flag)
        if confirmed and len(confirmed) >= task.flag_count:
            break

    print("\n========================================")
    if confirmed:
        print("SOLVED — grounded flag(s):")
        for f in confirmed:
            print("  " + f)
    else:
        print("NOT SOLVED — no grounded flag. Facts gathered:")
        print(board.render())
    print("========================================")
    sys.exit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
