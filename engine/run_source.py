from __future__ import annotations

import os
import sys
from pathlib import Path

from engine.checker import CheckerGate
from engine.loop import solve_challenge
from engine.profile import FindingSourceProfile
from engine.semgrep_runner import (load_corpus, make_runner, make_src_runner,
                                    semgrep_available)

LOG_ROOT = os.environ.get("HXCTF_LOG_ROOT", "/var/lib/hxctf/source")
PROVIDER, MODEL = "deepseek", "deepseek-flash"


def log(m: str) -> None:
    sys.stdout.write(m + "\n"); sys.stdout.flush()


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in str(s))[:40]


class _LoopView:
    def __init__(self, tsg): self.tsg = tsg


def _secure_log_root() -> None:
    try:
        os.makedirs(LOG_ROOT, exist_ok=True)
        os.chmod(LOG_ROOT, 0o700)
    except OSError:
        pass


def main(argv: list[str]) -> int:
    _secure_log_root()
    from engine.providers import resolve_active as _ra, resolve_key as _rk, PROVIDERS as _PV
    _pa = _ra(); _pr = _pa.get("provider", "deepseek")
    if not _rk(_pr, _pa.get("key", "")):
        _ev = _PV.get(_pr, ("", "SOLVER_API_KEY"))[1] or "HXCTF_LLM_API_KEY"
        sys.exit(f"LLM API key 未设置(provider={_pr}:请设 {_ev} 或通用 HXCTF_LLM_API_KEY)")
    roots = [a for a in argv if a.strip()]
    if not roots:
        sys.exit("用法: finding-source <source-root> [more...]")

    if not semgrep_available():
        sys.exit("[source] FATAL: semgrep 不可用 —— finding-source 需要它跑 checker(fail-closed)")
    corpus = load_corpus(os.environ.get("HXCTF_CVE_CORPUS"))
    if not corpus:
        sys.exit("[source] FATAL: 无 CVE 回放语料(设 HXCTF_CVE_CORPUS 指向 {name,vulnerable,patched} 的 json 目录)。"
                 "无历史反证不许放行 checker(fail-closed)")
    log(f"[source] CVE 回放语料 {len(corpus)} 条;semgrep OK")

    runner = make_runner()
    gate = CheckerGate(runner, corpus)
    extra_scope = [s.strip() for s in os.environ.get("HXCTF_SCOPE", "").split(",") if s.strip()]
    if extra_scope:
        log(f"[source] HXCTF_SCOPE 追加授权面: {extra_scope}")

    total = 0
    from engine.source_pipeline import run_pipeline
    for r in roots:
        root = str(Path(r).resolve())
        if not Path(root).exists():
            log(f"[source] SKIP 源码根不存在: {root}"); continue
        try:
            _pipe = run_pipeline(root, budget=10)
            log(f"[source] C 线流水线: 入口={_pipe['stats']['entry_count']} 可达={_pipe['stats']['reachable_count']}"
                f"/{_pipe['stats']['total_files']} taint假设={_pipe['stats']['hypothesis_count']}"
                f" 优先文件={_pipe['priority_files'][:3]}")
            for h in _pipe['hypotheses'][:5]:
                log(f"[source]   假设: {h['risk']} @ {h['file']}:{h['line']}")
        except Exception as e:
            log(f"[source] C 线流水线 non-fatal: {e!r}")
        prof = FindingSourceProfile(gate, need_findings=None, src_runner=make_src_runner(root))
        db = str(Path(LOG_ROOT) / _safe(root) / "source.tsg.db")
        Path(db).parent.mkdir(parents=True, exist_ok=True)
        ws = str(Path(LOG_ROOT) / _safe(root) / "ws")
        Path(ws).mkdir(parents=True, exist_ok=True)
        log(f"[source] auditing {root} (TSG {db})")
        outcome, tsg = solve_challenge(
            f"file://{root}",
            (f"TARGET CONTEXT (operator-provided): {os.environ.get('HXCTF_TASK_DESC')}\n\n"
             if os.environ.get("HXCTF_TASK_DESC") else "")
            + "Audit this read-only source tree. Synthesize checkers (Semgrep rules) for suspected vulnerabilities; "
            "each must pass CVE-replay and hit real code. "
            "When you have validated a rule, IMMEDIATELY submit it via: "
            "submit_capability: <rule-name> :: {\"rules\":[{\"id\":\"<rule-id>\","
            "\"severity\":\"WARNING\",\"message\":\"<one-line bug summary>\",\"patterns\":[{\"pattern\":\"<the exact semgrep pattern>\"}],\"languages\":[\"<the-language>\"]}]} "
            "— the COMPLETE rule as ONE LINE of JSON (never multi-line YAML, it gets truncated). IMPORTANT: patterns must match the VULNERABILITY CLASS's generic shape (e.g. any string-built shell call), not the target's specific identifiers — the corpus replay tests your rule against OTHER projects' bugs; over-specific rules will be rejected; "
            "the engine will replay it on the CVE corpus and run it against the source tree; "
            "that submission IS the deliverable, not your local test scripts.",
            provider=PROVIDER, model=MODEL, db_path=db, profile=prof,
            workspace=ws, max_waves=16, patience=6,
            authorized=extra_scope)
        try:
            claims = prof.summary(_LoopView(tsg))["gated_findings"]
            log(f"[source] {root} -> status={outcome.status} gated_findings={len(claims)}")
            for c in claims:
                log(f"[source]   [{c['severity']}] {c['vulnclass']} ({c.get('cwe')}) — {c['summary']}")
            total += len(claims)
        finally:
            tsg.close()
    log(f"\n[source] DONE. gated source findings={total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
