from __future__ import annotations

import os
import sys

_PATH_PREFIXES = ("file://", "/", "./", "../", "~")


def _is_path_form(a: str) -> bool:
    return a.startswith(_PATH_PREFIXES)


def _src_path(a: str) -> str:
    return os.path.expanduser(a[len("file://"):] if a.startswith("file://") else a)


def _looks_like_source(a: str) -> bool:
    return _is_path_form(a) and os.path.exists(_src_path(a))


def route(argv: list[str]) -> tuple[str, list[str]]:
    targets = [a for a in argv if a and a.strip()]
    flagged = [t for t in targets if t.startswith("-")]
    if flagged:
        return "error", [f"autoroute 不接旗标参数(不是目标): {flagged} —— 活体用 URL、源码用路径,旗标走显式子命令"]
    if os.environ.get("BENCHMARK_TOKEN") and os.environ.get("BENCHMARK_BASE_URL"):
        return "benchmark", targets
    missing = [t for t in targets if _is_path_form(t) and not os.path.exists(_src_path(t))]
    if missing:
        return "error", [f"源码路径不存在: {missing} —— 拒绝把打错的路径降级成活体网络扫描;查路径,或用 URL 指活体目标"]
    if targets and all(_looks_like_source(t) for t in targets):
        return "finding-source", targets
    src = [t for t in targets if _looks_like_source(t)]
    live = [t for t in targets if not _looks_like_source(t)]
    if src and live:
        return "finding-hybrid", targets
    return "finding-live", targets


def main(argv: list[str]) -> int:
    scenario, targets = route(argv)
    if scenario == "error":
        sys.exit(f"[autoroute] {targets[0]}")
    sys.stdout.write(f"[autoroute] 判形 → {scenario} (targets={len(targets)})\n"); sys.stdout.flush()
    if scenario == "benchmark":
        from engine.run_bench import main as run
    elif scenario == "finding-source":
        from engine.run_source import main as run
    elif scenario == "finding-hybrid":
        from engine.run_source import main as run_src
        from engine.run_finding import main as run_live
        src_targets = [t for t in targets if _looks_like_source(t)]
        live_targets = [t for t in targets if not _looks_like_source(t)]
        rc = run_src(src_targets)
        if live_targets:
            rc2 = run_live(live_targets)
            rc = rc or rc2
        return rc
    else:
        from engine.run_finding import main as run
    return run(targets)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
