#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from os import environ

from tsec_benchmark import TSecBenchmark, DuplicateSubmit, VpnCheckError, TSecError

CONCURRENCY = 3
MODEL = "deepseek-flash"
MAX_TURNS = "60"
TIMEOUT = "900"
FLAG_RX = re.compile(r"flag\{[A-Za-z0-9_-]{6,120}\}")

_lock = threading.Lock()


def log(msg: str) -> None:
    with _lock:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()


def solve_target(target: str, task: str, tag: str) -> set[str]:
    cmd = [
        "python3", "-m", "solver.solve", "--target", target, "--task", task,
        "--model", MODEL, "--max-turns", MAX_TURNS, "--timeout", TIMEOUT,
        "--disallow-tools", "", "--flag-regex", FLAG_RX.pattern,
    ]
    flags: set[str] = set()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    for line in proc.stdout:
        line = line.rstrip("\n")
        with _lock:
            sys.stdout.write(f"[{tag}] {line}\n")
            sys.stdout.flush()
        flags.update(FLAG_RX.findall(line))
    proc.wait()
    return flags


def run_one(client, ch) -> tuple[str, set[str], int]:
    code = ch.unique_code
    correct = 0
    captured: set[str] = set()
    log(f"[bench] ===== START {code} [{ch.difficulty}] flags={ch.flag_count} score={ch.total_score}")
    try:
        started = client.start_challenge(code)
    except TSecError as e:
        log(f"[bench] {code} start failed: {e}")
        return code, captured, 0
    log(f"[bench] {code} targets: {started.container_addr}")
    try:
        task = ch.description or "Find and capture all flags."
        for addr in started.container_addr:
            target = addr if addr.startswith("http") else f"http://{addr}/"
            captured |= solve_target(target, task, code)
        log(f"[bench] {code} captured: {sorted(captured) or 'NONE'}")
        for flag in sorted(captured):
            try:
                res = client.submit_flag(code, flag)
                log(f"[bench] {code} submit {flag} -> correct={res.correct} awarded={res.awarded} "
                    f"progress={res.correct_flag_count}/{res.total_flag_count}")
                if res.correct:
                    correct += 1
            except DuplicateSubmit:
                log(f"[bench] {code} {flag} duplicate")
            except TSecError as e:
                log(f"[bench] {code} submit error {flag}: {e}")
    except TSecError as e:
        log(f"[bench] {code} error mid-solve: {e}")
    finally:
        try:
            client.close_challenge(code)
        except TSecError:
            pass
    return code, captured, correct


def main(argv: list[str]) -> int:
    token = environ.get("BENCHMARK_TOKEN", "")
    base = environ.get("BENCHMARK_BASE_URL", "")
    if not token or not base:
        sys.exit("BENCHMARK_TOKEN / BENCHMARK_BASE_URL 未设置")
    if not environ.get("SOLVER_API_KEY"):
        sys.exit("SOLVER_API_KEY 未设置")

    codes = [c for c in argv if c.strip()]
    try:
        client_cm = TSecBenchmark(base_url=base, token=token)
    except VpnCheckError as e:
        sys.exit(f"[bench] VPN 预检失败: {e}")

    with client_cm as client:
        allch = client.list_challenges()
        stale = [c for c in allch if c.container_status in ("available", "pending", "stop_pending")]
        for c in stale:
            try:
                client.close_challenge(c.unique_code)
                log(f"[bench] cleanup: closed stale active {c.unique_code}")
            except TSecError:
                pass
        if stale:
            allch = client.list_challenges()
        todo = [ch for ch in allch
                if (not codes or ch.unique_code in codes) and not ch.is_completed]
        log(f"[bench] {len(allch)} total; running {len(todo)} "
            f"({codes or 'ALL'}); concurrency={CONCURRENCY}; model={MODEL}")
        results: list[tuple[str, set[str], int]] = []
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
            futs = {ex.submit(run_one, client, ch): ch.unique_code for ch in todo}
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception as e:
                    log(f"[bench] {futs[f]} crashed: {e}")

        total_correct = sum(c for _, _, c in results)
        fully = 0
        try:
            done_map = {c.unique_code: c for c in client.list_challenges()}
            fully = sum(1 for code, _, _ in results
                        if done_map.get(code) and done_map[code].is_completed)
        except TSecError:
            pass
        log(f"\n[bench] DONE. ran={len(results)} fully_solved={fully} correct_flags={total_correct}")
        for code, caps, corr in sorted(results):
            log(f"[bench]   {code}: correct_flags={corr} captured={len(caps)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
