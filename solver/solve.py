#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

from engine.providers import cc_env as _provider_cc_env


def cc_env(provider: str, model: str, api_key: str, custom_base_url: str = "") -> dict:
    return {**os.environ,
            **_provider_cc_env(provider, model, api_key=api_key, custom_base_url=custom_base_url)}


PROMPT = """\
You are an autonomous agent given ONE objective and a Linux shell with a full toolset already \
installed. OWN IT: work entirely on your own in this single session, chain as many shell \
commands as you need, build on what you discover, and keep going until you achieve the \
objective or genuinely exhaust every avenue. Never stop after a single observation. Verify \
every claim by actually running a command — never assume output you did not see.

OBJECTIVE: {task}
TARGET: {target}

When you have produced the deliverable the objective asks for, output it IMMEDIATELY on its \
own line, exactly:
    FinalAnswer: <the exact flag string>
Then stop.
"""

FLAG_RX_DEFAULT = r"canary\{[A-Za-z0-9_]{3,64}\}"


def _texts_from_event(ev: dict):
    out = []
    t = ev.get("type")
    if t == "assistant":
        for blk in ev.get("message", {}).get("content", []) or []:
            if isinstance(blk, dict) and blk.get("type") == "text":
                out.append(blk.get("text", ""))
    elif t == "user":
        for blk in ev.get("message", {}).get("content", []) or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_result":
                c = blk.get("content", "")
                if isinstance(c, list):
                    out.extend(b.get("text", "") for b in c if isinstance(b, dict))
                elif isinstance(c, str):
                    out.append(c)
    elif t == "result":
        r = ev.get("result")
        if isinstance(r, str):
            out.append(r)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--task", default="Find and capture the flag.")
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--model", default="deepseek-v4-flash")
    ap.add_argument("--max-turns", type=int, default=60)
    ap.add_argument("--timeout", type=int, default=1800, help="wall-clock seconds")
    ap.add_argument("--disallow-tools", default="WebSearch,WebFetch",
                    help="claude tools to disable (cloud mode has no internet); empty to allow all")
    ap.add_argument("--flag-regex", default=FLAG_RX_DEFAULT, help="regex to extract the flag")
    args = ap.parse_args()

    key = os.environ.get("SOLVER_API_KEY", "")
    if not key:
        sys.exit("SOLVER_API_KEY is empty — set the provider API key.")

    prompt = PROMPT.format(target=args.target, task=args.task)
    env = cc_env(args.provider, args.model, key)

    cmd = [
        "claude", "-p", prompt,
        "--output-format", "stream-json", "--verbose",
        "--dangerously-skip-permissions", "--max-turns", str(args.max_turns),
    ]
    if args.disallow_tools.strip():
        cmd += ["--disallowed-tools", *args.disallow_tools.split(",")]
    print(f"[solve] target={args.target} model={args.provider}/{args.model} "
          f"max_turns={args.max_turns} timeout={args.timeout}s", flush=True)

    flag_rx = re.compile(args.flag_regex)
    start = time.time()
    all_text: list[str] = []
    seen_flags: set[str] = set()
    flag = None

    # nosem 抑制说明:带 env 启动执行器 CLI 是本程序本职(模型网关凭据经 env 注入),非注入向量
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,  # nosem: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
                            text=True, bufsize=1)
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            for txt in _texts_from_event(ev):
                if not txt:
                    continue
                all_text.append(txt)
                for cand in flag_rx.findall(txt):
                    if cand not in seen_flags:
                        seen_flags.add(cand)
                        print(f"\n[solve] FLAG CANDIDATE: {cand}", flush=True)
                    if flag is None:
                        flag = cand
            if ev.get("type") == "assistant":
                for blk in ev.get("message", {}).get("content", []) or []:
                    if isinstance(blk, dict) and blk.get("type") == "tool_use":
                        inp = json.dumps(blk.get("input", {}), ensure_ascii=False)[:120]
                        print(f"  [tool] {blk.get('name')}: {inp}", flush=True)
            if time.time() - start > args.timeout:
                print("[solve] wall-clock timeout — killing claude", flush=True)
                proc.kill()
                break
    finally:
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    joined = "\n".join(all_text)
    if flag is None:
        m = re.search(r"FinalAnswer:\s*(" + args.flag_regex + ")", joined) or flag_rx.search(joined)
        if m:
            flag = m.group(1) if m.re.groups else m.group(0)

    elapsed = int(time.time() - start)
    print(f"\n[solve] done in {elapsed}s", flush=True)
    if flag:
        print(f"FLAG: {flag}")
        return 0
    print("FLAG: <none captured>")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
