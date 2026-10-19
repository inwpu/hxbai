#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import threading
import time
from pathlib import Path

from engine.loop import EngineLoop, _default_cc_decide, _default_cc_execute
from engine.profile import ScenarioProfile
from engine.tsg.store import TSG

DEFAULT_FLAG_RX = r"(?i)(dasctf|flag|ctf[0-9]?)\{[^}{}\n]{3,120}\}"


class CtfLocalProfile(ScenarioProfile):

    def __init__(self, need: int, flag_rx):
        self.need = need
        self.flag_rx = flag_rx

    def _hits(self, loop) -> list[str]:
        return [f for f in loop.captured if self.flag_rx.search(f)]

    def is_achieved(self, loop) -> bool:
        return len(self._hits(loop)) >= self.need

    def adjudicate(self, loop, candidates) -> None:
        return None

    def summary(self, loop) -> dict:
        return {"captured": sorted(self._hits(loop))}


def _watch_ws(ws: str, stop: threading.Event) -> None:
    proj_root = Path(ws) / ".claude" / "projects"
    pos = 0
    cur: Path | None = None
    while not stop.is_set():
        try:
            files = sorted(proj_root.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime) \
                if proj_root.is_dir() else []
            newest = files[-1] if files else None
            if newest != cur:
                cur, pos = newest, 0
            if cur is not None:
                data = cur.read_bytes()
                if len(data) > pos:
                    for line in data[pos:].split(b"\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            e = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        msg = e.get("message") or {}
                        content = msg.get("content")
                        if isinstance(content, list):
                            for b in content:
                                if not isinstance(b, dict):
                                    continue
                                if b.get("type") == "tool_use":
                                    cmd = (b.get("input") or {}).get("command") \
                                        or json.dumps(b.get("input") or {}, ensure_ascii=False)
                                    print(f"    ⚙ {b.get('name','?')}: {str(cmd)[:110]}", flush=True)
                                elif b.get("type") == "text" and msg.get("role") == "assistant":
                                    t = (b.get("text") or "").strip()
                                    if t and len(t) > 10:
                                        print(f"    💬 {t[:110]}", flush=True)
                    pos = len(data)
        except OSError:
            pass
        stop.wait(2.0)


def main() -> int:
    ap = argparse.ArgumentParser(prog="hunt", description="单题 CTF 狩猎(完整引擎)")
    ap.add_argument("--target", default="", help="目标 URL(Web 题)")
    ap.add_argument("--files", action="append", default=[], metavar="PATH",
                    help="附件文件/目录(附件题,可多次)")
    ap.add_argument("--task", default="Solve this CTF challenge and capture the flag.",
                    help="题面/目标描述")
    ap.add_argument("--budget", type=int, default=3600, help="总预算秒(默认 3600)")
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--need", type=int, default=1,
                    help="需要的旗数(如 HTB 机器 = 2:user.txt + root.txt)")
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--model", default="deepseek-flash")
    ap.add_argument("--flag-regex", default=DEFAULT_FLAG_RX)
    ap.add_argument("--root", default="/tmp/hxctf-hunt",
                    help="TSG/工作区根目录(默认 /tmp/hxctf-hunt;须在执行器 uid 可穿越的路径下)")
    ap.add_argument("--watch", action="store_true", help="实时显示执行器命令")
    args = ap.parse_args()

    if not os.environ.get("SOLVER_API_KEY"):
        sys.exit("SOLVER_API_KEY 未设置(模型 key)")
    if not args.target and not args.files:
        sys.exit("--target(URL)或 --files(附件)至少给一个")

    label = re.sub(r"[^A-Za-z0-9.-]+", "_",
                   (args.target.split("//")[-1].split("/")[0] if args.target
                    else Path(args.files[0]).name))[:48] or "chal"
    run_dir = Path(args.root) / label
    ws = run_dir / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    db = run_dir / "t0.tsg.db"
    events = run_dir / "t0.tsg.events.jsonl"

    if args.files:
        att = ws / "attachments"
        att.mkdir(exist_ok=True)
        for p in args.files:
            src = Path(p).expanduser()
            if not src.exists():
                sys.exit(f"附件不存在: {src}")
            dst = att / src.name
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
        _uid, _gid = int(os.environ.get("HXCTF_EXEC_UID", "61000")), int(os.environ.get("HXCTF_EXEC_GID", "61000"))
        for d, _, fs in os.walk(att):
            try:
                os.chown(d, _uid, _gid)
                for f in fs:
                    os.chown(os.path.join(d, f), _uid, _gid)
            except OSError:
                pass
        target = f"local attachments in your workspace at {att}"
        task = args.task + " (题目附件已放在工作区 attachments/ 目录)"
    else:
        target = args.target if args.target.startswith("http") else f"http://{args.target}/"
        task = args.task

    from engine.loop import role_llm_params
    kw_dec = role_llm_params(args.provider, args.model, "", "decide")
    kw_exe = role_llm_params(args.provider, args.model, "", "execute")
    for _kw in (kw_dec, kw_exe):
        _kw["workspace"] = str(ws)
    kw = kw_exe
    import re as _re
    flag_rx = _re.compile(args.flag_regex)
    cap_file = run_dir / "captured.json"
    prev = set()
    try:
        prev = set(json.loads(cap_file.read_text()) or [])
    except (OSError, ValueError):
        pass
    known_wrong = {f for f in prev if not flag_rx.search(f)}
    if known_wrong:
        print(f"[hunt] 上轮捕获中 {len(known_wrong)} 个不匹配旗格式 → 判诱饵,喂给引擎排除:"
              f"{sorted(known_wrong)[:3]}", flush=True)

    tsg = TSG(str(db), str(events))
    resume = "(续打:沿用既有 TSG)" if db.exists() and db.stat().st_size > 0 else ""
    print(f"[hunt] target={target}\n[hunt] budget={args.budget}s waves={args.waves} "
          f"model={args.provider}/{args.model} db={db} {resume}", flush=True)

    stop = threading.Event()
    if args.watch:
        threading.Thread(target=_watch_ws, args=(str(ws), stop), daemon=True).start()

    loop = EngineLoop(
        tsg, target, task,
        decide_fn=_default_cc_decide(**kw_dec),
        execute_fn=_default_cc_execute(**kw_exe),
        max_waves=args.waves, concurrency=args.concurrency,
        deadline=time.time() + args.budget,
        need_flags=args.need,
        profile=CtfLocalProfile(args.need, flag_rx),
        flag_regex=args.flag_regex,
        known_wrong=known_wrong,
        label=label[:20],
        workspace=str(ws),
    )
    oc = loop.run()
    stop.set()
    hits = [f for f in oc.captured if flag_rx.search(f)]
    try:
        cap_file.write_text(json.dumps(sorted(set(hits) | {f for f in prev if flag_rx.search(f)})))
    except OSError:
        pass
    decoys = sorted(f for f in oc.captured if not flag_rx.search(f))
    print(f"\n[hunt] DONE status={oc.status} waves={oc.waves_used} "
          f"captured={hits}", flush=True)
    if decoys:
        print(f"[hunt] 已捕获但不匹配旗格式(诱饵,已记录供下轮排除): {decoys}", flush=True)
    print("[hunt][usage] " + json.dumps(loop.usage_total), flush=True)
    tsg.close()
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
