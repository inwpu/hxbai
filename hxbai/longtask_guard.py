#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys

_PRODUCER = re.compile(
    r"(?i)\b(?:hydra|medusa|john|hashcat|nuclei|ffuf|gobuster|dirb|nikto|masscan|"
    r"\w*spray\w*|\w*brute\w*|\w*crack\w*)\b|authspray")
_RECON_TOOL = re.compile(r"(?i)\b(?:nmap|sqlmap)\b")
_NMAP_HEAVY = re.compile(r"(?i)-p-|-p\s*1-65535|--allports|\b\d+\.\d+\.\d+\.\d+/\d{2}\b")
_SQLMAP_HEAVY = re.compile(
    r"(?i)--dump(?:-all)?\b|--tables\b|--columns\b|--os-shell\b|--level\s*[3-5]\b|--risk\s*[2-3]\b|--threads")
_BIGSCAN = re.compile(r"(?i)\b\d+\.\d+\.\d+\.\d+/\d{2}\b")
_TIMEOUT = re.compile(r"\btimeout\s+(\d+)")
_BG = re.compile(r"(?i)\b(?:tmux|nohup|setsid|systemd-run|screen)\b|&\s*$")
_PIPE_TAIL = re.compile(r"(?i)\|\s*(?:\/\w+\/)?(?:tail|head)\b")
_READER = re.compile(r"(?i)^\s*(?:tail|head|cat|less|more|grep|egrep|rg|awk|sed|wc|nl|strings|find|ls|ps|tmux\s+ls)\b")

_R1_TMPL = ("拒绝:长任务的管道接进 tail/head——管道缓冲会吞掉全部输出,SIGTERM 时结果全丢"
            "(实测:一次定向爆破结果因此一份不剩)。改写为后台+落盘:\n"
            "  tmux new-session -d -s <名> '<原命令> >> /tmp/<名>.log 2>&1'\n"
            "然后轮询 `tail -5 /tmp/<名>.log` 取进度,绝不重启同任务。")
_R2_TMPL = ("拒绝:爆破/大扫描/长超时任务禁止前台跑——会话随时被掐,前台长任务=白干。改写:\n"
            "  tmux new-session -d -s <名> '<原命令> >> /tmp/<名>.log 2>&1'\n"
            "认证喷洒优先 `python3 /opt/tools/authspray.py`(自带 SUMMARY 错误核算);"
            "结果必须落盘,下个会话 tail 日志续力。")


def decide(command: str) -> tuple[str, str]:
    if not command or not os.environ.get("HXBAI_LONGTASK_GUARD", "1") == "1":
        return "allow", ""
    if _READER.match(command):
        return "allow", ""
    if _BG.search(command):
        return "allow", ""
    m = _TIMEOUT.search(command)
    secs = int(m.group(1)) if m else 0
    heavy = bool(_PRODUCER.search(command) or _BIGSCAN.search(command) or secs >= 120)
    if _RECON_TOOL.search(command):
        heavy = heavy or bool(_NMAP_HEAVY.search(command)) or bool(_SQLMAP_HEAVY.search(command))
    if not heavy:
        return "allow", ""
    if _PIPE_TAIL.search(command):
        return "deny", _R1_TMPL
    if heavy:
        return "deny", _R2_TMPL
    return "allow", ""


def main() -> int:
    try:
        evt = json.load(sys.stdin)
    except Exception:
        return 0
    if evt.get("tool_name") != "Bash":
        return 0
    cmd = (evt.get("tool_input") or {}).get("command", "") or ""
    decision, reason = decide(cmd)
    if decision == "deny":
        json.dump({"decision": "block", "reason": reason,
                   "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}},
                  sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
