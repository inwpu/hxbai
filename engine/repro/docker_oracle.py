from __future__ import annotations

import os
import subprocess
from pathlib import Path

from engine.repro.diff_oracle import differential_verdict

_DIFF_TIMEOUT_S = 30


def _run_once(image: str, poc_path: str | None, fuzz_target: str, timeout: int = _DIFF_TIMEOUT_S) -> tuple[str, bool]:
    cmd = ["docker", "run", "--rm"]
    if poc_path:
        p = Path(poc_path)
        if not p.is_file():
            return "", False
        cmd += ["-v", f"{p.resolve()}:/poc:ro"]
    if fuzz_target:
        cmd += ["--entrypoint", fuzz_target]
    cmd += [image]
    if poc_path:
        cmd += ["/poc"]
    cmd += ["-timeout=10"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + "\n" + (r.stderr or ""), True
    except subprocess.TimeoutExpired:
        return "", False
    except OSError:
        return "", False


def run_diff(entry: dict, poc_path: str | None, *, expected_dedup: str | None = None) -> str:
    vt = entry.get("vuln_img") or ""
    ft = entry.get("fix_img") or ""
    if not vt or not ft:
        return "ERROR"
    v_out, v_ok = _run_once(vt, poc_path, entry.get("fuzz_target") or "")
    f_out, f_ok = _run_once(ft, poc_path, entry.get("fuzz_target") or "")
    if not v_ok or not f_ok:
        return "ERROR"
    dedup = expected_dedup or entry.get("dedup_token") or ""
    return differential_verdict(
        vuln_output=v_out, fix_output=f_out,
        expected_crash_type=entry.get("crash_type") or "",
        expected_dedup=dedup)
