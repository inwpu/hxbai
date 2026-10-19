from __future__ import annotations

import hashlib
import secrets


def gen_canary(prefix: str = "CANARY") -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def canary_rce_verdict(shell_output: str, canary: str) -> str:
    if canary and canary in (shell_output or ""):
        return "CONFIRMED"
    return "NOT_CONFIRMED"


def db_checksum_diff(before_dump: str, after_dump: str) -> dict:
    bh = hashlib.sha256(before_dump.encode()).hexdigest()[:16]
    ah = hashlib.sha256(after_dump.encode()).hexdigest()[:16]
    return {"changed": bh != ah, "before_hash": bh, "after_hash": ah,
            "verdict": "DATA_MODIFIED" if bh != ah else "NO_CHANGE"}


def content_exact_exfil(observed_content: str, expected_content: str) -> str:
    if observed_content and observed_content.strip() == expected_content.strip():
        return "EXFIL_CONFIRMED"
    return "MISMATCH"


def privesc_verdict(before_id: str, after_id: str) -> str:
    before_uid = before_id.strip()
    after_uid = after_id.strip()
    if "uid=0" in after_uid and "uid=0" not in before_uid:
        return "PRIVESC_CONFIRMED"
    if "admin" in after_uid.lower() and "admin" not in before_uid.lower():
        return "PRIVESC_CONFIRMED"
    return "NO_ESCALATION"
