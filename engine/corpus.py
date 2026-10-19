from __future__ import annotations

import json
import os
import re

_REQUIRED_FIELDS = (
    "id", "project", "repo", "lang", "vuln_commit", "patch_commit",
    "fuzz_target", "sanitizer", "crash_type", "dedup_token", "poc_ptr",
    "vuln_img", "fix_img", "severity", "srcmap",
)

_NM_SYMBOL_RX = re.compile(r"^\s*[0-9a-fA-F]+\s+[tTwWdDbB]\s+(\S+)", re.M)


def _validate(entry) -> list:
    errs = []
    if not isinstance(entry, dict):
        return ["not a json object"]
    for k in _REQUIRED_FIELDS:
        if k not in entry or entry[k] in (None, "", [], {}):
            errs.append(f"missing/empty: {k}")
    sm = entry.get("srcmap")
    if isinstance(sm, list):
        for i, dep in enumerate(sm):
            for sub in ("url", "rev", "type"):
                if not isinstance(dep, dict) or not dep.get(sub):
                    errs.append(f"srcmap[{i}].{sub} missing (pinned deps required)")
    return errs


def load_cve_corpus(path: str) -> tuple:
    if not path or not os.path.isfile(path):
        return [], 0
    entries, rejected = [], 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    rejected += 1
                    continue
                errs = _validate(entry)
                if errs:
                    rejected += 1
                    continue
                entries.append(entry)
    except OSError:
        return [], 0
    return entries, rejected


def symbol_precheck(symbol_names, nm_output: str) -> tuple:
    names = [s for s in (symbol_names or []) if s]
    if not names:
        return False, []
    present = set(_NM_SYMBOL_RX.findall(nm_output or ""))
    missing = [s for s in names if s not in present]
    return (not missing), missing
