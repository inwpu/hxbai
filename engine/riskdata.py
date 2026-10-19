from __future__ import annotations

import csv
import json
import os
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "risk"


def _dir() -> Path:
    return Path(os.environ.get("HXCTF_RISK_DATA", "").strip() or _DATA_DIR)


def load_kev() -> set:
    p = _dir() / "kev.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return {it.get("cveID", "").upper() for it in d.get("known_exploited_vulnerabilities") or []
                if it.get("cveID")}
    except Exception:
        return set()


def load_epss() -> dict:
    p = _dir() / "epss.tsv"
    out: dict = {}
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            rd = csv.DictReader(f)
            for row in rd:
                cve = (row.get("cve") or row.get("CVE") or "").upper()
                if not cve:
                    continue
                try:
                    out[cve] = {"epss": float(row.get("epss") or 0.0),
                                "percentile": float(row.get("percentile") or 0.0)}
                except ValueError:
                    continue
    except OSError:
        return {}
    return out


def summary() -> str:
    k, e = load_kev(), load_epss()
    return f"[riskdata] KEV={len(k)} 条 EPSS={len(e)} 条(0=快照未烤,fail-open 不影响裁决)"
