from __future__ import annotations

import re

_G1_PATTERNS = (
    re.compile(r"ERROR: (AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer)", re.I),
    re.compile(r"runtime error:.*sanitizer", re.I),
    re.compile(r"SUMMARY: \w*Sanitizer"),
    re.compile(r"SIG(SEGV|BUS|ABRT|ILL|FPE)\b.*in\s+\w+"),
    re.compile(r"(?i)core dumped"),
    re.compile(r"\bOOB_CALLBACK_[0-9a-f]{8,}\b"),
    re.compile(r"(?i)nonce[-_ ]?(proof|match|ok)\b"),
    re.compile(r"\bCANARY_[0-9a-f]{8,}\b"),
)
_G1_FORBIDDEN = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"(?i)^exit(ed)? (with )?code \d+$", re.M),
    re.compile(r"(?i)panic:.*runtime error"),
    re.compile(r"(?i)segmentation fault\s*$", re.M),
)


def is_g1_signal(text: str) -> bool:
    if not text:
        return False
    has_allowed = any(p.search(text) for p in _G1_PATTERNS)
    has_forbidden_only = (not has_allowed) and any(p.search(text) for p in _G1_FORBIDDEN)
    return has_allowed and not (has_forbidden_only and not has_allowed)


VERDICT_CONFIRMED = "CONFIRMED"
VERDICT_NOT_CONFIRMED = "NOT_CONFIRMED"
VERDICT_NOT_THIS_BUG = "NOT_THIS_BUG"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_ERROR = "ERROR"


def confirm_with_g3a(*, vuln_hit: bool, benign_hit: bool = False, patched_hit: bool = False,
                     benign_error: bool = False, vuln_error: bool = False) -> str:
    if vuln_error:
        return VERDICT_ERROR
    if benign_error:
        return VERDICT_INCONCLUSIVE
    if patched_hit:
        return VERDICT_NOT_THIS_BUG
    if vuln_hit and not benign_hit:
        return VERDICT_CONFIRMED
    return VERDICT_NOT_CONFIRMED


def constrained_attacker_verdict(*, base: str, victim_other_party: bool,
                                 paths_tried: int, min_paths_for_blocked: int = 2) -> str:
    if base == VERDICT_CONFIRMED and not victim_other_party:
        return VERDICT_NOT_CONFIRMED
    if base == VERDICT_BLOCKED and paths_tried < max(2, min_paths_for_blocked):
        return VERDICT_INCONCLUSIVE
    return base


VERDICT_BLOCKED = "BLOCKED"


def verification_tier(layer: str, *, confirmed: bool,
                      kev_or_active: bool = False, epss: float = 0.0) -> str:
    if not confirmed:
        return "low-capped"
    if layer == "finding-live":
        return "P0"
    if layer == "finding-source":
        if kev_or_active:
            return "P1+"
        if epss >= 0.2:
            return "P1"
        return "P2"
    return "low-capped"


def guard_dominance_verdict(*, paths: list, guards: set) -> tuple[str, str]:
    if not paths:
        return VERDICT_INCONCLUSIVE, "no feasible paths enumerated"
    for g in sorted(guards):
        if all(g in p for p in paths):
            return VERDICT_NOT_CONFIRMED, f"guard dominates every source→sink path: {g}"
    return VERDICT_CONFIRMED, "no single guard dominates all paths" + (
        f" (partial guards noted: {sorted(guards)})" if guards else "")


def majority_vote(votes: list) -> tuple[str, float]:
    if not votes:
        return VERDICT_INCONCLUSIVE, 0.0
    n_err = sum(1 for v, _ in votes if v == VERDICT_ERROR)
    if n_err * 2 > len(votes):
        return VERDICT_ERROR, 0.0
    valid = [(v, c) for v, c in votes if v != VERDICT_ERROR]
    if not valid:
        return VERDICT_INCONCLUSIVE, 0.0
    counts: dict = {}
    for v, _ in valid:
        counts[v] = counts.get(v, 0) + 1
    best = max(counts.values())
    winners = [v for v, n in counts.items() if n == best]
    if len(winners) != 1:
        return VERDICT_INCONCLUSIVE, sum(c for _, c in valid) / len(valid)
    conf = sum(c for v, c in valid if v == winners[0]) / counts[winners[0]]
    return winners[0], conf


def enrich_with_epss(finding: dict, epss_data: dict = None, kev_list: set = None) -> dict:
    cve = finding.get("cve") or ""
    enriched = dict(finding)
    if epss_data and cve in epss_data:
        enriched["epss"] = epss_data[cve].get("epss", 0.0)
        enriched["epss_percentile"] = epss_data[cve].get("percentile", 0.0)
    if kev_list and cve in kev_list:
        enriched["kev"] = True
    return enriched
