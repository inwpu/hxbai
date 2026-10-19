from __future__ import annotations

import re
from collections import defaultdict


_SPEC_ASSERTION_RX = re.compile(
    r"(?:should|must|require|expected|only.*allowed|denied|forbidden|must not|should not"
    r"|only.*can|cannot|not authorized|permission required|admin only|owner only|rate.limit|must.be)", re.I)

_ROLE_HINTS = re.compile(r"\b(admin|root|sudo|owner|moderator|manager|superuser)\b", re.I)
_ID_HINTS = re.compile(r"\b(user_?id|uid|account_?id|owner_?id|tenant_?id)\b", re.I)


def extract_spec_assertions(doc_or_comments: str) -> list:
    assertions = []
    for line in (doc_or_comments or "").splitlines():
        line = line.strip()
        if not line or len(line) < 10:
            continue
        if _SPEC_ASSERTION_RX.search(line):
            cat = "auth"
            if _ROLE_HINTS.search(line):
                cat = "role"
            elif _ID_HINTS.search(line):
                cat = "ownership"
            elif re.search(r"rate|limit|throttl|cooldown", line, re.I):
                cat = "rate_limit"
            elif re.search(r"step|flow|order|sequence|state|approve|pending", line, re.I):
                cat = "workflow"
            assertions.append({"assertion": line[:200], "source_line": line[:100], "category": cat})
    return assertions


_AUTH_CHECK_PATTERNS = [
    "check_auth", "require_login", "verify_token", "authenticate", "authorize",
    "get_current_user", "session.get", "request.user", "@login_required",
    "@auth", "middleware", "permission", "is_admin", "has_role", "owner",
    "McpEndpointAccessValidator", "validate_access", "check_permission",
]


def build_protection_matrix(endpoints: list) -> dict:
    all_checks = set()
    for ep in endpoints:
        for c in (ep.get("auth_checks") or []):
            all_checks.add(c)
        for m in (ep.get("middleware") or []):
            all_checks.add(m)
    matrix = {}
    for ep in endpoints:
        route = ep.get("route", "?")
        present = set(ep.get("auth_checks") or []) | set(ep.get("middleware") or [])
        matrix[route] = {check: (check in present or _fuzzy_match(check, present)) for check in all_checks}
    counts = {r: sum(1 for v in checks.values() if v) for r, checks in matrix.items()}
    if counts:
        median = sorted(counts.values())[len(counts) // 2]
        outliers = [r for r, c in counts.items() if c < median * 0.5]
    else:
        outliers = []
    coverage = sum(counts.values()) / max(1, len(counts) * max(1, len(all_checks)))
    return {"matrix": matrix, "outliers": outliers, "coverage": coverage,
            "check_count": len(all_checks), "endpoint_count": len(endpoints)}


def _fuzzy_match(check: str, present: set) -> bool:
    norm = re.sub(r"[@_.]", "", check.lower())
    for p in present:
        if re.sub(r"[@_.]", "", p.lower()) in norm or norm in re.sub(r"[@_.]", "", p.lower()):
            return True
    return False


def metamorphic_auth_test(test_results: list) -> list:
    violations = []
    for tr in test_results:
        user = tr.get("user", "")
        owner = tr.get("resource_owner", "")
        action = tr.get("action", "")
        status = tr.get("status", 0)
        if user and owner and user != owner:
            if 200 <= status < 300:
                violations.append({
                    "type": "authorization_metamorphic_violation",
                    "detail": f"user={user} performed {action} on resource owned by {owner} "
                              f"with status {status} (expected 403/404)",
                    "severity": "high" if action in ("delete", "update", "modify") else "medium",
                })
    return violations


def generate_metamorphic_relations(endpoints: list, roles: list) -> list:
    relations = []
    for ep in endpoints:
        route = ep.get("route", "?")
        for i, ra in enumerate(roles):
            for rb in roles[i+1:]:
                if ra.get("level", 0) != rb.get("level", 0):
                    relations.append({
                        "relation": f"{ra['name']} can access {route} but {rb['name']} cannot",
                        "endpoint": route,
                        "role_a": ra["name"], "role_b": rb["name"],
                        "expected": "differential",
                    })
    for role in roles:
        relations.append({
            "relation": f"{role['name']} operating on another {role['name']}'s resource must fail",
            "endpoint": "*",
            "role_a": role["name"], "role_b": role["name"],
            "expected": "denied",
        })
    return relations

_OBS_STATUS_RX = re.compile(r"\b(HTTP[ /]?|status[=: ]+)?(200|201|204|30[1278])\b")
_OBS_TOKEN_RX = re.compile(
    r"(?:token|authorization|cookie|session|as\s+user|以|用户)\s*[:=]?\s*[\"']?"
    r"([A-Za-z0-9_.\-]{2,24})", re.I)
_OBS_OWNER_RX = re.compile(r"(?:owner(?:[_-]?id)?|user[_-]?id|uid|account(?:[_-]?id)?|resource|"
                           r"belonging to|属于)\s*[:=]?\s*[\"']?([A-Za-z0-9_.\-]{2,24})", re.I)
def _obs_canon(x: str) -> str:
    return re.sub(r"[_\-](sess|session|sig|signature|token|key|auth|id)$", "", (x or "").lower())


def _OBS_DIFFERENT(a, b) -> bool:
    ca, cb = _obs_canon(a), _obs_canon(b)
    return bool(ca and cb and ca != cb)


def scan_observation_metamorphic(obs_text: str) -> list:
    out = []
    for para in (obs_text or "").split("\n"):
        mst = _OBS_STATUS_RX.search(para)
        if not mst:
            continue
        ms = _OBS_TOKEN_RX.search(para)
        mo = _OBS_OWNER_RX.search(para)
        if ms and mo and _OBS_DIFFERENT(ms.group(1), mo.group(1)):
            out.append({"user": ms.group(1), "owner": mo.group(1),
                        "status": mst.group(2),
                        "snippet": para.strip()[:200]})
            if len(out) >= 3:
                break
    return out
