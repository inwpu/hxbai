from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


KINDS = ("host", "service", "component", "version", "endpoint", "credential",
         "cve", "vuln", "intel", "foothold", "note")


_EXTRACTORS = [
    ("cve",        re.compile(r"\bCVE-\d{4}-\d{4,7}\b"), 0.9),
    ("credential", re.compile(r"\b(?:AKIA|ASIA|AROA|LKIA|LSIA)[0-9A-Z]{12,17}\b"), 0.85),
    ("credential", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), 0.75),
    ("foothold",   re.compile(r"\buid=\d+\([^)]+\)(?:\s*gid=\d+\([^)]+\))?"), 0.9),
]
_HDR = re.compile(r"^(?:Server|X-Powered-By):\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_PRODVER = re.compile(r"\b([A-Za-z][A-Za-z0-9_.-]{1,30}/\d+(?:\.\d+){1,3})\b")
_NMAP = re.compile(r"^(\d{1,5}/(?:tcp|udp))\s+open\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_KV = re.compile(r"\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"',}\]);|&<>`\\]{3,60})",
                 re.IGNORECASE)
_URL = re.compile(r"final_url:\s*(\S+)|(https?://[^\s\"'<>]{6,120})")
_URL_HOST = re.compile(r"https?://([^/:\s]+)", re.IGNORECASE)
_DOC_CDN_HOSTS = ("googleapis.com", "gstatic.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                  "cloudflare.com", "kali.org", "curl.se", "w3.org", "github.com", "githubusercontent.com",
                  "npmjs.com", "npmjs.org", "pypi.org", "readthedocs.io", "readthedocs.org", "mozilla.org",
                  "fonts.googleapis.com", "schema.org", "example.com", "localhost.localdomain", "bootstrapcdn.com")
_KV_STOPWORDS = {"from", "where", "select", "and", "or", "null", "true", "false", "values", "into", "set",
                 "join", "on", "as", "by", "in", "not", "like", "admin", "password", "secret", "token", "test"}
_LOCAL_ID_RX = re.compile(r"^\s*(sudo\s+)?(id|whoami)\s*$")
_ARN = re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[\w:/.+=,@*-]{1,140}")
_ARN_KIND = {"iam": "credential", "sts": "credential", "s3": "service",
             "secretsmanager": "endpoint", "ssm": "endpoint", "kms": "credential"}
_ROLE_NAME = re.compile(r'"RoleName"\s*:\s*"([^"]{1,120})"')
_SECRET_NAME = re.compile(r'"(?:Name|SecretId)"\s*:\s*"([^"]*(?:secret|flag|shard|key|cred)[^"]*)"', re.IGNORECASE)
_S3LS = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+([\w.-]{3,63})\s*$", re.MULTILINE)


def extract_facts(tool: str, args: dict, output: str) -> list[tuple]:
    if not output:
        return []
    out = output[:20000]
    found: list[tuple] = []
    seen: set = set()

    def emit(kind, value, conf):
        v = (value or "").strip()
        if not v or len(v) > 160:
            return
        k = (kind, v.lower())
        if k in seen:
            return
        seen.add(k)
        found.append((kind, v, conf))

    cmd = (args.get("command") if isinstance(args, dict) else "") or ""
    local_id = bool(_LOCAL_ID_RX.match(cmd))
    outbound = any(x in cmd for x in ("curl", "wget", "nc ", "ncat", "ssh ", ".php", "cmd=", "c=", "exec", "socket"))
    for kind, rx, conf in _EXTRACTORS:
        for m in rx.findall(out):
            c = conf
            if kind == "foothold" and local_id and not outbound:
                c = 0.3
            emit(kind, m if isinstance(m, str) else m[0], c)
    for m in _HDR.findall(out):
        emit("component", m, 0.8)
    for m in _PRODVER.findall(out):
        emit("component", m, 0.75)
    for port, svc in _NMAP.findall(out):
        emit("service", f"{port} {svc}", 0.85)
    for kv in _KV.findall(out):
        val = kv[1].rstrip("\\]);|&<>`.,:")
        _code_junk = any(c in val for c in "([{") or "$_" in val or val.lower().startswith(("isset", "md5(", "select "))
        if (len(val) >= 4 and val.lower() not in _KV_STOPWORDS
                and re.search(r"[A-Za-z0-9]", val) and not _code_junk):
            emit("credential", f"{kv[0]}={val}", 0.4)
    for u in _URL.findall(out):
        url = u[0] or u[1]
        hm = _URL_HOST.match(url or "")
        host = (hm.group(1).lower() if hm else "")
        if host and any(host == d or host.endswith("." + d) for d in _DOC_CDN_HOSTS):
            continue
        emit("endpoint", url, 0.6)
    for m in _ARN.finditer(out):
        arn = m.group(0)
        emit(_ARN_KIND.get(arn.split(":")[2], "intel"), arn, 0.8)
    for rn in _ROLE_NAME.findall(out):
        emit("credential", f"role:{rn}", 0.8)
    for sn in _SECRET_NAME.findall(out):
        emit("endpoint", f"secret:{sn}", 0.75)
    for bk in _S3LS.findall(out):
        emit("service", f"s3-bucket:{bk}", 0.8)
    return found[:16]


@dataclass
class Fact:
    kind: str
    value: str
    source: str = ""
    confidence: float = 0.6
    ts: float = 0.0
    provenance: str = ""
    verified: bool = False

    def key(self) -> str:
        return f"{self.kind}:{self.value.strip().lower()[:120]}"


def _prov_command(provenance: str) -> str:
    return provenance.split(": ", 1)[1].strip() if ": " in provenance else ""


@dataclass
class Goal:
    id: str
    description: str
    trigger_kinds: frozenset = frozenset()
    satisfied: bool = False
    satisfied_by: str = ""


_DEFAULT_GOALS = [
    ("recon",  "Map the target: stack/version, services, endpoints, entry points",
     frozenset({"host", "service", "component", "endpoint", "version"})),
    ("vuln",   "Identify an exploitable vulnerability (class + exact sink/endpoint)",
     frozenset({"vuln", "cve"})),
    ("access", "Gain code execution or privileged access (foothold / valid creds)",
     frozenset({"foothold", "credential"})),
    ("flag",   "Locate and extract the flag", frozenset()),
]

PENTEST_GOALS = [
    ("recon",     "Map the EXTERNAL perimeter: hosts, services, versions, entry points",
     frozenset({"host", "service", "component", "endpoint", "version"})),
    ("foothold",  "Gain an initial foothold (exploit a public-facing app / valid accounts)",
     frozenset({"foothold"})),
    ("discovery", "From the foothold, enumerate INTERNAL hosts, credentials, and services",
     frozenset({"credential"})),
    ("privesc",   "Escalate privileges / obtain higher-value credentials", frozenset()),
    ("lateral",   "Pivot to internal hosts using discovered creds / a tunnel", frozenset()),
    ("exfil",     "Reach the core internal system and extract the flag", frozenset()),
]

BINARY_GOALS = [
    ("triage",  "Triage: file/checksec/strings; network service (pwn) or standalone binary (RE)?",
     frozenset({"component"})),
    ("bug",     "Identify the exact bug (overflow/format-string/UAF/memory-disclosure) or the check to invert",
     frozenset({"vuln"})),
    ("control", "Get control or a leak: exact offset (gdb cyclic -> $rip), leaked memory, or the decoded secret",
     frozenset()),
    ("exploit", "Build the exploit (ROP / leak-libc) or supply the accepted input, then read the flag",
     frozenset()),
]


def goals_for_category(category: Optional[str]):
    c = (category or "").lower()
    if c == "pentest":
        return PENTEST_GOALS
    if c in ("pwn", "reverse"):
        return BINARY_GOALS
    return _DEFAULT_GOALS


class Blackboard:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._facts: dict[str, Fact] = {}
        self._goals: list[Goal] = []
        self.objective: str = ""
        self._lock = threading.RLock()
        if path and os.path.isfile(path):
            self._load()

    def seed_goals(self, goals=None) -> None:
        if self._goals:
            return
        for gid, desc, kinds in (goals or _DEFAULT_GOALS):
            self._goals.append(Goal(id=gid, description=desc, trigger_kinds=kinds))

    def refresh_goals(self) -> None:
        allfacts = self.query()
        kinds_present = {f.kind for f in allfacts}
        for g in self._goals:
            if g.satisfied or not g.trigger_kinds:
                continue
            hit = g.trigger_kinds & kinds_present
            if hit:
                g.satisfied = True
                cands = [f for f in allfacts if f.kind in hit]
                g.satisfied_by = max(cands, key=lambda f: f.confidence).key() if cands else next(iter(hit))

    def satisfy_goal(self, gid: str, by: str = "") -> None:
        for g in self._goals:
            if g.id == gid:
                g.satisfied, g.satisfied_by = True, by or g.satisfied_by

    def next_open_goal(self) -> Optional[Goal]:
        self.refresh_goals()
        for g in self._goals:
            if not g.satisfied:
                return g
        return None

    def open_goal_count(self) -> int:
        self.refresh_goals()
        return sum(1 for g in self._goals if not g.satisfied)

    def add(self, kind: str, value: str, *, source: str = "", confidence: float = 0.6,
            provenance: str = "") -> bool:
        value = (value or "").strip()
        if not value or kind not in KINDS:
            return False
        f = Fact(kind=kind, value=value, source=source, confidence=confidence, ts=_now(),
                 provenance=provenance)
        k = f.key()
        with self._lock:
            prev = self._facts.get(k)
            if prev is None or confidence > prev.confidence:
                self._facts[k] = f
                self._save()
                return prev is None
            return False

    def observe(self, tool: str, args: dict, output: str, *, iter: int = 0) -> int:
        cmd = (args or {}).get("command") or (args or {}).get("url") or (args or {}).get("code") or tool
        prov = f"iter{iter} {tool}: {str(cmd)[:200]}"
        n = 0
        for kind, value, conf in extract_facts(tool, args or {}, output or ""):
            if self.add(kind, value, source=f"auto/{tool}", confidence=conf, provenance=prov):
                n += 1
        return n

    def add_many(self, kind: str, values, **kw) -> int:
        return sum(1 for v in (values or []) if self.add(kind, v, **kw))

    def actionable_assets(self) -> str:
        picks = [("foothold", "立足点/RCE"), ("credential", "凭据"), ("vuln", "已确认漏洞"),
                 ("cve", "已知CVE"), ("host", "内网/其它主机"), ("endpoint", "关键端点")]
        lines = []
        for kind, label in picks:
            vals = [f.value.strip() for f in self.query(kind) if f.value.strip() and f.confidence >= 0.4][:6]
            if vals:
                lines.append(f"- {label}: " + "；".join(v[:80] for v in vals))
        if not lines:
            return ""
        return ("你已拥有以下(别重新发现):直接用它们利用/pivot,严禁重跑 recon 或 grep 旧 `_transcripts/`。\n"
                + "\n".join(lines)
                + "\n下一步:从上面最有杀伤力的一项(foothold > 凭据 > 漏洞)接着打,而不是回顾自己干过啥。")

    def query(self, kind: Optional[str] = None) -> list[Fact]:
        with self._lock:
            facts = list(self._facts.values())
        if kind:
            facts = [f for f in facts if f.kind == kind]
        return sorted(facts, key=lambda f: (-f.confidence, f.ts))

    def render(self, max_per_kind: int = 8) -> str:
        lines: list[str] = []
        if self._goals:
            self.refresh_goals()
            from . import attack
            lines.append("# Goals (ATT&CK kill-chain) — pursue the first OPEN goal")
            for g in self._goals:
                mark = "[x]" if g.satisfied else "[ ]"
                by = f"  <- {g.satisfied_by}" if g.satisfied and g.satisfied_by else ""
                tac = attack.GOAL_TACTIC.get(g.id, "")
                tac = f" ({tac})" if tac else ""
                lines.append(f"- {mark} {g.id}{tac}: {g.description}{by}")
            lines.append("")
        if not self._facts:
            lines.append("(no facts gathered yet — start recon)")
            return "\n".join(lines)
        lines.append("# Facts gathered so far (auto-captured with provenance — all capabilities read/write this)")
        allfacts = self.query()
        for kind in KINDS:
            items = [f for f in allfacts if f.kind == kind]
            if not items:
                continue
            items.sort(key=lambda f: -f.confidence)
            shown = ", ".join(f"{f.value}{' [v]' if f.verified else ''}" for f in items[:max_per_kind])
            more = f" (+{len(items)-max_per_kind} more)" if len(items) > max_per_kind else ""
            lines.append(f"- {kind}: {shown}{more}")
        return "\n".join(lines)

    def summary_counts(self) -> dict:
        c: dict[str, int] = {}
        for f in self.query():
            c[f.kind] = c.get(f.kind, 0) + 1
        return c

    def _load(self):
        from dataclasses import fields as _fields
        allowed = {f.name for f in _fields(Fact)}
        try:
            records = json.load(open(self.path))
        except Exception:
            return
        for d in records:
            try:
                f = Fact(**{k: v for k, v in d.items() if k in allowed})
                self._facts[f.key()] = f
            except Exception:
                continue

    def _save(self):
        if not self.path:
            return
        try:
            with self._lock:
                snapshot = [asdict(f) for f in self._facts.values()]
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            json.dump(snapshot, open(self.path, "w"), ensure_ascii=False, indent=2)
        except Exception:
            pass


def plan_directive(board) -> str:
    g = board.next_open_goal()
    if g is None:
        return ""
    from . import attack
    counts = board.summary_counts()
    fsum = ", ".join(f"{k}:{v}" for k, v in counts.items()) or "none yet"
    tactic = attack.GOAL_TACTIC.get(g.id, "")
    tac = f" [ATT&CK tactic: {tactic}]" if tactic else ""
    _txt = (getattr(board, "objective", "") + " " + " ".join(f.value for f in board.query()))
    techs = attack.match_techniques(_txt, top=3)
    thint = (" Techniques your facts point to: " + "; ".join(attack.label(t) for t in techs) +
             " — advance ONE of these.") if techs else ""
    return (f"[PLAN] Current OPEN goal: '{g.id}'{tac} — {g.description}. Facts captured ({fsum}).{thint} "
            f"Reason on the graph above, then take the SINGLE concrete action that most advances "
            f"'{g.id}'. If '{g.id}' is already met by a fact, say so and move to the next goal.")


def verify_fact(fact: Fact, run) -> bool:
    cmd = _prov_command(fact.provenance)
    if not cmd or cmd.startswith(("http://", "https://")):
        return False
    try:
        out = run(cmd) or ""
    except Exception:
        return False
    val = fact.value
    reproduced = (val in out) or (val.split(":", 1)[-1] in out) or (val.split("=", 1)[-1] in out)
    fact.verified = reproduced
    fact.confidence = min(1.0, fact.confidence + 0.25) if reproduced else max(0.1, fact.confidence - 0.3)
    return reproduced


def reverify_facts(board, run, *, kinds=None, limit: int = 8) -> dict:
    cands = [f for f in board.query() if not f.verified and _prov_command(f.provenance)
             and (kinds is None or f.kind in kinds)]
    cands = cands[:max(0, limit)]
    ok = sum(1 for f in cands if verify_fact(f, run))
    if cands:
        board._save()
    return {"verified": ok, "failed": len(cands) - ok}


def _now() -> float:
    try:
        return time.time()
    except Exception:
        return 0.0
