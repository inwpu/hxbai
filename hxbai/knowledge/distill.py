from __future__ import annotations

import json
import re
import time

from ..llm import LLMClient
from .store import KnowledgeEntry

_JSON = re.compile(r"\{.*\}", re.DOTALL)

_SCHEMA = """Return ONE JSON object capturing the REUSABLE method (not the specific flag):
{"id": "short-kebab-id", "title": "...", "vuln_pattern": "...",
 "fingerprint": ["keywords/tech/version/endpoints that identify this target class", ...],
 "cve": ["CVE-..."], "category": "web|pwn|crypto|reverse|forensics|misc|cloud",
 "exploit_steps": ["concrete step", ...], "key_payloads": ["exact payload/command", ...],
 "tags": [...]}
Rules: fingerprint must be concrete recognizable signals (product names, versions, headers, error
strings, endpoints, response codes). NEVER put the actual flag value anywhere. Keep steps concrete
and ordered."""

INGEST_SYS = "You convert a security writeup into a structured, reusable exploitation playbook.\n" + _SCHEMA
DISTILL_SYS = "You convert a successful exploitation transcript into a structured, reusable playbook.\n" + _SCHEMA


def _parse(text: str) -> dict:
    try:
        from .verify import _parse_json
        d = _parse_json(text or "")
        if d:
            return d
    except Exception:
        pass
    m = _JSON.search(text or "")
    if not m:
        return {}
    for frag in (m.group(0), m.group(0)[: m.group(0).rfind("}") + 1]):
        try:
            return json.loads(frag)
        except Exception:
            continue
    return {}


def _to_entry(d: dict, source: str) -> KnowledgeEntry | None:
    if not d or not d.get("title"):
        return None
    eid = d.get("id") or re.sub(r"[^a-z0-9]+", "-", d["title"].lower())[:40]
    return KnowledgeEntry(
        id=eid, title=d.get("title", ""), vuln_pattern=d.get("vuln_pattern", ""),
        fingerprint=d.get("fingerprint", []) or [], exploit_steps=d.get("exploit_steps", []) or [],
        key_payloads=d.get("key_payloads", []) or [], category=d.get("category", ""),
        cve=d.get("cve", []) or [], tags=d.get("tags", []) or [], source=source,
        created_ts=_now(),
    )


_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\n]{1,200}\}")


def _redact_flags(text: str) -> str:
    return _FLAG_RE.sub("<FLAG>", text or "")


def ingest_writeup(text: str, client: LLMClient, source: str = "writeup") -> KnowledgeEntry | None:
    clean = _redact_flags(text)
    res = client.chat([{"role": "system", "content": INGEST_SYS},
                       {"role": "user", "content": clean[:20000]}], max_tokens=3500)
    entry = _to_entry(_parse(res.text), source)
    if entry:
        entry.exploit_steps = [_redact_flags(s) for s in entry.exploit_steps]
        entry.key_payloads = [_redact_flags(p) for p in entry.key_payloads]
    return entry


def distill_solution(objective: str, transcript: list[dict], flag: str, client: LLMClient,
                     source: str = "auto-solve") -> KnowledgeEntry | None:
    steps = []
    for s in transcript:
        if s.get("tool") in ("bash", "http", "python", "nuclei") and s.get("args"):
            a = s["args"]
            cmd = a.get("command") or a.get("url") or (a.get("code", "")[:120]) or ""
            if cmd:
                steps.append(f"{s.get('tool')}: {str(cmd)[:200]}")
    convo = f"OBJECTIVE: {objective[:800]}\n\nACTIONS THAT LED TO THE FLAG:\n" + "\n".join(steps[-40:])
    convo += f"\n\n(The flag was found. Do NOT include the flag value '{flag}' — capture the METHOD.)"
    res = client.chat([{"role": "system", "content": DISTILL_SYS},
                       {"role": "user", "content": convo}], max_tokens=2000)
    entry = _to_entry(_parse(res.text), source)
    if entry and flag:
        entry.key_payloads = [p for p in entry.key_payloads if flag not in p]
        entry.exploit_steps = [s.replace(flag, "<FLAG>") for s in entry.exploit_steps]
    return entry


def _now() -> float:
    try:
        return time.time()
    except Exception:
        return 0.0
