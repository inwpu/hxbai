from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict, fields
from typing import Optional

_ENTRIES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "entries")
_WORD = re.compile(r"[a-z0-9][a-z0-9._/+-]{1,}")
_CJK = re.compile(r"[一-鿿]+")
_MERGE_FP_CAP = 16
_KIN_CATEGORIES = frozenset({"web", "pentest", "cloud", "evasion"})


def _tokens(text: str) -> set[str]:
    t = (text or "").lower()
    toks = set(_WORD.findall(t))
    for run in _CJK.findall(t):
        if len(run) == 1:
            toks.add(run)
        else:
            for i in range(len(run) - 1):
                toks.add(run[i:i + 2])
    return toks


@dataclass
class KnowledgeEntry:
    id: str
    title: str
    vuln_pattern: str
    fingerprint: list[str] = field(default_factory=list)
    exploit_steps: list[str] = field(default_factory=list)
    key_payloads: list[str] = field(default_factory=list)
    category: str = ""
    cve: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = ""
    created_ts: float = field(default_factory=lambda: 0.0)
    preconditions: list[str] = field(default_factory=list)
    verify_oracle: str = ""
    pitfalls: list[str] = field(default_factory=list)
    anti_fingerprint: list[str] = field(default_factory=list)
    source_tier: str = ""

    def tier(self) -> str:
        if self.source_tier:
            return self.source_tier
        s = (self.source or "").lower()
        if s.startswith("auto"):
            return "verified"
        if "writeup" in s:
            return "writeup"
        return "seed"

    def match_text(self) -> str:
        return " ".join([self.title, self.vuln_pattern, " ".join(self.fingerprint),
                         " ".join(self.tags), " ".join(self.cve), self.category])

    def to_dict(self) -> dict:
        return asdict(self)

    def render(self) -> str:
        lines = [f"### {self.title}  [{self.category or '通用'}]"]
        if self.vuln_pattern:
            lines.append(f"- 漏洞模式: {self.vuln_pattern}")
        if self.cve:
            lines.append(f"- CVE: {', '.join(self.cve)}")
        if self.fingerprint:
            lines.append(f"- 指纹特征: {', '.join(self.fingerprint)}")
        if self.exploit_steps:
            lines.append("- 利用步骤:")
            lines += [f"    {i+1}. {s}" for i, s in enumerate(self.exploit_steps)]
        if self.key_payloads:
            lines.append("- 关键 payload:")
            lines += [f"    - `{p}`" for p in self.key_payloads]
        if self.preconditions:
            lines.append(f"- 前置条件: {'; '.join(self.preconditions)}")
        if self.verify_oracle:
            lines.append(f"- 验证预言机(命中即真): {self.verify_oracle}")
        if self.pitfalls:
            lines.append(f"- 常见坑: {'; '.join(self.pitfalls)}")
        if self.source:
            lines.append(f"- 来源: {self.source}")
        return "\n".join(lines)


class KnowledgeStore:
    def __init__(self, entries_dir: str = _ENTRIES_DIR):
        self.dir = entries_dir
        os.makedirs(self.dir, exist_ok=True)
        self.entries: list[KnowledgeEntry] = []
        self._load()

    def _load(self):
        self.entries = []
        for fn in sorted(os.listdir(self.dir)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, fn), encoding="utf-8") as f:
                    d = json.load(f)
                known = {f.name for f in fields(KnowledgeEntry)}
                self.entries.append(KnowledgeEntry(**{k: v for k, v in d.items() if k in known}))
            except Exception:
                continue

    def recall(self, query: str, top_k: int = 3, min_score: int = 1) -> list[tuple[KnowledgeEntry, int]]:
        q = _tokens(query)
        if not q:
            return []
        scored = []
        for e in self.entries:
            anti = _tokens(" ".join(e.anti_fingerprint)) if e.anti_fingerprint else set()
            if anti and (q & anti):
                continue
            fp = _tokens(" ".join(e.fingerprint)) | set(c.lower() for c in e.cve)
            fp_hits = len(q & fp)
            text_hits = len(q & _tokens(e.match_text()))
            score = fp_hits * 3 + text_hits
            if score >= min_score:
                scored.append((e, score))
        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]

    def _common_fp_tokens(self) -> set:
        cached = getattr(self, "_common_fp_cache", None)
        if cached is None:
            df: dict[str, int] = {}
            for e in self.entries:
                for t in set(_tokens(" ".join(e.fingerprint))):
                    df[t] = df.get(t, 0) + 1
            n = max(1, len(self.entries))
            cached = {t for t, c in df.items() if c >= max(3, n // 4)} if n >= 8 else set()
            self._common_fp_cache = cached
        return cached

    def force_recall(self, query: str, top_k: int = 1, *, first_visit: bool = False,
                     category: str = "") -> list[tuple[KnowledgeEntry, int]]:
        q = _tokens(query)
        if not q:
            return []
        cat = (category or "").strip().lower()
        common = self._common_fp_tokens()
        scored = []
        for e in self.entries:
            anti = _tokens(" ".join(e.anti_fingerprint)) if e.anti_fingerprint else set()
            if anti and (q & anti):
                continue
            if first_visit and e.tier() not in ("verified", "seed"):
                continue
            if cat:
                ecat = (e.category or "").strip().lower()
                if ecat and ecat != cat and not {ecat, cat} <= _KIN_CATEGORIES:
                    continue
            fp = _tokens(" ".join(e.fingerprint)) | set(c.lower() for c in e.cve)
            fp_hits = len(q & (fp - common))
            text_hits = len(q & _tokens(e.match_text()))
            score = fp_hits * 3 + text_hits
            if fp_hits >= 2 or (fp_hits >= 1 and score >= 6):
                scored.append((e, score))
        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]

    def _fname(self, entry_id: str) -> str:
        import hashlib
        raw = (entry_id or "").lower()
        safe = re.sub(r"[^a-z0-9_-]+", "-", raw).strip("-") or "entry"
        if safe != raw:
            safe = f"{safe}-{hashlib.sha1(raw.encode()).hexdigest()[:6]}"
        return f"{safe}.json"

    def _write(self, entry: KnowledgeEntry) -> str:
        path = os.path.join(self.dir, self._fname(entry.id))
        with open(path, "w") as f:
            json.dump(entry.to_dict(), f, ensure_ascii=False, indent=2)
        return path

    @staticmethod
    def _sig(e: KnowledgeEntry) -> set:
        return _tokens(" ".join([e.vuln_pattern, e.title, e.category] + list(e.fingerprint)))

    @classmethod
    def _similarity(cls, a: KnowledgeEntry, b: KnowledgeEntry) -> float:
        sa, sb = cls._sig(a), cls._sig(b)
        return (len(sa & sb) / len(sa | sb)) if (sa and sb) else 0.0

    @staticmethod
    def _merge(into: KnowledgeEntry, other: KnowledgeEntry) -> KnowledgeEntry:
        def _uni(x, y):
            out = list(x)
            for v in y:
                if v not in out:
                    out.append(v)
            return out
        into.fingerprint = _uni(into.fingerprint, other.fingerprint)
        if len(into.fingerprint) > _MERGE_FP_CAP:
            into.fingerprint = into.fingerprint[:_MERGE_FP_CAP - 4] + into.fingerprint[-4:]
        into.cve = _uni(into.cve, other.cve)
        into.tags = _uni(into.tags, other.tags)
        into.preconditions = _uni(into.preconditions, other.preconditions)
        into.pitfalls = _uni(into.pitfalls, other.pitfalls)
        into.anti_fingerprint = _uni(into.anti_fingerprint, other.anti_fingerprint)
        if not into.source_tier and other.source_tier:
            into.source_tier = other.source_tier
        if sum(len(s) for s in other.exploit_steps) > sum(len(s) for s in into.exploit_steps):
            into.exploit_steps = other.exploit_steps
        if sum(len(s) for s in other.key_payloads) > sum(len(s) for s in into.key_payloads):
            into.key_payloads = other.key_payloads
        if not into.verify_oracle and other.verify_oracle:
            into.verify_oracle = other.verify_oracle
        return into

    _GENERIC_SRC = {"", "cybench", "tsecbench", "auto-solve", "auto", "manual", "seed"}

    @classmethod
    def _challenge_key(cls, entry: KnowledgeEntry) -> str:
        s = (entry.source or "").strip()
        m = re.search(r"\(([^)]+)\)\s*$", s)
        chal = (m.group(1) if m else "").strip()
        if not chal or chal.lower() in cls._GENERIC_SRC or chal.startswith("<"):
            return ""
        return f"{(entry.category or '').lower()}::{chal.lower()}"

    @staticmethod
    def _technique_key(entry: KnowledgeEntry) -> str:
        vp = (entry.vuln_pattern or "").strip().lower()
        if not vp:
            return ""
        cat = (entry.category or "").strip().lower()
        if vp == cat:
            return ""
        return f"{cat}::{vp}"

    def add(self, entry: KnowledgeEntry, dedup: bool = True) -> str:
        if not entry.created_ts:
            entry.created_ts = _now()
        self._common_fp_cache = None
        if dedup:
            key = self._challenge_key(entry)
            if key:
                for e in self.entries:
                    if self._challenge_key(e) == key:
                        self._merge(e, entry)
                        return self._write(e)
            tkey = self._technique_key(entry)
            if tkey:
                for e in self.entries:
                    if self._technique_key(e) == tkey:
                        self._merge(e, entry)
                        return self._write(e)
        self.entries.append(entry)
        return self._write(entry)

    def dedup_existing(self) -> dict:
        before = len(self.entries)
        canon_by_key: dict[str, KnowledgeEntry] = {}
        canon: list[KnowledgeEntry] = []
        merged = 0
        for e in self.entries:
            key = self._challenge_key(e)
            if key and key in canon_by_key:
                self._merge(canon_by_key[key], e)
                merged += 1
            else:
                if key:
                    canon_by_key[key] = e
                canon.append(e)
        keep = set()
        for c in canon:
            keep.add(self._fname(c.id))
            self._write(c)
        removed = 0
        for fn in os.listdir(self.dir):
            if fn.endswith(".json") and fn not in keep:
                os.remove(os.path.join(self.dir, fn))
                removed += 1
        self._load()
        return {"before": before, "after": len(self.entries), "merged": merged, "removed_files": removed}

    def has(self, entry_id: str) -> bool:
        return any(e.id == entry_id for e in self.entries)


def _now() -> float:
    try:
        return time.time()
    except Exception:
        return 0.0
