from __future__ import annotations

import math
import re
from collections import Counter


def build_vuln_entry(purpose: str, behavior: str, trigger_action: str,
                     abstract_desc: str, detailed_desc: str,
                     fix_summary: str, fix_code: str = "") -> dict:
    return {"purpose": purpose, "behavior": behavior,
            "trigger_action": trigger_action,
            "abstract_description": abstract_desc,
            "detailed_description": detailed_desc,
            "fix_summary": fix_summary, "fix_code": fix_code}


def _tokenize(text: str) -> list:
    return re.findall(r"[a-zA-Z_]\w{0,30}", text.lower())


def bm25_score(query_tokens: list, doc_tokens: list,
               doc_freq: dict, n_docs: int, avg_len: float,
               k1: float = 1.2, b: float = 0.75) -> float:
    if not doc_tokens or not query_tokens:
        return 0.0
    doc_len = len(doc_tokens)
    tf = Counter(doc_tokens)
    score = 0.0
    for qt in query_tokens:
        if qt not in tf:
            continue
        df = doc_freq.get(qt, 0)
        idf = math.log((n_docs - df + 0.5) / (df + 0.5) + 1)
        score += idf * tf[qt] * (k1 + 1) / (tf[qt] + k1 * (1 - b + b * doc_len / avg_len))
    return score


def rrf_rerank(ranked_lists: list, k: int = 60) -> list:
    scores = {}
    for lst in ranked_lists:
        for rank, item in enumerate(lst, 1):
            key = str(item)
            scores[key] = scores.get(key, 0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda x: -scores[x])


def retrieve(query: str, entries: list, top_k: int = 10) -> list:
    if not entries:
        return []
    query_toks = _tokenize(query)
    all_docs_1 = [_tokenize(f"{e.get('purpose','')} {e.get('behavior','')} {e.get('trigger_action','')}") for e in entries]
    all_docs_2 = [_tokenize(f"{e.get('abstract_description','')} {e.get('detailed_description','')} {e.get('fix_summary','')}") for e in entries]
    all_docs = all_docs_1 + all_docs_2
    n_docs = len(all_docs)
    avg_len = sum(len(d) for d in all_docs) / max(1, n_docs)
    doc_freq = Counter()
    for doc in all_docs:
        doc_freq.update(set(doc))
    ranked_1 = sorted(range(len(entries)),
                      key=lambda i: -bm25_score(query_toks, all_docs_1[i], doc_freq, n_docs, avg_len))[:top_k]
    ranked_2 = sorted(range(len(entries)),
                      key=lambda i: -bm25_score(query_toks, all_docs_2[i], doc_freq, n_docs, avg_len))[:top_k]
    fused = rrf_rerank([ranked_1, ranked_2])
    seen = set(); result = []
    for key in fused:
        idx = int(key)
        if idx < len(entries) and idx not in seen:
            result.append(entries[idx])
            seen.add(idx)
            if len(result) >= top_k:
                break
    return result


def cause_and_not_fix(entry: dict, code_context: str) -> str:
    trigger = entry.get("trigger_action", "")
    fix = entry.get("fix_code", "") or entry.get("fix_summary", "")
    has_cause = bool(trigger) and trigger.lower() in code_context.lower()
    has_fix = bool(fix) and fix.lower() in code_context.lower()
    if has_cause and not has_fix:
        return "VULNERABLE"
    if has_cause and has_fix:
        return "PATCHED"
    return "NO_MATCH"

def entries_from_corpus(corpus_dir: str) -> list:
    import json as _json
    from pathlib import Path as _P
    out = []
    d = _P(corpus_dir)
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.json")):
        try:
            c = _json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = c.get("name") or f.stem
        vuln_code = (c.get("vulnerable") or "")[:400]
        fix_code = (c.get("patched") or "")[:400]
        out.append(build_vuln_entry(
            purpose=name, behavior=f"vulnerable pattern: {name}",
            trigger_action=vuln_code.split("\n")[0][:120] if vuln_code else name,
            abstract_desc=vuln_code[:200], detailed_desc=vuln_code,
            fix_summary=fix_code[:200], fix_code=fix_code))
    return out
