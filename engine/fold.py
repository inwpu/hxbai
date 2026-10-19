from __future__ import annotations

import json
import re

_SALIENT_FACT = re.compile(
    r"cred|password|passwd|secret|api[_-]?key|\btoken\b|private[_ ]key|foothold|web ?shell|"
    r"admin:|root:|version|\bv?\d+\.\d+\.\d+|flag\{|uid=0|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}|"
    r"(?<![\w-])/[A-Za-z0-9_./-]{2,}|:\d{2,5}\b|/tcp\b|\bopen\b|"
    r"eyJ[A-Za-z0-9_-]{6,}|[A-Za-z0-9+/]{40,}={0,2}|"
    r"\b\w+_id\b|\bparam(?:eter)?\b|\bcookie\b|authoriz|bearer|"
    r"0x[0-9a-fA-F]{3,}|\.(?:text|data|bss|rodata|plt|got)\b|opcode|disasm|bytecode|register|"
    r"\bxor\b|\brc4\b|\baes\b|\bdes\b|\brsa\b|keystream|cipher|plaintext|ciphertext|decrypt|decode|nonce|"
    r"tunnel|pivot|lateral|reachable|extracted|recovered|decrypted|cracked|bypassed|ruled out|reverse|"
    r"\b[1-5]\d\d\b", re.I)


def _est_tokens(s: str) -> int:
    return len(s) // 4 + 1


def _near_dup(a: str, b: str, thresh: float = 0.72) -> bool:
    ta = set((a or "").lower().split()); tb = set((b or "").lower().split())
    if not ta or not tb:
        return False
    union = len(ta | tb)
    return union > 0 and len(ta & tb) / union >= thresh


def _rows(conn, sql, args=()):
    return conn.execute(sql, args).fetchall()


def _terminal_fact(conn, subgoal_id: str) -> str:
    r = conn.execute(
        "SELECT n.title FROM nodes n JOIN edges e ON e.src = n.id "
        "WHERE n.type='insight' AND e.dst=? AND e.rel='observed_under' "
        "ORDER BY n.updated_ts DESC LIMIT 1", (subgoal_id,)).fetchone()
    return r["title"] if r else ""


COLD_THRESHOLD = 60
COLD_BLOCK_MAX = 40


def cold_block(conn) -> list:
    r = conn.q1("SELECT COUNT(*) c FROM nodes WHERE type='insight' AND "
                "(state IS NULL OR state != 'digested') AND provenance != 'digest'")
    if not r or r["c"] < COLD_THRESHOLD:
        return []
    rows = conn.q("SELECT id, ukey, title FROM nodes WHERE type='insight' "
                  "AND (state IS NULL OR state NOT IN ('digested','refuted')) "
                  "AND provenance != 'digest' ORDER BY updated_ts ASC LIMIT ?", (COLD_BLOCK_MAX,))
    return [dict(x) for x in rows if x["title"] and not _SALIENT_FACT.search(x["title"])]


def compact_cold(conn, members: list):
    import hashlib as _h
    if not members:
        return None
    key = "digest:" + _h.md5(("\x00".join(m["ukey"] for m in members)).encode(), usedforsecurity=False).hexdigest()[:12]
    title = (f"[digest] {len(members)} cold recon notes folded: "
             f"{members[0]['title'][:60]} … {members[-1]['title'][:40]}")
    did = conn.upsert_node("insight", key, title=title, provenance="digest")
    for m in members:
        try:
            with conn._lock:
                conn.conn.execute("UPDATE nodes SET state='digested' WHERE id=?", (m["id"],))
                conn.conn.commit()
            conn.add_edge(did, m["id"], "covers")
        except Exception:
            pass
    return did


def folded_projection(conn, *, token_budget: int = 2800, recent_keep: int = 8,
                      cap_limit: int = 20, completed_keep: int = 12) -> dict:
    caps = [{"title": r["title"]}
            for r in _rows(conn, "SELECT title FROM nodes WHERE type='capability' AND verified=1 "
                                 "ORDER BY updated_ts DESC LIMIT ?", (cap_limit,))]
    findings = [dict(r) for r in _rows(
        conn, "SELECT vulnclass,severity,summary FROM findings ORDER BY created_ts DESC LIMIT ?", (cap_limit,))]

    active = []
    for r in _rows(conn, "SELECT id,title FROM nodes WHERE type='subgoal' AND state IN ('open','active') "
                         "ORDER BY created_ts LIMIT ?", (cap_limit,)):
        steps = [s["title"] for s in _rows(
            conn, "SELECT n.title FROM nodes n JOIN edges e ON e.src=n.id "
            "WHERE n.type='step' AND n.state='open' AND e.dst=? AND e.rel='serves' LIMIT 5", (r["id"],))]
        active.append({"title": r["title"], "steps": steps})

    total_completed = conn.execute("SELECT COUNT(*) c FROM nodes WHERE type='subgoal' "
                                   "AND state IN ('achieved','abandoned')").fetchone()["c"]
    completed = []
    for r in _rows(conn, "SELECT id,title,state FROM nodes WHERE type='subgoal' "
                         "AND state IN ('achieved','abandoned') ORDER BY updated_ts DESC LIMIT ?",
                   (completed_keep,)):
        completed.append({"title": r["title"][:100], "state": r["state"],
                          "terminal": _terminal_fact(conn, r["id"])[:80]})
    completed_overflow = max(0, total_completed - len(completed))

    total_facts = conn.execute("SELECT COUNT(*) c FROM nodes WHERE type='insight'").fetchone()["c"]

    _FACT_TRUNC = 500

    def build(keep, salient_keep):
        window = max(keep * 5, 40)
        _raw = [r["title"] for r in _rows(
            conn, "SELECT title FROM nodes WHERE type='insight' AND ukey NOT LIKE 'refuted:%' "
            "ORDER BY updated_ts DESC LIMIT ?", (window,))]
        recent_full = []
        for _t in _raw:
            if len(recent_full) >= keep:
                break
            if any(_near_dup(_t, _k) for _k in recent_full):
                continue
            recent_full.append(_t)
        seen = set(recent_full)
        salient = []
        for r in _rows(conn, "SELECT title FROM nodes WHERE type='insight' "
                             "AND (state IS NULL OR state != 'digested') "
                             "ORDER BY updated_ts DESC LIMIT 800"):
            if len(salient) >= salient_keep:
                break
            t = r["title"]
            if not t or t in seen or not _SALIENT_FACT.search(t):
                continue
            if any(_near_dup(t, k) for k in recent_full) or any(_near_dup(t, k) for k in salient):
                continue
            salient.append(t)
            seen.add(t)
        recent = [(t or "")[:_FACT_TRUNC] for t in (recent_full + salient)]
        archived = max(0, total_facts - len(recent))
        digests = [r["title"] for r in _rows(
            conn, "SELECT title FROM nodes WHERE type='insight' AND provenance='digest' "
                  "ORDER BY updated_ts DESC LIMIT 5")]
        return {
            "digests": digests,
            "capabilities": caps, "recent_findings": findings,
            "open_subgoals": active, "folded_completed": completed,
            "completed_overflow": completed_overflow,
            "recent_facts": recent, "archived_fact_count": archived,
            "asset_counts": {r["type"]: r["c"] for r in _rows(
                conn, "SELECT type, COUNT(*) c FROM nodes "
                "WHERE type IN ('host','service','endpoint','credential') GROUP BY type")},
        }

    salient_keep = 12
    proj = build(recent_keep, salient_keep)
    def over():
        return _est_tokens(json.dumps(proj, ensure_ascii=False)) > token_budget
    while over() and (recent_keep > 2 or salient_keep > 2):
        if recent_keep > 2:
            recent_keep = max(2, recent_keep // 2)
        else:
            salient_keep = max(2, salient_keep // 2)
        proj = build(recent_keep, salient_keep)
    if over():
        for c in proj["folded_completed"]:
            c["terminal"] = ""
    _trunc = 500
    while over() and _trunc > 80:
        _trunc = max(80, _trunc // 2)
        proj["recent_facts"] = [(t or "")[:_trunc] for t in proj["recent_facts"]]
    return proj


def execute_projection(conn, *, recent_keep: int = 8, salient_keep: int = 12,
                       fact_trunc: int = 500, idx_trunc: int = 90, index_cap: int = 200,
                       plan_keep: int = 8) -> dict:
    confirmed = [(r["title"] or "")[:fact_trunc] for r in _rows(
        conn, "SELECT title FROM nodes WHERE type='insight' AND verified=1 "
              "AND (provenance IS NULL OR provenance != 'plan-intent') ORDER BY updated_ts DESC LIMIT 40")]
    plans = [(r["title"] or "")[:fact_trunc] for r in _rows(
        conn, "SELECT title FROM nodes WHERE type='insight' AND provenance='plan-intent' "
              "ORDER BY updated_ts DESC LIMIT ?", (plan_keep,))]
    _CAND = "type='insight' AND verified=0 AND (provenance IS NULL OR provenance != 'plan-intent') AND ukey NOT LIKE 'refuted:%'"
    recent_full = [r["title"] for r in _rows(
        conn, f"SELECT title FROM nodes WHERE {_CAND} ORDER BY updated_ts DESC LIMIT ?", (recent_keep,))]
    seen = set(recent_full) | set(confirmed) | set(plans)
    salient = []
    for r in _rows(conn, f"SELECT title FROM nodes WHERE {_CAND} ORDER BY updated_ts DESC LIMIT 800"):
        if len(salient) >= salient_keep:
            break
        t = r["title"] or ""
        if t and t not in seen and _SALIENT_FACT.search(t):
            salient.append(t); seen.add(t)
    recent = [(t or "")[:fact_trunc] for t in (recent_full + salient)]
    index = []
    overflow = 0
    for r in _rows(conn, f"SELECT title FROM nodes WHERE {_CAND} ORDER BY updated_ts DESC"):
        t = r["title"] or ""
        if not t or t in seen:
            continue
        seen.add(t)
        if len(index) < index_cap:
            index.append(t[:idx_trunc])
        else:
            overflow += 1
    return {"confirmed_facts": confirmed, "recent_facts": recent, "fact_index": index,
            "index_overflow": overflow, "plans": plans}


def drill_down(conn, keyword: str, limit: int = 20) -> list[str]:
    if not (keyword or "").strip():
        return []
    kw = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like = f"%{kw}%"
    out = [r["title"] or r["ukey"] for r in _rows(
        conn, "SELECT title, ukey FROM nodes WHERE type='insight' AND "
        "(title LIKE ? ESCAPE '\\' OR ukey LIKE ? ESCAPE '\\') ORDER BY updated_ts DESC LIMIT ?",
        (like, like, limit))]
    out += [r["content"] for r in _rows(
        conn, "SELECT content FROM evidence WHERE content LIKE ? ESCAPE '\\' "
        "ORDER BY created_ts DESC LIMIT ?", (like, limit))]
    return out[:limit]
