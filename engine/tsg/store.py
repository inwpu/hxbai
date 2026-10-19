from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

_SCHEMA = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")

_VULN_BACKBONE = {
    "rce":            ("CWE-94",  "A03:2021-Injection",              "rce"),
    "sqli":           ("CWE-89",  "A03:2021-Injection",              "injection"),
    "cmdi":           ("CWE-77",  "A03:2021-Injection",              "rce"),
    "ssti":           ("CWE-1336","A03:2021-Injection",              "rce"),
    "deserialization":("CWE-502", "A08:2021-Software-Data-Integrity","rce"),
    "lfi":            ("CWE-98",  "A03:2021-Injection",              "injection"),
    "pathtraversal":  ("CWE-22",  "A01:2021-Broken-Access-Control",  "injection"),
    "ssrf":           ("CWE-918", "A10:2021-SSRF",                   "injection"),
    "authbypass":     ("CWE-287", "A07:2021-Auth-Failures",          "authbypass"),
    "privesc":        ("CWE-269", "A01:2021-Broken-Access-Control",  "authbypass"),
    "idor":           ("CWE-639", "A01:2021-Broken-Access-Control",  "idor"),
    "xxe":            ("CWE-611", "A05:2021-Security-Misconfig",     "injection"),
    "xss":            ("CWE-79",  "A03:2021-Injection",              "xss"),
    "fileupload":     ("CWE-434", "A04:2021-Insecure-Design",        "rce"),
    "infoleak":       ("CWE-200", "A01:2021-Broken-Access-Control",  "infoleak"),
    "weakcred":       ("CWE-521", "A07:2021-Auth-Failures",          "authbypass"),
}
_IMPACT_SCORE = {"rce": 4, "authbypass": 3, "injection": 3, "idor": 2,
                 "xss": 2, "infoleak": 1, "info": 0}


def _norm_vulnclass(vc: str) -> str:
    return "".join(ch for ch in (vc or "").lower() if ch.isalnum())


def compute_severity(vulnclass: str, *, verified: bool, exploitability: float = 1.0,
                     impact_override: str | None = None) -> tuple[str, dict]:
    key = _norm_vulnclass(vulnclass)
    impact_face = impact_override or (_VULN_BACKBONE.get(key, (None, None, "info"))[2])
    imp = _IMPACT_SCORE.get(impact_face, 0)
    expl = max(0.0, min(1.0, exploitability if verified else exploitability * 0.4))
    score = imp * expl
    if score >= 3.5:   sev = "critical"
    elif score >= 2.5: sev = "high"
    elif score >= 1.2: sev = "medium"
    elif score >= 0.3: sev = "low"
    else:              sev = "info"
    if not verified and sev in ("critical", "high"):
        sev = "medium"
    basis = {"impact_face": impact_face, "impact_score": imp, "exploitability": round(expl, 2),
             "score": round(score, 2), "verified": verified, "rule": "impact×exploitability"}
    return sev, basis


def anchor_vulnclass(vulnclass: str) -> tuple[str | None, str | None]:
    cwe, owasp, _ = _VULN_BACKBONE.get(_norm_vulnclass(vulnclass), (None, None, None))
    return cwe, owasp


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _nid() -> str:
    return uuid.uuid4().hex[:16]


def _det_node_id(type: str, ukey: str) -> str:
    return hashlib.sha256(f"{type}\x00{ukey}".encode("utf-8")).hexdigest()[:16]


class TSG:

    def __init__(self, db_path: str, events_path: str | None = None):
        self.db_path = str(db_path)
        self.events_path = str(events_path) if events_path else str(Path(db_path).with_suffix(".events.jsonl"))
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        for _col, _typ in (("verdict", "TEXT"), ("tier", "TEXT"), ("risk_meta", "TEXT DEFAULT '{}'"),
                       ("extra", "TEXT DEFAULT '{}'")):
            try:
                self.conn.execute(f"ALTER TABLE findings ADD COLUMN {_col} {_typ}")
            except Exception:
                pass
        self.conn.commit()
        try:
            if os.path.exists(self.events_path) and os.path.getsize(self.events_path) > 0:
                with open(self.events_path, "rb") as _f:
                    _f.seek(-1, os.SEEK_END)
                    if _f.read(1) != b"\n":
                        with open(self.events_path, "a", encoding="utf-8") as _pad:
                            _pad.write("\n")
        except OSError:
            pass
        self._jsonl = open(self.events_path, "a", encoding="utf-8")
        self._lock = threading.RLock()
        self._closed = False

    def emit(self, kind: str, actor: str, payload: dict) -> int:
        with self._lock:
            if self._closed:
                return -1
            ts = time.time()
            cur = self.conn.execute(
                "INSERT INTO events(ts, kind, actor, payload) VALUES(?,?,?,?)",
                (ts, kind, actor, json.dumps(payload, ensure_ascii=False)))
            seq = cur.lastrowid
            self._apply(kind, ts, payload)
            self._jsonl.write(json.dumps({"seq": seq, "ts": ts, "kind": kind,
                                          "actor": actor, "payload": payload}, ensure_ascii=False) + "\n")
            self._jsonl.flush()
            self.conn.commit()
            return seq

    def q(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            if self._closed:
                return []
            return self.conn.execute(sql, params).fetchall()

    def q1(self, sql: str, params: tuple = ()):
        with self._lock:
            if self._closed:
                return None
            return self.conn.execute(sql, params).fetchone()

    def read_locked(self, fn, *args, **kwargs):
        with self._lock:
            if self._closed:
                return None
            return fn(self.conn, *args, **kwargs)

    def _apply(self, kind: str, ts: float, p: dict) -> None:
        c = self.conn
        if kind == "node_upsert":
            c.execute("""INSERT INTO nodes(id,type,ukey,title,state,confidence,freshness,
                           provenance,verified,extra,created_ts,updated_ts)
                         VALUES(:id,:type,:ukey,:title,:state,:confidence,:freshness,
                           :provenance,:verified,:extra,:ts,:ts)
                         ON CONFLICT(type,ukey) DO UPDATE SET
                           title=excluded.title, state=excluded.state,
                           confidence=excluded.confidence, freshness=excluded.freshness,
                           provenance=excluded.provenance, verified=excluded.verified,
                           extra=excluded.extra, updated_ts=excluded.updated_ts""",
                      {**_node_defaults(p), "ts": ts})
        elif kind == "edge_add":
            c.execute("""INSERT OR IGNORE INTO edges(id,src,dst,rel,extra,created_ts)
                         VALUES(:id,:src,:dst,:rel,:extra,:ts)""",
                      {"id": p.get("id") or _nid(), "src": p["src"], "dst": p["dst"],
                       "rel": p["rel"], "extra": json.dumps(p.get("extra", {}), ensure_ascii=False), "ts": ts})
        elif kind == "evidence_add":
            c.execute("""INSERT OR REPLACE INTO evidence(id,node_id,kind,content,sha256,triple,created_ts)
                         VALUES(:id,:node_id,:kind,:content,:sha256,:triple,:ts)""",
                      {"id": p["id"], "node_id": p.get("node_id"), "kind": p["kind"],
                       "content": p.get("content", ""), "sha256": p["sha256"],
                       "triple": json.dumps(p.get("triple", {}), ensure_ascii=False), "ts": ts})
        elif kind == "finding_upsert":
            c.execute("""INSERT INTO findings(id,node_id,vulnclass,cwe,owasp,severity,severity_basis,
                           status,verified,summary,evidence_ref,asset_ids,report_md,verdict,tier,risk_meta,extra,
                           created_ts,updated_ts)
                         VALUES(:id,:node_id,:vulnclass,:cwe,:owasp,:severity,:severity_basis,
                           :status,:verified,:summary,:evidence_ref,:asset_ids,:report_md,:verdict,:tier,
                           :risk_meta,:extra,:ts,:ts)
                         ON CONFLICT(id) DO UPDATE SET
                           vulnclass=excluded.vulnclass, cwe=excluded.cwe, owasp=excluded.owasp,
                           severity=excluded.severity, severity_basis=excluded.severity_basis,
                           status=excluded.status, verified=excluded.verified, summary=excluded.summary,
                           evidence_ref=excluded.evidence_ref, asset_ids=excluded.asset_ids,
                           report_md=excluded.report_md, verdict=excluded.verdict, tier=excluded.tier,
                           extra=excluded.extra,
                           risk_meta=excluded.risk_meta, updated_ts=excluded.updated_ts""",
                      {**_finding_defaults(p), "ts": ts})

    def upsert_node(self, type: str, ukey: str, title: str = "", state: str = "",
                    confidence: float = 0.5, verified: bool = False,
                    provenance: str = "observation", extra: dict | None = None) -> str:
        nid = _det_node_id(type, ukey)
        self.emit("node_upsert", "control", {
            "id": nid, "type": type, "ukey": ukey, "title": title, "state": state,
            "confidence": confidence, "freshness": time.time(), "provenance": provenance,
            "verified": 1 if verified else 0, "extra": extra or {}})
        return nid

    def add_edge(self, src: str, dst: str, rel: str, extra: dict | None = None) -> None:
        self.emit("edge_add", "control",
                  {"id": _nid(), "src": src, "dst": dst, "rel": rel, "extra": extra or {}})

    def add_evidence(self, node_id: str | None, kind: str, content: str, triple: dict | None = None) -> str:
        eid = _nid()
        self.emit("evidence_add", "adjudicate", {
            "id": eid, "node_id": node_id, "kind": kind, "content": content,
            "sha256": _sha(content), "triple": triple or {}})
        return eid

    def add_finding(self, vulnclass: str, *, summary: str, verified: bool,
                    exploitability: float = 1.0, node_id: str | None = None,
                    evidence_ref: str | None = None, asset_ids: list | None = None,
                    status: str | None = None, impact_override: str | None = None,
                    fid: str | None = None,
                    verdict: str | None = None, tier: str | None = None,
                    risk_meta: dict | None = None,
                    extra: dict | None = None) -> str:
        cwe, owasp = anchor_vulnclass(vulnclass)
        sev, basis = compute_severity(vulnclass, verified=verified,
                                      exploitability=exploitability, impact_override=impact_override)
        fid = fid or _nid()
        self.emit("finding_upsert", "adjudicate", {
            "id": fid, "node_id": node_id, "vulnclass": vulnclass, "cwe": cwe, "owasp": owasp,
            "severity": sev, "severity_basis": basis,
            "status": status or ("confirmed" if verified else "candidate"),
            "verified": 1 if verified else 0, "summary": summary,
            "evidence_ref": evidence_ref,
            "verdict": verdict, "tier": tier, "risk_meta": risk_meta or {}, "asset_ids": asset_ids or [], "report_md": None,
            "extra": extra or {}})
        return fid

    def _node_id(self, type: str, ukey: str) -> str | None:
        with self._lock:
            if self._closed:
                return None
            r = self.conn.execute("SELECT id FROM nodes WHERE type=? AND ukey=?", (type, ukey)).fetchone()
        return r["id"] if r else None

    def findings_summary(self) -> dict:
        with self._lock:
            rows = [] if self._closed else self.conn.execute("SELECT severity, vulnclass, verified FROM findings").fetchall()
        sev = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        cls: dict[str, int] = {}
        verified_n = 0
        for r in rows:
            sev[r["severity"]] = sev.get(r["severity"], 0) + 1
            cls[r["vulnclass"]] = cls.get(r["vulnclass"], 0) + 1
            if r["verified"]:
                verified_n += 1
        return {"by_severity": sev, "by_vulnclass": cls,
                "total": sum(sev.values()), "total_verified": verified_n,
                "total_candidate": sum(sev.values()) - verified_n}

    def snapshot(self) -> dict:
        def dump(t):
            return [dict(r) for r in self.conn.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()]
        with self._lock:
            if self._closed:
                return {t: [] for t in ("nodes", "edges", "evidence", "findings")}
            return {t: dump(t) for t in ("nodes", "edges", "evidence", "findings")}

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._jsonl.close()
            finally:
                self.conn.close()


_LEGIT_VERIFIER = {"flag": "oracle"}


def _node_defaults(p: dict) -> dict:
    typ = p["type"]
    state = p.get("state", "")
    prov = p.get("provenance", "observation")
    verified = 1 if p.get("verified", 0) else 0
    _legit = _LEGIT_VERIFIER.get(typ)
    if _legit is not None and state == "confirmed" and prov != _legit:
        state = "candidate"
        verified = 0
    return {"id": p.get("id") or _nid(), "type": typ, "ukey": p.get("ukey"),
            "title": p.get("title", ""), "state": state,
            "confidence": p.get("confidence", 0.5), "freshness": p.get("freshness"),
            "provenance": prov, "verified": verified,
            "extra": json.dumps(p.get("extra", {}), ensure_ascii=False)}


def _finding_defaults(p: dict) -> dict:
    return {"id": p["id"], "node_id": p.get("node_id"), "vulnclass": p["vulnclass"],
            "cwe": p.get("cwe"), "owasp": p.get("owasp"), "severity": p["severity"],
            "severity_basis": json.dumps(p.get("severity_basis", {}), ensure_ascii=False),
            "status": p.get("status", "candidate"), "verified": p.get("verified", 0),
            "summary": p.get("summary", ""), "evidence_ref": p.get("evidence_ref"),
            "asset_ids": json.dumps(p.get("asset_ids", []), ensure_ascii=False),
            "report_md": p.get("report_md"),
            "verdict": p.get("verdict"), "tier": p.get("tier"),
            "risk_meta": json.dumps(p.get("risk_meta", {}), ensure_ascii=False),
            "extra": json.dumps(p.get("extra", {}), ensure_ascii=False)}


def replay(events_jsonl: str, out_db: str) -> "TSG":
    g = TSG(out_db, events_path=str(Path(out_db).with_suffix(".replay.jsonl")))
    lines = open(events_jsonl, encoding="utf-8").read().splitlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            if i == len(lines) - 1:
                break
            continue
        try:
            g._apply(ev["kind"], ev["ts"], ev["payload"])
        except (KeyError, TypeError, sqlite3.DatabaseError):
            continue
    g.conn.commit()
    return g
