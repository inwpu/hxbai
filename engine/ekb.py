from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

_TYPES = ("convention", "cred-hypothesis", "topology", "technique")

import re as _re
_FAMILY_RX = _re.compile(r"^([a-z]+\d*)-\d+", _re.I)


def _code_family(code: str | None) -> str | None:
    if not code:
        return None
    m = _FAMILY_RX.match(code.strip())
    return m.group(1).lower() if m else None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, kind TEXT NOT NULL, actor TEXT, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ekb_nodes(
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  ukey TEXT NOT NULL,
  title TEXT DEFAULT '',
  state TEXT DEFAULT '',
  confidence REAL DEFAULT 0.5,
  freshness REAL,
  provenance TEXT NOT NULL,        -- 源观察引用(必填,红线)
  verified INTEGER DEFAULT 1,      -- EKB 恒 verified(门只纳 verified);字段对齐 TSG
  extra TEXT DEFAULT '{}',         -- 情报细节(同 TSG extra),JSON
  source_challenge TEXT,           -- 交战级新增:贡献此情报的题号
  created_ts REAL, updated_ts REAL,
  UNIQUE(type, ukey));
"""


def _nid() -> str:
    return uuid.uuid4().hex[:16]


def _det_id(type: str, ukey: str) -> str:
    return hashlib.sha256(f"{type}\x00{ukey}".encode("utf-8")).hexdigest()[:16]


def _ekb_node_defaults(p: dict) -> dict:
    return {"id": p.get("id") or _det_id(p["type"], p["ukey"]), "type": p["type"], "ukey": p["ukey"],
            "title": p.get("title", ""), "state": p.get("state", ""),
            "confidence": p.get("confidence", 0.5), "freshness": p.get("freshness"),
            "provenance": p["provenance"], "verified": p.get("verified", 1),
            "extra": json.dumps(p.get("extra", {}), ensure_ascii=False),
            "source_challenge": p.get("source_challenge")}


def _contains_flag(*strings) -> bool:
    try:
        from engine.judge import _CAND_RX
    except Exception:
        return True
    for v in _iter_strings(strings):
        if _CAND_RX.search(v):
            return True
    return False


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


class EKB:

    def __init__(self, db_path: str, events_path: str | None = None, *,
                 enabled: bool = True, types_enabled=None):
        self.enabled = enabled
        self.types_enabled = set(types_enabled) if types_enabled is not None else set(_TYPES)
        self.db_path = str(db_path)
        self.events_path = str(events_path) if events_path else str(
            Path(db_path).with_suffix(".events.jsonl"))
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
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

    def emit(self, kind: str, actor: str, payload: dict) -> int:
        with self._lock:
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

    def _apply(self, kind: str, ts: float, p: dict) -> None:
        c = self.conn
        if kind == "ekb_curate":
            c.execute(
                """INSERT INTO ekb_nodes(id,type,ukey,title,state,confidence,freshness,
                     provenance,verified,extra,source_challenge,created_ts,updated_ts)
                   VALUES(:id,:type,:ukey,:title,:state,:confidence,:freshness,
                     :provenance,:verified,:extra,:source_challenge,:ts,:ts)
                   ON CONFLICT(type,ukey) DO UPDATE SET
                     title=excluded.title, state=excluded.state, confidence=excluded.confidence,
                     freshness=excluded.freshness, provenance=excluded.provenance,
                     verified=excluded.verified, extra=excluded.extra,
                     source_challenge=excluded.source_challenge, updated_ts=excluded.updated_ts""",
                {**_ekb_node_defaults(p), "ts": ts})

    def curate(self, type: str, ukey: str, *, title: str = "", state: str = "",
               extra: dict | None = None, provenance: str, source_challenge: str | None = None,
               source_verified: bool = False, confidence: float = 0.5) -> str | None:
        extra = extra or {}
        reasons = []
        if not self.enabled:
            reasons.append("master-off")
        if type not in _TYPES:
            reasons.append(f"bad-type:{type}")
        elif type not in self.types_enabled:
            reasons.append(f"type-off:{type}")
        if not (isinstance(ukey, str) and ukey.strip()):
            reasons.append("empty-ukey")
        if not (isinstance(provenance, str) and provenance.strip()):
            reasons.append("no-provenance")
        if not source_verified:
            reasons.append("not-verified")
        if _contains_flag(ukey, title, state, extra, provenance):
            reasons.append("flag-in-content")
        if reasons:
            self.emit("ekb_reject", "curate",
                      {"type": type, "ukey": ukey, "reasons": reasons, "source_challenge": source_challenge})
            return None
        nid = _det_id(type, ukey)
        with self._lock:
            _row = self.conn.execute(
                "SELECT title,state,provenance,extra FROM ekb_nodes WHERE id=?", (nid,)).fetchone()
        if _row is not None:
            try:
                _cur_extra = json.loads(_row["extra"]) if _row["extra"] else {}
            except (TypeError, json.JSONDecodeError):
                _cur_extra = {}
            if (_row["title"], _row["state"], _row["provenance"], _cur_extra) == (title, state, provenance, extra):
                return nid
        self.emit("ekb_curate", "curate", {
            "id": nid, "type": type, "ukey": ukey, "title": title, "state": state,
            "confidence": confidence, "freshness": time.time(), "provenance": provenance,
            "verified": 1, "extra": extra, "source_challenge": source_challenge})
        return nid

    def record_inject(self, to_challenge: str, node_ids: list[str]) -> None:
        self.emit("ekb_inject", "inject", {"to": to_challenge, "node_ids": list(node_ids)})

    def record_cred_hit(self, ukey: str, target: str, hit: bool) -> None:
        self.emit("ekb_cred_hit", "inject", {"ukey": ukey, "target": target, "hit": bool(hit)})

    def query(self, type: str | None = None) -> list[dict]:
        with self._lock:
            if type:
                rows = self.conn.execute(
                    "SELECT * FROM ekb_nodes WHERE type=? ORDER BY updated_ts", (type,)).fetchall()
            else:
                rows = self.conn.execute("SELECT * FROM ekb_nodes ORDER BY type, updated_ts").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["extra"] = json.loads(d["extra"]) if d.get("extra") else {}
            out.append(d)
        return out

    def cred_hypotheses(self) -> list[dict]:
        return self.query("cred-hypothesis")

    def project(self, exclude_challenge: str | None = None, limit: int = 24,
                for_challenge: str | None = None) -> dict:
        if not self.enabled:
            return {t: [] for t in _TYPES}
        fam = _code_family(for_challenge)
        out: dict[str, list] = {t: [] for t in _TYPES}
        cand = [n for n in self.query()
                if n["type"] in self.types_enabled
                and not (exclude_challenge and n["source_challenge"] == exclude_challenge)]
        if fam:
            cand.sort(key=lambda n: 0 if _code_family(n["source_challenge"]) == fam else 1)
        for n in cand:
            if len(out[n["type"]]) >= limit:
                continue
            out[n["type"]].append({"ukey": n["ukey"], "title": n["title"], "state": n["state"],
                                   "extra": n["extra"], "provenance": n["provenance"],
                                   "from": n["source_challenge"]})
        return out

    def snapshot(self) -> dict:
        def dump(t):
            return [dict(r) for r in self.conn.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()]
        with self._lock:
            return {t: dump(t) for t in ("ekb_nodes",)}

    def close(self):
        self._jsonl.close()
        self.conn.close()


_PROMOTE = {
    "credential": "cred-hypothesis",
    "foothold_host": "topology",
    "route": "topology",
    "capability": "technique",
    "convention": "convention",
}
_LEARNED_ONLY = {"foothold_host", "route"}
_TOPOLOGY_FROM_FOOTHOLD = frozenset({"foothold-learned"})

_CRED_FIELD_WORDS = frozenset({
    "user", "username", "login", "pass", "passwd", "password", "credential", "creds",
    "none", "null", "nil", "example", "changeme", "your", "the",
})


def credential_plausible(user: str, secret: str) -> bool:
    u = (user or "").strip()
    s = (secret or "").strip()
    if len(s) < 4:
        return False
    if s[0] in "([{<\"'" or s[-1] in ",;:)]}>\"'`":
        return False
    if u.lower() in _CRED_FIELD_WORDS:
        return False
    if not u or not all(c.isalnum() or c in "_.-@" for c in u):
        return False
    return True


def _cred_user_secret(extra: dict):
    if not isinstance(extra, dict):
        return None, None
    if extra.get("user") or extra.get("secret"):
        return extra.get("user", ""), extra.get("secret", "")
    c = extra.get("cred") or ""
    if isinstance(c, str) and ":" in c:
        u, s = c.split(":", 1)
        return u, s
    return None, None


def curate_from_tsg(ekb: "EKB", tsg, challenge_code: str) -> int:
    if not ekb.enabled:
        return 0
    try:
        rows = tsg.q("SELECT type,ukey,title,state,provenance,extra FROM nodes WHERE verified=1")
    except Exception:
        return 0
    before = len(ekb.query())
    for r in rows:
        etype = _PROMOTE.get(r["type"])
        if etype is None or etype not in ekb.types_enabled:
            continue
        if r["type"] in _LEARNED_ONLY and (r["provenance"] or "") not in _TOPOLOGY_FROM_FOOTHOLD:
            continue
        try:
            extra = json.loads(r["extra"]) if r["extra"] else {}
        except (TypeError, json.JSONDecodeError):
            extra = {}
        if etype == "cred-hypothesis":
            _cu, _cs = _cred_user_secret(extra)
            if _cu is not None and not credential_plausible(_cu, _cs):
                continue
        title = r["title"] or r["ukey"]
        ukey = r["ukey"]
        if etype == "technique":
            if not extra.get("entry"):
                continue
            extra = {k: extra[k] for k in ("access", "entry", "grammar", "failures") if extra.get(k)}
            ukey = f"technique:{extra.get('access', '')}:{extra['entry']}"[:200]
            title = extra["entry"]
        state = "hypothesis" if etype == "cred-hypothesis" else (r["state"] or "")
        ekb.curate(etype, ukey=ukey, title=title, state=state,
                   extra=extra, provenance=r["provenance"] or f"tsg:{challenge_code}:{r['type']}",
                   source_challenge=challenge_code, source_verified=True)
    return len(ekb.query()) - before


def replay(events_jsonl: str, out_db: str) -> "EKB":
    e = EKB(out_db, events_path=str(Path(out_db).with_suffix(".replay.jsonl")))
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
            e._apply(ev["kind"], ev["ts"], ev["payload"])
        except (KeyError, TypeError, sqlite3.DatabaseError):
            continue
    e.conn.commit()
    return e


def disprove_technique(ekb, label: str, *, technique: str, host: str, rule: str) -> None:
    import time as _tm
    import sqlite3 as _sq
    db = ekb if isinstance(ekb, str) else getattr(ekb, "_path", None)
    if not db:
        return
    try:
        conn = _sq.connect(db, timeout=10)
        conn.execute("CREATE TABLE IF NOT EXISTS technique_disproof ("
                     "technique TEXT, host TEXT, rule TEXT, by TEXT, ts REAL, PRIMARY KEY(technique, host, rule))")
        conn.execute("INSERT OR REPLACE INTO technique_disproof VALUES (?,?,?,?,?)",
                     (technique[:120], host, rule, label, _tm.time()))
        conn.commit(); conn.close()
    except Exception:
        pass
