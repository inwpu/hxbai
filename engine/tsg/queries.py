from __future__ import annotations

import json

_STRUCT_REL = ("contains", "resolves_to", "exposes", "runs_on")
_ASSET_TYPES = ("domain", "host", "service", "endpoint")


def _rows(conn, sql, args=()):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def neighbors(conn, node_id: str, rel: str | None = None, direction: str = "out") -> list[dict]:
    col_self, col_other = ("src", "dst") if direction == "out" else ("dst", "src")
    sql = f"SELECT e.rel, n.* FROM edges e JOIN nodes n ON n.id=e.{col_other} WHERE e.{col_self}=?"
    args = [node_id]
    if rel:
        sql += " AND e.rel=?"; args.append(rel)
    return _rows(conn, sql, tuple(args))


def _host_state(conn, host_id: str) -> str:
    caps = _rows(conn, """SELECT n.type,n.extra FROM edges e JOIN nodes n ON n.id=e.dst
                          WHERE e.src=? AND n.type IN ('capability','foothold') AND n.verified=1""", (host_id,))
    for c in caps:
        try:
            ex = json.loads(c["extra"] or "{}")
        except Exception:
            ex = {}
        if c["type"] == "capability" and (ex.get("access") in ("root", "admin") or ex.get("rce")):
            return "root"
    if caps:
        return "foothold"
    probed = conn.execute("""SELECT 1 FROM edges WHERE src=? AND rel IN ('exposes','runs_on') LIMIT 1""",
                          (host_id,)).fetchone()
    if not probed:
        probed = conn.execute("SELECT 1 FROM findings WHERE node_id=? LIMIT 1", (host_id,)).fetchone()
    return "tested" if probed else "untested"


def asset_topology(conn) -> dict:
    assets = _rows(conn, f"SELECT * FROM nodes WHERE type IN ({','.join('?'*len(_ASSET_TYPES))})", _ASSET_TYPES)
    by_id = {a["id"]: a for a in assets}
    children: dict[str, list[str]] = {a["id"]: [] for a in assets}
    has_parent = set()
    for e in _rows(conn, f"SELECT src,dst,rel FROM edges WHERE rel IN ({','.join('?'*len(_STRUCT_REL))})", _STRUCT_REL):
        if e["src"] in by_id and e["dst"] in by_id:
            children[e["src"]].append(e["dst"]); has_parent.add(e["dst"])
    fcount = {r["node_id"]: r["c"] for r in _rows(conn,
              "SELECT node_id, COUNT(*) c FROM findings WHERE verified=1 GROUP BY node_id")}

    def build(nid: str, seen: frozenset, depth: int = 0) -> dict:
        a = by_id[nid]
        kids = [] if depth >= 64 else [build(c, seen | {nid}, depth + 1)
                                       for c in children[nid] if c not in seen]
        node = {"id": nid, "type": a["type"], "label": a["title"] or a["ukey"],
                "verified": bool(a["verified"]),
                "findings": fcount.get(nid, 0),
                "coverage": "covered" if a["verified"] else "untested",
                "children": kids}
        cyc = [c for c in children[nid] if c in seen]
        if cyc:
            node["cycle_refs"] = cyc
        if a["type"] == "host":
            node["pivot_state"] = _host_state(conn, nid)
        return node

    roots = [a["id"] for a in assets if a["id"] not in has_parent]
    if not roots and assets:
        roots = [assets[0]["id"]]
    roots.sort(key=lambda i: _ASSET_TYPES.index(by_id[i]["type"]) if by_id[i]["type"] in _ASSET_TYPES else 9)
    return {"roots": [build(r, frozenset()) for r in roots], "asset_count": len(assets)}


def host_pivot_topology(conn) -> dict:
    hosts = _rows(conn, "SELECT * FROM nodes WHERE type='host'")
    nodes = [{"id": h["id"], "label": h["title"] or h["ukey"],
              "state": _host_state(conn, h["id"]),
              "reached_ts": h["created_ts"]} for h in hosts]
    hset = {h["id"] for h in hosts}
    edges = []
    for e in _rows(conn, "SELECT src,dst,rel,extra,created_ts FROM edges WHERE rel='pivots_to' ORDER BY created_ts"):
        if e["src"] in hset and e["dst"] in hset:
            try:
                ex = json.loads(e["extra"] or "{}")
            except Exception:
                ex = {}
            edges.append({"src": e["src"], "dst": e["dst"],
                          "method": ex.get("method", ""), "order_ts": e["created_ts"]})
    nodes.sort(key=lambda n: n["reached_ts"])
    return {"nodes": nodes, "edges": edges}


def decide_projection(conn, *, limit: int = 12) -> dict:
    def q(sql, a=()):
        return _rows(conn, sql, a)
    return {
        "capabilities": q("SELECT title,extra FROM nodes WHERE type='capability' AND verified=1 ORDER BY updated_ts DESC LIMIT ?", (limit,)),
        "open_subgoals": q("SELECT id,title,state FROM nodes WHERE type='subgoal' AND state IN ('open','active') ORDER BY created_ts LIMIT ?", (limit,)),
        "open_steps": q("SELECT id,title FROM nodes WHERE type='step' AND state='open' ORDER BY created_ts LIMIT ?", (limit,)),
        "deadends": q("SELECT title FROM nodes WHERE type='deadend' AND state='active' LIMIT ?", (limit,)),
        "insights": q("SELECT title FROM nodes WHERE type='insight' ORDER BY updated_ts DESC LIMIT ?", (limit,)),
        "recent_findings": q("SELECT vulnclass,severity,summary FROM findings ORDER BY created_ts DESC LIMIT ?", (limit,)),
        "asset_counts": {r["type"]: r["c"] for r in q("SELECT type, COUNT(*) c FROM nodes WHERE type IN ('host','service','endpoint','credential') GROUP BY type")},
    }
