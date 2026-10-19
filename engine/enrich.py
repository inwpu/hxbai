from __future__ import annotations

import re
import socket
import time

_ENRICHED_KEY = "engine_enriched"


def _host_of(url: str) -> str:
    s = re.sub(r"^\w+://", "", str(url).strip()).split("#", 1)[0].split("/", 1)[0]
    return (s.rpartition(":")[0] if ":" in s else s).strip("[]")


def _probe_http(url: str, timeout: float = 4.0) -> dict:
    try:
        s = re.sub(r"^\w+://", "", str(url).strip()).split("#", 1)[0].split("/", 1)[0]
        host, _, p = (s.rpartition(":") if ":" in s else (s, "", ""))
        host = (host or s).strip("[]")
        port = int(p) if p.isdigit() else 80
        path = "/" + str(url).strip().split("/", 3)[-1] if str(url).count("/") >= 3 else "/"
        with socket.create_connection((host, port), timeout=timeout) as c:
            c.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            head = (c.recv(2048) or b"").decode("latin1", "ignore")
        first = head.splitlines()[0] if head else ""
        m = re.search(r"HTTP/\d\.\d (\d{3})", first)
        sm = re.search(r"Server:\s*(.+)", head, re.I)
        return {"http_status": int(m.group(1)) if m else None,
                "http_server": (sm.group(1).strip()[:80] if sm else "")}
    except Exception:
        return {}


def _resolve(host: str) -> str:
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception:
        return ""


def enrich_pending(tsg, scope_check, budget_s: float = 30.0) -> int:
    import json
    t0 = time.time()
    done = 0
    try:
        rows = tsg.q("SELECT id, title, extra FROM nodes WHERE type='endpoint' "
                     "AND (extra IS NULL OR extra NOT LIKE ?) LIMIT 24", (f'%"{_ENRICHED_KEY}"%',))
    except Exception:
        return 0
    for r in rows:
        if time.time() - t0 > budget_s:
            break
        host = _host_of(r["title"])
        if not host or not scope_check(host):
            continue
        ex = json.loads(r["extra"] or "{}")
        attrs = {"dns": _resolve(host)}
        attrs.update(_probe_http(r["title"]))
        if not attrs["dns"] and not attrs.get("http_status"):
            continue
        ex.update(attrs)
        ex[_ENRICHED_KEY] = int(time.time())
        try:
            with tsg._lock:
                tsg.conn.execute("UPDATE nodes SET extra=? WHERE id=?",
                                 (json.dumps(ex, ensure_ascii=False), r["id"]))
                tsg.conn.commit()
            done += 1
        except Exception:
            pass
    return done
