from __future__ import annotations

import re
import threading

_FP_ALLOW_RX = re.compile(r"[A-Za-z][A-Za-z0-9 ._/()+,\-]*$")
_FP_LONGRUN_RX = re.compile(r"[A-Za-z0-9]{20,}")
_FP_MAXLEN = 60


def _clean_fp(f: str) -> str:
    s = str(f).strip()[:_FP_MAXLEN]
    if not s or not _FP_ALLOW_RX.fullmatch(s) or _FP_LONGRUN_RX.search(s):
        return ""
    return s


def _sqlite_retry(fn, *, tries: int = 3, backoff: float = 0.1):
    import time as _t
    import sqlite3 as _sq
    def wrapper(*a, **kw):
        for i in range(tries):
            try:
                return fn(*a, **kw)
            except _sq.OperationalError as e:
                if 'locked' in str(e) and i < tries - 1:
                    _t.sleep(backoff * (2 ** i))
                    continue
                raise
    return wrapper

class SharedReconCache:

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_host: dict[str, dict] = {}


    @_sqlite_retry
    def contribute(self, host: str, ports, fingerprints, *, existence: bool = False) -> None:
        if not host:
            return
        ps = {int(p) for p in ports if isinstance(p, int) or (isinstance(p, str) and p.isdigit())}
        ps = {p for p in ps if 1 <= p <= 65535}
        fps = {c for c in (_clean_fp(f) for f in fingerprints) if c}
        if not ps and not fps and not existence:
            return
        with self._lock:
            e = self._by_host.setdefault(host, {"ports": set(), "fps": set()})
            e["ports"].update(ps)
            e["fps"].update(fps)
            if len(e["ports"]) > 256:
                e["ports"] = set(sorted(e["ports"])[:256])
            if len(e["fps"]) > 64:
                e["fps"] = set(sorted(e["fps"])[:64])

    def evict_port(self, host: str, port: int) -> bool:
        if not host:
            return False
        try:
            p = int(port)
        except (TypeError, ValueError):
            return False
        with self._lock:
            e = self._by_host.get(host)
            if e and p in e["ports"]:
                e["ports"].discard(p)
                return True
        return False

    def known(self, host: str, exclude_ports=()) -> dict:
        _ex = set()
        for p in (exclude_ports or ()):
            try:
                _q = int(p)
            except (TypeError, ValueError):
                continue
            if 1 <= _q <= 65535:
                _ex.add(_q)
        with self._lock:
            e = self._by_host.get(host)
            if not e:
                return {"ports": [], "fps": []}
            return {"ports": sorted(p for p in e["ports"] if p not in _ex),
                    "fps": sorted(e["fps"])}

    def hosts_in(self, cidr: str) -> list[str]:
        import ipaddress as _ip
        try:
            net = _ip.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return []
        out = []
        with self._lock:
            for h in self._by_host:
                try:
                    if _ip.ip_address(h) in net:
                        out.append(h)
                except (ValueError, TypeError):
                    continue
        return sorted(out)

    def summary_line(self, host: str, exclude_ports=()) -> str:
        k = self.known(host, exclude_ports)
        with self._lock:
            _exists = host in self._by_host
        if not k["ports"] and not k["fps"]:
            return f"internal host {host} reachable (shared recon; ports not yet enumerated)" if _exists else ""
        parts = []
        if k["ports"]:
            parts.append("open ports " + ",".join(str(p) for p in k["ports"]))
        if k["fps"]:
            parts.append("service banners: " + " | ".join(k["fps"][:8]))
        return f"known infrastructure on {host} (shared recon): " + "; ".join(parts)
