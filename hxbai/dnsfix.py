from __future__ import annotations

import os
import socket
import struct
import threading

_PUBLIC_RESOLVERS = ("223.5.5.5", "119.29.29.29")
_LOCK = threading.Lock()

_DNS_ERR_MARKS = ("name or service not known", "temporary failure in name resolution",
                  "eai_again", "getaddrinfo failed", "nodename nor servname provided")


def hosts_path() -> str:
    return os.environ.get("HXBAI_HOSTS_PATH", "/etc/hosts")


def is_dns_error(exc) -> bool:
    t = str(exc).lower()
    return any(m in t for m in _DNS_ERR_MARKS)


def _dns_a_query(hostname: str, resolver: str, timeout: float = 2.0) -> str:
    q = b"".join(bytes([len(l)]) + l.encode() for l in hostname.split(".")) + b"\x00"
    pkt = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (resolver, 53))
        data, _ = s.recvfrom(512)
    except OSError:
        return ""
    finally:
        s.close()
    try:
        i = 12
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        i += 5
        n_ans = struct.unpack(">H", data[6:8])[0]
        for _ in range(n_ans):
            if i >= len(data):
                break
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while i < len(data) and data[i] != 0:
                    i += 1 + data[i]
                i += 1
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4 and i + 4 <= len(data):
                return ".".join(str(b) for b in data[i:i + 4])
            i += rdlen
    except (OSError, struct.error, IndexError):
        return ""
    return ""


def resolve_public(hostname: str) -> str:
    if not hostname:
        return ""
    for r in _PUBLIC_RESOLVERS:
        ip = _dns_a_query(hostname, r)
        if ip:
            return ip
    return ""


def pin_host(hostname: str, ip: str, path: str | None = None) -> str:
    if not hostname or not ip:
        return ""
    path = path or hosts_path()
    try:
        with _LOCK:
            try:
                with open(path, encoding="utf-8") as f:
                    existing = f.read().splitlines()
            except OSError:
                existing = []
            rows = []
            for r in existing:
                parts = r.split()
                if parts and not r.startswith("#") and hostname in parts[1:]:
                    continue
                if r.startswith("# hxbai dnsfix pin"):
                    continue
                rows.append(r)
            rows.append("# hxbai dnsfix pin (public-DNS resolved, auto-refreshed)")
            rows.append(f"{ip} {hostname}")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(rows) + "\n")
        return ip
    except OSError:
        return ""


def api_hostname(base_url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(base_url or "").hostname or ""
    except Exception:
        return ""


def repin_on_dns_error(exc, base_url: str) -> str:
    if not is_dns_error(exc):
        return ""
    host = api_hostname(base_url)
    if not host:
        return ""
    ip = resolve_public(host)
    if not ip:
        return ""
    return pin_host(host, ip)


def pin_api_host(base_url: str) -> str:
    if not base_url:
        return ""
    host = api_hostname(base_url)
    if not host:
        return ""
    ip = resolve_public(host)
    if not ip:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return ""
    return pin_host(host, ip)
