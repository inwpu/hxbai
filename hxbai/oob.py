from __future__ import annotations

import json
import socket
import struct
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def new_token() -> str:
    return uuid.uuid4().hex[:20]


def poll_server(token: str, timeout: int = 8) -> list:
    import os
    import urllib.request
    if not token:
        return []
    base = os.getenv("OOB_HTTP_BASE", "http://oob-server").rstrip("/")
    q = f"token={token}"
    secret = os.getenv("OOB_POLL_SECRET", "")
    if secret:
        q += f"&secret={secret}"
    try:
        with urllib.request.urlopen(f"{base}/_oob/poll?{q}", timeout=timeout) as r:
            return json.loads(r.read().decode()).get("hits", []) or []
    except Exception:
        return []


def token_from_host(host: str, domain: str) -> tuple[str, str]:
    host = (host or "").split(":")[0].lower().rstrip(".")
    domain = (domain or "").lower().rstrip(".")
    if domain and (host == domain or host.endswith("." + domain)):
        rem = host[: -(len(domain) + 1)] if host != domain else ""
        labels = [l for l in rem.split(".") if l]
        if labels:
            return labels[-1], ".".join(labels[:-1])
    return "", ""


class _Store:

    PER_TOKEN = 1000
    GLOBAL = 10_000

    def __init__(self):
        self._d: dict[str, list] = {}
        self._lock = threading.Lock()

    def add(self, token: str, rec: dict) -> None:
        if not token:
            return
        with self._lock:
            lst = self._d.setdefault(token, [])
            lst.append(rec)
            if len(lst) > self.PER_TOKEN:
                del lst[: len(lst) - self.PER_TOKEN]
            total = sum(len(v) for v in self._d.values())
            while total > self.GLOBAL and len(self._d) > 1:
                big = max(self._d, key=lambda k: len(self._d[k]))
                total -= len(self._d.pop(big))

    def get(self, token: str) -> list:
        with self._lock:
            return list(self._d.get(token, []))


class OOBListener:

    def __init__(self, domain: str = "oob.lab", http_port: int = 80, dns_port: int = 53,
                 resolve_ip: str = "127.0.0.1"):
        self.domain = domain
        self.http_port = http_port
        self.dns_port = dns_port
        self.resolve_ip = resolve_ip
        self.store = _Store()
        self._httpd = None
        self._dns_sock = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> "OOBListener":
        store, domain = self.store, self.domain

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _handle(self):
                import os as _os
                u = urlparse(self.path)
                if u.path.startswith("/_oob/poll"):
                    want = _os.getenv("OOB_POLL_SECRET", "")
                    got = (parse_qs(u.query).get("secret") or [""])[0]
                    if want and got != want:
                        body = json.dumps({"error": "forbidden"}).encode()
                        self.send_response(403); self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body))); self.end_headers()
                        self.wfile.write(body); return
                    tok = (parse_qs(u.query).get("token") or [""])[0]
                    body = json.dumps({"token": tok, "hits": store.get(tok)}).encode()
                    self.send_response(200); self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    self.wfile.write(body); return
                host = self.headers.get("Host", "")
                tok, data = token_from_host(host, domain)
                if not tok:
                    tok = (u.path.strip("/").split("/") or [""])[0]
                store.add(tok, {"protocol": "http", "path": self.path, "host": host,
                                "source_ip": self.client_address[0], "exfil_data": data})
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_HEAD = _handle

        self._httpd = ThreadingHTTPServer(("0.0.0.0", self.http_port), H)
        self.http_port = self._httpd.server_address[1]
        t = threading.Thread(target=self._httpd.serve_forever, daemon=True); t.start()
        self._threads.append(t)

        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._dns_sock.bind(("0.0.0.0", self.dns_port))
        self.dns_port = self._dns_sock.getsockname()[1]
        td = threading.Thread(target=self._dns_loop, daemon=True); td.start()
        self._threads.append(td)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._httpd:
            self._httpd.shutdown()
        if self._dns_sock:
            try:
                self._dns_sock.close()
            except OSError:
                pass

    def _dns_loop(self) -> None:
        self._dns_sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = self._dns_sock.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            try:
                qname = self._parse_qname(data)
                if not (qname == self.domain or qname.endswith("." + self.domain)):
                    continue
                tok, exfil = token_from_host(qname, self.domain)
                if tok:
                    self.store.add(tok, {"protocol": "dns", "qname": qname,
                                         "source_ip": addr[0], "exfil_data": exfil})
                self._dns_sock.sendto(self._build_answer(data), addr)
            except Exception:
                continue

    @staticmethod
    def _parse_qname(pkt: bytes) -> str:
        i = 12
        labels = []
        while i < len(pkt):
            n = pkt[i]
            if n == 0:
                break
            labels.append(pkt[i + 1:i + 1 + n].decode("latin-1"))
            i += 1 + n
        return ".".join(labels).lower()

    def _build_answer(self, query: bytes) -> bytes:
        tid = query[:2]
        header = tid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
        i = 12
        while i < len(query) and query[i] != 0:
            i += 1 + query[i]
        qend = i + 1 + 4
        question = query[12:qend]
        ip = bytes(int(o) for o in self.resolve_ip.split("."))
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + ip
        return header + question + answer

    def poll(self, token: str) -> list:
        return self.store.get(token)


def serve() -> None:
    import os
    import time

    srv = OOBListener(
        domain=os.getenv("OOB_DOMAIN", "oob.lab"),
        http_port=int(os.getenv("OOB_HTTP_PORT", "80")),
        dns_port=int(os.getenv("OOB_DNS_PORT", "53")),
        resolve_ip=os.getenv("OOB_RESOLVE_IP", "127.0.0.1"),
    ).start()
    print(f"[oob] listening domain={srv.domain} http={srv.http_port} dns={srv.dns_port}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    serve()
