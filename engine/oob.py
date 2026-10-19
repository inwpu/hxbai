from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class OOBListener:

    def __init__(self, host: str = "0.0.0.0", advertise_host: str = "127.0.0.1", port: int = 0):
        self._hits: dict[str, str] = {}
        self._expected: set[str] = set()
        self._lock = threading.Lock()
        hits, lock, expected = self._hits, self._lock, self._expected

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                nonce = self.path.strip("/").split("/")[0].split("?")[0]
                with lock:
                    if nonce and nonce in expected:
                        hits[nonce] = self.client_address[0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                return

        self._srv = ThreadingHTTPServer((host, port), _H)
        self.port = self._srv.server_address[1]
        self.advertise_host = advertise_host
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()

    def expect(self, nonce: str) -> None:
        with self._lock:
            self._expected.add(nonce)

    def url(self, nonce: str) -> str:
        return f"http://{self.advertise_host}:{self.port}/{nonce}"

    def hit(self, nonce: str) -> str | None:
        with self._lock:
            return self._hits.get(nonce)

    def stop(self) -> None:
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass
