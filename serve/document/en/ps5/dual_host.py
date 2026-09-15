#!/usr/bin/env python3
"""dual_host - serve PSAITO root on HTTP+HTTPS + /log endpoint. No sudo: 8000/8443."""
import http.server, ssl, threading, os, sys, datetime
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))  # repo root has index.html/go.html
def ts(): return datetime.datetime.now().strftime("%H:%M:%S")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=BASE, **kw)
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{ts()}] {self.client_address[0]} " + (fmt % args) + "\n")
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/log" or u.path == "/log/":
            return self._ok("ok")
        return super().do_GET()
    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        if u.path.startswith("/log"):
            if body: sys.stderr.write(f"[{ts()}] LOG {body[:500]}\n")
            else: sys.stderr.write(f"[{ts()}] LOG (empty post)\n")
            return self._ok("ok")
        return super().do_GET()
    def _ok(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

plain = http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
secure = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(BASE, "serve", "cert.pem"), os.path.join(BASE, "serve", "key.pem"))
secure.socket = ctx.wrap_socket(secure.socket, server_side=True)
threading.Thread(target=plain.serve_forever, daemon=True).start()
print(f"[*] HTTP  http://0.0.0.0:8000/  root={BASE}")
print(f"[*] HTTPS https://0.0.0.0:8443/ cert=serve/cert.pem")
print("[*] LOG endpoint: http://<PC-IP>:8000/log (POST)")
print("[*] Ctrl+C to stop.")
sys.stderr.flush()
try:
    secure.serve_forever()
except KeyboardInterrupt:
    print("\n[*] stopping")
