#!/usr/bin/env python3
import http.server, ssl, threading, signal, sys, datetime, os, json
from urllib.parse import urlparse, parse_qs

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "serve")
WEBROOT = BASE
LATCH = {"set": False, "detail": ""}

def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEBROOT, **kw)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{ts()}] {self.client_address[0]} " + (fmt % args) + "\n")

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/latch":
            q = parse_qs(u.query)
            if "set" in q or "detail" in q:
                LATCH["set"] = q.get("set", ["1"])[0] not in ("0", "false")
                LATCH["detail"] = q.get("detail", [""])[0]
                sys.stderr.write(f"[{ts()}] LATCH-SET(GET) {q}\n")
                return self._send(200, json.dumps(LATCH))
            sys.stderr.write(f"[{ts()}] LATCH-READ -> {LATCH}\n")
                                           return self._send(200, json.dumps(LATCH))                                                   if u.path.startswith("/log/"):                                                                      return self._send(200, "ok", "text/plain")                                                  return super().do_GET()

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0))                                                  body = self.rfile.read(n).decode("utf-8", "replace") if n else ""                               if u.path == "/latch":                                                                              LATCH["set"] = True                                                                             LATCH["detail"] = body[:200]
            sys.stderr.write(f"[{ts()}] LATCH-SET(POST) {body[:200]}\n")                                    return self._send(200, json.dumps(LATCH))
        if u.path.startswith("/log/"):                                                                      return self._send(200, "ok", "text/plain")
        sys.stderr.write(f"[{ts()}] {self.client_address[0]} POST {u.path} BODY: {body}\n")
        return self._send(200, "ok", "text/plain")
                                              plain = http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler)
                               secure = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(BASE, "cert.pem"), os.path.join(BASE, "key.pem"))
secure.socket = ctx.wrap_socket(secure.socket, server_side=True)

def shutdown(*_):
                                                                                   sys.stderr.write("\n[*] shutting down\n")
                                                       sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)
threading.Thread(target=plain.serve_forever, daemon=True).start()
print(f"[*] HTTP  on 0.0.0.0:80   webroot: {WEBROOT}")
print(f"[*] HTTPS on 0.0.0.0:443  cert: {os.path.join(BASE, 'cert.pem')}")
print("[*] Ctrl+C to stop.")
sys.stderr.flush()
secure.serve_forever()
