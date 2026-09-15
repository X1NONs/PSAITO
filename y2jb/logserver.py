#!/usr/bin/env python3
"""Y2JB log receiver: prints POSTs, appends to y2jb/session.log. Listens :8080."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
HERE = os.path.dirname(os.path.abspath(__file__))
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        print(body, flush=True)
        try:
            with open(os.path.join(HERE, "session.log"), "a") as f:
                f.write(body + "\n")
        except OSError: pass
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
print("y2jb logserver on :8080 (log: y2jb/session.log)")
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
