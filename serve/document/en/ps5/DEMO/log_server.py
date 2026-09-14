#!/usr/bin/env python3
# log_server.py — receptor de telemetria para PSAITO en consola.
#
# Escucha en 0.0.0.0:8080 e imprime cada linea que el exploit (modules/exploit.js)
# y el bridge (modules/bridge.js) envian por POST de texto plano. Es el mismo
# endpoint que espera el runtime Y2JB cuando se usa ?logserver=http://<PC-IP>:8080/log.
#
# Uso:
#   python3 DEMO/log_server.py            # puerto 8080
#   python3 DEMO/log_server.py 9000       # puerto alternativo
#
# En la PS5 abre el toolkit con:
#   ?log=1&logserver=http://<PC-IP>:8080/log
#
# Notas:
#   - El log de pantalla (#scr) es lossy y desaparece al recargar/reiniciar la
#     pestana; este log sobrevive a un crash de la consola.
#   - No requiere dependencias: solo la libreria estandar.
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        # El flujo previo hacia GET log/<linea>; se acepta como linea.
        # checkLogServer() del runtime Y2JB tambien hace GET para probar.
        if self.path.startswith("/log/"):
            self._emit(self.path[len("/log/"):])
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(n) if n else b""
        self._emit(body.decode("utf-8", "replace"))
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    @staticmethod
    def _emit(line):
        line = line.rstrip("\r\n")
        if not line:
            return
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        for logical in line.splitlines():
            print(f"[{ts}] {logical}", flush=True)

    def log_message(self, *args):
        pass  # silencia el log HTTP por defecto


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"log_server escuchando en 0.0.0.0:{PORT}", flush=True)
    print("en la PS5 usa: ?log=1&logserver=http://<tu-IP>:%d/log" % PORT, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\ncerrando...", flush=True)