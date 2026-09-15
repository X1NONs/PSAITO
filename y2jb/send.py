#!/usr/bin/env python3
"""Send a JS payload to the Y2JB loader over TCP. Usage: send.py <host> [port] <file>"""
import socket, sys
def send_payload(path, host, port=50000):
    with open(path, "rb") as f:
        data = f.read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(data)
    s.close()
    print(f"Sent {len(data)} bytes to {host}:{port}")
if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 2: send_payload(a[1], a[0])
    elif len(a) == 3: send_payload(a[2], a[0], int(a[1]))
    else: print("Usage: send.py <host> [port] <file>")
