#!/usr/bin/env python3
"""
Send a raw (possibly invalid) request to the proxy and print the reply. Works on Windows too.

  python rawsend.py "HELLO\\r\\n\\r\\n"                               -> 400 Bad Request
  python rawsend.py "POST http://example.com/ HTTP/1.1\\r\\n\\r\\n"    -> 405 Method Not Allowed
  python rawsend.py "GET https://example.com/ HTTP/1.1\\r\\n\\r\\n"    -> 501 Not Implemented
  python rawsend.py "GET http://example.com:abc/ HTTP/1.1\\r\\n\\r\\n" -> 400 Bad Request

Options: --proxy HOST:PORT (default 127.0.0.1:8888)
"""
import argparse
import socket

ap = argparse.ArgumentParser()
ap.add_argument("request", help=r'raw text; \r and \n are converted to CR and LF')
ap.add_argument("--proxy", default="127.0.0.1:8888")
args = ap.parse_args()

host, port = args.proxy.rsplit(":", 1)
raw = args.request.replace("\\r", "\r").replace("\\n", "\n").encode("utf-8", errors="replace")
try:
    with socket.create_connection((host, int(port)), timeout=15) as s:
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
except OSError as e:
    raise SystemExit(f"ERROR: {e}")
print(data.decode("utf-8", errors="replace") or "(no response)")
