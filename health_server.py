#!/usr/bin/env python3
"""Minimal HTTP health endpoint. Run on the internal-service VM so the
honeypot's healthcheck has a real target.

    python3 health_server.py 0.0.0.0 8080
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):  # quiet
        pass

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    print(f"health on {host}:{port}/health")
    ThreadingHTTPServer((host, port), H).serve_forever()
