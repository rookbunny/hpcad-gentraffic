#!/usr/bin/env python3
"""Minimal WebSocket echo server. Run on the chat VM so the honeypot's
chat_ws keepalive has a real endpoint without standing up Mattermost.

    pip install websockets
    python3 ws_echo_server.py 0.0.0.0 8765
"""
import sys
from websockets.sync.server import serve

def handler(ws):
    for msg in ws:
        ws.send(msg)  # echo pings back as pongs

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
    print(f"ws echo on {host}:{port}")
    with serve(handler, host, port) as server:
        server.serve_forever()
