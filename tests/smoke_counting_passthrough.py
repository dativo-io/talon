"""Counting pass-through between Talon and the real provider (smoke 13, #575).

Forwards every request to the upstream (default https://api.openai.com),
counts it, and records the upstream round trip in milliseconds, so the smoke
run can prove that a request Talon denied never reached the provider and can
separate the provider's latency from Talon's. It records path, status and
timing only: never a body, a header or a key.

Usage: smoke_counting_passthrough.py <port> <log.jsonl> [upstream]
"""
import http.server
import json
import sys
import time
import urllib.error
import urllib.request

PORT, LOG = int(sys.argv[1]), sys.argv[2]
UPSTREAM = (sys.argv[3] if len(sys.argv) > 3 else "https://api.openai.com").rstrip("/")
HOP = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "keep-alive"}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def forward(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(UPSTREAM + self.path, data=body, method=self.command,
                                     headers={k: v for k, v in self.headers.items() if k.lower() not in HOP})
        start = time.time()
        try:
            resp = urllib.request.urlopen(req, timeout=120)
            status, data, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as err:
            status, data, headers = err.code, err.read(), err.headers
        took = round((time.time() - start) * 1000, 1)
        with open(LOG, "a") as log:
            log.write(json.dumps({"path": self.path, "status": status, "upstream_ms": took}) + "\n")
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() not in HOP:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_POST = forward
    do_GET = forward


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
