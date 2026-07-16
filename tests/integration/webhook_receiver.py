#!/usr/bin/env python3
"""Small loopback webhook receiver used by browser integration tests."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


last_request = {}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        last_request.clear()
        last_request.update({
            "path": self.path,
            "raw": body.decode(),
            "body": json.loads(body or b"{}"),
            "signature": self.headers.get("X-Domain-OSS-Signature", ""),
        })
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        data = json.dumps(last_request).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18026), Handler).serve_forever()
