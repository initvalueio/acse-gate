#!/usr/bin/env python3
"""A stand-in for ACSE's report endpoint, for the fixture CI only.

It records every request (method, path, whether a bearer token came, the body) as one JSON line, and answers as its
mode says:

  accept       202 {"state": "counted"}
  withdrawn    403 TEMPLATE_WITHDRAWN with the published reason
  not-current  403 TEMPLATE_NOT_CURRENT ("your copy was edited")
  flaky        503 to the first request, then 202
  duplicate    502 to the first request, then 409 REPORT_DUPLICATE (an earlier attempt was accepted)

It also serves GET /token?...&audience=... as a stand-in for GitHub's OIDC token endpoint, for local runs only; on
GitHub the gate asks the real one.

Usage: mock_receiver.py --mode accept --port 8787 --log receiver.jsonl
"""

from __future__ import annotations

import argparse
import http.server
import json
import threading
import urllib.parse

ANSWERS = {
    "withdrawn": (403, {"code": "TEMPLATE_WITHDRAWN",
                        "message": "gate template 1.0.0 withdrawn: security fix in 1.0.1; update your policy repository"}),
    "not-current": (403, {"code": "TEMPLATE_NOT_CURRENT",
                          "message": "the gate template at this commit is not a published release"}),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True,
                        choices=["accept", "withdrawn", "not-current", "flaky", "duplicate"])
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    lock = threading.Lock()
    seen = {"reports": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):  # quiet
            pass

        def _answer(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/token":
                audience = urllib.parse.parse_qs(parsed.query).get("audience", [""])[0]
                self._answer(200, {"value": "local-test-token-for-" + audience})
            elif parsed.path == "/ready":
                self._answer(200, {})
            else:
                self._answer(404, {})

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            with lock:
                seen["reports"] += 1
                n = seen["reports"]
                with open(args.log, "a", encoding="utf-8") as log:
                    log.write(json.dumps({
                        "n": n, "path": self.path,
                        "bearer": (self.headers.get("Authorization") or "").startswith("Bearer ")
                        and len(self.headers.get("Authorization")) > len("Bearer "),
                        "content_type": self.headers.get("Content-Type"),
                        "body": body,
                    }) + "\n")
            if args.mode == "accept":
                self._answer(202, {"result": "accepted", "receipt_id": "rcpt-%d" % n, "state": "counted"})
            elif args.mode in ANSWERS:
                self._answer(*ANSWERS[args.mode])
            elif args.mode == "flaky":
                if n == 1:
                    self._answer(503, {"code": "KEYS_UNAVAILABLE", "message": "try again"})
                else:
                    self._answer(202, {"result": "accepted", "receipt_id": "rcpt-%d" % n, "state": "counted"})
            elif args.mode == "duplicate":
                if n == 1:
                    self._answer(502, {})
                else:
                    self._answer(409, {"code": "REPORT_DUPLICATE", "message": "this report was already received"})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
