#!/usr/bin/env python3
"""Loopback-only Idena RPC proxy for local web UI access.

The browser talks to this proxy with a harmless placeholder key. The proxy reads
the real node key from a protected local file, injects it into each JSON-RPC
request, and forwards to an SSH tunnel.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


MAX_BODY_BYTES = 2 * 1024 * 1024


class ProxyConfig:
    def __init__(self, upstream: str, key_file: str, allowed_origins: set[str]):
        self.upstream = upstream
        self.key_file = key_file
        self.allowed_origins = allowed_origins

    def read_key(self) -> str:
        with open(self.key_file, "r", encoding="utf-8") as f:
            return f.read().strip()


class IdenaRpcProxy(BaseHTTPRequestHandler):
    server_version = "IdenaRpcLoopbackProxy/1.0"

    @property
    def config(self) -> ProxyConfig:
        return self.server.config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        if not self._origin_allowed():
            self._send_text(403, "origin not allowed")
            return
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def do_GET(self) -> None:
        self._send_text(200, "Idena RPC loopback proxy is running\n")

    def do_POST(self) -> None:
        if not self._origin_allowed():
            self._send_text(403, "origin not allowed")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid content length"})
            return

        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "invalid request body size"})
            return

        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            payload = self._with_key(payload, self.config.read_key())
            encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except Exception as exc:
            self._send_json(400, {"error": "invalid json-rpc request", "message": str(exc)})
            return

        req = urllib.request.Request(
            self.config.upstream,
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read()
                status = resp.status
                content_type = resp.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as exc:
            data = exc.read()
            status = exc.code
            content_type = exc.headers.get("Content-Type", "application/json")
        except Exception as exc:
            self._send_json(502, {"error": "upstream unavailable", "message": str(exc)})
            return

        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _with_key(self, payload: Any, key: str) -> Any:
        if isinstance(payload, list):
            return [self._with_key(item, key) for item in payload]
        if isinstance(payload, dict):
            item = dict(payload)
            item["key"] = key
            return item
        raise ValueError("json-rpc payload must be an object or array")

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        return not origin or origin in self.config.allowed_origins

    def _send_cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin in self.config.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Credentials", "false")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, status: int, text: str) -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19009)
    args = parser.parse_args()

    upstream = os.environ.get("IDENA_RPC_UPSTREAM", "http://127.0.0.1:19010/")
    key_file = os.environ.get("IDENA_API_KEY_FILE")
    if not key_file:
        print("IDENA_API_KEY_FILE is required", file=sys.stderr)
        return 2

    allowed = {
        origin.strip()
        for origin in os.environ.get(
            "IDENA_RPC_ALLOWED_ORIGINS",
            "http://127.0.0.1:3030,http://localhost:3030",
        ).split(",")
        if origin.strip()
    }
    server = ThreadingHTTPServer((args.host, args.port), IdenaRpcProxy)
    server.config = ProxyConfig(upstream, key_file, allowed)  # type: ignore[attr-defined]
    print(f"Idena RPC proxy listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
