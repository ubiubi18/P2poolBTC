#!/usr/bin/env python3
"""Loopback-only Idena RPC proxy for local web UI access.

The browser talks to this proxy with a harmless placeholder key. The proxy reads
the real node key from a protected local file, injects it into each JSON-RPC
request, and forwards to an SSH tunnel.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_API_KEY_BYTES = 4096
MAX_BATCH_REQUESTS = 100


def _contains_unsafe_header_chars(value: str) -> bool:
    return any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    )


def validate_loopback_address(
    value: str, label: str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if value != value.strip():
        raise ValueError(f"{label} must be a literal loopback IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a literal loopback IP address") from exc
    if not address.is_loopback:
        raise ValueError(f"{label} must be a loopback IP address")
    return address


def validate_upstream(value: str) -> str:
    if _contains_unsafe_header_chars(value) or "\\" in value:
        raise ValueError("IDENA_RPC_UPSTREAM contains unsafe characters")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http":
        raise ValueError("IDENA_RPC_UPSTREAM must use http")
    if (
        not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("IDENA_RPC_UPSTREAM must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("IDENA_RPC_UPSTREAM must not contain a query or fragment")
    if parsed.hostname is None:
        raise ValueError("IDENA_RPC_UPSTREAM has no host")
    validate_loopback_address(parsed.hostname, "IDENA_RPC_UPSTREAM host")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("IDENA_RPC_UPSTREAM has an invalid port") from exc
    return value


def validate_origin(value: str) -> str:
    if _contains_unsafe_header_chars(value) or "\\" in value:
        raise ValueError("allowed origin contains unsafe characters")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("allowed origin must use http or https")
    if not parsed.netloc or parsed.hostname is None:
        raise ValueError("allowed origin has no host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("allowed origin must not contain credentials")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("allowed origin must not contain a path, query, or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("allowed origin has an invalid port") from exc
    return value


def validate_private_key_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    try:
        metadata = os.lstat(parent)
    except OSError as exc:
        raise ValueError("IDENA_API_KEY_FILE parent is not inspectable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("IDENA_API_KEY_FILE parent must be a real directory")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(
            "IDENA_API_KEY_FILE parent must not be writable by group or others"
        )

    current = parent
    while current and current != os.path.dirname(current):
        if os.path.islink(current):
            try:
                link_metadata = os.lstat(current)
                parent_metadata = os.lstat(os.path.dirname(current) or os.sep)
            except OSError as exc:
                raise ValueError(
                    "IDENA_API_KEY_FILE has an uninspectable symlink ancestor"
                ) from exc
            if (
                os.name != "posix"
                or link_metadata.st_uid != 0
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
            ):
                raise ValueError(
                    "IDENA_API_KEY_FILE has an unsafe symlink ancestor"
                )
        current = os.path.dirname(current)


class ProxyConfig:
    def __init__(self, upstream: str, key_file: str, allowed_origins: set[str]):
        self.upstream = validate_upstream(upstream)
        self.key_file = key_file
        self.allowed_origins = {
            validate_origin(origin) for origin in allowed_origins
        }

    def read_key(self) -> str:
        validate_private_key_parent(self.key_file)
        if os.path.islink(self.key_file):
            raise ValueError("IDENA_API_KEY_FILE must not be a symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.key_file, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("IDENA_API_KEY_FILE must be a regular file")
            if metadata.st_size <= 0 or metadata.st_size > MAX_API_KEY_BYTES:
                raise ValueError("IDENA_API_KEY_FILE has an invalid size")
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError(
                    "IDENA_API_KEY_FILE must not be accessible by group or others"
                )
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                key = handle.read(MAX_API_KEY_BYTES + 1).strip()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not key or len(key.encode("utf-8")) > MAX_API_KEY_BYTES:
            raise ValueError("IDENA_API_KEY_FILE contains an invalid key")
        if any(ord(character) < 32 or ord(character) == 127 for character in key):
            raise ValueError("IDENA_API_KEY_FILE contains control characters")
        return key


class IdenaRpcProxy(BaseHTTPRequestHandler):
    server_version = "IdenaRpcLoopbackProxy/1.0"

    @property
    def config(self) -> ProxyConfig:
        return self.server.config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        if not self._origin_allowed(require_origin=True):
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
        if not self._origin_allowed(require_origin=True):
            self._send_text(403, "origin not allowed")
            return

        if self.headers.get("Transfer-Encoding") is not None:
            self._send_json(400, {"error": "transfer encoding is not supported"})
            return
        content_lengths = self.headers.get_all("Content-Length", [])
        if len(content_lengths) != 1:
            self._send_json(400, {"error": "exactly one content length is required"})
            return
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/json":
            self._send_json(415, {"error": "content type must be application/json"})
            return

        try:
            raw_length = content_lengths[0]
            if not raw_length.isascii() or not raw_length.isdecimal():
                raise ValueError
            length = int(raw_length, 10)
        except ValueError:
            self._send_json(400, {"error": "invalid content length"})
            return

        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "invalid request body size"})
            return

        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            self._send_json(400, {"error": "invalid json-rpc request"})
            return

        try:
            key = self.config.read_key()
        except (OSError, UnicodeError, ValueError) as exc:
            self.log_error("cannot prepare JSON-RPC request: %s", exc)
            self._send_json(500, {"error": "proxy configuration is invalid"})
            return
        try:
            payload = self._with_key(payload, key)
        except ValueError:
            self._send_json(400, {"error": "invalid json-rpc request"})
            return
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        req = urllib.request.Request(
            self.config.upstream,
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read(MAX_RESPONSE_BYTES + 1)
                status = resp.status
        except urllib.error.HTTPError as exc:
            data = exc.read(MAX_RESPONSE_BYTES + 1)
            status = exc.code
        except Exception as exc:
            self.log_error("upstream request failed: %s", exc)
            self._send_json(502, {"error": "upstream unavailable"})
            return

        if len(data) > MAX_RESPONSE_BYTES:
            self._send_json(502, {"error": "upstream response is too large"})
            return

        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _with_key(self, payload: Any, key: str) -> Any:
        if isinstance(payload, list):
            if not payload or len(payload) > MAX_BATCH_REQUESTS:
                raise ValueError("json-rpc batch size is invalid")
            if not all(isinstance(item, dict) for item in payload):
                raise ValueError("json-rpc batch entries must be objects")
            return [self._with_key(item, key) for item in payload]
        if isinstance(payload, dict):
            item = dict(payload)
            item["key"] = key
            return item
        raise ValueError("json-rpc payload must be an object or array")

    def _origin_allowed(self, *, require_origin: bool = False) -> bool:
        origins = self.headers.get_all("Origin", [])
        if not origins:
            return not require_origin
        return self._matched_origin(origins) is not None

    def _matched_origin(self, origins: list[str] | None = None) -> str | None:
        candidates = (
            origins
            if origins is not None
            else self.headers.get_all("Origin", [])
        )
        if len(candidates) != 1:
            return None
        requested = candidates[0]
        return next(
            (origin for origin in self.config.allowed_origins if origin == requested),
            None,
        )

    def _send_cors_headers(self) -> None:
        origin = self._matched_origin()
        if origin is not None:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, status: int, text: str) -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
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

    try:
        bind_address = validate_loopback_address(args.host, "--host")
        allowed = {
            origin.strip()
            for origin in os.environ.get(
                "IDENA_RPC_ALLOWED_ORIGINS",
                "http://127.0.0.1:3030,http://localhost:3030",
            ).split(",")
            if origin.strip()
        }
        config = ProxyConfig(upstream, key_file, allowed)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    server_type = ThreadingHTTPServer
    if bind_address.version == 6:
        class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
            address_family = socket.AF_INET6

        server_type = IPv6ThreadingHTTPServer
    server = server_type((args.host, args.port), IdenaRpcProxy)
    server.daemon_threads = True
    server.config = config  # type: ignore[attr-defined]
    print(f"Idena RPC proxy listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
