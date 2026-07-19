#!/usr/bin/env python3
"""Serve the dashboard and proxy its authenticated loopback API.

The browser never receives the dashboard API token. The token is read from a
systemd credential and added only to bounded same-origin API requests.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import mimetypes
import os
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


MAX_STATIC_BYTES = 32 * 1024 * 1024
MAX_API_BYTES = 16 * 1024 * 1024
MAX_TOKEN_BYTES = 4096
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bind-host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    return parser.parse_args()


def require_loopback_host(raw: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise SystemExit(f"{label} must be a literal loopback address") from exc
    if not address.is_loopback:
        raise SystemExit(f"{label} must be a loopback address")
    return address.compressed


def parse_api_origin(raw: str) -> tuple[str, int]:
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("API origin must be credential-free loopback HTTP")
    host = require_loopback_host(parsed.hostname, "API origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise SystemExit("API origin has an invalid port") from exc
    if port is None or not 1 <= port <= 65535:
        raise SystemExit("API origin must include a valid port")
    return host, port


def load_token(path: Path) -> str:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SystemExit("dashboard API credential is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("dashboard API credential must be a regular non-symlink file")
    if metadata.st_size == 0 or metadata.st_size > MAX_TOKEN_BYTES:
        raise SystemExit("dashboard API credential has an unsafe size")
    token = path.read_text(encoding="utf-8").rstrip("\r\n")
    if not token or any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise SystemExit("dashboard API credential contains unsafe characters")
    return token


def validate_static_root(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise SystemExit("dashboard static root must be a real directory")
    root = path.resolve(strict=True)
    for directory, names, files in os.walk(root, followlinks=False):
        for name in [*names, *files]:
            candidate = Path(directory, name)
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise SystemExit("dashboard static root must not contain symlinks")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise SystemExit("dashboard static root contains a special file")
    if not (root / "index.html").is_file():
        raise SystemExit("dashboard static root is missing index.html")
    return root


class DashboardUiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        root: Path,
        api_host: str,
        api_port: int,
        token: str,
    ) -> None:
        self.static_root = root.resolve(strict=True)
        self.api_host = api_host
        self.api_port = api_port
        self.api_token = token
        super().__init__(address, DashboardUiHandler)


class DashboardUiHandler(BaseHTTPRequestHandler):
    server: DashboardUiServer
    server_version = "PoHWDashboardUI/1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(send_body=False)

    def do_POST(self) -> None:  # noqa: N802
        self._json_error(405, "method not allowed")

    def do_PUT(self) -> None:  # noqa: N802
        self._json_error(405, "method not allowed")

    def do_DELETE(self) -> None:  # noqa: N802
        self._json_error(405, "method not allowed")

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _dispatch(self, send_body: bool) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/dashboard.json" or parsed.path.startswith("/api/v1/"):
            self._proxy_api(parsed.path, parsed.query, send_body)
            return
        self._serve_static(parsed.path, send_body)

    def _proxy_api(self, path: str, query: str, send_body: bool) -> None:
        target = path + (f"?{query}" if query else "")
        connection = http.client.HTTPConnection(
            self.server.api_host,
            self.server.api_port,
            timeout=5,
        )
        try:
            connection.request(
                "GET" if send_body else "HEAD",
                target,
                headers={
                    "Accept": "application/json",
                    "X-PoHW-Dashboard-Token": self.server.api_token,
                },
            )
            response = connection.getresponse()
            declared_length = response.getheader("Content-Length")
            if declared_length is not None and int(declared_length) > MAX_API_BYTES:
                raise ValueError("upstream response is too large")
            body = response.read(MAX_API_BYTES + 1) if send_body else b""
            if len(body) > MAX_API_BYTES:
                raise ValueError("upstream response is too large")
            response_length = len(body) if send_body else int(declared_length or 0)
            self.send_response(response.status)
            self.send_header(
                "Content-Type",
                response.getheader("Content-Type") or "application/json",
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(response_length))
            self._send_security_headers()
            self.end_headers()
            if send_body:
                self.wfile.write(body)
        except (OSError, http.client.HTTPException, ValueError):
            self._json_error(502, "dashboard API unavailable", send_body=send_body)
        finally:
            connection.close()

    def _serve_static(self, raw_path: str, send_body: bool) -> None:
        try:
            decoded = unquote(raw_path, errors="strict")
        except (UnicodeDecodeError, ValueError):
            self._json_error(400, "invalid path", send_body=send_body)
            return
        if "\x00" in decoded or "\\" in decoded or not decoded.startswith("/"):
            self._json_error(400, "invalid path", send_body=send_body)
            return
        relative = decoded.lstrip("/") or "index.html"
        parts = relative.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            self._json_error(404, "not found", send_body=send_body)
            return
        try:
            candidate = self.server.static_root.joinpath(*parts).resolve(strict=True)
            candidate.relative_to(self.server.static_root)
            metadata = candidate.stat()
        except (FileNotFoundError, OSError, ValueError):
            self._json_error(404, "not found", send_body=send_body)
            return
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_STATIC_BYTES:
            self._json_error(404, "not found", send_body=send_body)
            return
        body = candidate.read_bytes() if send_body else b""
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(metadata.st_size))
        self.send_header("Cache-Control", "no-store" if candidate.name.endswith((".html", ".js")) else "public, max-age=3600")
        self._send_security_headers()
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _json_error(self, status_code: int, message: str, send_body: bool = True) -> None:
        body = json.dumps({"error": message}, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body) if send_body else 0))
        self._send_security_headers()
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _send_security_headers(self) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)


def main() -> None:
    args = parse_args()
    bind_host = require_loopback_host(args.bind_host, "dashboard bind host")
    if not 1 <= args.port <= 65535:
        raise SystemExit("dashboard port must be between 1 and 65535")
    api_host, api_port = parse_api_origin(args.api_origin)
    root = validate_static_root(args.root)
    token = load_token(args.token_file)
    server = DashboardUiServer((bind_host, args.port), root, api_host, api_port, token)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
