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
MAX_API_TARGET_BYTES = 2048
MAX_API_QUERY_BYTES = 512
MAX_EXPLORER_CURSOR = 10_000_000
MAX_PAGE_LIMIT = 100
MAX_UINT64 = (1 << 64) - 1
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
ASCII_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
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


def parse_loopback_authority(raw: str, label: str) -> tuple[str, int | None]:
    if not raw or raw != raw.strip() or any(ord(char) < 33 or ord(char) == 127 for char in raw):
        raise ValueError(f"{label} has invalid whitespace or control characters")
    parsed = urlsplit(f"//{raw}")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a loopback authority")
    hostname = parsed.hostname.lower()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError(f"{label} must use localhost or a literal loopback address") from exc
        if not address.is_loopback:
            raise ValueError(f"{label} must use a loopback address")
        hostname = address.compressed
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{label} has an invalid port")
    return hostname, port


def parse_loopback_origin(raw: str) -> tuple[str, int | None]:
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("request Origin must be loopback HTTP")
    return parse_loopback_authority(parsed.netloc, "request Origin")


def parse_api_query(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        encoded = raw.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("API query must be ASCII") from exc
    if len(encoded) > MAX_API_QUERY_BYTES or "%" in raw or "+" in raw:
        raise ValueError("API query is invalid")
    query: dict[str, str] = {}
    for pair in raw.split("&"):
        key, separator, value = pair.partition("=")
        if (
            not separator
            or not key
            or any(ord(char) < 33 or ord(char) == 127 for char in pair)
            or key in query
        ):
            raise ValueError("API query is invalid")
        query[key] = value
    return query


def canonical_hash(raw: str, label: str) -> str:
    if len(raw) != 64 or any(char not in HEX_DIGITS for char in raw):
        raise ValueError(f"{label} must be 32 bytes encoded as hexadecimal")
    return bytes.fromhex(raw).hex()


def canonical_uint(raw: str, label: str, maximum: int) -> str:
    if not raw or not raw.isascii() or not raw.isdecimal():
        raise ValueError(f"{label} must be an unsigned integer")
    value = int(raw, 10)
    if value > maximum:
        raise ValueError(f"{label} exceeds the supported range")
    return str(value)


def canonical_bitcoin_address(raw: str) -> str:
    if not 1 <= len(raw) <= 128 or any(char not in ASCII_ALNUM for char in raw):
        raise ValueError("Bitcoin address has an unsafe representation")
    # Rebuild only from a fixed alphabet. The upstream API performs the full
    # network and checksum validation.
    return "".join(ASCII_ALNUM[ASCII_ALNUM.index(char)] for char in raw)


def canonical_api_query(raw: str, mode: str) -> str:
    query = parse_api_query(raw)
    rendered: list[tuple[str, str]] = []
    if mode == "none":
        allowed: set[str] = set()
    elif mode == "hash-page":
        allowed = {"cursor", "limit"}
        if cursor := query.get("cursor"):
            rendered.append(("cursor", canonical_hash(cursor, "explorer cursor")))
        if "limit" in query:
            limit = canonical_uint(query["limit"], "explorer limit", MAX_PAGE_LIMIT)
            if int(limit) == 0:
                raise ValueError("explorer limit must be positive")
            rendered.append(("limit", limit))
    elif mode == "numeric-page":
        allowed = {"cursor", "limit"}
        if "cursor" in query:
            rendered.append(
                (
                    "cursor",
                    canonical_uint(query["cursor"], "explorer cursor", MAX_EXPLORER_CURSOR),
                )
            )
        if "limit" in query:
            limit = canonical_uint(query["limit"], "explorer limit", MAX_PAGE_LIMIT)
            if int(limit) == 0:
                raise ValueError("explorer limit must be positive")
            rendered.append(("limit", limit))
    elif mode == "hash-cursor":
        allowed = {"cursor"}
        if cursor := query.get("cursor"):
            rendered.append(("cursor", canonical_hash(cursor, "history cursor")))
    elif mode == "numeric-cursor":
        allowed = {"cursor"}
        if "cursor" in query:
            rendered.append(
                (
                    "cursor",
                    canonical_uint(query["cursor"], "history cursor", MAX_EXPLORER_CURSOR),
                )
            )
    elif mode == "start-height":
        allowed = {"startHeight"}
        if "startHeight" in query:
            rendered.append(
                (
                    "startHeight",
                    canonical_uint(query["startHeight"], "start height", MAX_UINT64),
                )
            )
    else:
        raise ValueError("unknown API query policy")
    if set(query) - allowed:
        raise ValueError("unsupported API query parameter")
    return "" if not rendered else "?" + "&".join(f"{key}={value}" for key, value in rendered)


def canonical_api_target(path: str, raw_query: str) -> str:
    try:
        encoded_path = path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("API path must be ASCII") from exc
    if (
        not path.startswith("/")
        or len(encoded_path) > MAX_API_TARGET_BYTES
        or "%" in path
        or "\\" in path
        or any(byte < 33 or byte == 127 for byte in encoded_path)
    ):
        raise ValueError("API path is invalid")
    if path == "/dashboard.json":
        return "/dashboard.json" + canonical_api_query(raw_query, "none")
    if not path.startswith("/api/v1/"):
        raise ValueError("API route is not allowed")

    parts = path.split("/")
    if any(not part for part in parts[1:]):
        raise ValueError("API path contains an empty segment")
    route = tuple(parts[3:])
    target: str
    query_mode = "none"
    if route in {("overview",), ("governance",), ("idena", "snapshot")}:
        target = "/api/v1/" + "/".join(route)
    elif route in {("fork", "blocks"), ("sharechain", "shares")}:
        target = "/api/v1/" + "/".join(route)
        query_mode = "hash-page"
    elif route == ("bitcoin", "blocks"):
        target = "/api/v1/bitcoin/blocks"
        query_mode = "start-height"
    elif len(route) == 3 and route[:2] in {
        ("fork", "heights"),
        ("bitcoin", "heights"),
    }:
        height = canonical_uint(route[2], "block height", MAX_UINT64)
        target = f"/api/v1/{route[0]}/heights/{height}"
    elif len(route) == 3 and route[:2] in {
        ("fork", "blocks"),
        ("fork", "transactions"),
        ("bitcoin", "blocks"),
        ("bitcoin", "transactions"),
        ("sharechain", "shares"),
    }:
        identifier = canonical_hash(route[2], "explorer identifier")
        target = f"/api/v1/{route[0]}/{route[1]}/{identifier}"
    elif (
        len(route) == 4
        and route[:2] == ("fork", "blocks")
        and route[3] == "transactions"
    ):
        identifier = canonical_hash(route[2], "fork block hash")
        target = f"/api/v1/fork/blocks/{identifier}/transactions"
        query_mode = "numeric-page"
    elif (
        len(route) == 4
        and route[:2] == ("bitcoin", "blocks")
        and route[3] == "transactions"
    ):
        identifier = canonical_hash(route[2], "Bitcoin block hash")
        target = f"/api/v1/bitcoin/blocks/{identifier}/transactions"
        query_mode = "numeric-cursor"
    elif (
        len(route) == 4
        and route[:2] == ("bitcoin", "transactions")
        and route[3] == "outspends"
    ):
        identifier = canonical_hash(route[2], "Bitcoin transaction id")
        target = f"/api/v1/bitcoin/transactions/{identifier}/outspends"
    elif len(route) in {3, 4} and route[:2] in {
        ("fork", "addresses"),
        ("bitcoin", "addresses"),
    }:
        address = canonical_bitcoin_address(route[2])
        target = f"/api/v1/{route[0]}/addresses/{address}"
        if len(route) == 4:
            if route[3] not in {"transactions", "utxos"}:
                raise ValueError("address API resource is not allowed")
            target += f"/{route[3]}"
            if route[3] == "transactions":
                query_mode = "numeric-page" if route[0] == "fork" else "hash-cursor"
            elif route[0] == "fork":
                query_mode = "numeric-page"
    else:
        raise ValueError("API route is not allowed")
    return target + canonical_api_query(raw_query, query_mode)


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
        if not self._request_is_local():
            self._json_error(421, "request authority is not local", send_body=send_body)
            return
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            self._json_error(400, "invalid request target", send_body=send_body)
            return
        if parsed.path == "/dashboard.json" or parsed.path.startswith("/api/v1/"):
            if not self._api_fetch_is_same_origin():
                self._json_error(403, "cross-origin API request rejected", send_body=send_body)
                return
            try:
                target = canonical_api_target(parsed.path, parsed.query)
            except ValueError:
                self._json_error(400, "invalid API request", send_body=send_body)
                return
            self._proxy_api(target, send_body)
            return
        self._serve_static(parsed.path, send_body)

    def _request_is_local(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            return False
        try:
            parse_loopback_authority(hosts[0], "request Host")
        except ValueError:
            return False
        return True

    def _api_fetch_is_same_origin(self) -> bool:
        origins = self.headers.get_all("Origin", [])
        if len(origins) > 1:
            return False
        if origins:
            try:
                origin_host, origin_port = parse_loopback_origin(origins[0])
                request_host, request_port = parse_loopback_authority(
                    self.headers["Host"], "request Host"
                )
            except ValueError:
                return False
            if (origin_host, origin_port) != (request_host, request_port):
                return False
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        if len(fetch_sites) > 1:
            return False
        return not fetch_sites or fetch_sites[0].lower() in {"none", "same-origin"}

    def _proxy_api(self, target: str, send_body: bool) -> None:
        connection = http.client.HTTPConnection(
            self.server.api_host,
            self.server.api_port,
            timeout=5,
        )
        try:
            # canonical_api_target has already reduced the browser input to a
            # bounded route grammar before any credential is attached.
            connection.putrequest(
                "GET" if send_body else "HEAD",
                target,
                skip_accept_encoding=True,
            )
            connection.putheader("Accept", "application/json")
            connection.putheader("X-PoHW-Dashboard-Token", self.server.api_token)
            connection.endheaders()
            response = connection.getresponse()
            declared_length = response.getheader("Content-Length")
            if declared_length is not None:
                parsed_length = int(declared_length)
                if not 0 <= parsed_length <= MAX_API_BYTES:
                    raise ValueError("upstream response has an unsafe length")
            body = response.read(MAX_API_BYTES + 1) if send_body else b""
            if len(body) > MAX_API_BYTES:
                raise ValueError("upstream response is too large")
            response_length = len(body) if send_body else int(declared_length or 0)
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
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
