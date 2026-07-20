from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "scripts" / "pohw-dashboard-ui-server.py"
SPEC = importlib.util.spec_from_file_location("pohw_dashboard_ui_server", SERVER_PATH)
assert SPEC is not None and SPEC.loader is not None
SERVER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER_MODULE)


class FakeDashboardApiHandler(BaseHTTPRequestHandler):
    received_token: str | None = None
    received_path: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        type(self).received_token = self.headers.get("X-PoHW-Dashboard-Token")
        type(self).received_path = self.path
        body = json.dumps({"source": "live-test"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class DashboardUiServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pohw-dashboard-proxy-")
        self.root = Path(self.temp.name)
        self.static_root = self.root / "www"
        self.static_root.mkdir()
        (self.static_root / "index.html").write_text(
            "<!doctype html><title>PoHW</title>\n", encoding="utf-8"
        )
        self.upstream = ThreadingHTTPServer(
            ("127.0.0.1", 0), FakeDashboardApiHandler
        )
        self.upstream_thread = threading.Thread(
            target=self.upstream.serve_forever, daemon=True
        )
        self.upstream_thread.start()
        self.server = SERVER_MODULE.DashboardUiServer(
            ("127.0.0.1", 0),
            self.static_root,
            "127.0.0.1",
            self.upstream.server_port,
            "test-dashboard-token",
        )
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.server_thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.server_thread.join(timeout=2)
        self.upstream_thread.join(timeout=2)
        self.temp.cleanup()

    def test_proxies_dashboard_with_server_side_token(self) -> None:
        with urllib.request.urlopen(f"{self.origin}/dashboard.json", timeout=2) as response:
            payload = json.load(response)

        self.assertEqual(payload, {"source": "live-test"})
        self.assertEqual(
            FakeDashboardApiHandler.received_token, "test-dashboard-token"
        )
        self.assertEqual(FakeDashboardApiHandler.received_path, "/dashboard.json")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Content-Type"], "application/json")

    def request_with_headers(self, path: str, headers: dict[str, str]) -> tuple[int, dict]:
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_rejects_dns_rebinding_host_before_proxying(self) -> None:
        FakeDashboardApiHandler.received_token = None

        status, payload = self.request_with_headers(
            "/dashboard.json", {"Host": "attacker.example"}
        )

        self.assertEqual(status, 421)
        self.assertEqual(payload, {"error": "request authority is not local"})
        self.assertIsNone(FakeDashboardApiHandler.received_token)

    def test_accepts_explicit_loopback_authorities(self) -> None:
        for host in (
            f"127.0.0.1:{self.server.server_port}",
            f"localhost:{self.server.server_port}",
        ):
            with self.subTest(host=host):
                status, payload = self.request_with_headers(
                    "/dashboard.json", {"Host": host, "Origin": f"http://{host}"}
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload, {"source": "live-test"})

    def test_rejects_cross_origin_api_fetch_before_proxying(self) -> None:
        FakeDashboardApiHandler.received_token = None
        host = f"127.0.0.1:{self.server.server_port}"

        status, payload = self.request_with_headers(
            "/dashboard.json",
            {
                "Host": host,
                "Origin": "http://attacker.example",
                "Sec-Fetch-Site": "cross-site",
            },
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload, {"error": "cross-origin API request rejected"})
        self.assertIsNone(FakeDashboardApiHandler.received_token)

    def test_rejects_unrecognized_or_unsafe_api_targets_before_proxying(self) -> None:
        host = f"127.0.0.1:{self.server.server_port}"
        for path in (
            "/api/v1/admin",
            "/api/v1/sharechain/shares?unknown=1",
            "/api/v1/sharechain/shares?limit=101",
            "/api/v1/fork/blocks/%2e%2e",
            "/api/v1/bitcoin/heights/-1",
        ):
            with self.subTest(path=path):
                FakeDashboardApiHandler.received_token = None
                FakeDashboardApiHandler.received_path = None
                status, payload = self.request_with_headers(path, {"Host": host})
                self.assertEqual(status, 400)
                self.assertEqual(payload, {"error": "invalid API request"})
                self.assertIsNone(FakeDashboardApiHandler.received_token)
                self.assertIsNone(FakeDashboardApiHandler.received_path)

    def test_canonicalizes_allowed_dynamic_api_target(self) -> None:
        block_hash = "AB" * 32
        path = f"/api/v1/fork/blocks/{block_hash}/transactions?limit=025&cursor=0007"

        status, payload = self.request_with_headers(
            path, {"Host": f"127.0.0.1:{self.server.server_port}"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"source": "live-test"})
        self.assertEqual(
            FakeDashboardApiHandler.received_path,
            f"/api/v1/fork/blocks/{block_hash.lower()}/transactions?cursor=7&limit=25",
        )

    def test_accepts_the_documented_explorer_route_grammar(self) -> None:
        block_hash = "ab" * 32
        address = "bc1q" + "a" * 38
        cases = (
            ("/dashboard.json", "/dashboard.json"),
            ("/api/v1/overview", "/api/v1/overview"),
            ("/api/v1/governance", "/api/v1/governance"),
            ("/api/v1/idena/snapshot", "/api/v1/idena/snapshot"),
            (
                f"/api/v1/fork/blocks?limit=25&cursor={block_hash}",
                f"/api/v1/fork/blocks?cursor={block_hash}&limit=25",
            ),
            (
                f"/api/v1/sharechain/shares?cursor={block_hash}",
                f"/api/v1/sharechain/shares?cursor={block_hash}",
            ),
            (
                "/api/v1/bitcoin/blocks?startHeight=00042",
                "/api/v1/bitcoin/blocks?startHeight=42",
            ),
            ("/api/v1/fork/heights/00042", "/api/v1/fork/heights/42"),
            ("/api/v1/bitcoin/heights/42", "/api/v1/bitcoin/heights/42"),
            (f"/api/v1/fork/blocks/{block_hash}", f"/api/v1/fork/blocks/{block_hash}"),
            (
                f"/api/v1/fork/blocks/{block_hash}/transactions?cursor=2&limit=100",
                f"/api/v1/fork/blocks/{block_hash}/transactions?cursor=2&limit=100",
            ),
            (
                f"/api/v1/fork/transactions/{block_hash}",
                f"/api/v1/fork/transactions/{block_hash}",
            ),
            (f"/api/v1/fork/addresses/{address}", f"/api/v1/fork/addresses/{address}"),
            (
                f"/api/v1/fork/addresses/{address}/transactions?cursor=2&limit=100",
                f"/api/v1/fork/addresses/{address}/transactions?cursor=2&limit=100",
            ),
            (
                f"/api/v1/fork/addresses/{address}/utxos?limit=100",
                f"/api/v1/fork/addresses/{address}/utxos?limit=100",
            ),
            (
                f"/api/v1/bitcoin/blocks/{block_hash}",
                f"/api/v1/bitcoin/blocks/{block_hash}",
            ),
            (
                f"/api/v1/bitcoin/blocks/{block_hash}/transactions?cursor=2",
                f"/api/v1/bitcoin/blocks/{block_hash}/transactions?cursor=2",
            ),
            (
                f"/api/v1/bitcoin/transactions/{block_hash}",
                f"/api/v1/bitcoin/transactions/{block_hash}",
            ),
            (
                f"/api/v1/bitcoin/transactions/{block_hash}/outspends",
                f"/api/v1/bitcoin/transactions/{block_hash}/outspends",
            ),
            (
                f"/api/v1/bitcoin/addresses/{address}",
                f"/api/v1/bitcoin/addresses/{address}",
            ),
            (
                f"/api/v1/bitcoin/addresses/{address}/transactions?cursor={block_hash}",
                f"/api/v1/bitcoin/addresses/{address}/transactions?cursor={block_hash}",
            ),
            (
                f"/api/v1/bitcoin/addresses/{address}/utxos",
                f"/api/v1/bitcoin/addresses/{address}/utxos",
            ),
            (
                f"/api/v1/sharechain/shares/{block_hash}",
                f"/api/v1/sharechain/shares/{block_hash}",
            ),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                parsed = urllib.parse.urlsplit(raw)
                self.assertEqual(
                    SERVER_MODULE.canonical_api_target(parsed.path, parsed.query),
                    expected,
                )

    def test_serves_static_ui_with_restrictive_headers(self) -> None:
        with urllib.request.urlopen(f"{self.origin}/", timeout=2) as response:
            body = response.read().decode("utf-8")

        self.assertIn("<title>PoHW</title>", body)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("connect-src 'self'", response.headers["Content-Security-Policy"])

    def test_rejects_path_escape_and_write_methods(self) -> None:
        for request in (
            urllib.request.Request(f"{self.origin}/%2e%2e/secret"),
            urllib.request.Request(
                f"{self.origin}/dashboard.json", data=b"{}", method="POST"
            ),
        ):
            with self.subTest(url=request.full_url, method=request.get_method()):
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=2)
                self.assertIn(raised.exception.code, {404, 405})

    def test_token_loader_rejects_symlinks(self) -> None:
        target = self.root / "token"
        target.write_text("secret\n", encoding="utf-8")
        link = self.root / "token-link"
        link.symlink_to(target)

        with self.assertRaises(SystemExit):
            SERVER_MODULE.load_token(link)


if __name__ == "__main__":
    unittest.main()
