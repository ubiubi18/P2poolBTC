from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
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

    def do_GET(self) -> None:  # noqa: N802
        type(self).received_token = self.headers.get("X-PoHW-Dashboard-Token")
        body = json.dumps({"source": "live-test"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
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
        self.assertEqual(response.headers["Cache-Control"], "no-store")

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
