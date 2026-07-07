#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("pohw-idena-import-ui.py")
SPEC = importlib.util.spec_from_file_location("pohw_idena_import_ui", SCRIPT_PATH)
import_ui = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(import_ui)


class IdenaImportUiValidationTests(unittest.TestCase):
    def tearDown(self):
        import_ui.ACCESS_TOKEN = ""

    def test_rpc_url_must_be_loopback_without_userinfo(self):
        import_ui.validate_loopback_rpc_url("http://127.0.0.1:9009")
        import_ui.validate_loopback_rpc_url("http://localhost:9009")

        for url in [
            "ftp://127.0.0.1:9009",
            "http://user:pass@127.0.0.1:9009",
            "http://198.51.100.10:9009",
            "http://127.0.0.1:9009/?key=leak",
            "http://127.0.0.1:9009/#fragment",
            "http://127.0.0.1:9009/\nX-Bad: yes",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    import_ui.validate_loopback_rpc_url(url)

    def test_api_key_file_must_be_regular_private_and_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.key"
            path.write_text("secret-key\n", encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(import_ui.validate_api_key_file(path), "secret-key")

            path.write_text("bad\nkey", encoding="utf-8")
            with self.assertRaises(ValueError):
                import_ui.validate_api_key_file(path)

            path.write_text("secret-key", encoding="utf-8")
            os.chmod(path, 0o644)
            if os.name == "posix":
                with self.assertRaises(ValueError):
                    import_ui.validate_api_key_file(path)

    def test_api_key_file_must_be_bounded_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.key"
            path.write_bytes(b"a" * (import_ui.MAX_API_KEY_BYTES + 1))
            if os.name == "posix":
                os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                import_ui.validate_api_key_file(path)

            path.write_bytes(b"\xff")
            if os.name == "posix":
                os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                import_ui.validate_api_key_file(path)

    def test_read_api_key_uses_validated_bounded_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.key"
            path.write_text("secret-key\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(path, 0o600)
            original = import_ui.API_KEY_FILE
            try:
                import_ui.API_KEY_FILE = path
                self.assertEqual(import_ui.read_api_key(), "secret-key")
            finally:
                import_ui.API_KEY_FILE = original

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_api_key_parent_must_not_be_group_or_world_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "api.key"
            path.write_text("secret-key\n", encoding="utf-8")
            os.chmod(path, 0o600)
            os.chmod(root, 0o777)
            try:
                with self.assertRaises(ValueError):
                    import_ui.validate_api_key_file(path)
            finally:
                os.chmod(root, 0o700)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_api_key_parent_must_not_be_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            link = root / "link"
            real.mkdir()
            os.symlink(real, link)
            path = link / "api.key"
            path.write_text("secret-key\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                import_ui.validate_api_key_file(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_api_key_path_must_not_have_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            child = real / "child"
            link = root / "link"
            child.mkdir(parents=True)
            os.symlink(real, link)
            path = link / "child" / "api.key"
            path.write_text("secret-key\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                import_ui.validate_api_key_file(path)

    def test_content_length_must_be_single_bounded_integer(self):
        headers = Message()
        headers["Content-Length"] = "12"
        self.assertEqual(import_ui.request_content_length(headers), 12)

        for values in [
            [],
            ["0"],
            ["not-a-number"],
            [str(import_ui.MAX_BODY_BYTES + 1)],
            ["1", "1"],
        ]:
            with self.subTest(values=values):
                bad_headers = Message()
                for value in values:
                    bad_headers["Content-Length"] = value
                with self.assertRaises(ValueError):
                    import_ui.request_content_length(bad_headers)

    def test_request_path_ignores_query_but_not_prefixes(self):
        self.assertEqual(import_ui.request_path("/api/status?x=1"), "/api/status")
        self.assertEqual(import_ui.request_path("/api/status-extra"), "/api/status-extra")
        self.assertTrue(import_ui.request_has_query_token("/?token=secret"))
        self.assertTrue(import_ui.request_has_query_token("/?next=1&TOKEN=secret"))
        self.assertFalse(import_ui.request_has_query_token("/#token=secret"))
        self.assertFalse(import_ui.request_has_query_token("/?next=1"))
        self.assertFalse(import_ui.request_has_query_token("/?mytoken=secret"))

    def test_static_ui_uses_strict_csp_and_safe_dom_rendering(self):
        self.assertNotIn("unsafe-inline", import_ui.HTML_CSP)
        self.assertNotIn(b"<style", import_ui.INDEX_HTML)
        self.assertNotIn(b"<script>", import_ui.INDEX_HTML)
        self.assertIn(b'<link rel="stylesheet" href="/app.css">', import_ui.INDEX_HTML)
        self.assertIn(b'<script src="/app.js" defer></script>', import_ui.INDEX_HTML)
        self.assertNotIn(b"innerHTML", import_ui.APP_JS)
        self.assertNotIn(b"location.search", import_ui.APP_JS)
        self.assertIn(b"textContent", import_ui.APP_JS)

    def test_rpc_response_must_be_bounded_json_object(self):
        self.assertEqual(import_ui.parse_rpc_response(b'{"result":true}'), {"result": True})

        for data in [
            b"[]",
            b"not-json",
            b"\xff",
            b"{" + (b'"x":' + b'"' + b"a" * import_ui.MAX_RPC_RESPONSE_BYTES + b'"}'),
        ]:
            with self.subTest(length=len(data)):
                with self.assertRaises(RuntimeError):
                    import_ui.parse_rpc_response(data)

    def test_import_payload_requires_strings_with_bounds(self):
        key, password = import_ui.parse_import_payload(
            b'{"key":" encrypted-key ","password":"secret"}'
        )
        self.assertEqual(key, "encrypted-key")
        self.assertEqual(password, "secret")

        for body in [
            b"[]",
            b"not-json",
            b'{"key":["not-string"],"password":"secret"}',
            b'{"key":"abc","password":123}',
            b'{"key":"","password":"secret"}',
            b'{"key":"abc","password":""}',
            json_bytes(
                {"key": "a" * (import_ui.MAX_IMPORT_KEY_CHARS + 1), "password": "secret"}
            ),
            json_bytes(
                {"key": "abc", "password": "p" * (import_ui.MAX_IMPORT_PASSWORD_CHARS + 1)}
            ),
            b'{"key":"abc\\n","password":"secret"}',
        ]:
            with self.subTest(body=body[:32]):
                with self.assertRaises(ValueError):
                    import_ui.parse_import_payload(body)

    def test_authorization_rejects_missing_duplicate_or_malformed_token(self):
        import_ui.ACCESS_TOKEN = "a" * import_ui.MIN_ACCESS_TOKEN_CHARS
        self.assertTrue(import_ui.authorized(handler_with_token(import_ui.ACCESS_TOKEN)))
        self.assertFalse(import_ui.authorized(handler_with_token("wrong")))
        self.assertFalse(import_ui.authorized(handler_with_token("bad token")))
        self.assertFalse(
            import_ui.authorized(handler_with_token("a" * (import_ui.MAX_API_KEY_BYTES + 1)))
        )
        self.assertFalse(import_ui.authorized(handler_with_token(None)))
        self.assertFalse(
            import_ui.authorized(handler_with_token(import_ui.ACCESS_TOKEN, duplicate=True))
        )


class DummyHandler:
    def __init__(self, headers):
        self.headers = headers


def handler_with_token(token, duplicate=False):
    headers = Message()
    if token is not None:
        headers["X-Import-Token"] = token
        if duplicate:
            headers["X-Import-Token"] = token
    return DummyHandler(headers)


def json_bytes(value):
    return import_ui.json.dumps(value).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
