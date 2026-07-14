from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "idena-rpc-loopback-proxy.py"
SPEC = importlib.util.spec_from_file_location("idena_rpc_loopback_proxy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROXY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROXY)


class IdenaRpcLoopbackProxyTest(unittest.TestCase):
    def test_origin_matching_returns_only_validated_config_values(self) -> None:
        handler = object.__new__(PROXY.IdenaRpcProxy)
        handler.server = SimpleNamespace(
            config=PROXY.ProxyConfig(
                "http://127.0.0.1:19010/",
                "/unused/api.key",
                {"http://localhost:3030"},
            )
        )
        handler.headers = Message()
        handler.headers.add_header("Origin", "http://localhost:3030")

        self.assertEqual(handler._matched_origin(), "http://localhost:3030")

        handler.headers.add_header("Origin", "http://attacker.example")
        self.assertIsNone(handler._matched_origin())

    def test_json_rpc_batches_are_bounded_and_object_only(self) -> None:
        handler = object.__new__(PROXY.IdenaRpcProxy)
        self.assertEqual(
            handler._with_key({"method": "dna_epoch"}, "test-key"),
            {"method": "dna_epoch", "key": "test-key"},
        )
        for payload in (
            [],
            ["not-an-object"],
            [{"method": "dna_epoch"}] * (PROXY.MAX_BATCH_REQUESTS + 1),
        ):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                handler._with_key(payload, "test-key")

    def test_bind_and_upstream_require_literal_loopback_addresses(self) -> None:
        for value in ("0.0.0.0", "192.0.2.10", "localhost", "example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PROXY.validate_loopback_address(value, "test host")

        self.assertTrue(PROXY.validate_loopback_address("127.0.0.1", "test host").is_loopback)
        self.assertTrue(PROXY.validate_loopback_address("::1", "test host").is_loopback)
        self.assertEqual(
            PROXY.validate_upstream("http://127.0.0.1:19010/"),
            "http://127.0.0.1:19010/",
        )
        for value in (
            "https://127.0.0.1:19010/",
            "http://example.com:19010/",
            "http://localhost:19010/",
            "http://user:secret@127.0.0.1:19010/",
            "http://127.0.0.1:19010/?target=remote",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PROXY.validate_upstream(value)

    def test_allowed_origins_reject_header_injection_and_non_origins(self) -> None:
        self.assertEqual(
            PROXY.validate_origin("http://localhost:3030"),
            "http://localhost:3030",
        )
        for value in (
            "http://localhost:3030/path",
            "http://localhost:3030/",
            "http://user@localhost:3030",
            "http://localhost:3030\r\nX-Injected: true",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PROXY.validate_origin(value)

    def test_api_key_reader_requires_a_small_private_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-rpc-key-") as temp:
            key_file = Path(temp) / "api.key"
            key_file.write_text("test-secret\n", encoding="utf-8")
            if os.name == "posix":
                key_file.chmod(0o600)
            config = PROXY.ProxyConfig(
                "http://127.0.0.1:19010/",
                str(key_file),
                {"http://localhost:3030"},
            )

            self.assertEqual(config.read_key(), "test-secret")

            if os.name == "posix":
                key_file.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "group or others"):
                    config.read_key()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_api_key_reader_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-rpc-key-link-") as temp:
            root = Path(temp)
            key_file = root / "api.key"
            key_file.write_text("test-secret\n", encoding="utf-8")
            if os.name == "posix":
                key_file.chmod(0o600)
            link = root / "api-link.key"
            link.symlink_to(key_file)
            config = PROXY.ProxyConfig(
                "http://127.0.0.1:19010/",
                str(link),
                {"http://localhost:3030"},
            )

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                config.read_key()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_api_key_reader_rejects_unsafe_symlink_ancestors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-rpc-key-parent-") as temp:
            root = Path(temp)
            real_parent = root / "real"
            real_parent.mkdir(mode=0o700)
            key_file = real_parent / "api.key"
            key_file.write_text("test-secret\n", encoding="utf-8")
            if os.name == "posix":
                key_file.chmod(0o600)
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            config = PROXY.ProxyConfig(
                "http://127.0.0.1:19010/",
                str(linked_parent / "api.key"),
                {"http://localhost:3030"},
            )

            with self.assertRaisesRegex(ValueError, "parent must be a real directory"):
                config.read_key()


if __name__ == "__main__":
    unittest.main()
