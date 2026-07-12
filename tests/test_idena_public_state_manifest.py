import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "scripts" / "idena-public-state-manifest.py"
TRANSFER_ID = "0123456789abcdef0123456789abcdef"


class IdenaPublicStateManifestTest(unittest.TestCase):
    def make_transfer(self, root: Path) -> None:
        for component in ("idenachain.db", "ipfs-badgerds", "snapshots"):
            (root / component).mkdir(parents=True)
        (root / "idenachain.db" / "000001.ldb").write_bytes(b"chain")
        (root / "ipfs-badgerds" / "000001.sst").write_bytes(b"ipfs")
        (root / "snapshots" / "snapshot-1").write_bytes(b"snapshot")

    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(TOOL), *args],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def create_manifest(self, root: Path, transfer_id: str = TRANSFER_ID):
        manifest = root / "manifest.json"
        result = self.run_tool(
            "create",
            "--root",
            str(root),
            "--transfer-id",
            transfer_id,
            "--source-height",
            "100",
            "--source-highest",
            "100",
            "--output",
            str(manifest),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return manifest

    def write_ready(
        self, root: Path, transfer_id: str = TRANSFER_ID, source_height: int = 100
    ) -> None:
        (root / "READY").write_text(
            json.dumps(
                {
                    "schema": 2,
                    "sourceHeight": source_height,
                    "transferId": transfer_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

    def validate(self, root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return self.run_tool(
            "validate",
            "--root",
            str(root),
            "--manifest",
            str(root / "manifest.json"),
            *extra,
        )

    def test_create_and_validate_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            manifest = self.create_manifest(root)
            self.write_ready(root)
            validated = self.validate(root, "--print-summary")
            payload = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.assertEqual(validated.stdout.strip(), f"100 {TRANSFER_ID} 17")
        component = payload["components"]["idenachain.db"]
        self.assertEqual(component["bytes"], 5)
        self.assertEqual(component["files"], 1)
        self.assertRegex(component["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(payload["hashAlgorithm"], "sha256-tree-v1")
        self.assertEqual(payload["schema"], 2)

    def test_rejects_invalid_transfer_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-id-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            result = self.run_tool(
                "create",
                "--root",
                str(root),
                "--transfer-id",
                "not-random",
                "--source-height",
                "100",
                "--source-highest",
                "100",
                "--output",
                str(root / "manifest.json"),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("transferId", result.stderr)

    def test_rejects_private_key_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-key-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            (root / "nodekey").write_text("not-a-real-key", encoding="ascii")
            result = self.run_tool(
                "create",
                "--root",
                str(root),
                "--transfer-id",
                TRANSFER_ID,
                "--source-height",
                "100",
                "--source-highest",
                "100",
                "--output",
                str(root / "manifest.json"),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected top-level", result.stderr)

    def test_rejects_symlink_inside_component(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-link-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            (root / "idenachain.db" / "link").symlink_to("/etc/passwd")
            result = self.run_tool(
                "create",
                "--root",
                str(root),
                "--transfer-id",
                TRANSFER_ID,
                "--source-height",
                "100",
                "--source-highest",
                "100",
                "--output",
                str(root / "manifest.json"),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-regular file", result.stderr)

    def test_rejects_hard_link_into_component(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-hardlink-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            secret = root.parent / f"{root.name}-outside-secret"
            secret.write_bytes(b"must-not-transfer")
            try:
                os.link(secret, root / "idenachain.db" / "linked-state")
                result = self.run_tool(
                    "create",
                    "--root",
                    str(root),
                    "--transfer-id",
                    TRANSFER_ID,
                    "--source-height",
                    "100",
                    "--source-highest",
                    "100",
                    "--output",
                    str(root / "manifest.json"),
                )
            finally:
                secret.unlink(missing_ok=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one hard link", result.stderr)

    def test_rejects_symlinked_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-manifest-link-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            manifest = self.create_manifest(root)
            self.write_ready(root)
            with tempfile.NamedTemporaryFile() as target:
                target.write(manifest.read_bytes())
                target.flush()
                manifest.unlink()
                manifest.symlink_to(target.name)
                result = self.validate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest must not be a symlink", result.stderr)

    def test_detects_same_size_content_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-modified-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            self.create_manifest(root)
            self.write_ready(root)
            (root / "idenachain.db" / "000001.ldb").write_bytes(b"CHAIN")
            result = self.validate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("component counters differ", result.stderr)

    def test_rejects_mismatched_ready_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-ready-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            self.create_manifest(root)
            self.write_ready(root, transfer_id="f" * 32)
            result = self.validate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("READY transferId does not match", result.stderr)

    def test_rejects_unexpected_manifest_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="idena-public-state-field-") as temp:
            root = Path(temp)
            self.make_transfer(root)
            manifest = self.create_manifest(root)
            self.write_ready(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["address"] = "must-not-be-present"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            result = self.validate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest fields do not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
