import datetime as dt
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_SCRIPT = REPO_ROOT / "scripts" / "pohw-snapshot-if-synced.sh"


class SnapshotIfSyncedScriptTest(unittest.TestCase):
    def write_fake_indexer(self, root: Path, height: int = 123) -> Path:
        fake = root / "idena-lite-indexer"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '{{\"idena_height\": {height}}}\\n'\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def write_fake_curl(self, root: Path, response: Optional[str] = None) -> Path:
        fake_bin = root / "bin"
        fake_bin.mkdir(exist_ok=True)
        fake = fake_bin / "curl"
        response = response or '{"result":{"syncing":false,"wrongTime":false}}'
        fake.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s\\n' '{response}'\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake_bin

    def write_api_key(self, root: Path) -> Path:
        key_dir = root / "idena"
        key_dir.mkdir(mode=0o700)
        key_file = key_dir / "api.key"
        key_file.write_text("local-test-key", encoding="utf-8")
        key_file.chmod(0o600)
        return key_file

    def base_env(self, root: Path) -> dict[str, str]:
        env = dict(os.environ)
        fake_bin = self.write_fake_curl(root)
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
                "IDENA_API_KEY_FILE": str(self.write_api_key(root)),
                "IDENA_RPC_URL": "http://127.0.0.1:9009",
                "POHW_IDENA_INDEXER_BIN": str(self.write_fake_indexer(root)),
                "POHW_ALLOW_EMPTY_REWARD_REPLAY": "true",
                "POHW_WORKDIR": str(REPO_ROOT),
                "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
            }
        )
        return env

    def test_treats_stale_syncing_boolean_at_head_as_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-snapshot-stale-sync-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            stale_response = (
                '{"result":{"syncing":true,"wrongTime":false,'
                '"currentBlock":11005935,"highestBlock":11005934}}'
            )
            env["PATH"] = (
                f"{self.write_fake_curl(root, stale_response)}"
                f"{os.pathsep}{os.environ.get('PATH', '')}"
            )

            result = subprocess.run(
                ["bash", str(SNAPSHOT_SCRIPT)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Wrote", result.stdout)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_refuses_symlinked_snapshot_output_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-snapshot-output-symlink-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            real = root / "real-snapshots"
            link = root / "snapshots-link"
            real.mkdir()
            os.symlink(real, link)
            env["POHW_SNAPSHOT_DIR"] = str(link / "nested")

            result = subprocess.run(
                ["bash", str(SNAPSHOT_SCRIPT)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to use symlinked path component", result.stderr)
            self.assertFalse((real / "nested").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_refuses_api_key_under_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-snapshot-api-key-symlink-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            real = root / "real-idena"
            child = real / "child"
            link = root / "idena-link"
            child.mkdir(parents=True)
            os.symlink(real, link)
            key_file = child / "api.key"
            key_file.write_text("local-test-key", encoding="utf-8")
            key_file.chmod(0o600)
            env["IDENA_API_KEY_FILE"] = str(link / "child" / "api.key")

            result = subprocess.run(
                ["bash", str(SNAPSHOT_SCRIPT)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to use symlinked path component", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_refuses_symlinked_reward_ledger_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-snapshot-ledger-symlink-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            real = root / "real-rewards"
            link = root / "rewards-link"
            real.mkdir()
            os.symlink(real, link)
            db_url_file = root / "indexer-db-url"
            db_url_file.write_text("postgres://localhost/idena", encoding="utf-8")
            db_url_file.chmod(0o600)
            env.update(
                {
                    "IDENA_INDEXER_DATABASE_URL_FILE": str(db_url_file),
                    "IDENA_REWARD_LEDGER_DB": str(link / "nested" / "reward.sqlite3"),
                }
            )

            result = subprocess.run(
                ["bash", str(SNAPSHOT_SCRIPT)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to use symlinked path component", result.stderr)
            self.assertFalse((real / "nested").exists())

    def test_existing_snapshot_file_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-snapshot-existing-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            out_dir = Path(env["POHW_SNAPSHOT_DIR"])
            out_dir.mkdir(mode=0o700)
            snapshot_day = dt.datetime.now(dt.timezone.utc).date().isoformat()
            existing = out_dir / f"idena-snapshot-{snapshot_day}-123.json"
            existing.write_text("keep-me", encoding="utf-8")

            result = subprocess.run(
                ["bash", str(SNAPSHOT_SCRIPT)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("leaving existing file unchanged", result.stdout)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep-me")


if __name__ == "__main__":
    unittest.main()
