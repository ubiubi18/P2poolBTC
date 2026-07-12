from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "pohw-idena-workers-if-synced.py"

spec = importlib.util.spec_from_file_location("pohw_idena_workers", SCRIPT)
workers = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(workers)


class IdenaWorkersIfSyncedTest(unittest.TestCase):
    def test_sync_ready_requires_head_and_valid_time(self) -> None:
        self.assertTrue(
            workers.sync_is_ready(
                {
                    "currentBlock": 100,
                    "highestBlock": 100,
                    "syncing": True,
                    "wrongTime": False,
                }
            )
        )
        self.assertFalse(
            workers.sync_is_ready(
                {"currentBlock": 99, "highestBlock": 100, "wrongTime": False}
            )
        )
        self.assertFalse(
            workers.sync_is_ready(
                {"currentBlock": 100, "highestBlock": 100, "wrongTime": True}
            )
        )

    def test_watcher_never_starts_idena_node(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('"start", IDENA_SERVICE', source)
        self.assertIn("WORKER_SERVICES", source)

    def test_script_parses(self) -> None:
        result = subprocess.run(
            ["python3", "-m", "py_compile", str(SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
