import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "pohw-verify-bitcoin-core-source.sh"
MANIFEST = ROOT / "compatibility" / "experiment-1-full-consensus.json"


class BitcoinCoreSourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.source = Path(self.temp.name) / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.name", "Test Builder"],
            check=True,
        )
        (self.source / "README").write_text("trusted\n", encoding="ascii")
        subprocess.run(["git", "-C", str(self.source), "add", "README"], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "commit", "-q", "-m", "fixture"],
            check=True,
        )
        self.env = os.environ.copy()
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self):
        self.temp.cleanup()

    def run_verifier(self):
        return subprocess.run(
            [
                "bash",
                str(VERIFIER),
                "--source-dir",
                str(self.source),
                "--manifest",
                str(MANIFEST),
            ],
            cwd=ROOT,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_assume_unchanged_hidden_modification_is_rejected(self):
        alternate_index = Path(self.temp.name) / "clean-index"
        shutil.copyfile(self.source / ".git" / "index", alternate_index)
        subprocess.run(
            ["git", "-C", str(self.source), "update-index", "--assume-unchanged", "README"],
            check=True,
        )
        (self.source / "README").write_text("hidden malicious change\n", encoding="ascii")
        self.env["GIT_INDEX_FILE"] = str(alternate_index)
        status = subprocess.check_output(
            ["git", "-C", str(self.source), "status", "--porcelain"], text=True
        )
        self.assertEqual(status, "", "fixture must reproduce the hidden-index bypass")

        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assume-unchanged", result.stderr)

    def test_skip_worktree_entry_is_rejected(self):
        subprocess.run(
            ["git", "-C", str(self.source), "update-index", "--skip-worktree", "README"],
            check=True,
        )
        (self.source / "README").write_text("hidden worktree change\n", encoding="ascii")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("skip-worktree", result.stderr)

    def test_snapshot_does_not_copy_or_trust_the_caller_index(self):
        source = VERIFIER.read_text(encoding="utf-8")
        self.assertNotIn('cp -- "$REAL_INDEX"', source)
        self.assertIn("git init -q --bare", source)
        self.assertIn('read-tree "$UPSTREAM_COMMIT"', source)
        self.assertIn("checkout-index --all --force", source)
        self.assertIn('chmod 0555 "$SNAPSHOT_DIR"', source)
        self.assertIn("published source snapshot differs", source)
        self.assertIn("source snapshot root is writable", (ROOT / "scripts" / "pohw-bitcoin-core-build-evidence.py").read_text(encoding="utf-8"))

    def test_privileged_installer_drops_privileges_and_disables_reuse(self):
        installer = (ROOT / "scripts" / "pohw-install-bitcoin-core-fork.sh").read_text(
            encoding="utf-8"
        )
        builder = (ROOT / "scripts" / "pohw-build-bitcoin-core-fork.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("run_as_build_user", installer)
        self.assertIn("--use-verified-build is intentionally disabled", installer)
        self.assertNotIn('"$INSTALL_ROOT/bin/bitcoind" -version', installer)
        self.assertIn("refusing to configure, build, test, or execute source as root", builder)
        self.assertIn("pohw-depends-prefix.json", installer)
        self.assertIn("pohw-depends-prefix.json", builder)


if __name__ == "__main__":
    unittest.main()
