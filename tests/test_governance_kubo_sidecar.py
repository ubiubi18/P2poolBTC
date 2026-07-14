import os
import pathlib
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "governance" / "kubo-sidecar-e2e.sh"


class GovernanceKuboSidecarTests(unittest.TestCase):
    def test_script_is_fail_closed_and_loopback_only(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("ipfs/kubo:v0.42.0", source)
        self.assertIn("--publish 127.0.0.1::5001", source)
        self.assertIn("--publish 127.0.0.1::8080", source)
        self.assertEqual(source.count('start_kubo "$NODE_'), 2)
        self.assertIn("docker info", source)
        self.assertIn("verify --car", source)
        self.assertIn("diff -ru", source)
        self.assertNotIn("$HOME/.ipfs", source)
        self.assertNotIn("--allow-remote-api", source)

    @unittest.skipUnless(
        os.environ.get("POHW_RUN_KUBO_E2E") == "1",
        "set POHW_RUN_KUBO_E2E=1 to run the disposable Docker/Kubo integration",
    )
    def test_disposable_kubo_sidecars(self):
        self.assertIsNotNone(shutil.which("docker"))
        subprocess.run([str(SCRIPT)], cwd=ROOT, check=True, timeout=600)


if __name__ == "__main__":
    unittest.main()
