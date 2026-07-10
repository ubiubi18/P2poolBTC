from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TUNNEL = REPO_ROOT / "scripts" / "pohw-dashboard-tunnel.sh"


class DashboardTunnelTest(unittest.TestCase):
    def test_optional_ssh_port_is_forwarded_to_ssh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-tunnel-") as temp:
            root = Path(temp)
            log = root / "ssh.log"
            fake_ssh = root / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$POHW_FAKE_SSH_LOG\"\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o700)
            env = dict(os.environ)
            env.update(
                {
                    "POHW_SSH_BIN": str(fake_ssh),
                    "POHW_FAKE_SSH_LOG": str(log),
                    "POHW_PI_SSH_PORT": "2222",
                }
            )

            result = subprocess.run(
                ["bash", str(TUNNEL), "ubuntu@pibtc"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            args = log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-p", args)
        self.assertIn("2222", args)
        self.assertEqual(args[-1], "ubuntu@pibtc")

    def test_invalid_ssh_port_is_rejected_before_ssh(self) -> None:
        env = dict(os.environ)
        env["POHW_PI_SSH_PORT"] = "70000"
        result = subprocess.run(
            ["bash", str(TUNNEL), "ubuntu@pibtc"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid SSH TCP port", result.stderr)


if __name__ == "__main__":
    unittest.main()
