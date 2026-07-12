from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
INSTALLER = ROOT / "scripts" / "pohw-install-pi-modern-runtime.sh"


class IdenaModernRuntimeTest(unittest.TestCase):
    def test_sdcard_dropins_replace_legacy_ssd_paths(self) -> None:
        expected = {
            "idena-modern-sdcard.conf": (
                "/usr/local/libexec/idena-node-modern",
                "/var/lib/idena",
            ),
            "idena-reward-indexer-sdcard.conf": (
                "/opt/p2pool/pohw_idena_rpc/idena_reward_indexer.py",
                "/var/lib/pohw-p2pool/rewards",
            ),
            "idena-session-recorder-sdcard.conf": (
                "/opt/p2pool/pohw_idena_rpc/idena_session_recorder.py",
                "/var/lib/pohw-p2pool/idena-session-recorder",
            ),
            "pohw-idena-snapshot-sdcard.conf": (
                "/opt/p2pool/scripts/pohw-snapshot-if-synced.sh",
                "/var/lib/pohw-p2pool/snapshots",
            ),
            "pohw-health-status-sdcard.conf": (
                "/opt/p2pool/scripts/pohw-health-status.py",
                "--idena-ipfs-repo-version 18",
            ),
        }

        for name, required in expected.items():
            with self.subTest(dropin=name):
                unit = (SYSTEMD / name).read_text(encoding="utf-8")
                self.assertNotIn("/mnt/ssd", unit)
                self.assertIn("RequiresMountsFor=\n", unit)
                self.assertIn("ReadOnlyPaths=\n", unit)
                for value in required:
                    self.assertIn(value, unit)

    def test_installer_is_fail_closed_and_does_not_enable_services(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('RUNTIME_DIR="${POHW_RUNTIME_DIR:-/opt/p2pool}"', installer)
        self.assertIn('MODERN_IDENA_BIN="${IDENA_MODERN_BIN:-/usr/local/libexec/idena-node-modern}"', installer)
        self.assertIn('"$(cat "$IDENA_DATADIR/ipfs/version")" != "18"', installer)
        self.assertIn("systemd-analyze verify", installer)
        self.assertNotIn("\nsystemctl enable", installer)
        self.assertNotIn("\nsystemctl restart", installer)

    def test_installer_parses(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
