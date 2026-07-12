from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
INSTALLER = ROOT / "scripts" / "pohw-install-pi-modern-runtime.sh"


class IdenaModernRuntimeTest(unittest.TestCase):
    def test_sdcard_units_replace_legacy_ssd_paths(self) -> None:
        expected = {
            "idena-modern-sdcard.service": (
                "/usr/local/libexec/idena-node-modern",
                "/var/lib/idena",
            ),
            "idena-reward-indexer-sdcard.service": (
                "/opt/p2pool/pohw_idena_rpc/idena_reward_indexer.py",
                "/var/lib/pohw-p2pool/rewards",
            ),
            "idena-session-recorder-sdcard.service": (
                "/opt/p2pool/pohw_idena_rpc/idena_session_recorder.py",
                "/var/lib/pohw-p2pool/idena-session-recorder",
            ),
            "pohw-idena-snapshot-sdcard.service": (
                "/opt/p2pool/scripts/pohw-snapshot-if-synced.sh",
                "/var/lib/pohw-p2pool/snapshots",
            ),
        }

        for name, required in expected.items():
            with self.subTest(dropin=name):
                unit = (SYSTEMD / name).read_text(encoding="utf-8")
                self.assertNotIn("/mnt/ssd", unit)
                self.assertIn("RequiresMountsFor=", unit)
                self.assertIn("ReadOnlyPaths=", unit)
                for value in required:
                    self.assertIn(value, unit)

        idena_unit = (SYSTEMD / "idena-modern-sdcard.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("Environment=HOME=/var/lib/idena", idena_unit)
        self.assertIn(
            "Environment=XDG_CONFIG_HOME=/var/lib/idena/.config", idena_unit
        )
        self.assertIn("ProtectHome=true", idena_unit)
        self.assertNotIn("/home/", idena_unit)

    def test_sdcard_health_unit_has_no_legacy_mount_dependency(self) -> None:
        unit = (SYSTEMD / "pohw-health-status-sdcard.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("/opt/p2pool/scripts/pohw-health-status.py", unit)
        self.assertIn("--idena-ipfs-repo-version 18", unit)
        self.assertIn(
            "RequiresMountsFor=/opt/p2pool /var/lib/idena /var/lib/pohw-p2pool/health",
            unit,
        )
        self.assertNotIn("RequiresMountsFor=/mnt", unit)
        self.assertNotIn("ReadOnlyPaths=/mnt", unit)

    def test_installer_is_fail_closed_and_does_not_enable_services(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('RUNTIME_DIR="${POHW_RUNTIME_DIR:-/opt/p2pool}"', installer)
        self.assertIn('MODERN_IDENA_BIN="${IDENA_MODERN_BIN:-/usr/local/libexec/idena-node-modern}"', installer)
        self.assertIn('"$(cat "$IDENA_DATADIR/ipfs/version")" != "18"', installer)
        for unit in (
            "idena.service",
            "idena-reward-indexer.service",
            "idena-session-recorder.service",
            "pohw-idena-snapshot.service",
            "pohw-health-status.service",
        ):
            self.assertIn(f"install_full_unit {unit}", installer)
        self.assertIn("pohw-health-status.service.d/50-bitcoin-wd.conf", installer)
        self.assertIn("still depends on a legacy runtime path", installer)
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
