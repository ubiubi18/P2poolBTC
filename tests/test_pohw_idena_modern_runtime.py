from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
INSTALLER = ROOT / "scripts" / "pohw-install-pi-modern-runtime.sh"
HETZNER_INSTALLER = ROOT / "scripts" / "pohw-install-hetzner-idena-runtime.sh"
IPFS_MIGRATION_AUDIT = ROOT / "scripts" / "pohw-audit-ipfs-datastore-migration.sh"


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
        self.assertIn("StartLimitIntervalSec=5min", idena_unit)
        self.assertIn("StartLimitBurst=3", idena_unit)
        self.assertIn("Restart=on-failure", idena_unit)
        self.assertIn("RestartSec=30", idena_unit)

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
        self.assertIn('MODERN_IDENA_PROVENANCE="${IDENA_MODERN_PROVENANCE_FILE:-${MODERN_IDENA_BIN}.source-commit}"', installer)
        self.assertIn("pohw-idena-compatibility-lock.py", installer)
        self.assertIn("--modern-provenance-file", installer)
        self.assertIn('"$(cat "$IDENA_DATADIR/ipfs/version")" != "18"', installer)
        self.assertIn('find "$RUNTIME_DIR" -xdev', installer)
        self.assertIn("-type l -o ! -uid 0 -o -perm /022", installer)
        self.assertIn("rollback_transaction", installer)
        self.assertIn('systemd-analyze verify "${STAGED_UNITS[@]}"', installer)
        self.assertIn('cp -a "$BACKUP_DIR/$unit.d"', installer)
        self.assertIn('cp -a "$target.d" "$persistent_backup.d"', installer)
        self.assertIn("pohw-health-status.service.d/50-bitcoin-wd.conf", installer)
        self.assertIn("has an unsafe non-root, writable, or symlinked drop-in", installer)
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

    def test_hetzner_units_use_separate_locked_down_identities(self) -> None:
        expected = {
            "idena-hetzner-modern.service": (
                "idena-modern",
                "/srv/idena",
                "/etc/idena-modern/config.json",
                "/srv/idena-original-relay",
            ),
            "idena-hetzner-legacy-relay.service": (
                "idena-relay",
                "/srv/idena-original-relay",
                "/etc/idena-relay/config.json",
                "/srv/idena",
            ),
        }

        for name, (user, datadir, config, inaccessible) in expected.items():
            with self.subTest(unit=name):
                unit = (SYSTEMD / name).read_text(encoding="utf-8")
                self.assertIn(f"User={user}", unit)
                self.assertIn(f"Group={user}", unit)
                self.assertIn(f"WorkingDirectory={datadir}", unit)
                self.assertIn(f"--config={config}", unit)
                self.assertIn(f"ReadWritePaths={datadir}", unit)
                self.assertIn(f"InaccessiblePaths={inaccessible}", unit)
                self.assertIn("StartLimitIntervalSec=5min", unit)
                self.assertIn("StartLimitBurst=3", unit)
                self.assertIn("Restart=on-failure", unit)
                self.assertIn("RestartSec=30", unit)
                self.assertIn("ProtectSystem=strict", unit)
                self.assertIn("CapabilityBoundingSet=", unit)

    def test_hetzner_installer_is_transactional_and_parses(self) -> None:
        installer = HETZNER_INSTALLER.read_text(encoding="utf-8")
        self.assertIn("--restart", installer)
        self.assertIn("rollback_transaction", installer)
        self.assertIn('systemd-analyze verify "${STAGED_UNITS[@]}"', installer)
        self.assertIn('runuser -u idena-modern -- test ! -x', installer)
        self.assertIn('runuser -u idena-relay -- test ! -x', installer)
        self.assertIn("PROVENANCE_FILES=(", installer)
        self.assertIn("--legacy-provenance-file", installer)
        self.assertNotIn("\nsystemctl enable", installer)

        result = subprocess.run(
            ["bash", "-n", str(HETZNER_INSTALLER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ipfs_migration_audit_fails_closed_on_unpinned_blocks(self) -> None:
        audit = IPFS_MIGRATION_AUDIT.read_text(encoding="utf-8")
        self.assertIn("unpinned_local_blocks", audit)
        self.assertIn("Pinned-data migration would omit local blocks", audit)
        self.assertIn("exit 2", audit)
        self.assertNotIn("pin ls --type=recursive --quiet\n", audit)

        result = subprocess.run(
            ["bash", "-n", str(IPFS_MIGRATION_AUDIT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
