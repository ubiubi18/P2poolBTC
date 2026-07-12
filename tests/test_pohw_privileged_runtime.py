from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_DIR = REPO_ROOT / "deploy" / "systemd"
INSTALLER = REPO_ROOT / "scripts" / "pohw-install-pi-self-recovery.sh"


class PrivilegedRuntimeTest(unittest.TestCase):
    def test_root_services_execute_only_installed_libexec_helpers(self) -> None:
        expected = {
            "pohw-network-watchdog.service": (
                "ExecStart=/usr/bin/env "
                "POHW_NETWORK_WATCHDOG_STATE_DIR=/var/lib/pohw/network-watchdog "
                "/usr/local/libexec/pohw/pohw-network-watchdog.sh"
            ),
            "pohw-bitcoin-pressure-guard.service": (
                "ExecStart=/usr/bin/env "
                "POHW_BITCOIN_PRESSURE_STATE_DIR=/var/lib/pohw/bitcoin-pressure "
                "/usr/bin/python3 "
                "/usr/local/libexec/pohw/pohw-bitcoin-pressure-guard.py"
            ),
            "pohw-idena-priority-guard.service": (
                "ExecStart=/usr/bin/env "
                "POHW_IDENA_PRIORITY_STATE_DIR=/var/lib/pohw/idena-priority "
                "/usr/bin/python3 "
                "/usr/local/libexec/pohw/pohw-idena-priority-guard.py"
            ),
            "pohw-idena-workers-if-synced.service": (
                "ExecStart=/usr/bin/python3 "
                "/usr/local/libexec/pohw/pohw-idena-workers-if-synced.py"
            ),
        }
        for unit_name, exec_start in expected.items():
            with self.subTest(unit=unit_name):
                unit = (SYSTEMD_DIR / unit_name).read_text(encoding="utf-8")
                self.assertIn(exec_start, unit)
                self.assertNotIn("ExecStart=/mnt/ssd/p2pool", unit)
                self.assertIn("ReadWritePaths=/var/lib/pohw/", unit)

    def test_installer_copies_root_helpers_and_protects_configuration(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        runtime_sources = (
            REPO_ROOT / "scripts" / "pohw-network-watchdog.sh",
            REPO_ROOT / "scripts" / "pohw-bitcoin-pressure-guard.py",
            REPO_ROOT / "scripts" / "pohw-idena-priority-guard.py",
            REPO_ROOT / "scripts" / "pohw-idena-workers-if-synced.py",
            REPO_ROOT / "pohw_idena_rpc" / "__init__.py",
            REPO_ROOT / "pohw_idena_rpc" / "idena_rpc_client_minimal.py",
        )
        for source in runtime_sources:
            with self.subTest(source=source):
                self.assertTrue(source.is_file(), f"missing runtime source: {source}")
                self.assertFalse(source.is_symlink(), f"symlinked runtime source: {source}")
                self.assertIn(source.name, installer)
        for helper in (
            "pohw-network-watchdog.sh",
            "pohw-bitcoin-pressure-guard.py",
            "pohw-idena-priority-guard.py",
            "pohw-idena-workers-if-synced.py",
            "idena_rpc_client_minimal.py",
        ):
            with self.subTest(helper=helper):
                self.assertIn(helper, installer)
        self.assertIn('RUNTIME_DIR="/usr/local/libexec/pohw"', installer)
        self.assertIn('install -d -m 755 -o root -g root "$CONFIG_DIR"', installer)
        self.assertIn('chown root:root "$CONFIG_FILE"', installer)
        self.assertIn('chmod 600 "$CONFIG_FILE"', installer)

    def test_optional_guards_require_explicit_installer_opt_in(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("POHW_INSTALL_ENABLE_IDENA_PRIORITY_GUARD", installer)
        self.assertIn("POHW_INSTALL_ENABLE_BITCOIN_PRESSURE_GUARD", installer)
        self.assertIn("POHW_INSTALL_ENABLE_IDENA_WORKERS_WATCHER", installer)
        self.assertEqual(
            installer.count(
                "systemctl enable --now pohw-network-watchdog.timer "
                "pohw-bitcoin-pressure-guard.timer"
            ),
            0,
        )

        idena_unit = (SYSTEMD_DIR / "pohw-idena-priority-guard.service").read_text(
            encoding="utf-8"
        )
        wants_line = next(line for line in idena_unit.splitlines() if line.startswith("Wants="))
        self.assertNotIn("idena.service", wants_line)

        workers_unit = (SYSTEMD_DIR / "pohw-idena-workers-if-synced.service").read_text(
            encoding="utf-8"
        )
        workers_wants = next(
            (line for line in workers_unit.splitlines() if line.startswith("Wants=")),
            "",
        )
        self.assertNotIn("idena.service", workers_wants)
        self.assertIn("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", workers_unit)
        self.assertIn("AmbientCapabilities=CAP_DAC_READ_SEARCH", workers_unit)
        self.assertNotIn("CAP_DAC_OVERRIDE", workers_unit)


if __name__ == "__main__":
    unittest.main()
