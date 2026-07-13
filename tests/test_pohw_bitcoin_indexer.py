from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BitcoinHistoryIndexerProfileTest(unittest.TestCase):
    def test_upstream_source_and_dependency_lock_are_pinned(self) -> None:
        lock = json.loads(
            (ROOT / "compatibility" / "explorer-stack-lock.json").read_text(
                encoding="utf-8"
            )
        )["bitcoinHistoryIndexer"]
        self.assertEqual(lock["repository"], "https://github.com/Blockstream/electrs.git")
        self.assertRegex(lock["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(lock["cargoLockSha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            lock["requiredRuntimeFlags"], ["--jsonrpc-import", "--lightmode"]
        )

        build = (ROOT / "scripts" / "pohw-build-bitcoin-indexer.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("cargo build --locked --release", build)
        self.assertIn("sha256sum", build)
        self.assertIn("rev-parse HEAD", build)
        self.assertNotIn("--branch master", build)

    def test_runtime_and_installer_keep_every_listener_on_loopback(self) -> None:
        runtime = (ROOT / "scripts" / "pohw-run-bitcoin-indexer.sh").read_text(
            encoding="utf-8"
        )
        installer = (
            ROOT / "scripts" / "pohw-install-bitcoin-indexer.sh"
        ).read_text(encoding="utf-8")
        env = (ROOT / "deploy" / "pohw-bitcoin-indexer.env.example").read_text(
            encoding="utf-8"
        )
        for port in (8332, 50001, 3002, 4225):
            self.assertIn(f"127.0.0.1:{port}", env)
        self.assertIn("address.is_loopback", runtime)
        self.assertIn("--network mainnet", runtime)
        self.assertIn("--jsonrpc-import", runtime)
        self.assertIn("--lightmode", runtime)
        self.assertNotIn("--blocks-dir", runtime)
        self.assertIn("must stay under /srv/bitcoin", installer)
        self.assertIn("at least 2 TiB free", installer)
        self.assertIn("invalid Bitcoin indexer environment line", installer)
        self.assertIn("rollback_unit", installer)
        self.assertIn('rm -f "/etc/systemd/system/$UNIT"', installer)
        self.assertNotIn('test -r "$BLOCKS_DIR/xor.dat"', installer)
        self.assertNotIn("source \"$ENV_FILE\"", installer)
        self.assertNotIn("--cookie ", runtime)
        self.assertNotIn("PASSWORD=", env.upper())

        for script in (
            ROOT / "scripts" / "pohw-build-bitcoin-indexer.sh",
            ROOT / "scripts" / "pohw-run-bitcoin-indexer.sh",
            ROOT / "scripts" / "pohw-install-bitcoin-indexer.sh",
        ):
            result = subprocess.run(
                ["bash", "-n", str(script)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_service_is_isolated_and_participant_independent(self) -> None:
        unit = (
            ROOT / "deploy" / "systemd" / "pohw-bitcoin-indexer.service"
        ).read_text(encoding="utf-8")
        self.assertIn("User=pohw-bitcoin-index", unit)
        self.assertIn("SupplementaryGroups=bitcoin", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("MemoryDenyWriteExecute=true", unit)
        self.assertIn("CapabilityBoundingSet=", unit)
        self.assertIn("ReadOnlyPaths=/opt/p2pool /etc/pohw /srv/bitcoin/mainnet", unit)
        self.assertIn("ReadWritePaths=/srv/bitcoin/esplora-index", unit)
        self.assertNotIn("0.0.0.0", unit)
        self.assertNotIn("pohw-gossip", unit)
        self.assertNotIn("pohw-mining", unit)


if __name__ == "__main__":
    unittest.main()
