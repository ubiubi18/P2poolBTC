import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"


class SystemdLayoutTests(unittest.TestCase):
    def test_cookie_watchers_do_not_pull_services_into_paths_target(self) -> None:
        for name in (
            "pohw-dashboard-api-cookie-watch.path",
            "pohw-dashboard-api-cookie-watch@.path",
        ):
            unit = (SYSTEMD / name).read_text(encoding="utf-8")
            self.assertNotIn("Wants=pohw-dashboard-api.service", unit)
            self.assertNotIn("After=bitcoind-mainnet.service", unit)
            self.assertIn("Unit=pohw-dashboard-api-cookie-watch.service", unit)
            self.assertIn("RequiresMountsFor=", unit)

    def test_dedicated_disk_dropin_replaces_runtime_and_write_paths(self) -> None:
        unit = (SYSTEMD / "bitcoind-mainnet-wd.conf").read_text(encoding="utf-8")
        datadir = "/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet"
        self.assertIn(f"RequiresMountsFor=/mnt/bitcoin-wd", unit)
        self.assertIn(f"WorkingDirectory={datadir}", unit)
        self.assertIn("ExecStartPre=\n", unit)
        self.assertIn("ExecStart=\n", unit)
        self.assertIn("ReadWritePaths=\n", unit)
        self.assertIn(f"-datadir={datadir}", unit)
        self.assertIn("-disablewallet=1", unit)

    def test_dedicated_disk_consumer_dropin_replaces_read_paths(self) -> None:
        unit = (SYSTEMD / "pohw-bitcoin-wd-readonly.conf").read_text(encoding="utf-8")
        self.assertIn("RequiresMountsFor=/mnt/bitcoin-wd", unit)
        self.assertIn("ReadOnlyPaths=\n", unit)
        self.assertIn("/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet", unit)

    def test_fork_chain_service_is_confined_and_restarted(self) -> None:
        unit = (SYSTEMD / "pohw-fork-chain-node.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/opt/p2pool/scripts/pohw-run-fork-chain-node.sh", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertIn("ReadOnlyPaths=/opt/p2pool /etc/pohw", unit)
        self.assertIn("ReadWritePaths=/var/lib/pohw-p2pool", unit)
        self.assertNotIn("bitcoind-mainnet.service", unit)

    def test_mining_adapter_variants_start_after_fork_chain(self) -> None:
        variants = {
            "pohw-mining-adapter.service": (
                "/mnt/ssd/p2pool/scripts/pohw-run-mining-adapter.sh",
                "/mnt/ssd/pohw-p2pool",
            ),
            "pohw-mining-adapter-sdcard.service": (
                "/opt/p2pool/scripts/pohw-run-mining-adapter.sh",
                "/var/lib/pohw-p2pool",
            ),
        }
        for name, (exec_start, write_path) in variants.items():
            unit = (SYSTEMD / name).read_text(encoding="utf-8")
            self.assertIn("After=network-online.target pohw-gossip-mesh.service pohw-fork-chain-node.service", unit)
            self.assertIn(f"ExecStart={exec_start}", unit)
            self.assertIn(f"ReadWritePaths={write_path}", unit)


if __name__ == "__main__":
    unittest.main()
