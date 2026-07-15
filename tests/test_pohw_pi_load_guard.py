import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "pohw-install-pi-load-guard.sh"


class PiLoadGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = INSTALLER.read_text(encoding="utf-8")

    def test_observer_only_units_are_disabled_and_condition_gated(self) -> None:
        for unit in (
            "bitcoind-mainnet.service",
            "bitcoind-pohw-experiment-1.service",
            "pohw-fork-chain-node.service",
            "pohw-gossip-mesh.service",
            "pohw-mining-adapter.service",
        ):
            self.assertIn(unit, self.script)
        self.assertIn('systemctl disable --now "${observer_only_units[@]}"', self.script)
        self.assertIn("pohw-pi-observer-only.conf", self.script)
        self.assertIn("90-pi-observer-only.conf", self.script)

        dropin = (
            ROOT / "deploy" / "systemd" / "pohw-pi-observer-only.conf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "ConditionPathExists=/etc/pohw/enable-pi-local-pohw-runtime", dropin
        )

    def test_all_local_launch_markers_are_removed(self) -> None:
        for marker in (
            "/etc/pohw/enable-local-bitcoin",
            "/etc/pohw/enable-experiment-0-fork",
            "/etc/pohw/enable-experiment-0-mining",
            "/etc/pohw/enable-experiment-1-mining",
            "/etc/pohw/enable-pi-local-pohw-runtime",
        ):
            self.assertIn(marker, self.script)


if __name__ == "__main__":
    unittest.main()
