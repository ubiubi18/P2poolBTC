from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "pohw-install-explorer-host.sh"
SYSTEMD = ROOT / "deploy" / "systemd"
CADDY = ROOT / "deploy" / "caddy" / "pohw-explorer.Caddyfile.example"
ENV_EXAMPLE = ROOT / "deploy" / "pohw-explorer-host.env.example"


class ExplorerHostProfileTest(unittest.TestCase):
    def test_installer_is_transactional_and_validates_data_ownership(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("rollback", installer)
        self.assertIn("systemd-analyze verify", installer)
        self.assertIn("validate_loopback_endpoint", installer)
        self.assertIn("validate_bitcoin_index_url", installer)
        self.assertIn("remote HTTPS mode requires explicit opt-in", installer)
        self.assertIn("runuser -u pohw -- test -r", installer)
        self.assertIn("runuser -u pohw -- test -w", installer)
        self.assertIn("chown root:root", installer)
        self.assertIn("chmod 0600", installer)
        self.assertIn("useradd --system --user-group", installer)
        self.assertIn("/usr/sbin/nologin", installer)
        self.assertIn("validate_explorer_environment", installer)
        self.assertIn("explorer environment contains forbidden key", installer)
        self.assertIn("must not be group/world writable", installer)
        self.assertIn("require_root_runtime_directory", installer)
        self.assertIn("POHW_EXPLORER_POHW_CORE_MANIFEST", installer)
        self.assertIn("POHW_EXPLORER_FORK_ADDRESS_INDEX must be true", installer)
        self.assertIn("Fork address-index limits must be positive", installer)
        self.assertIn("POHW_ENABLE_BITCOIN_RPC must be true", installer)
        self.assertIn("http://127.0.0.1:40414", installer)
        self.assertIn("/run/bitcoin-pohw-rpc/.cookie", installer)
        self.assertIn("retired Experiment 0 fork RPC", installer)
        self.assertIn("corepack pnpm@11.11.0", installer)
        self.assertNotIn("corepack pnpm@10.13.1", installer)
        self.assertNotIn('chown -R', installer)

        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_units_separate_consensus_reader_from_static_ui(self) -> None:
        api = (SYSTEMD / "pohw-dashboard-api-host.service").read_text(
            encoding="utf-8"
        )
        ui = (SYSTEMD / "pohw-dashboard-ui-host.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("User=pohw", api)
        self.assertIn("Group=pohw", api)
        self.assertIn("SupplementaryGroups=bitcoin-pohw-rpc", api)
        self.assertIn("bitcoind-pohw-experiment-1.service", api)
        self.assertNotIn("pohw-fork-chain-node.service", api)
        self.assertIn("EnvironmentFile=/etc/pohw/explorer.env", api)
        self.assertIn(
            "LoadCredential=dashboard-api.token:/etc/pohw/dashboard-api.token",
            api,
        )
        self.assertIn("User=pohw-explorer-ui", ui)
        self.assertIn("Group=pohw-explorer-ui", ui)
        self.assertIn("EnvironmentFile=/etc/pohw/explorer.env", ui)
        self.assertNotIn("/etc/pohw/p2pool.env", api + ui)
        for unit in (api, ui):
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn("NoNewPrivileges=true", unit)
            self.assertIn("CapabilityBoundingSet=", unit)
            self.assertIn("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", unit)

    def test_proxy_publishes_only_versioned_explorer_api(self) -> None:
        config = CADDY.read_text(encoding="utf-8")
        self.assertIn("handle /api/v1/*", config)
        self.assertIn("handle /dashboard.json", config)
        self.assertIn("handle /health", config)
        self.assertNotIn("reverse_proxy 0.0.0.0", config)
        self.assertIn("frame-ancestors 'none'", config)

    def test_example_environment_is_loopback_only_and_contains_no_secret(self) -> None:
        config = ENV_EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("POHW_DASHBOARD_BIND_ADDR=127.0.0.1:40407", config)
        self.assertIn(
            "POHW_EXPLORER_POHW_CORE_MANIFEST=/opt/p2pool/compatibility/experiment-1-full-consensus.json",
            config,
        )
        self.assertIn("BITCOIN_RPC_URL=http://127.0.0.1:40414", config)
        self.assertIn("BITCOIN_RPC_COOKIE_FILE=/run/bitcoin-pohw-rpc/.cookie", config)
        self.assertIn("POHW_EXPLORER_FORK_ADDRESS_INDEX=true", config)
        self.assertIn("POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_BLOCKS=60000", config)
        self.assertIn(
            "POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_TRANSACTIONS=500000", config
        )
        self.assertIn("POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_OUTPUTS=2000000", config)
        self.assertIn("POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_ADDRESSES=500000", config)
        self.assertNotIn("POHW_EXPLORER_FORK_CHAIN_RPC_ADDR", config)
        self.assertIn("POHW_EXPLORER_BITCOIN_INDEX_URL=http://127.0.0.1:3002", config)
        self.assertIn("POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX=false", config)
        self.assertIn("POHW_DASHBOARD_UI_BIND_HOST=127.0.0.1", config)
        self.assertIn("POHW_DASHBOARD_UI_PARTICIPANT_ENABLED=false", config)
        self.assertNotIn("PASSWORD=", config.upper())
        self.assertNotIn("PRIVATE_KEY", config.upper())


if __name__ == "__main__":
    unittest.main()
