import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
EXPERIMENT_1_POLICY_PRESTART = (
    "ExecStartPre=/usr/bin/python3 -I "
    "/usr/local/libexec/p2pool-experiment-1/pohw-experiment-1-launch-policy.py "
    "/usr/local/libexec/p2pool-experiment-1/compatibility/"
    "experiment-1-launch-policy.json "
    "--repo-root /usr/local/libexec/p2pool-experiment-1 "
    "--readiness-car /etc/pohw/experiment-1-deployment-readiness.car "
    "--readiness-evidence-car "
    "/etc/pohw/experiment-1-deployment-readiness-evidence.car "
    "--governance-cli /usr/local/libexec/p2pool-experiment-1/pohw-governance "
    "--idena-anchor-policy /etc/pohw/idena-anchor-policy-v2.json "
    "--require-ready"
)
EXPERIMENT_1_LIVE_IDENA_COMMAND = (
    "/usr/local/libexec/p2pool-experiment-1/p2pool-node "
    "verify-idena-registry-deployment "
    "--idena-anchor-policy /etc/pohw/idena-anchor-policy-v2.json "
    "--idena-rpc-url http://127.0.0.1:9009 "
    "--idena-api-key-file /etc/pohw/secrets/idena-api.key"
)


class SystemdLayoutTests(unittest.TestCase):
    def test_experiment_1_launches_require_verified_ready_policy(self) -> None:
        units = (
            ("bitcoind-pohw-experiment-1.service", "ExecStartPre=!"),
            ("pohw-gossip-experiment-1.conf", "ExecStartPre="),
            ("pohw-mining-experiment-1.conf", "ExecStartPre="),
        )
        for name, prefix in units:
            unit = (SYSTEMD / name).read_text(encoding="utf-8")
            self.assertEqual(unit.count(EXPERIMENT_1_POLICY_PRESTART), 1, name)
            self.assertEqual(
                unit.count(prefix + EXPERIMENT_1_LIVE_IDENA_COMMAND), 1, name
            )
            self.assertNotIn("/opt/p2pool/scripts/", unit, name)

        core = (SYSTEMD / "bitcoind-pohw-experiment-1.service").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            core.index(EXPERIMENT_1_POLICY_PRESTART),
            core.index(EXPERIMENT_1_LIVE_IDENA_COMMAND),
        )
        self.assertIn("SupplementaryGroups=bitcoin-pohw bitcoin-chain-read", core)
        self.assertNotIn("SupplementaryGroups=bitcoin-pohw bitcoin-chain-read pohw", core)
        self.assertIn("ExecStartPre=!/usr/local/libexec/p2pool-experiment-1/p2pool-node", core)
        self.assertLess(
            core.index(EXPERIMENT_1_LIVE_IDENA_COMMAND),
            core.index("ExecStart=/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoind"),
        )

    def test_bootstrap_miner_is_bounded_host_only_and_non_persistent(self) -> None:
        service = (SYSTEMD / "pohw-bootstrap-miner.service").read_text(
            encoding="utf-8"
        )
        timer = (SYSTEMD / "pohw-bootstrap-miner.timer").read_text(
            encoding="utf-8"
        )

        self.assertIn("User=pohw", service)
        self.assertIn("SupplementaryGroups=bitcoin-pohw-rpc", service)
        self.assertIn(
            "Requisite=bitcoind-pohw-experiment-1.service pohw-mining-adapter.service",
            service,
        )
        self.assertNotIn(
            "Requires=bitcoind-pohw-experiment-1.service pohw-mining-adapter.service",
            service,
        )
        self.assertIn(
            "ConditionPathExists=/etc/pohw/enable-experiment-1-bootstrap-miner",
            service,
        )
        self.assertIn(
            "ExecStart=/opt/p2pool/scripts/pohw-run-bootstrap-miner.sh", service
        )
        self.assertIn("CPUQuota=5%", service)
        self.assertIn("Nice=19", service)
        self.assertIn("IPAddressDeny=any", service)
        self.assertIn("IPAddressAllow=localhost", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("OnCalendar=*:0/10", timer)
        self.assertNotIn("OnActiveSec=", timer)
        self.assertNotIn("OnUnitActiveSec=", timer)
        self.assertIn("Persistent=false", timer)

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
                "/usr/local/libexec/p2pool-experiment-1/pohw-run-mining-adapter.sh",
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

    def test_experiment_1_units_use_the_installed_evidence_bound_runtime(self) -> None:
        wrappers = {
            "pohw-mining-adapter.service": "pohw-run-mining-adapter.sh",
            "pohw-gossip-mesh.service": "pohw-run-gossip-mesh.sh",
        }
        runtime_dir = "/usr/local/libexec/p2pool-experiment-1"
        for name, wrapper in wrappers.items():
            unit = (SYSTEMD / name).read_text(encoding="utf-8")
            self.assertIn(
                f"Environment=POHW_P2POOL_NODE_BIN={runtime_dir}/p2pool-node",
                unit,
            )
            self.assertIn(f"ExecStart={runtime_dir}/{wrapper}", unit)
            self.assertIn(runtime_dir, unit)
            self.assertNotIn(f"/p2pool/scripts/{wrapper}", unit)
        mining = (SYSTEMD / "pohw-mining-adapter.service").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"Environment=POHW_HEALTH_SCRIPT={runtime_dir}/pohw-health-status.py",
            mining,
        )

    def test_server_dropins_use_dedicated_sharechain_volume(self) -> None:
        for name in (
            "pohw-fork-chain-node-server.conf",
            "pohw-gossip-mesh-server.conf",
            "pohw-mining-adapter-server.conf",
        ):
            unit = (SYSTEMD / name).read_text(encoding="utf-8")
            self.assertIn("User=pohw", unit)
            self.assertIn("Group=pohw", unit)
            self.assertIn("ReadWritePaths=\n", unit)
            self.assertIn("ReadWritePaths=/srv/sharechain", unit)

        gossip = (SYSTEMD / "pohw-gossip-mesh-server.conf").read_text(encoding="utf-8")
        self.assertIn("RequiresMountsFor=\n", gossip)
        self.assertIn("RequiresMountsFor=/srv/sharechain", gossip)
        self.assertIn("WorkingDirectory=/opt/p2pool", gossip)
        self.assertNotIn("pohw-fork-chain-node.service", gossip)

        mining = (SYSTEMD / "pohw-mining-adapter-server.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("RequiresMountsFor=\n", mining)
        self.assertIn("RequiresMountsFor=/srv/sharechain", mining)
        self.assertIn("WorkingDirectory=/opt/p2pool", mining)

        runtime_dir = "/usr/local/libexec/p2pool-experiment-1"
        server_profiles = {
            "pohw-mining-adapter-server.conf": "pohw-run-mining-adapter.sh",
            "pohw-gossip-mesh-server.conf": "pohw-run-gossip-mesh.sh",
        }
        for name, wrapper in server_profiles.items():
            profile = (SYSTEMD / name).read_text(encoding="utf-8")
            self.assertIn(
                f"Environment=POHW_P2POOL_NODE_BIN={runtime_dir}/p2pool-node",
                profile,
            )
            self.assertIn("ExecStart=\n", profile)
            self.assertIn(f"ExecStart={runtime_dir}/{wrapper}", profile)
            self.assertIn("ReadOnlyPaths=\n", profile)
            self.assertIn(
                f"ReadOnlyPaths=/opt/p2pool /etc/pohw {runtime_dir}", profile
            )
            self.assertNotIn(f"/opt/p2pool/scripts/{wrapper}", profile)
        self.assertIn(
            f"Environment=POHW_HEALTH_SCRIPT={runtime_dir}/pohw-health-status.py",
            mining,
        )

    def test_mainnet_handoff_is_root_only_timed_and_overlays_mining_mode(self) -> None:
        service = (SYSTEMD / "pohw-mainnet-handoff.service").read_text(encoding="utf-8")
        timer = (SYSTEMD / "pohw-mainnet-handoff.timer").read_text(encoding="utf-8")
        installer = (ROOT / "scripts" / "pohw-install-mainnet-handoff.sh").read_text(
            encoding="utf-8"
        )
        fork_gate = (SYSTEMD / "pohw-fork-mainnet-handoff.conf").read_text(
            encoding="utf-8"
        )
        overlay = (SYSTEMD / "pohw-mining-mainnet-handoff.conf").read_text(
            encoding="utf-8"
        )

        self.assertIn("User=root", service)
        self.assertIn(
            "ExecStart=/usr/bin/python3 /usr/local/libexec/pohw/pohw-mainnet-handoff.py",
            service,
        )
        self.assertIn(
            "Environment=POHW_P2POOL_NODE_BIN=/usr/local/libexec/pohw/p2pool-node-mainnet-handoff",
            service,
        )
        self.assertIn(
            "Environment=POHW_MAINNET_HANDOFF_STATE_DIR=/var/lib/pohw-p2pool/mainnet-handoff",
            service,
        )
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn(
            "ReadWritePaths=/var/lib/pohw-p2pool -/srv/sharechain /etc/pohw",
            service,
        )
        self.assertIn("OnUnitActiveSec=1min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RUNTIME_DIR=/usr/local/libexec/pohw", installer)
        self.assertIn("p2pool-node-mainnet-handoff", installer)
        self.assertIn("pohw-mainnet-handoff.py", installer)
        self.assertIn(
            "ConditionPathExists=!/var/lib/pohw-p2pool/mainnet-handoff/mainnet-activated.json",
            fork_gate,
        )
        self.assertIn(
            "EnvironmentFile=-/var/lib/pohw-p2pool/mainnet-handoff/mining-mode.env",
            overlay,
        )

        mining = (SYSTEMD / "pohw-mining-adapter-server.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("RequiresMountsFor=\n", mining)
        self.assertIn("RequiresMountsFor=/srv/sharechain", mining)
        self.assertIn("WorkingDirectory=/opt/p2pool", mining)
        self.assertIn("ExecStart=\n", mining)
        self.assertIn(
            "ExecStart=/usr/local/libexec/p2pool-experiment-1/pohw-run-mining-adapter.sh",
            mining,
        )
        self.assertIn(
            "Environment=POHW_P2POOL_NODE_BIN=/usr/local/libexec/p2pool-experiment-1/p2pool-node",
            mining,
        )
        self.assertIn(
            "Environment=POHW_HEALTH_SCRIPT=/usr/local/libexec/p2pool-experiment-1/pohw-health-status.py",
            mining,
        )
        self.assertIn("ReadOnlyPaths=\n", mining)
        self.assertIn(
            "ReadOnlyPaths=/opt/p2pool /etc/pohw /usr/local/libexec/p2pool-experiment-1",
            mining,
        )

    def test_mainnet_handoff_is_root_only_timed_and_overlays_mining_mode(self) -> None:
        service = (SYSTEMD / "pohw-mainnet-handoff.service").read_text(encoding="utf-8")
        timer = (SYSTEMD / "pohw-mainnet-handoff.timer").read_text(encoding="utf-8")
        installer = (ROOT / "scripts" / "pohw-install-mainnet-handoff.sh").read_text(
            encoding="utf-8"
        )
        fork_gate = (SYSTEMD / "pohw-fork-mainnet-handoff.conf").read_text(
            encoding="utf-8"
        )
        overlay = (SYSTEMD / "pohw-mining-mainnet-handoff.conf").read_text(
            encoding="utf-8"
        )

        self.assertIn("User=root", service)
        self.assertIn(
            "ExecStart=/usr/bin/python3 /usr/local/libexec/pohw/pohw-mainnet-handoff.py",
            service,
        )
        self.assertIn(
            "Environment=POHW_P2POOL_NODE_BIN=/usr/local/libexec/pohw/p2pool-node-mainnet-handoff",
            service,
        )
        self.assertIn(
            "Environment=POHW_MAINNET_HANDOFF_STATE_DIR=/var/lib/pohw-p2pool/mainnet-handoff",
            service,
        )
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn(
            "ReadWritePaths=/var/lib/pohw-p2pool -/srv/sharechain /etc/pohw",
            service,
        )
        self.assertIn("OnUnitActiveSec=1min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RUNTIME_DIR=/usr/local/libexec/pohw", installer)
        self.assertIn("p2pool-node-mainnet-handoff", installer)
        self.assertIn("pohw-mainnet-handoff.py", installer)
        self.assertIn(
            "ConditionPathExists=!/var/lib/pohw-p2pool/mainnet-handoff/mainnet-activated.json",
            fork_gate,
        )
        self.assertIn(
            "EnvironmentFile=-/var/lib/pohw-p2pool/mainnet-handoff/mining-mode.env",
            overlay,
        )


if __name__ == "__main__":
    unittest.main()
