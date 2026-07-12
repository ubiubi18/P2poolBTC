import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HEALTH_SCRIPT = REPO_ROOT / "scripts" / "pohw-health-status.py"

spec = importlib.util.spec_from_file_location("pohw_health_status", HEALTH_SCRIPT)
health = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(health)


class PohwHealthStatusTest(unittest.TestCase):
    def test_probe_idena_rpc_reports_client_version(self) -> None:
        class FakeClient:
            def __init__(self, **_: object) -> None:
                pass

            def call(self, method: str) -> object:
                if method == "bcn_syncing":
                    return {
                        "currentBlock": 100,
                        "highestBlock": 100,
                        "syncing": False,
                        "wrongTime": False,
                    }
                if method == "dna_version":
                    return "1.1.2-modern.4+compat"
                if method == "net_peers":
                    return [{"id": "peer-a"}, {"id": "peer-b"}]
                raise AssertionError(method)

        original = health.IdenaRPCClientMinimal
        health.IdenaRPCClientMinimal = FakeClient
        try:
            parsed = health.probe_idena_rpc(
                "http://127.0.0.1:9009",
                Path("/not/read/by/fake-client"),
                timeout_seconds=1,
            )
        finally:
            health.IdenaRPCClientMinimal = original

        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["clientVersion"], "1.1.2-modern.4+compat")
        self.assertEqual(parsed["peerCount"], 2)

    def test_parse_bitcoin_debug_log_extracts_tip_and_limited_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-health-log-") as temp:
            log = Path(temp) / "debug.log"
            log.write_text(
                "\n".join(
                    [
                        "2026-07-08T05:07:09Z * Using 1526.0 MiB for in-memory UTXO set",
                        "2026-07-08T05:07:24Z Loaded best chain: hashBestChain=00 height=373841 date=2015-09-10T07:44:47Z progress=0.060279",
                        "2026-07-08T05:07:25Z [Chainstate [snapshot] @ height 942007 (00)] resized coinstip cache to 1449.7 MiB",
                        "2026-07-08T05:09:20Z Running node in NODE_NETWORK_LIMITED mode until snapshot background sync completes",
                        "2026-07-08T05:10:00Z UpdateTip: new best=00 height=942008 version=0x1 log2_work=1 tx=1 date='2026-03-24T13:32:31Z' progress=0.964188 cache=128.5MiB(847308txo)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = health.parse_bitcoin_debug_log(log)

        self.assertTrue(parsed["available"])
        self.assertTrue(parsed["nodeNetworkLimited"])
        self.assertEqual(parsed["latestTip"]["height"], 942008)
        self.assertEqual(parsed["inMemoryUtxoCacheMiB"], 1526.0)
        self.assertEqual(parsed["coinstipCacheMiB"]["snapshot"], 1449.7)

    def test_parse_iostat_extracts_second_sample_for_mount_device(self) -> None:
        output = """
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           8.12    0.00    8.48   44.23    0.00   39.17

Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await wareq-sz     d/s     dkB/s   drqm/s  %drqm d_await dareq-sz     f/s f_await  aqu-sz  %util
sda             10.00   1000.00     0.00   0.00    1.00   100.00    5.00    500.00     0.00   0.00    2.00   100.00    0.00      0.00     0.00   0.00    0.00     0.00    1.00    1.00    1.00  20.00

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           3.32    0.00   11.25   60.10    0.00   25.32

Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await wareq-sz     d/s     dkB/s   drqm/s  %drqm d_await dareq-sz     f/s f_await  aqu-sz  %util
sda            157.00  32136.00    54.00  25.59   86.87   204.69   16.00   2220.00    29.00  64.44   74.62   138.75    0.00      0.00     0.00   0.00    0.00     0.00    4.00   60.00   15.07  74.00
"""

        parsed = health.parse_iostat(output, "/dev/sda1")

        self.assertEqual(parsed["cpuIowaitPercent"], 60.10)
        self.assertEqual(parsed["device"], "sda")
        self.assertEqual(parsed["utilPercent"], 74.00)
        self.assertEqual(parsed["readKiBPerSecond"], 32136.00)

    def test_check_mining_ready_accepts_fresh_ready_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-health-ready-") as temp:
            path = Path(temp) / "status.json"
            path.write_text(
                json.dumps(
                    {
                        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                        "readiness": {"miningReady": True, "blockers": []},
                    }
                ),
                encoding="utf-8",
            )

            code = health.check_mining_ready(path, max_age_seconds=60)

        self.assertEqual(code, 0)

    def test_check_mining_ready_rejects_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-health-blocked-") as temp:
            path = Path(temp) / "status.json"
            path.write_text(
                json.dumps(
                    {
                        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                        "readiness": {
                            "miningReady": False,
                            "blockers": ["bitcoin_node_network_limited"],
                        },
                    }
                ),
                encoding="utf-8",
            )

            code = health.check_mining_ready(path, max_age_seconds=60)

        self.assertEqual(code, 1)

    def test_compute_readiness_preserves_inactive_service_state(self) -> None:
        readiness = health.compute_readiness(
            services={
                "bitcoind-mainnet.service": {"active": False, "state": "timeout"},
                "idena.service": {"active": True, "state": "active"},
                "idena-reward-indexer.service": {"active": True, "state": "active"},
            },
            bitcoin_log={"nodeNetworkLimited": False},
            bitcoin_rpc={"ok": True, "initialBlockDownload": False},
            template={"ok": True},
            idena_rpc={"ready": True},
            idena_p2p={"warnings": []},
        )

        self.assertIn("bitcoind-mainnet.service:timeout", readiness["blockers"])

    def test_probe_idena_p2p_warns_on_port_drift_and_low_peers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-p2p-") as temp:
            datadir = Path(temp)
            (datadir / "logs").mkdir()
            (datadir / "config.json").write_text(
                json.dumps({"IpfsConf": {"IpfsPort": 40405}}),
                encoding="utf-8",
            )
            (datadir / "logs" / "output.log").write_text(
                "\n".join(
                    [
                        "INFO [07-09|11:44:56.914] Start changing IPFS port current=40405",
                        "INFO [07-09|11:45:02.529] Finish changing IPFS port new=40409",
                        (
                            "INFO [07-09|12:00:13.047] Start loop round=11012930 "
                            "head=0xabc shardId=1 p2p-shardId=0 total-peers=1  "
                            "own-shard-peers=1  online-nodes=66 network=128"
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = health.probe_idena_p2p(datadir, min_peers=3)

        self.assertEqual(parsed["status"], "warning")
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["configuredIpfsPort"], 40405)
        self.assertEqual(parsed["activeIpfsPort"], 40409)
        self.assertEqual(parsed["latestLoop"]["total_peers"], 1)
        self.assertIn("idena_ipfs_port_drift", parsed["warnings"])
        self.assertIn("idena_low_peer_count", parsed["warnings"])

    def test_probe_idena_p2p_ignores_port_drift_before_latest_restart(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-p2p-restart-") as temp:
            datadir = Path(temp)
            (datadir / "logs").mkdir()
            (datadir / "config.json").write_text(
                json.dumps({"IpfsConf": {"IpfsPort": 40405}}),
                encoding="utf-8",
            )
            (datadir / "logs" / "output.log").write_text(
                "\n".join(
                    [
                        "INFO [07-09|11:45:02.529] Finish changing IPFS port new=40409",
                        "INFO [07-09|12:16:09.347] Idena node is starting version=1.1.2",
                        (
                            "INFO [07-09|12:25:35.279] Start loop round=11013007 "
                            "head=0xabc shardId=1 p2p-shardId=0 total-peers=5 "
                            "own-shard-peers=5 online-nodes=66 network=128"
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = health.probe_idena_p2p(datadir, min_peers=3)

        self.assertEqual(parsed["status"], "ok")
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["configuredIpfsPort"], 40405)
        self.assertEqual(parsed["activeIpfsPort"], 40405)
        self.assertEqual(parsed["latestLoop"]["total_peers"], 5)
        self.assertNotIn("idena_ipfs_port_drift", parsed["warnings"])

    def test_probe_idena_p2p_checks_modern_repo_version(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-repo-version-") as temp:
            datadir = Path(temp)
            (datadir / "ipfs").mkdir()
            (datadir / "logs").mkdir()
            (datadir / "config.json").write_text(
                json.dumps({"IpfsConf": {"IpfsPort": 40405}}),
                encoding="utf-8",
            )
            (datadir / "ipfs" / "version").write_text("12\n", encoding="utf-8")
            (datadir / "logs" / "output.log").write_text("", encoding="utf-8")

            parsed = health.probe_idena_p2p(
                datadir,
                min_peers=0,
                expected_repo_version=18,
            )

        self.assertEqual(parsed["repoVersion"], 12)
        self.assertEqual(parsed["status"], "warning")
        self.assertIn("idena_ipfs_repo_version_mismatch", parsed["warnings"])

    def test_probe_idena_p2p_prefers_current_rpc_peer_count(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-rpc-peers-") as temp:
            datadir = Path(temp)
            (datadir / "logs").mkdir()
            (datadir / "config.json").write_text(
                json.dumps({"IpfsConf": {"IpfsPort": 40405}}),
                encoding="utf-8",
            )
            (datadir / "logs" / "output.log").write_text("", encoding="utf-8")

            parsed = health.probe_idena_p2p(
                datadir,
                min_peers=2,
                peer_count=1,
            )

        self.assertEqual(parsed["peerCount"], 1)
        self.assertIn("idena_low_peer_count", parsed["warnings"])

    def test_summary_lines_include_idena_p2p_warnings(self) -> None:
        lines = health.summary_lines(
            {
                "status": "waiting",
                "readiness": {
                    "miningReady": False,
                    "blockers": ["bitcoin_node_network_limited"],
                    "warnings": ["idena_ipfs_port_drift"],
                },
                "bitcoin": {
                    "debugLog": {
                        "nodeNetworkLimited": True,
                        "latestTip": {"height": 942943, "verificationProgress": 0.965849},
                    },
                    "rpc": {"status": "error"},
                    "getblocktemplate": {"status": "skipped"},
                },
                "idena": {
                    "rpc": {"status": "ok", "ready": True, "currentBlock": 11012930},
                    "p2p": {
                        "status": "warning",
                        "configuredIpfsPort": 40405,
                        "activeIpfsPort": 40409,
                        "latestLoop": {"total_peers": 1},
                    },
                },
            }
        )

        self.assertIn(
            "Idena: status=ok ready=True height=11012930 p2p=warning port=40409(config=40405) peers=1",
            lines,
        )
        self.assertIn("Warnings: idena_ipfs_port_drift", lines)


if __name__ == "__main__":
    unittest.main()
