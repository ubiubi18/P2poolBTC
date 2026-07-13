import os
import json
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_SCRIPTS = [
    REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
    REPO_ROOT / "scripts" / "pohw-experiment-report.sh",
    REPO_ROOT / "scripts" / "pohw-experiment-register-miner.sh",
    REPO_ROOT / "scripts" / "pohw-experiment-publish-snapshot-vote.sh",
    REPO_ROOT / "scripts" / "pohw-experiment-start-gossip.sh",
    REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
]
INIT_SCRIPT = REPO_ROOT / "scripts" / "pohw-experiment-init.sh"
PACKAGING_SCRIPT = REPO_ROOT / "scripts" / "pohw-experiment-package.sh"
NOTEBOOK_HOST_PATTERN = "Mac" + "Book" + r"[^\s\"']*"


PRIVATE_MACHINE_DATA_RE = re.compile(
    r"\b(?:"
    r"10(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}|"
    r"192\.168(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){2}"
    r")\b|/Users/[A-Za-z0-9._-]+\b|" + NOTEBOOK_HOST_PATTERN,
    re.IGNORECASE,
)


class ExperimentShellEnvValidationTest(unittest.TestCase):
    def run_script(self, script: Path, env_file: Path) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.pop("POHW_EXPERIMENT_ENV", None)
        return subprocess.run(
            ["bash", str(script), str(env_file)],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def write_env(self, path: Path, extra: str = "") -> None:
        path.write_text(
            "POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE\n" + extra,
            encoding="utf-8",
        )
        if os.name == "posix":
            path.chmod(0o600)

    def fake_date_bin(self, root: Path, stamp: str = "20260704T120000Z") -> Path:
        bin_dir = root / "bin"
        bin_dir.mkdir()
        date_bin = bin_dir / "date"
        date_bin.write_text(
            "#!/usr/bin/env bash\n"
            f"if [[ \"$*\" == *'+%Y%m%dT%H%M%SZ'* ]]; then echo {stamp}; "
            "else echo 2026-07-04T12:00:00Z; fi\n",
            encoding="utf-8",
        )
        date_bin.chmod(0o700)
        return bin_dir

    def fake_p2pool_bin(self, root: Path, preflight_padding_bytes: int = 0) -> Path:
        fake = root / "p2pool-node"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "case \"${1:-}\" in\n"
            "  status)\n"
            "    printf '{\"ok\":true,\"datadir\":\"/private/path\"}\\n'\n"
            "    ;;\n"
            "  list-gossip-peers)\n"
            "    printf '[]\\n'\n"
            "    ;;\n"
            "  multinode-preflight)\n"
            "    python3 - <<'PY'\n"
            "import json\n"
            f"padding = 'x' * {preflight_padding_bytes}\n"
            "print(json.dumps({'readiness': {'local_node': True}, 'peer_inventory_probe': [], 'padding': padding}))\n"
            "PY\n"
            "    ;;\n"
            "  fork-chain-status)\n"
            "    printf '{\"activation_id\":\"%s\"}\\n' "
            '"${POHW_FAKE_FORK_ACTIVATION_ID:-0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e}"\n'
            "    ;;\n"
            "  *)\n"
            "    printf '{}\\n'\n"
            "    ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def fake_p2pool_bin_with_network_data(self, root: Path) -> Path:
        fake = root / "p2pool-node-network-data"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "case \"${1:-}\" in\n"
            "  status)\n"
            "    printf '{\"ok\":true,\"datadir\":\"/private/path\"}\\n'\n"
            "    ;;\n"
            "  list-gossip-peers)\n"
            "    printf '[{\"addr\":\"203.0.113.77:40406\",\"source\":\"seed\"}]\\n'\n"
            "    ;;\n"
            "  multinode-preflight)\n"
            "    printf '{\"readiness\":{},\"peer_book\":[{\"addr\":\"203.0.113.77:40406\"}],\"peer_inventory_probe\":[{\"peer_addr\":\"203.0.113.77:40406\",\"reachable\":false,\"error\":\"connect 203.0.113.77:40406 failed\"}]}\\n'\n"
            "    ;;\n"
            "  *)\n"
            "    printf '{}\\n'\n"
            "    ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_experiment_scripts_reject_symlinked_env_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-env-symlink-") as temp:
            root = Path(temp)
            real_env = root / "real.env"
            link_env = root / "link.env"
            self.write_env(real_env)
            os.symlink(real_env, link_env)

            for script in EXPERIMENT_SCRIPTS:
                with self.subTest(script=script.name):
                    result = self.run_script(script, link_env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("symlinked env file", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_experiment_scripts_reject_env_through_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-env-symlink-ancestor-") as temp:
            root = Path(temp)
            real_parent = root / "real"
            real_child = real_parent / "child"
            link_parent = root / "link"
            real_child.mkdir(parents=True)
            os.symlink(real_parent, link_parent)
            env_file = real_child / ".pohw-experiment.env"
            self.write_env(env_file)
            linked_env_file = link_parent / "child" / ".pohw-experiment.env"

            for script in EXPERIMENT_SCRIPTS:
                with self.subTest(script=script.name):
                    result = self.run_script(script, linked_env_file)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("symlinked path component", result.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_experiment_scripts_reject_env_from_writable_parent(self) -> None:
        for script in EXPERIMENT_SCRIPTS:
            with self.subTest(script=script.name):
                with tempfile.TemporaryDirectory(prefix="pohw-env-writable-") as temp:
                    root = Path(temp)
                    env_file = root / ".pohw-experiment.env"
                    self.write_env(env_file)
                    root.chmod(0o777)
                    try:
                        result = self.run_script(script, env_file)
                    finally:
                        root.chmod(0o700)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("group/world-writable directory", result.stderr)

    def test_snapshot_vote_wrapper_fails_cleanly_without_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-empty-snapshot-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            snapshot_dir = root / "snapshots"
            output = root / "output"
            snapshot_dir.mkdir()
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={snapshot_dir}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={output}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-publish-snapshot-vote.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No snapshot JSON found", result.stderr)

    def test_snapshot_vote_skips_oversized_snapshot_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-oversized-snapshot-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            snapshot_dir = root / "snapshots"
            output = root / "output"
            snapshot_dir.mkdir()
            oversized = snapshot_dir / "idena-snapshot-oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={snapshot_dir}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={output}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-publish-snapshot-vote.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No snapshot JSON found", result.stderr)

    def test_preflight_rejects_oversized_preflight_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-oversized-preflight-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            output = root / "output"
            fake_bin = self.fake_p2pool_bin(root, preflight_padding_bytes=16 * 1024 * 1024 + 1)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={output}",
                        f"POHW_P2POOL_NODE_BIN={fake_bin}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preflight report JSON exceeds", result.stderr)

    def test_preflight_rejects_peerless_ordinary_experiment_join(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-preflight-peerless-join-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=join-existing",
                        "POHW_FORK_BOOTSTRAP_FIRST_SEED=false",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires at least one POHW_FORK_PEER_ADDRS entry", result.stderr)

    def test_preflight_allows_explicit_canonical_first_seed_without_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-preflight-first-seed-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            datadir.mkdir()
            manifest = datadir / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            fake_bin = self.fake_p2pool_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_FORK_ACTIVATION_MANIFEST={manifest}",
                        f"POHW_P2POOL_NODE_BIN={fake_bin}",
                        "POHW_EXPERIMENT_NETWORK_MODE=join-existing",
                        "POHW_FORK_BOOTSTRAP_FIRST_SEED=true",
                        "POHW_MINER_ID=coordinator",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
                env_file,
            )
            reports = list((root / "output").glob("experiment-preflight-*"))
            fork_peer_status = json.loads(
                (reports[0] / "fork-peer-preflight.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(reports), 1)
        self.assertTrue(fork_peer_status["bootstrap_first_seed"])
        self.assertEqual(fork_peer_status["configured_peer_count"], 0)
        self.assertEqual(fork_peer_status["activation_matching_reachable_peer_count"], 0)

    def test_preflight_requires_activation_matching_reachable_fork_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-preflight-fork-peer-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            datadir.mkdir()
            manifest = datadir / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            fake_bin = self.fake_p2pool_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_FORK_ACTIVATION_MANIFEST={manifest}",
                        f"POHW_P2POOL_NODE_BIN={fake_bin}",
                        "POHW_EXPERIMENT_NETWORK_MODE=join-existing",
                        "POHW_FORK_BOOTSTRAP_FIRST_SEED=false",
                        "POHW_FORK_PEER_ADDRS=127.0.0.1:40409",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )

            accepted = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
                env_file,
            )
            accepted_report = next((root / "output").glob("experiment-preflight-*"))
            fork_peer_status = json.loads(
                (accepted_report / "fork-peer-preflight.json").read_text(encoding="utf-8")
            )

            rejected_env_file = root / ".pohw-rejected.env"
            rejected_env_file.write_text(
                env_file.read_text(encoding="utf-8").replace(
                    f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                    f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'rejected-output'}",
                ),
                encoding="utf-8",
            )
            rejected_env_file.chmod(0o600)
            rejected_env = dict(os.environ)
            rejected_env["POHW_FAKE_FORK_ACTIVATION_ID"] = "11" * 32
            rejected_env["POHW_EXPERIMENT_ENV"] = str(rejected_env_file)
            rejected = subprocess.run(
                ["bash", str(REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh")],
                cwd=REPO_ROOT,
                env=rejected_env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(fork_peer_status["configured_peer_count"], 1)
        self.assertEqual(fork_peer_status["activation_matching_reachable_peer_count"], 1)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("could not verify any configured fork peer", rejected.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_preflight_refuses_symlinked_fork_activation_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-preflight-manifest-link-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            manifest = root / "fork-activation-real.json"
            link = root / "fork-activation-link.json"
            manifest.write_text("{}", encoding="utf-8")
            os.symlink(manifest, link)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_FORK_ACTIVATION_MANIFEST={link}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing symlinked fork activation manifest", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_report_refuses_fork_activation_manifest_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-manifest-ancestor-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            real_parent = root / "real-manifests"
            link_parent = root / "manifest-link"
            existing_child = real_parent / "existing"
            existing_child.mkdir(parents=True)
            manifest = existing_child / "fork-activation.json"
            manifest.write_text("{}", encoding="utf-8")
            os.symlink(real_parent, link_parent)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_FORK_ACTIVATION_MANIFEST={link_parent / 'existing' / 'fork-activation.json'}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-report.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to write through symlinked path component", result.stderr)

    def test_report_refuses_non_regular_fork_activation_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-manifest-directory-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            manifest_dir = root / "fork-activation.json"
            manifest_dir.mkdir()
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_FORK_ACTIVATION_MANIFEST={manifest_dir}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-report.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Fork activation manifest must be a regular file", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_report_refuses_symlinked_gossip_envelope_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-gossip-log-link-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            datadir.mkdir()
            target = root / "real-gossip.ndjson"
            target.write_text("{}\n", encoding="utf-8")
            os.symlink(target, datadir / "gossip-envelopes.ndjson")
            fake_bin = self.fake_p2pool_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_P2POOL_NODE_BIN={fake_bin}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-report.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing symlinked gossip envelope log", result.stderr)

    def test_report_refuses_oversized_gossip_envelope_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-gossip-log-large-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            datadir.mkdir()
            (datadir / "gossip-envelopes.ndjson").write_text(
                '{"message":{"type":"MinerRegistration","payload":{"miner_id":"alice"}}}\n',
                encoding="utf-8",
            )
            fake_bin = self.fake_p2pool_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        f"POHW_P2POOL_NODE_BIN={fake_bin}",
                        "POHW_MINER_ID=alice",
                        "POHW_MAX_GOSSIP_LOG_EXPORT_BYTES=16",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-report.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Gossip envelope log is too large", result.stderr)

    def test_prepare_fork_activation_refuses_default_join_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-join-guard-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            manifest = root / "fork-activation.json"
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        "POHW_EXPERIMENT_NETWORK_MODE=join-existing",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-13T00:52:48Z",
                        f"POHW_FORK_ACTIVATION_MANIFEST={manifest}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to derive a fork activation manifest", result.stderr)
        self.assertFalse(manifest.exists())

    def test_prepare_fork_activation_requires_launch_timestamp(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-missing-launch-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Launch timestamp is required", result.stderr)

    def test_prepare_fork_activation_forwards_handoff_hashrate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-handoff-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            args_out = root / "args.txt"
            manifest = root / "state" / "fork-activation.json"
            fake_bin = root / "p2pool-node"
            fake_bin.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f"printf '%s\\n' \"$@\" > {args_out!s}\n"
                "while (( $# )); do\n"
                "  if [[ \"$1\" == --manifest-out ]]; then\n"
                "    mkdir -p \"$(dirname \"$2\")\"\n"
                "    printf '{}\\n' > \"$2\"\n"
                "    break\n"
                "  fi\n"
                "  shift\n"
                "done\n"
                "printf '{}\\n'\n",
                encoding="utf-8",
            )
            fake_bin.chmod(0o700)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z",
                        f"POHW_FORK_ACTIVATION_MANIFEST={manifest}",
                        "POHW_FORK_BOOTSTRAP_HANDOFF_HASHRATE_HPS=123456789",
                        f"POHW_P2POOL_NODE_BIN={fake_bin}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )
            args = args_out.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        threshold_index = args.index("--bootstrap-handoff-hashrate-hps")
        self.assertEqual(args[threshold_index + 1], "123456789")

    def test_prepare_fork_activation_refuses_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-existing-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            manifest = root / "fork-activation.json"
            manifest.write_text("{}", encoding="utf-8")
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z",
                        f"POHW_FORK_ACTIVATION_MANIFEST={manifest}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to overwrite existing activation manifest", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_prepare_fork_activation_refuses_symlinked_manifest_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-symlink-parent-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            real_parent = root / "real-manifests"
            link_parent = root / "manifest-link"
            real_parent.mkdir()
            os.symlink(real_parent, link_parent)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z",
                        f"POHW_FORK_ACTIVATION_MANIFEST={link_parent / 'fork-activation.json'}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to write activation manifest under symlinked directory", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_prepare_fork_activation_refuses_symlinked_manifest_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-symlink-ancestor-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            real_parent = root / "real-manifests"
            link_parent = root / "manifest-link"
            real_parent.mkdir()
            os.symlink(real_parent, link_parent)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z",
                        f"POHW_FORK_ACTIVATION_MANIFEST={link_parent / 'nested' / 'fork-activation.json'}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to write through symlinked path component", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_prepare_fork_activation_refuses_existing_symlinked_manifest_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-existing-symlink-ancestor-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            real_parent = root / "real-manifests"
            link_parent = root / "manifest-link"
            existing_child = real_parent / "existing"
            existing_child.mkdir(parents=True)
            os.symlink(real_parent, link_parent)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z",
                        f"POHW_FORK_ACTIVATION_MANIFEST={link_parent / 'existing' / 'fork-activation.json'}",
                        "",
                    ]
                ),
            )

            result = self.run_script(
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
                env_file,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to write through symlinked path component", result.stderr)
        self.assertFalse((existing_child / "fork-activation.json").exists())

    def test_init_defaults_to_existing_experiment_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-existing-network-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                    "--datadir",
                    str(datadir),
                    "--snapshot-dir",
                    str(root / "snapshots"),
                    "--output-root",
                    str(root / "output"),
                    "--fork-peer-addrs",
                    "127.0.0.1:40409",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            manifest = datadir / "fork-activation.json"
            env_text = env_file.read_text(encoding="utf-8")
            canonical = REPO_ROOT / "compatibility" / "experiment-0-activation.json"
            manifest_bytes = manifest.read_bytes()
            canonical_bytes = canonical.read_bytes()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("POHW_EXPERIMENT_NETWORK_MODE=join-existing", env_text)
        self.assertIn("POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-13T00:52:48Z", env_text)
        self.assertIn("POHW_FORK_PEER_ADDRS=127.0.0.1:40409", env_text)
        self.assertIn("POHW_FORK_BOOTSTRAP_FIRST_SEED=false", env_text)
        self.assertEqual(manifest_bytes, canonical_bytes)

    def test_init_allows_explicit_canonical_first_seed_without_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-first-seed-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "coordinator",
                    "--workdir",
                    str(REPO_ROOT),
                    "--datadir",
                    str(datadir),
                    "--snapshot-dir",
                    str(root / "snapshots"),
                    "--output-root",
                    str(root / "output"),
                    "--bootstrap-first-seed",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            env_text = env_file.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("POHW_EXPERIMENT_NETWORK_MODE=join-existing", env_text)
        self.assertIn("POHW_FORK_BOOTSTRAP_FIRST_SEED=true", env_text)
        self.assertIn("POHW_FORK_PEER_ADDRS=", env_text)

    def test_init_rejects_first_seed_exception_with_existing_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-first-seed-peer-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "coordinator",
                    "--workdir",
                    str(REPO_ROOT),
                    "--bootstrap-first-seed",
                    "--fork-peer-addrs",
                    "127.0.0.1:40409",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "--bootstrap-first-seed cannot be combined with --fork-peer-addrs",
            result.stderr,
        )
        self.assertFalse(env_file.exists())

    def test_init_separate_experiment_rejects_existing_fork_peers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-separate-peers-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--separate-experiment",
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                    "--fork-peer-addrs",
                    "127.0.0.1:40409",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "--fork-peer-addrs cannot be used while creating a separate experiment",
            result.stderr,
        )
        self.assertFalse(env_file.exists())

    def test_init_requires_explicit_mode_for_separate_experiment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-separate-network-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--separate-experiment",
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                    "--datadir",
                    str(datadir),
                    "--snapshot-dir",
                    str(root / "snapshots"),
                    "--output-root",
                    str(root / "output"),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            env_text = env_file.read_text(encoding="utf-8")
            manifest_exists = (datadir / "fork-activation.json").exists()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("POHW_EXPERIMENT_NETWORK_MODE=create-separate", env_text)
        self.assertFalse(manifest_exists)

    def test_init_join_mode_refuses_different_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-network-mismatch-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            datadir.mkdir()
            manifest = datadir / "fork-activation.json"
            manifest.write_text('{"activation_id":"different-network"}\n', encoding="utf-8")

            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                    "--datadir",
                    str(datadir),
                    "--snapshot-dir",
                    str(root / "snapshots"),
                    "--output-root",
                    str(root / "output"),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            manifest_text = manifest.read_text(encoding="utf-8")
            env_exists = env_file.exists()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different fork activation manifest", result.stderr)
        self.assertEqual(manifest_text, '{"activation_id":"different-network"}\n')
        self.assertFalse(env_exists)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_init_rejects_writable_env_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-writable-parent-") as temp:
            root = Path(temp)
            parent = root / "shared"
            parent.mkdir()
            parent.chmod(0o777)
            env_file = parent / ".pohw-experiment.env"
            try:
                result = subprocess.run(
                    [
                        "bash",
                        str(INIT_SCRIPT),
                        "--env-file",
                        str(env_file),
                        "--miner-id",
                        "alice",
                        "--workdir",
                        str(REPO_ROOT),
                    ],
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
            finally:
                parent.chmod(0o700)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("group/world-writable directory", result.stderr)
            self.assertFalse(env_file.exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_init_rejects_symlinked_env_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-symlink-parent-") as temp:
            root = Path(temp)
            real = root / "real"
            link = root / "link"
            real.mkdir()
            os.symlink(real, link)
            env_file = link / ".pohw-experiment.env"

            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlinked directory", result.stderr)
            self.assertFalse((real / ".pohw-experiment.env").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_init_rejects_symlinked_env_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-symlink-ancestor-") as temp:
            root = Path(temp)
            real = root / "real"
            link = root / "link"
            real.mkdir()
            os.symlink(real, link)
            env_file = link / "nested" / ".pohw-experiment.env"

            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to write through symlinked path component", result.stderr)
            self.assertFalse((real / "nested" / ".pohw-experiment.env").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_init_rejects_existing_symlinked_env_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-existing-symlink-ancestor-") as temp:
            root = Path(temp)
            real = root / "real"
            link = root / "link"
            existing_child = real / "existing"
            existing_child.mkdir(parents=True)
            os.symlink(real, link)
            env_file = link / "existing" / ".pohw-experiment.env"

            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to write through symlinked path component", result.stderr)
            self.assertFalse((existing_child / ".pohw-experiment.env").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_init_rejects_symlinked_datadir_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-init-datadir-symlink-ancestor-") as temp:
            root = Path(temp)
            real = root / "real-datadir"
            link = root / "datadir-link"
            real.mkdir()
            os.symlink(real, link)
            env_file = root / ".pohw-experiment.env"

            result = subprocess.run(
                [
                    "bash",
                    str(INIT_SCRIPT),
                    "--env-file",
                    str(env_file),
                    "--miner-id",
                    "alice",
                    "--workdir",
                    str(REPO_ROOT),
                    "--datadir",
                    str(link / "nested"),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to write through symlinked path component", result.stderr)
            self.assertFalse((real / "nested").exists())

    def test_register_miner_refuses_existing_output_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-existing-output-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            output_dir = root / "registration-output"
            output_dir.mkdir()
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        "POHW_MINER_ID=alice",
                        "POHW_IDENA_ADDRESS=0x1111111111111111111111111111111111111111",
                        "",
                    ]
                ),
            )

            result = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-register-miner.sh"),
                    str(env_file),
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to reuse existing output directory", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_wrappers_refuse_symlinked_output_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-output-parent-symlink-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            key_dir = datadir / "keys" / "alice"
            key_dir.mkdir(parents=True)
            (key_dir / "mining.key").write_text("", encoding="utf-8")
            (key_dir / "gossip-node.key").write_text("", encoding="utf-8")
            snapshot_file = root / "snapshot.json"
            snapshot_file.write_text("{}", encoding="utf-8")
            real_output = root / "real-output"
            link_output = root / "output-link"
            nested_output = link_output / "nested"
            real_output.mkdir()
            os.symlink(real_output, link_output)
            fake_bin = self.fake_date_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={nested_output}",
                        "POHW_MINER_ID=alice",
                        "POHW_IDENA_ADDRESS=0x1111111111111111111111111111111111111111",
                        "",
                    ]
                ),
            )
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"

            commands = [
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh"),
                    str(env_file),
                ],
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-report.sh"),
                    str(env_file),
                ],
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-register-miner.sh"),
                    str(env_file),
                    "--output-dir",
                    str(nested_output / "registration-output"),
                ],
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-publish-snapshot-vote.sh"),
                    str(env_file),
                    "--snapshot-file",
                    str(snapshot_file),
                    "--output-dir",
                    str(nested_output / "snapshot-vote-output"),
                ],
            ]
            for command in commands:
                with self.subTest(script=Path(command[1]).name):
                    result = subprocess.run(
                        command,
                        cwd=REPO_ROOT,
                        env=env,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Refusing to write through symlinked path component", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_wrappers_refuse_existing_symlinked_output_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-existing-output-ancestor-symlink-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            key_dir = datadir / "keys" / "alice"
            key_dir.mkdir(parents=True)
            (key_dir / "mining.key").write_text("", encoding="utf-8")
            (key_dir / "gossip-node.key").write_text("", encoding="utf-8")
            snapshot_file = root / "snapshot.json"
            snapshot_file.write_text("{}", encoding="utf-8")
            real_output = root / "real-output"
            link_output = root / "output-link"
            existing_output = link_output / "existing"
            (real_output / "existing").mkdir(parents=True)
            os.symlink(real_output, link_output)
            fake_bin = self.fake_date_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={existing_output}",
                        "POHW_MINER_ID=alice",
                        "POHW_IDENA_ADDRESS=0x1111111111111111111111111111111111111111",
                        "",
                    ]
                ),
            )
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"

            commands = [
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh"),
                    str(env_file),
                ],
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-report.sh"),
                    str(env_file),
                ],
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-register-miner.sh"),
                    str(env_file),
                    "--output-dir",
                    str(existing_output / "registration-output"),
                ],
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-publish-snapshot-vote.sh"),
                    str(env_file),
                    "--snapshot-file",
                    str(snapshot_file),
                    "--output-dir",
                    str(existing_output / "snapshot-vote-output"),
                ],
            ]
            for command in commands:
                with self.subTest(script=Path(command[1]).name):
                    result = subprocess.run(
                        command,
                        cwd=REPO_ROOT,
                        env=env,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Refusing to write through symlinked path component", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_wrappers_refuse_symlinked_datadir_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-datadir-ancestor-symlink-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            real_datadir = root / "real-datadir"
            link_datadir = root / "datadir-link"
            datadir = link_datadir / "nested"
            real_datadir.mkdir()
            os.symlink(real_datadir, link_datadir)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        "POHW_EXPERIMENT_NETWORK_MODE=create-separate",
                        "POHW_MINER_ID=alice",
                        "POHW_IDENA_ADDRESS=0x1111111111111111111111111111111111111111",
                        "POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z",
                        "",
                    ]
                ),
            )

            scripts = [
                REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh",
                REPO_ROOT / "scripts" / "pohw-experiment-register-miner.sh",
                REPO_ROOT / "scripts" / "pohw-experiment-start-gossip.sh",
                REPO_ROOT / "scripts" / "pohw-experiment-prepare-fork-activation.sh",
            ]
            for script in scripts:
                with self.subTest(script=script.name):
                    result = self.run_script(script, env_file)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Refusing to write through symlinked path component", result.stderr)

            self.assertFalse((real_datadir / "nested").exists())

    def test_preflight_refuses_existing_timestamp_output_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-existing-preflight-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            output_root = root / "output"
            (output_root / "experiment-preflight-20260704T120000Z").mkdir(parents=True)
            fake_bin = self.fake_date_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={output_root}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"

            result = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-preflight.sh"),
                    str(env_file),
                ],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to reuse existing output directory", result.stderr)

    def test_report_refuses_existing_timestamp_output_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-existing-report-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            output_root = root / "output"
            (output_root / "experiment-report-20260704T120000Z").mkdir(parents=True)
            fake_bin = self.fake_date_bin(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={output_root}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"

            result = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-report.sh"),
                    str(env_file),
                ],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to reuse existing output directory", result.stderr)

    def test_shareable_report_redacts_network_endpoints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-network-redaction-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            output_root = root / "output"
            fake_date_dir = self.fake_date_bin(root)
            fake_p2pool = self.fake_p2pool_bin_with_network_data(root)
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={root / 'datadir'}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={output_root}",
                        f"POHW_P2POOL_NODE_BIN={fake_p2pool}",
                        "POHW_MINER_ID=alice",
                        "POHW_GOSSIP_BIND_ADDR=203.0.113.77:40406",
                        "POHW_ADVERTISE_ADDR=203.0.113.77:40406",
                        "POHW_PEER_ADDRS=203.0.113.77:40406",
                        "",
                    ]
                ),
            )
            env = dict(os.environ)
            env["PATH"] = f"{fake_date_dir}{os.pathsep}{env.get('PATH', '')}"

            result = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-report.sh"),
                    str(env_file),
                ],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = output_root / "experiment-report-20260704T120000Z"
            self.assertEqual(report.stat().st_mode & 0o077, 0)
            published_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in report.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("203.0.113.77", published_text)
            self.assertIn("gossip_peer_count=1", published_text)
            self.assertIn('"peer_addr": "<redacted>"', published_text)

    def test_snapshot_vote_refuses_existing_output_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-existing-snapshot-vote-") as temp:
            root = Path(temp)
            env_file = root / ".pohw-experiment.env"
            datadir = root / "datadir"
            key_dir = datadir / "keys" / "alice"
            key_dir.mkdir(parents=True)
            (key_dir / "mining.key").write_text("", encoding="utf-8")
            (key_dir / "gossip-node.key").write_text("", encoding="utf-8")
            snapshot_file = root / "snapshot.json"
            snapshot_file.write_text("{}", encoding="utf-8")
            output_dir = root / "snapshot-vote-output"
            output_dir.mkdir()
            self.write_env(
                env_file,
                "\n".join(
                    [
                        f"POHW_WORKDIR={REPO_ROOT}",
                        f"POHW_DATADIR={datadir}",
                        f"POHW_SNAPSHOT_DIR={root / 'snapshots'}",
                        f"POHW_EXPERIMENT_OUTPUT_ROOT={root / 'output'}",
                        "POHW_MINER_ID=alice",
                        "",
                    ]
                ),
            )

            result = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "pohw-experiment-publish-snapshot-vote.sh"),
                    str(env_file),
                    "--snapshot-file",
                    str(snapshot_file),
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to reuse existing output directory", result.stderr)

    def test_experiment_package_contains_public_reproducible_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-package-") as temp:
            output_root = Path(temp) / "packages"
            result = subprocess.run(
                [
                    "bash",
                    str(PACKAGING_SCRIPT),
                    "--output-root",
                    str(output_root),
                    "--package-name",
                    "experiment0-test",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            archive = output_root / "experiment0-test.tar.gz"
            archive_sha = output_root / "experiment0-test.tar.gz.sha256"
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(archive.is_file())
            self.assertTrue(archive_sha.is_file())

            with tarfile.open(archive, "r:gz") as handle:
                members = handle.getmembers()
                names = sorted(member.name for member in members)
                machine_data_hits = []
                for member in members:
                    self.assertFalse(
                        member.issym() or member.islnk(),
                        f"package must not contain link entries: {member.name}",
                    )
                    if member.isfile():
                        extracted = handle.extractfile(member)
                        if extracted is not None:
                            text = extracted.read().decode("utf-8", errors="ignore")
                            if match := PRIVATE_MACHINE_DATA_RE.search(text):
                                machine_data_hits.append(f"{member.name}: {match.group(0)}")
                quickstart_text = handle.extractfile(
                    "experiment0-test/QUICKSTART.md"
                ).read().decode("utf-8")
                canonical_activation = json.load(
                    handle.extractfile(
                        "experiment0-test/compatibility/experiment-0-activation.json"
                    )
                )
                manifest = json.load(handle.extractfile("experiment0-test/MANIFEST.json"))
                sha_text = handle.extractfile("experiment0-test/SHA256SUMS").read().decode("utf-8")

        self.assertEqual([], machine_data_hits)
        required = {
            "experiment0-test/.github/ISSUE_TEMPLATE/experiment-0-bug.yml",
            "experiment0-test/BETA-TESTING.md",
            "experiment0-test/COMMUNITY-README.md",
            "experiment0-test/QUICKSTART.md",
            "experiment0-test/LICENSE",
            "experiment0-test/SECURITY.md",
            "experiment0-test/MANIFEST.json",
            "experiment0-test/SHA256SUMS",
            "experiment0-test/EXPERIMENT-0.md",
            "experiment0-test/compatibility/experiment-0-activation.json",
            "experiment0-test/compatibility/explorer-stack-lock.json",
            "experiment0-test/compatibility/stack-lock.json",
            "experiment0-test/deploy/caddy/pohw-explorer.Caddyfile.example",
            "experiment0-test/deploy/pohw-bitcoin-indexer.env.example",
            "experiment0-test/deploy/pohw-explorer-host.env.example",
            "experiment0-test/deploy/pohw-experiment.env.example",
            "experiment0-test/docs/assets/dashboard-overview.png",
            "experiment0-test/docs/explorer.md",
            "experiment0-test/docs/fork-chain-node.md",
            "experiment0-test/scripts/pohw-experiment-init.sh",
            "experiment0-test/scripts/pohw-experiment-package.sh",
            "experiment0-test/scripts/pohw-experiment-prepare-fork-activation.sh",
            "experiment0-test/crates/p2pool-node/src/main.rs",
            "experiment0-test/ui/pohw-dashboard/src/main.tsx",
            "experiment0-test/contracts/idena-snapshot-registry/assembly/index.ts",
        }
        self.assertTrue(required.issubset(set(names)))
        self.assertEqual(manifest["package"], "experiment0-test")
        self.assertIn("scripts/pohw-experiment-init.sh", manifest["files"])
        self.assertEqual(
            canonical_activation["activation_id"],
            "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e",
        )
        self.assertIn("Five-Step Fast Path", quickstart_text)
        self.assertIn("A different activation ID is a different experiment", quickstart_text)
        self.assertIn("QUICKSTART.md", sha_text)
        self.assertIn("MANIFEST.json", sha_text)

        forbidden_fragments = [
            "/.git/",
            "/target/",
            "/output/",
            "/.pohw-p2pool/",
            "node_modules",
            "/dist/",
            "/build/",
            "idena-data",
            "bitcoin-data",
        ]
        forbidden_suffixes = (
            ".key",
            ".cookie",
            ".pid",
            ".log",
            ".sqlite",
            ".sqlite3",
            ".db",
            ".tar.gz",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertFalse(any(fragment in name for fragment in forbidden_fragments))
                self.assertFalse(name.endswith(forbidden_suffixes))
                self.assertNotIn("/.env", name)

    def test_manual_launch_gate_is_fail_closed_for_fork_and_mining(self) -> None:
        installer = (REPO_ROOT / "scripts" / "pohw-install-manual-launch-gate.sh").read_text(
            encoding="utf-8"
        )
        fork_dropin = (
            REPO_ROOT / "deploy" / "systemd" / "pohw-fork-chain-manual-approval.conf"
        ).read_text(encoding="utf-8")
        mining_dropin = (
            REPO_ROOT / "deploy" / "systemd" / "pohw-mining-manual-approval.conf"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "ConditionPathExists=/etc/pohw/enable-experiment-0-fork", fork_dropin
        )
        self.assertIn(
            "ConditionPathExists=/etc/pohw/enable-experiment-0-mining", mining_dropin
        )
        self.assertIn('rm -f "$FORK_MARKER" "$MINING_MARKER"', installer)
        self.assertIn('systemctl start "$FORK_UNIT" "$MINING_UNIT"', installer)
        self.assertIn('systemctl is-active --quiet "$unit"', installer)

    def test_experiment_package_refuses_existing_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-package-existing-") as temp:
            output_root = Path(temp) / "packages"
            output_root.mkdir()
            (output_root / "experiment0-test.tar.gz").write_text("exists", encoding="utf-8")
            result = subprocess.run(
                [
                    "bash",
                    str(PACKAGING_SCRIPT),
                    "--output-root",
                    str(output_root),
                    "--package-name",
                    "experiment0-test",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to overwrite existing package artifact", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_experiment_package_refuses_symlinked_output_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-package-symlink-ancestor-") as temp:
            root = Path(temp)
            real = root / "real-output"
            link = root / "output-link"
            real.mkdir()
            os.symlink(real, link)
            result = subprocess.run(
                [
                    "bash",
                    str(PACKAGING_SCRIPT),
                    "--output-root",
                    str(link / "missing" / "nested"),
                    "--package-name",
                    "experiment0-test",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to write through symlinked path component", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_experiment_package_refuses_existing_symlinked_output_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-package-existing-symlink-ancestor-") as temp:
            root = Path(temp)
            real = root / "real-output"
            link = root / "output-link"
            (real / "existing").mkdir(parents=True)
            os.symlink(real, link)
            result = subprocess.run(
                [
                    "bash",
                    str(PACKAGING_SCRIPT),
                    "--output-root",
                    str(link / "existing" / "nested"),
                    "--package-name",
                    "experiment0-test",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to write through symlinked path component", result.stderr)

    def test_experiment_package_rejects_unsafe_package_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-package-name-") as temp:
            output_root = Path(temp) / "packages"
            for name in [".", "..", "-experiment0", ".experiment0"]:
                with self.subTest(name=name):
                    result = subprocess.run(
                        [
                            "bash",
                            str(PACKAGING_SCRIPT),
                            "--output-root",
                            str(output_root),
                            "--package-name",
                            name,
                        ],
                        cwd=REPO_ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Package name must be", result.stderr)


if __name__ == "__main__":
    unittest.main()
