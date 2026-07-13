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
                manifest = json.load(handle.extractfile("experiment0-test/MANIFEST.json"))
                sha_text = handle.extractfile("experiment0-test/SHA256SUMS").read().decode("utf-8")

        self.assertEqual([], machine_data_hits)
        required = {
            "experiment0-test/QUICKSTART.md",
            "experiment0-test/MANIFEST.json",
            "experiment0-test/SHA256SUMS",
            "experiment0-test/EXPERIMENT-0.md",
            "experiment0-test/deploy/pohw-experiment.env.example",
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
