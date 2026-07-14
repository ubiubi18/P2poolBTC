from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPARE_REPORTS = REPO_ROOT / "scripts" / "pohw-experiment-compare-reports.py"
FORK_ACTIVATION_HASH_TAG = b"POHW1_FORK_ACTIVATION"
EXPECTED_ACTIVATION_ID = "eaa1046d1f672b49edcb0fe31ae17545da98ea73405d65a81ac668bd6684a841"


class ExperimentCompareReportsTest(unittest.TestCase):
    def run_comparison(self, *reports: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(COMPARE_REPORTS),
                "--min-nodes",
                "0",
                *map(str, reports),
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def write_archive_member(
        self,
        archive: tarfile.TarFile,
        name: str,
        content: bytes = b"test",
        *,
        entry_type: bytes | None = None,
    ) -> None:
        member = tarfile.TarInfo(name)
        if entry_type is not None:
            member.type = entry_type
            member.linkname = "metadata.txt"
            archive.addfile(member)
            return
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    def write_forged_report(self, root: Path, idx: int, activation_id: str | None = None) -> Path:
        report = root / f"report-{idx}"
        report.mkdir()
        miner_id = f"miner-{idx}"
        (report / "metadata.txt").write_text(
            f"miner_id={miner_id}\ngit_commit=test-commit\ngit_dirty=false\n",
            encoding="utf-8",
        )
        (report / "status.json").write_text(json.dumps({"replay": {}}), encoding="utf-8")
        (report / "latest-snapshot-summary.json").write_text(
            json.dumps({"configured": False, "latest": None}),
            encoding="utf-8",
        )
        (report / "multinode-preflight.json").write_text(
            json.dumps(
                {
                    "local": {
                        "sharechain_message_count": 0,
                        "gossip_envelope_count": 0,
                        "replay": {},
                    },
                    "readiness": {},
                    "peer_inventory_probe": [],
                    "snapshot_directory": {"latest": None},
                    "miner_registration": {
                        "registered": True,
                        "miner_id": miner_id,
                        "idena_address": "0x" + f"{idx + 1:040x}",
                        "btc_payout_script_hex": "0014" + f"{idx + 1:040x}",
                        "claim_owner_pubkey_hex": f"{idx + 2:064x}",
                        "mining_pubkey_hex": f"{idx + 3:064x}",
                    },
                }
            ),
            encoding="utf-8",
        )
        if activation_id is not None:
            self.write_activation_manifest(report, activation_id)
        return report

    def write_activation_manifest(self, report: Path, activation_id: str) -> None:
        manifest = {
            "schema_version": 2,
            "config": {
                "chain_name": "pohw-experiment-0",
                "launch_timestamp_utc": "2026-07-05T00:00:00Z",
                "inherited_utxo_spending_enabled": False,
                "post_fork_pow_limit_bits": 545259519,
                "target_spacing_seconds": 600,
                "difficulty_algorithm": "bootstrap_then_bitcoin_2016_v1",
                "bootstrap_handoff_hashrate_hps": 1_000_000_000_000_000,
            },
            "fork_point": {
                "inherited_tip_height": 100,
                "inherited_tip_hash": "aa" * 32,
                "first_fork_height": 101,
                "launch_timestamp_utc": "2026-07-05T00:00:00Z",
            },
            "launch_block": {
                "height": 101,
                "block_hash": "bb" * 32,
                "timestamp": "2026-07-05T00:01:00Z",
            },
            "replay_protection_required": True,
        }
        if activation_id == "22" * 32:
            manifest["config"]["target_spacing_seconds"] = 120
        manifest["activation_id"] = self.compute_activation_id(manifest)
        if activation_id == "11" * 32:
            self.assertEqual(manifest["activation_id"], EXPECTED_ACTIVATION_ID)
        (report / "fork-activation.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    def compute_activation_id(self, manifest: dict[str, object]) -> str:
        config = manifest["config"]
        fork_point = manifest["fork_point"]
        launch_block = manifest["launch_block"]
        assert isinstance(config, dict)
        assert isinstance(fork_point, dict)
        assert isinstance(launch_block, dict)
        payload = {
            "schema_version": manifest["schema_version"],
            "config": {
                "chain_name": config["chain_name"],
                "launch_timestamp_utc": config["launch_timestamp_utc"],
                "inherited_utxo_spending_enabled": config[
                    "inherited_utxo_spending_enabled"
                ],
                "post_fork_pow_limit_bits": config["post_fork_pow_limit_bits"],
                "target_spacing_seconds": config["target_spacing_seconds"],
                "difficulty_algorithm": config["difficulty_algorithm"],
                "bootstrap_handoff_hashrate_hps": config[
                    "bootstrap_handoff_hashrate_hps"
                ],
            },
            "fork_point": {
                "inherited_tip_height": fork_point["inherited_tip_height"],
                "inherited_tip_hash": fork_point["inherited_tip_hash"],
                "first_fork_height": fork_point["first_fork_height"],
                "launch_timestamp_utc": fork_point["launch_timestamp_utc"],
            },
            "launch_block": {
                "height": launch_block["height"],
                "block_hash": launch_block["block_hash"],
                "timestamp": launch_block["timestamp"],
            },
            "replay_protection_required": manifest["replay_protection_required"],
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(FORK_ACTIVATION_HASH_TAG + b"\0" + encoded).hexdigest()

    def rewrite_activation_manifest(self, report: Path, manifest: dict[str, object]) -> None:
        manifest["activation_id"] = self.compute_activation_id(manifest)
        (report / "fork-activation.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    def test_forged_preflight_registrations_do_not_satisfy_quorum(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-forged-reports-") as temp:
            root = Path(temp)
            reports = [self.write_forged_report(root, idx) for idx in range(3)]
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "3",
                    *map(str, reports),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "expected at least 3 registered unique participants, got 0",
            result.stdout,
        )
        self.assertIn("no verified registered miner proof", result.stdout)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_report_path_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-path-link-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0)
            link = root / "report-link"
            link.symlink_to(report, target_is_directory=True)
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    str(link),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("report path must not be a symlink", result.stdout)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_report_member_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-member-link-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0)
            target = root / "status-target.json"
            target.write_text(json.dumps({"replay": {}}), encoding="utf-8")
            status = report / "status.json"
            status.unlink()
            status.symlink_to(target)
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    str(report),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("report directory contains symlink: status.json", result.stdout)

    def test_archive_parent_traversal_is_rejected_without_writing_outside(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-archive-traversal-") as temp:
            root = Path(temp)
            archive_path = root / "report.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                self.write_archive_member(archive, "../outside.txt")

            result = self.run_comparison(archive_path)

            self.assertFalse((root / "outside.txt").exists())

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unsafe archive path: ../outside.txt", result.stdout)

    def test_archive_windows_traversal_and_links_are_rejected(self) -> None:
        cases = [
            ("windows-traversal", "..\\outside.txt", None, "unsafe archive path"),
            ("symbolic-link", "report-link", tarfile.SYMTYPE, "unsupported entry"),
        ]
        for case_name, member_name, entry_type, expected in cases:
            with self.subTest(case=case_name):
                with tempfile.TemporaryDirectory(prefix=f"pohw-report-{case_name}-") as temp:
                    root = Path(temp)
                    archive_path = root / "report.tar.gz"
                    with tarfile.open(archive_path, "w:gz") as archive:
                        self.write_archive_member(
                            archive,
                            member_name,
                            entry_type=entry_type,
                        )
                    result = self.run_comparison(archive_path)

                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected, result.stdout)

    def test_archive_file_directory_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-archive-collision-") as temp:
            root = Path(temp)
            archive_path = root / "report.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                self.write_archive_member(archive, "report")
                self.write_archive_member(archive, "report/status.json")

            result = self.run_comparison(archive_path)

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("archive path crosses a file", result.stdout)

    def test_safe_archive_is_extracted_for_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-report-safe-archive-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0)
            archive_path = root / "report.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(report, arcname="report")

            result = self.run_comparison(archive_path)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS WITH WARNINGS", result.stdout)

    def test_matching_activation_manifests_are_accepted_for_debug_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-match-") as temp:
            root = Path(temp)
            reports = [
                self.write_forged_report(root, idx, activation_id="11" * 32)
                for idx in range(2)
            ]
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    *map(str, reports),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS WITH WARNINGS", result.stdout)
        self.assertNotIn("fork activation manifests differ", result.stdout)

    def test_mismatched_activation_manifests_fail_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-mismatch-") as temp:
            root = Path(temp)
            reports = [
                self.write_forged_report(root, 0, activation_id="11" * 32),
                self.write_forged_report(root, 1, activation_id="22" * 32),
            ]
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    *map(str, reports),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fork activation manifests differ", result.stdout)

    def test_partial_activation_manifests_warn_but_do_not_fail_debug_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-partial-") as temp:
            root = Path(temp)
            reports = [
                self.write_forged_report(root, 0, activation_id="11" * 32),
                self.write_forged_report(root, 1),
            ]
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    *map(str, reports),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missing fork activation manifest in reports: miner-1", result.stdout)
        self.assertIn("PASS WITH WARNINGS", result.stdout)

    def test_invalid_activation_manifest_json_fails_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-invalid-json-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0)
            (report / "fork-activation.json").write_text("{not json", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    str(report),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("invalid fork-activation.json", result.stdout)

    def test_incomplete_activation_manifest_fails_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-incomplete-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0)
            (report / "fork-activation.json").write_text(
                json.dumps({"activation_id": "11" * 32}),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    str(report),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("invalid fork-activation.json: schema_version", result.stdout)
        self.assertIn("invalid fork-activation.json: config must be an object", result.stdout)

    def test_activation_manifest_with_wrong_id_fails_comparison(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-activation-wrong-id-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0, activation_id="11" * 32)
            manifest_path = report / "fork-activation.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["config"]["target_spacing_seconds"] = 120
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    str(report),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "invalid fork-activation.json: activation_id does not match manifest content",
            result.stdout,
        )

    def test_semantically_invalid_activation_manifest_fails_comparison(self) -> None:
        cases = [
            (
                "timestamp-mismatch",
                lambda manifest: manifest["fork_point"].update(
                    {"launch_timestamp_utc": "2026-07-05T00:00:01Z"}
                ),
                "config.launch_timestamp_utc must match fork_point.launch_timestamp_utc",
            ),
            (
                "early-launch-block",
                lambda manifest: manifest["launch_block"].update(
                    {"timestamp": "2026-07-04T23:59:59Z"}
                ),
                "launch_block.timestamp must not be before config.launch_timestamp_utc",
            ),
            (
                "replay-protection-mismatch",
                lambda manifest: manifest.update({"replay_protection_required": False}),
                "replay_protection_required must be the inverse",
            ),
            (
                "invalid-difficulty-algorithm",
                lambda manifest: manifest["config"].update(
                    {"difficulty_algorithm": "fixed_target"}
                ),
                "config.difficulty_algorithm must be bootstrap_then_bitcoin_2016_v1",
            ),
            (
                "zero-handoff-hashrate",
                lambda manifest: manifest["config"].update(
                    {"bootstrap_handoff_hashrate_hps": 0}
                ),
                "bootstrap_handoff_hashrate_hps must be positive",
            ),
            (
                "too-small-spacing",
                lambda manifest: manifest["config"].update(
                    {"target_spacing_seconds": 3}
                ),
                "config.target_spacing_seconds must be at least 4",
            ),
            (
                "noncanonical-pow-limit",
                lambda manifest: manifest["config"].update(
                    {"post_fork_pow_limit_bits": 0x02000100}
                ),
                "config.post_fork_pow_limit_bits must be canonical",
            ),
            (
                "oversized-pow-target",
                lambda manifest: manifest["config"].update(
                    {"post_fork_pow_limit_bits": 0xFF000001}
                ),
                "config.post_fork_pow_limit_bits decodes to a zero target",
            ),
        ]
        for case_name, mutate, expected_error in cases:
            with self.subTest(case=case_name):
                with tempfile.TemporaryDirectory(prefix=f"pohw-activation-{case_name}-") as temp:
                    root = Path(temp)
                    report = self.write_forged_report(root, 0, activation_id="11" * 32)
                    manifest_path = report / "fork-activation.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    mutate(manifest)
                    self.rewrite_activation_manifest(report, manifest)
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(COMPARE_REPORTS),
                            "--min-nodes",
                            "0",
                            str(report),
                        ],
                        cwd=REPO_ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected_error, result.stdout)

    def test_malformed_peer_probe_entries_fail_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-malformed-peer-probe-") as temp:
            root = Path(temp)
            report = self.write_forged_report(root, 0)
            preflight_path = report / "multinode-preflight.json"
            preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
            preflight["peer_inventory_probe"] = [{"reachable": False}, "not-an-object", 42]
            preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_REPORTS),
                    "--min-nodes",
                    "0",
                    str(report),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "peer_inventory_probe contains 2 non-object entries",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
