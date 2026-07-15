import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import pwd
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-bitcoin-core-build-evidence.py"
CANONICAL_FLAGS = [
    "-DBUILD_GUI=OFF",
    "-DBUILD_TESTS=ON",
    "-DBUILD_BENCH=OFF",
    "-DBUILD_FUZZ_BINARY=OFF",
    "-DENABLE_IPC=OFF",
]
TEST_FILTERS = {
    "pow_sanity": "pow_tests/ChainParams_POHW_sanity",
    "bootstrap_marker": "pow_tests/POHW_bootstrap_and_handoff_marker",
    "template_difficulty": "pow_tests/POHW_update_time_refreshes_template_difficulty",
    "replay_marker": (
        "transaction_tests/"
        "pohw_inherited_spend_requires_fork_only_replay_marker"
    ),
}


class BitcoinCoreBuildEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "source-snapshot"
        self.build = self.root / "build"
        self.bin_dir = self.root / "tools"
        self.snapshot.mkdir()
        (self.snapshot / "src").mkdir()
        (self.snapshot / "depends").mkdir()
        (self.snapshot / "README").write_text("fixture\n", encoding="ascii")
        source_tool = self.snapshot / "src" / "tool.sh"
        source_tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        source_tool.chmod(0o755)
        (self.build / "bin").mkdir(parents=True)
        (self.build / "pohw-depends").mkdir()
        self.depends_source = self.build / "pohw-depends" / "source"
        self.depends_prefix = self.depends_source / "x86_64-fixture-linux-gnu"
        self.bin_dir.mkdir()

        for name in ("bitcoind", "bitcoin-cli", "test_bitcoin"):
            artifact = self.build / "bin" / name
            artifact.write_text(f"#!/bin/sh\necho fixture-{name}\n", encoding="ascii")
            artifact.chmod(0o755)
        release_paths = {
            "bitcoind": self.build / "pohw-release" / "bin" / "bitcoind",
            "bitcoin-cli": self.build / "pohw-release" / "bin" / "bitcoin-cli",
            "test_bitcoin": self.build
            / "pohw-release"
            / "libexec"
            / "test_bitcoin",
        }
        for name, artifact in release_paths.items():
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(
                f"#!/bin/sh\necho release-fixture-{name}\n", encoding="ascii"
            )
            artifact.chmod(0o755)
        for name in ("cmake", "ctest", "ninja", "c++", "make"):
            tool = self.bin_dir / name
            tool.write_text(
                f"#!/bin/sh\necho '{name} fixture-version'\n", encoding="ascii"
            )
            tool.chmod(0o755)

        self.commit = "11" * 20
        self.patch_sha256 = "22" * 32
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "activation_id": "33" * 32,
                    "upstream": {"commit": self.commit},
                    "build": {
                        "patch_sha256": self.patch_sha256,
                        "cmake_flags": CANONICAL_FLAGS,
                    },
                },
                sort_keys=True,
            ),
            encoding="ascii",
        )
        self.metadata = self.build / "pohw-source-snapshot.json"
        self.depends_source_metadata = self.build / "pohw-depends-source.json"
        self.depends_metadata = self.build / "pohw-depends-prefix.json"
        self.run_record = self.build / "pohw-build-run.json"
        self.evidence = self.build / "pohw-build-evidence.json"
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.bin_dir}:{self.env['PATH']}"
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

        self.make_snapshot_read_only()
        result = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "snapshot-metadata",
                "--snapshot-dir",
                str(self.snapshot),
                "--metadata",
                str(self.metadata),
                "--tree-oid",
                self.commit,
                "--upstream-commit",
                self.commit,
                "--patch-sha256",
                self.patch_sha256,
                "--manifest-sha256",
                hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            ],
            cwd=ROOT,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "depends-prepare",
                "--source",
                str(self.snapshot / "depends"),
                "--destination",
                str(self.depends_source),
                "--metadata",
                str(self.depends_source_metadata),
            ],
            cwd=ROOT,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.depends_prefix.mkdir()
        (self.depends_prefix / "toolchain.cmake").write_text(
            "# fixture depends toolchain\n", encoding="ascii"
        )
        result = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "depends-metadata",
                "--prefix",
                str(self.depends_prefix),
                "--metadata",
                str(self.depends_metadata),
                "--host",
                "x86_64-fixture-linux-gnu",
            ],
            cwd=ROOT,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot_sha256 = json.loads(self.metadata.read_text(encoding="ascii"))[
            "snapshot"
        ]["sha256"]

        cache = [
            f"CMAKE_HOME_DIRECTORY:INTERNAL={self.snapshot}",
            "CMAKE_GENERATOR:INTERNAL=Ninja",
            "BUILD_GUI:BOOL=OFF",
            "BUILD_TESTS:BOOL=ON",
            "BUILD_BENCH:BOOL=OFF",
            "BUILD_FUZZ_BINARY:BOOL=OFF",
            "ENABLE_IPC:BOOL=OFF",
            f"CMAKE_MAKE_PROGRAM:FILEPATH={(self.bin_dir / 'ninja').resolve()}",
            f"CMAKE_TOOLCHAIN_FILE:FILEPATH={(self.depends_prefix / 'toolchain.cmake').resolve()}",
            (
                "CMAKE_C_FLAGS:STRING="
                f"-ffile-prefix-map={self.snapshot.resolve()}=/pohw/source "
                f"-ffile-prefix-map={self.build.resolve()}=/pohw/build"
            ),
            (
                "CMAKE_CXX_FLAGS:STRING="
                f"-ffile-prefix-map={self.snapshot.resolve()}=/pohw/source "
                f"-ffile-prefix-map={self.build.resolve()}=/pohw/build"
            ),
        ]
        (self.build / "CMakeCache.txt").write_text(
            "\n".join(cache) + "\n", encoding="ascii"
        )
        compiler_configuration = self.build / "CMakeFiles" / "fixture"
        compiler_configuration.mkdir(parents=True)
        (compiler_configuration / "CMakeCXXCompiler.cmake").write_text(
            f'set(CMAKE_CXX_COMPILER "{(self.bin_dir / "c++").resolve()}")\n',
            encoding="ascii",
        )
        self.write_run_record(snapshot_sha256)

    def make_snapshot_read_only(self):
        for path in sorted(
            self.snapshot.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                continue
            if path.is_dir():
                path.chmod(0o555)
            else:
                path.chmod(0o555 if mode & 0o111 else 0o444)
        self.snapshot.chmod(0o555)

    def make_snapshot_writable(self):
        if not self.snapshot.exists():
            return
        self.snapshot.chmod(0o755)
        for path in self.snapshot.rglob("*"):
            if not path.is_symlink():
                mode = path.lstat().st_mode
                path.chmod(
                    0o755 if path.is_dir() or mode & 0o111 else 0o644
                )

    def make_depends_writable(self):
        if not self.depends_prefix.exists():
            return
        self.depends_prefix.chmod(0o755)
        for path in self.depends_prefix.rglob("*"):
            if not path.is_symlink():
                mode = path.lstat().st_mode
                path.chmod(0o755 if path.is_dir() or mode & 0o111 else 0o644)

    def make_depends_read_only(self):
        for path in sorted(
            self.depends_prefix.rglob("*"),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            if not path.is_symlink():
                mode = path.lstat().st_mode
                path.chmod(0o555 if path.is_dir() or mode & 0o111 else 0o444)
        self.depends_prefix.chmod(0o555)

    def write_run_record(self, snapshot_sha256):
        logs = self.build / "pohw-build-logs"
        logs.mkdir(exist_ok=True)
        cmake = str((self.bin_dir / "cmake").resolve())
        ctest = str((self.bin_dir / "ctest").resolve())
        make = str((self.bin_dir / "make").resolve())
        test_binary = str((self.build / "bin" / "test_bitcoin").resolve())
        tmpdir = str((self.build / ".test-tmp.fixture").resolve())
        depends_args = [
            make,
            "-C",
            str(self.depends_source.resolve()),
            "HOST=x86_64-fixture-linux-gnu",
            "NO_QT=1",
            "NO_QR=1",
            "NO_ZMQ=1",
            "NO_IPC=1",
            "NO_USDT=1",
        ]
        prefix_map_flags = (
            f"-ffile-prefix-map={self.snapshot.resolve()}=/pohw/source "
            f"-ffile-prefix-map={self.build.resolve()}=/pohw/build"
        )
        steps = [
            {
                "label": "depends_fetch",
                "argv": [*depends_args, "download-one"],
                "env": {},
            },
            {
                "label": "depends_build",
                "argv": [*depends_args, "install"],
                "env": {},
            },
            {
                "label": "configure",
                "argv": [
                    cmake,
                    "-S",
                    str(self.snapshot.resolve()),
                    "-B",
                    str(self.build.resolve()),
                    "-G",
                    "Ninja",
                    "--toolchain",
                    str((self.depends_prefix / "toolchain.cmake").resolve()),
                    *CANONICAL_FLAGS,
                ],
                "env": {
                    "CFLAGS": prefix_map_flags,
                    "CXXFLAGS": prefix_map_flags,
                },
            },
            {
                "label": "build",
                "argv": [cmake, "--build", str(self.build.resolve())],
                "env": {},
            },
        ]
        for label, test_filter in TEST_FILTERS.items():
            steps.append(
                {
                    "label": label,
                    "argv": [test_binary, f"--run_test={test_filter}"],
                    "env": {"TMPDIR": tmpdir},
                }
            )
        steps.append(
            {
                "label": "ctest",
                "argv": [
                    ctest,
                    "--test-dir",
                    str(self.build.resolve()),
                    "--output-on-failure",
                ],
                "env": {"TMPDIR": tmpdir},
            }
        )
        steps.append(
            {
                "label": "install",
                "argv": [
                    cmake,
                    "--install",
                    str(self.build.resolve()),
                    "--prefix",
                    str((self.build / "pohw-release").resolve()),
                    "--strip",
                ],
                "env": {},
            }
        )
        for step in steps:
            payload = f"{step['label']} passed\n".encode("ascii")
            log_path = logs / f"{step['label']}.log"
            log_path.write_bytes(payload)
            step.update(
                {
                    "exit_code": 0,
                    "log_path": f"pohw-build-logs/{step['label']}.log",
                    "output_sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        self.run_record.write_text(
            json.dumps(
                {
                    "schema_version": "pohw-bitcoin-core-build-run/v4",
                    "source_snapshot_sha256": snapshot_sha256,
                    "environment": {
                        "HOME": "/nonexistent",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "LOGNAME": pwd.getpwuid(os.getuid()).pw_name,
                        "PATH": self.env["PATH"],
                        "TZ": "UTC",
                        "USER": pwd.getpwuid(os.getuid()).pw_name,
                    },
                    "steps": steps,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )

    def tearDown(self):
        self.make_snapshot_writable()
        self.make_depends_writable()
        self.temp.cleanup()

    def run_script(self, command, manifest=None):
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                command,
                "--manifest",
                str(manifest or self.manifest),
                "--snapshot-dir",
                str(self.snapshot),
                "--snapshot-metadata",
                str(self.metadata),
                "--build-dir",
                str(self.build),
                "--run-record",
                str(self.run_record),
                "--evidence",
                str(self.evidence),
            ],
            cwd=ROOT,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_write_verify_and_artifact_mutation(self):
        result = self.run_script("write")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script("verify")
        self.assertEqual(result.returncode, 0, result.stderr)

        (self.build / "pohw-release" / "bin" / "bitcoind").write_bytes(
            b"substituted\n"
        )
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)

    def test_noncanonical_cmake_cache_is_rejected(self):
        cache = self.build / "CMakeCache.txt"
        cache.write_text(
            cache.read_text(encoding="ascii").replace(
                "BUILD_GUI:BOOL=OFF", "BUILD_GUI:BOOL=ON"
            ),
            encoding="ascii",
        )
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BUILD_GUI must be OFF", result.stderr)

    def test_substituted_depends_command_is_rejected(self):
        record = json.loads(self.run_record.read_text(encoding="ascii"))
        record["steps"][0]["argv"][-1] = "install"
        self.run_record.write_text(json.dumps(record) + "\n", encoding="ascii")
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("depends fetch command", result.stderr)

    def test_missing_compiler_path_map_is_rejected(self):
        record = json.loads(self.run_record.read_text(encoding="ascii"))
        record["steps"][2]["env"].pop("CXXFLAGS")
        self.run_record.write_text(json.dumps(record) + "\n", encoding="ascii")
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configure command", result.stderr)

        self.write_run_record(record["source_snapshot_sha256"])
        cache = self.build / "CMakeCache.txt"
        cache.write_text(
            cache.read_text(encoding="ascii").replace(
                f" -ffile-prefix-map={self.build.resolve()}=/pohw/build", ""
            ),
            encoding="ascii",
        )
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical path map", result.stderr)

    def test_mutated_depends_prefix_is_rejected(self):
        result = self.run_script("write")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.make_depends_writable()
        (self.depends_prefix / "toolchain.cmake").write_text(
            "# substituted depends toolchain\n", encoding="ascii"
        )
        self.make_depends_read_only()
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("depends metadata does not match", result.stderr)

    def test_duplicate_manifest_keys_are_rejected(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"activation_id":"first","activation_id":"second"}\n',
            encoding="ascii",
        )
        result = self.run_script("write", duplicate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON key", result.stderr)

    def test_incomplete_or_failed_test_record_is_rejected(self):
        record = json.loads(self.run_record.read_text(encoding="ascii"))
        record["steps"] = record["steps"][:-1]
        self.run_record.write_text(json.dumps(record) + "\n", encoding="ascii")
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete", result.stderr)

        self.write_run_record(record["source_snapshot_sha256"])
        record = json.loads(self.run_record.read_text(encoding="ascii"))
        record["steps"][2]["exit_code"] = 1
        self.run_record.write_text(json.dumps(record) + "\n", encoding="ascii")
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not pass", result.stderr)

    def test_unrecorded_or_tampered_baseline_environment_is_rejected(self):
        record = json.loads(self.run_record.read_text(encoding="ascii"))
        record["environment"]["CC"] = "/tmp/unrecorded-compiler"
        self.run_record.write_text(json.dumps(record) + "\n", encoding="ascii")
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("environment has missing or unexpected fields", result.stderr)

    def test_stale_snapshot_and_mutated_log_are_rejected(self):
        result = self.run_script("write")
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.build / "pohw-build-logs" / "ctest.log"
        log.write_text("forged pass\n", encoding="ascii")
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("log digest mismatch", result.stderr)

        self.write_run_record(
            json.loads(self.metadata.read_text(encoding="ascii"))["snapshot"]["sha256"]
        )
        self.make_snapshot_writable()
        (self.snapshot / "README").write_text("changed\n", encoding="ascii")
        self.make_snapshot_read_only()
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot metadata does not match", result.stderr)

    def test_writable_snapshot_and_stale_manifest_are_rejected(self):
        self.make_snapshot_writable()
        result = self.run_script("write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot root is writable", result.stderr)
        self.make_snapshot_read_only()

        result = self.run_script("write")
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(self.manifest.read_text(encoding="ascii"))
        manifest["activation_id"] = "44" * 32
        self.manifest.write_text(json.dumps(manifest) + "\n", encoding="ascii")
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale manifest digest", result.stderr)

    def test_fabricated_legacy_evidence_is_rejected(self):
        self.evidence.write_text(
            json.dumps(
                {
                    "schema_version": "pohw-bitcoin-core-build-evidence/v1",
                    "tests": {"status": "passed"},
                    "artifacts": {},
                }
            )
            + "\n",
            encoding="ascii",
        )
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)

    def test_run_step_captures_exact_command_and_output(self):
        self.run_record.unlink()
        shutil.rmtree(self.build / "pohw-build-logs")
        cmake = str((self.bin_dir / "cmake").resolve())
        Path(cmake).write_text(
            "#!/bin/sh\n"
            'test -z "${POHW_UNRECORDED_SECRET+x}" || exit 91\n'
            "echo 'cmake fixture-version'\n",
            encoding="ascii",
        )
        Path(cmake).chmod(0o755)
        self.env["POHW_UNRECORDED_SECRET"] = "must-not-reach-build-command"
        argv = [
            "python3",
            str(SCRIPT),
            "run-step",
            "--snapshot-dir",
            str(self.snapshot),
            "--build-dir",
            str(self.build),
            "--run-record",
            str(self.run_record),
            "--label",
            "configure",
            "--",
            cmake,
            "-S",
            str(self.snapshot.resolve()),
            "-B",
            str(self.build.resolve()),
            "-G",
            "Ninja",
            *CANONICAL_FLAGS,
        ]
        result = subprocess.run(
            argv,
            cwd=ROOT,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(self.run_record.read_text(encoding="ascii"))
        self.assertEqual(set(record["environment"]), {
            "HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "TZ", "USER"
        })
        self.assertEqual(record["steps"][0]["argv"], argv[argv.index("--") + 1 :])
        log = self.build / record["steps"][0]["log_path"]
        self.assertEqual(
            record["steps"][0]["output_sha256"],
            hashlib.sha256(log.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
