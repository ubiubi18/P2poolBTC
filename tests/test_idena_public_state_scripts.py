import os
import py_compile
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPORTER = REPO_ROOT / "scripts" / "idena-public-state-export-push.sh"
IMPORTER = REPO_ROOT / "scripts" / "idena-public-state-import.sh"
RESTRICTED_SHELL = REPO_ROOT / "scripts" / "idena-return-restricted-shell.sh"
RRSYNC_GUARD = REPO_ROOT / "scripts" / "idena-return-rrsync-guard.py"
LOCK_HELPER = REPO_ROOT / "scripts" / "idena-private-lock-exec.py"
EXPORT_UNIT = REPO_ROOT / "deploy" / "systemd" / "idena-public-state-export.service"
IMPORT_UNIT = REPO_ROOT / "deploy" / "systemd" / "idena-public-state-import.service"
IMPORT_PATH = REPO_ROOT / "deploy" / "systemd" / "idena-public-state-import.path"
TMPFILES = REPO_ROOT / "deploy" / "tmpfiles" / "idena-return.conf"
PRIVATE_LOCK_TMPFILES = REPO_ROOT / "deploy" / "tmpfiles" / "idena-public-state-locks.conf"


class IdenaPublicStateScriptsTest(unittest.TestCase):
    def test_scripts_parse(self) -> None:
        for script in (EXPORTER, IMPORTER, RESTRICTED_SHELL):
            with self.subTest(script=script.name):
                result = subprocess.run(
                    ["sh" if script == RESTRICTED_SHELL else "bash", "-n", str(script)],
                    cwd=REPO_ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        for script in (RRSYNC_GUARD, LOCK_HELPER):
            py_compile.compile(str(script), doraise=True)

    def test_runtime_locks_live_only_under_run_lock(self) -> None:
        for script in (EXPORTER, IMPORTER):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIn("/run/lock/", text)
                self.assertNotIn('chmod 0700 "$(dirname "$LOCK_FILE")"', text)
                self.assertNotIn('install -d -o root -g root -m 0700 "$(dirname "$LOCK_FILE")"', text)
                self.assertIn("IDENA_PRIVATE_LOCK_HELPER", text)
                self.assertNotIn('exec 9>"$LOCK_FILE"', text)

    def test_systemd_bind_mounted_roots_are_explicitly_allowed(self) -> None:
        exporter = EXPORTER.read_text(encoding="utf-8")
        importer = IMPORTER.read_text(encoding="utf-8")
        self.assertIn('safe_directory "$EXPORT_DIR" "export directory" true', exporter)
        self.assertIn('safe_directory "$STATE_DIR" "export state directory" true', exporter)
        self.assertIn('clear_directory "$EXPORT_DIR" "export directory" true', exporter)
        self.assertIn('safe_directory "$INBOX_ROOT" "return inbox root" true', importer)
        self.assertIn('safe_directory "$BACKUP_ROOT" "rollback root" true', importer)
        self.assertIn('safe_directory "$FAILED_ROOT" "failed-transfer root" true', importer)
        self.assertIn('safe_directory "$STATE_DIR" "import state directory" true', importer)

    def test_shared_transfer_lock_covers_validation_and_import(self) -> None:
        importer = IMPORTER.read_text(encoding="utf-8")
        guard = RRSYNC_GUARD.read_text(encoding="utf-8")
        lock_acquired = importer.index('exec 8<>"$TRANSFER_LOCK_FILE"')
        manifest_validated = importer.index('summary="$($MANIFEST_TOOL validate')
        import_swap = importer.index('mv "$INBOX/idenachain.db"')
        committed = importer.index('write_transaction "committed"', import_swap)
        final_cleanup = importer.index("finalize_success", committed)

        self.assertLess(lock_acquired, manifest_validated)
        self.assertLess(manifest_validated, import_swap)
        self.assertLess(import_swap, committed)
        self.assertLess(committed, final_cleanup)
        self.assertIn("fcntl.flock(lock_descriptor, fcntl.LOCK_EX)", guard)
        self.assertIn("MIN_FREE_BYTES = 10 * 1024**3", guard)
        self.assertIn("stop_process_group(process)", guard)

    def test_exporter_persists_intent_before_ready(self) -> None:
        text = EXPORTER.read_text(encoding="utf-8")
        intent = text.index('write_delivery_state "ready-intent"')
        ready_send = text.index('"$ready_file" "$RETURN_TARGET:$RETURN_DIR/READY"')
        sent = text.index('write_delivery_state "ready-sent"')

        self.assertLess(intent, ready_send)
        self.assertLess(ready_send, sent)
        self.assertIn('atomic_text_file "$SOURCE_RECOVERY_FILE"', text)

    def test_export_copy_does_not_require_chown_capability(self) -> None:
        text = EXPORTER.read_text(encoding="utf-8")
        self.assertEqual(3, text.count("cp -a --no-preserve=ownership --reflink=auto"))

    def test_importer_journals_each_destructive_boundary(self) -> None:
        text = IMPORTER.read_text(encoding="utf-8")
        normal_flow = text[text.index('clear_directory "$BACKUP" "rollback directory"', 10000) :]
        prepared = normal_flow.index('write_transaction "prepared"')
        stopped = normal_flow.index('"$SYSTEMCTL_BIN" stop "$SERVICE"')
        swapping = normal_flow.index('write_transaction "swapping"')
        first_move = normal_flow.index('mv "$DATADIR/idenachain.db"')
        running = normal_flow.index('write_transaction "running"')
        committed = normal_flow.index('write_transaction "committed"')
        finalized = normal_flow.index("finalize_success", committed)

        self.assertLess(prepared, stopped)
        self.assertLess(stopped, swapping)
        self.assertLess(swapping, first_move)
        self.assertLess(first_move, running)
        self.assertLess(running, committed)
        self.assertLess(committed, finalized)
        self.assertIn('case "$TRANSACTION_PHASE" in', text)
        self.assertIn("swapping|running)", text)
        self.assertIn("committed)", text)

    def test_restricted_shell_denies_non_forced_commands(self) -> None:
        cases = (
            ([], ""),
            (["-c", "true"], "true"),
            (
                ["-c", "/usr/bin/rrsync -wo /var/lib/idena-return-inbox"],
                "true",
            ),
            (["-c", "rsync --server -logDtpre . current/"], "rsync --server -logDtpre . current/"),
        )
        for arguments, original_command in cases:
            env = dict(os.environ)
            env["SSH_ORIGINAL_COMMAND"] = original_command
            with self.subTest(arguments=arguments, original_command=original_command):
                result = subprocess.run(
                    [str(RESTRICTED_SHELL), *arguments],
                    cwd=REPO_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("only accepts write-only", result.stderr)

    def test_restricted_shell_routes_only_capacity_and_guarded_rsync(self) -> None:
        text = RESTRICTED_SHELL.read_text(encoding="utf-8")
        self.assertIn("idena-return-capacity)", text)
        self.assertIn('exec "$GUARD" capacity', text)
        self.assertIn('exec "$GUARD" transfer', text)
        self.assertNotIn("exec /usr/bin/rrsync", text)

    def test_systemd_units_include_recovery_and_sandboxing(self) -> None:
        export_unit = EXPORT_UNIT.read_text(encoding="utf-8")
        import_unit = IMPORT_UNIT.read_text(encoding="utf-8")
        import_path = IMPORT_PATH.read_text(encoding="utf-8")
        tmpfiles = TMPFILES.read_text(encoding="utf-8")
        private_locks = PRIVATE_LOCK_TMPFILES.read_text(encoding="utf-8")

        self.assertIn("ExecStopPost=/usr/local/sbin/idena-public-state-export-push --recover-source", export_unit)
        for unit in (export_unit, import_unit):
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn("CapabilityBoundingSet=", unit)
            self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)
        self.assertIn("Restart=on-failure", import_unit)
        self.assertIn("PathExists=/var/lib/idena-return-state/in-progress.json", import_path)
        self.assertIn(
            "f /run/lock/idena-return-transfer.lock 0660 root idena-return -",
            tmpfiles,
        )
        self.assertIn(
            "f /run/lock/idena-public-state-export.lock 0600 root root -",
            private_locks,
        )
        self.assertIn(
            "f /run/lock/idena-public-state-import.lock 0600 root root -",
            private_locks,
        )


if __name__ == "__main__":
    unittest.main()
