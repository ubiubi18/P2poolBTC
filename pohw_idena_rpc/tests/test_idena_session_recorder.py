import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pohw_idena_rpc.idena_session_recorder import (
    empty_status,
    SessionLedger,
    SessionRecorder,
    validate_rpc_url,
)


def block(height, flags=None, txs=None):
    return {
        "height": height,
        "hash": f"0x{height:064x}",
        "parentHash": f"0x{height - 1:064x}",
        "timestamp": 1_720_000_000 + height,
        "root": f"0x{height + 1000:064x}",
        "identityRoot": f"0x{height + 2000:064x}",
        "coinbase": "0x" + "a" * 40,
        "isEmpty": False,
        "ipfsCid": "",
        "transactions": txs or [],
        "flags": flags or [],
    }


def tx(tx_hash, tx_type="send"):
    return {
        "hash": tx_hash,
        "type": tx_type,
        "from": "0x" + "b" * 40,
        "to": "0x" + "c" * 40,
        "amount": "1",
        "tips": "0",
        "maxFee": "0.1",
        "usedFee": "0.01",
        "epoch": 211,
        "nonce": 7,
        "payload": "0x",
    }


class FakeClient:
    def __init__(
        self,
        blocks,
        transactions=None,
        syncing=False,
        wrong_time=False,
        current_block=None,
        highest_block=None,
    ):
        self.blocks = {item["height"]: item for item in blocks}
        self.transactions = transactions or {}
        self.syncing = syncing
        self.wrong_time = wrong_time
        self.current_block = current_block
        self.highest_block = highest_block

    def call(self, method, params=None):
        params = params or []
        if method == "bcn_syncing":
            head = max(self.blocks) if self.blocks else 0
            return {
                "syncing": self.syncing,
                "wrongTime": self.wrong_time,
                "currentBlock": self.current_block if self.current_block is not None else head,
                "highestBlock": self.highest_block if self.highest_block is not None else head,
                "genesisBlock": 1,
                "message": "",
            }
        if method == "bcn_lastBlock":
            return self.blocks[max(self.blocks)]
        if method == "bcn_blockAt":
            return self.blocks[int(params[0])]
        if method == "bcn_transaction":
            return self.transactions[params[0]]
        raise AssertionError(f"unexpected RPC method {method}")


class SessionRecorderTests(unittest.TestCase):
    def test_validate_rpc_url_rejects_remote_without_override(self):
        self.assertEqual(
            validate_rpc_url("http://127.0.0.1:9009"),
            "http://127.0.0.1:9009",
        )
        self.assertEqual(
            validate_rpc_url("http://localhost:9009"),
            "http://localhost:9009",
        )
        self.assertEqual(
            validate_rpc_url("http://LOCALHOST:9009"),
            "http://LOCALHOST:9009",
        )
        with self.assertRaisesRegex(ValueError, "loopback"):
            validate_rpc_url("http://198.51.100.2:9009")
        self.assertEqual(
            validate_rpc_url("http://198.51.100.2:9009", allow_remote_rpc=True),
            "http://198.51.100.2:9009",
        )
        with self.assertRaisesRegex(ValueError, "userinfo"):
            validate_rpc_url("http://user:pass@127.0.0.1:9009")

    def test_records_session_lifecycle_from_block_flags(self):
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            ledger.record_block(block(10, ["FlipLotteryStarted"]))
            ledger.record_block(block(11, ["ShortSessionStarted"]))
            ledger.record_block(block(12, ["LongSessionStarted"]))
            ledger.record_block(block(13, ["AfterLongSessionStarted"]))
            ledger.record_block(block(14, ["ValidationFinished", "IdentityUpdate"]))

            status = ledger.status()
            self.assertEqual(status["blocks"], 5)
            self.assertEqual(status["sessions"], 1)
            self.assertIsNone(status["openSessionStartHeight"])

            session = ledger.conn.execute("SELECT * FROM sessions").fetchone()
            self.assertEqual(int(session["start_height"]), 10)
            self.assertEqual(int(session["end_height"]), 14)
            self.assertEqual(session["status"], "closed")

            flags = {
                row["flag"]
                for row in ledger.conn.execute("SELECT flag FROM session_events").fetchall()
            }
            self.assertEqual(
                flags,
                {
                    "FlipLotteryStarted",
                    "ShortSessionStarted",
                    "LongSessionStarted",
                    "AfterLongSessionStarted",
                    "ValidationFinished",
                    "IdentityUpdate",
                },
            )
            ledger.close()

    def test_record_block_is_idempotent_and_caches_transactions(self):
        tx_hash = "0x" + "1" * 64
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            ledger.record_block(block(20, ["OfflineCommit"], [tx_hash]), [tx(tx_hash)])
            ledger.record_block(block(20, ["OfflineCommit"], [tx_hash]), [tx(tx_hash)])
            status = ledger.status()
            self.assertEqual(status["blocks"], 1)
            self.assertEqual(status["transactions"], 1)
            self.assertEqual(status["recentFlags"][0]["flag"], "OfflineCommit")
            ledger.close()

    def test_record_block_caches_non_printable_transaction_payload(self):
        tx_hash = "0x" + "1" * 64
        raw_tx = tx(tx_hash)
        raw_tx["payload"] = "hello\x00world"
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            ledger.record_block(block(20, ["OfflineCommit"], [tx_hash]), [raw_tx])

            stored = ledger.conn.execute(
                "SELECT payload, raw_json FROM block_transactions WHERE tx_hash = ?",
                (tx_hash,),
            ).fetchone()
            self.assertEqual(stored["payload"], 'json:"hello\\u0000world"')
            self.assertIn("\\u0000", stored["raw_json"])
            ledger.close()

    def test_record_block_rejects_same_height_different_hash(self):
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            ledger.record_block(block(21))
            conflicting = block(21)
            conflicting["hash"] = "0x" + "f" * 64
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                ledger.record_block(conflicting)
            ledger.close()

    def test_manual_backfill_does_not_rewind_live_cursor(self):
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            ledger.record_block(block(30))
            ledger.record_block(block(29))
            status = ledger.status()
            self.assertEqual(status["lastScannedHeight"], 30)
            ledger.close()

    def test_status_is_empty_before_database_exists(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "missing.sqlite3"
            self.assertEqual(empty_status(db)["blocks"], 0)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_session_ledger_rejects_symlink_ancestor_database_path(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real"
            child_dir = real_dir / "child"
            link_dir = base / "link"
            child_dir.mkdir(parents=True)
            real_dir.chmod(0o700)
            child_dir.chmod(0o700)
            os.symlink(real_dir, link_dir)

            try:
                with self.assertRaisesRegex(ValueError, "unsafe symlink ancestor"):
                    SessionLedger(link_dir / "child" / "sessions.sqlite3")
                self.assertFalse((child_dir / "sessions.sqlite3").exists())
            finally:
                child_dir.chmod(0o700)
                real_dir.chmod(0o700)

    def test_session_ledger_readonly_uri_escapes_question_mark_path(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "sessions?ledger.sqlite3"
            ledger = SessionLedger(db)
            ledger.close()

            readonly = SessionLedger(db, read_only=True)
            try:
                self.assertEqual(readonly.status()["blocks"], 0)
            finally:
                readonly.close()

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_session_ledger_rejects_group_writable_database_directory(self):
        with TemporaryDirectory() as tmp:
            db_dir = Path(tmp) / "sessions"
            db_dir.mkdir()
            db_dir.chmod(0o777)

            try:
                with self.assertRaisesRegex(ValueError, "group/world writable"):
                    SessionLedger(db_dir / "sessions.sqlite3")
            finally:
                db_dir.chmod(0o700)

    def test_scan_once_starts_at_head_for_new_forward_recorder(self):
        blocks = [block(30), block(31, ["FlipLotteryStarted"])]
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            recorder = SessionRecorder(
                ledger=ledger,
                client=FakeClient(blocks),
                poll_interval=1,
                max_blocks_per_pass=10,
                fetch_transactions=False,
            )
            result = recorder.scan_once()
            self.assertEqual(result["fromHeight"], 31)
            self.assertEqual(result["toHeight"], 31)
            self.assertEqual(ledger.status()["blocks"], 1)
            ledger.close()

    def test_scan_once_skips_when_node_is_syncing(self):
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            recorder = SessionRecorder(
                ledger=ledger,
                client=FakeClient([block(40)], syncing=True, current_block=40, highest_block=41),
                poll_interval=1,
                max_blocks_per_pass=10,
                fetch_transactions=False,
            )
            result = recorder.scan_once()
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(ledger.status()["blocks"], 0)
            ledger.close()

    def test_scan_once_treats_stale_syncing_boolean_at_head_as_ready(self):
        with TemporaryDirectory() as tmp:
            ledger = SessionLedger(Path(tmp) / "sessions.sqlite3")
            recorder = SessionRecorder(
                ledger=ledger,
                client=FakeClient([block(40)], syncing=True, current_block=40, highest_block=40),
                poll_interval=1,
                max_blocks_per_pass=10,
                fetch_transactions=False,
            )
            result = recorder.scan_once()
            self.assertEqual(result["status"], "scanned")
            self.assertEqual(ledger.status()["blocks"], 1)
            ledger.close()


if __name__ == "__main__":
    unittest.main()
