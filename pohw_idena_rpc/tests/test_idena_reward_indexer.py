import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pohw_idena_rpc import idena_rpc_client_minimal
from pohw_idena_rpc import idena_reward_indexer as reward_indexer
from pohw_idena_rpc.idena_rpc_client_minimal import IdenaRPCClientMinimal, IdenaRPCError
from pohw_idena_rpc.idena_reward_indexer import (
    Delta,
    Position,
    RewardLedger,
    atoms_to_decimal_string,
    classify_delta,
    collapse_rolling_changes,
    decimal_to_atoms,
    sync_official_indexer_rewards,
    validate_rpc_url,
)


class FakeRpcResponse:
    def __init__(self, *, body: bytes, status: int = 200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getcode(self):
        return self.status

    def getheader(self, name: str):
        return self.headers.get(name)

    def read(self, size: int = -1):
        if size is None or size < 0:
            return self.body
        return self.body[:size]


class RewardIndexerTests(unittest.TestCase):
    def test_decimal_roundtrip(self):
        atoms = decimal_to_atoms("1.234567890123456789")
        self.assertEqual(atoms, 1234567890123456789)
        self.assertEqual(atoms_to_decimal_string(atoms), "1.234567890123456789")

    def test_rpc_url_must_be_loopback_by_default(self):
        self.assertEqual(validate_rpc_url("http://127.0.0.1:9009"), "http://127.0.0.1:9009")
        self.assertEqual(validate_rpc_url("http://localhost:9009"), "http://localhost:9009")
        with self.assertRaisesRegex(ValueError, "loopback"):
            validate_rpc_url("http://198.51.100.10:9009")
        self.assertEqual(
            validate_rpc_url("http://198.51.100.10:9009", allow_remote_rpc=True),
            "http://198.51.100.10:9009",
        )

    def test_main_rejects_remote_rpc_before_client_setup(self):
        with TemporaryDirectory() as tmp:
            with patch.object(reward_indexer, "IdenaRPCClientMinimal") as client:
                code = reward_indexer.main(
                    [
                        "--db",
                        str(Path(tmp) / "rewards.sqlite3"),
                        "--rpc-url",
                        "http://198.51.100.10:9009",
                        "once",
                    ]
                )

        self.assertEqual(code, 2)
        client.assert_not_called()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_reward_ledger_rejects_symlink_ancestor_database_path(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real"
            child_dir = real_dir / "child"
            link_dir = base / "link"
            child_dir.mkdir(parents=True)
            os.symlink(real_dir, link_dir)

            with self.assertRaisesRegex(ValueError, "unsafe symlink ancestor"):
                RewardLedger(link_dir / "child" / "rewards.sqlite3")
            self.assertFalse((child_dir / "rewards.sqlite3").exists())

    def test_reward_ledger_readonly_uri_escapes_question_mark_path(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards?ledger.sqlite3"
            ledger = RewardLedger(db)
            ledger.close()

            readonly = RewardLedger(db, read_only=True)
            try:
                self.assertEqual(readonly.status()["events"], 0)
            finally:
                readonly.close()

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_reward_ledger_rejects_group_writable_database_directory(self):
        with TemporaryDirectory() as tmp:
            db_dir = Path(tmp) / "rewards"
            db_dir.mkdir()
            db_dir.chmod(0o777)

            try:
                with self.assertRaisesRegex(ValueError, "group/world writable"):
                    RewardLedger(db_dir / "rewards.sqlite3")
            finally:
                db_dir.chmod(0o700)

    def test_locked_stake_increase_is_invitation_liability(self):
        kind, direction, confidence, _ = classify_delta(
            address="0xabc",
            delta=Delta(stake_atoms=100, locked_stake_atoms=100),
            old_state="Newbie",
            new_state="Newbie",
            block={"height": 1, "coinbase": "0xdef", "flags": []},
            source="test",
        )
        self.assertEqual(kind, "invitation_locked_reward")
        self.assertEqual(direction, "credit")
        self.assertEqual(confidence, "inferred")

    def test_validation_finished_credit_is_session_reward(self):
        kind, direction, confidence, _ = classify_delta(
            address="0xabc",
            delta=Delta(balance_atoms=10, stake_atoms=20),
            old_state="Verified",
            new_state="Human",
            block={"height": 1, "coinbase": "0xdef", "flags": ["ValidationFinished"]},
            source="test",
        )
        self.assertEqual(kind, "session_reward")
        self.assertEqual(direction, "credit")
        self.assertEqual(confidence, "inferred")

    def test_coinbase_credit_is_mining_reward(self):
        kind, _, _, _ = classify_delta(
            address="0xabc",
            delta=Delta(balance_atoms=10),
            old_state="Human",
            new_state="Human",
            block={"height": 1, "coinbase": "0xAbC", "flags": []},
            source="test",
        )
        self.assertEqual(kind, "mining_proposer_reward")

    def test_collapse_rolling_changes_uses_current_position_as_old_value(self):
        current = Position(
            address="0xabc",
            epoch=211,
            state="Human",
            age=10,
            balance_atoms=decimal_to_atoms("10"),
            stake_atoms=decimal_to_atoms("20"),
            replenished_stake_atoms=0,
            locked_stake_atoms=0,
            delegatee="",
            inviter_address="",
            inviter_tx_hash="",
            invite_epoch_height=None,
            updated_height=1,
            updated_at="now",
            raw={},
        )
        changes = collapse_rolling_changes(
            [
                {"changes": {"balance": ["1", "11"]}},
                {"changes": {"balance": ["1", "12"], "stake": ["2", "21"]}},
            ],
            current,
        )
        self.assertEqual(changes["balance"], ["10", "12"])
        self.assertEqual(changes["stake"], ["20", "21"])

    def test_export_replay_events_maps_only_positive_credit_rewards(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            ledger = RewardLedger(db)
            base_event = {
                "id": "1",
                "address": "0xABC",
                "epoch": 211,
                "height": 10,
                "block_hash": "0xhash",
                "timestamp": "2026-07-03T00:00:00Z",
                "kind": "session_reward",
                "direction": "credit",
                "amount_atoms": 100,
                "balance_atoms_delta": 100,
                "stake_atoms_delta": 0,
                "replenished_stake_atoms_delta": 0,
                "locked_stake_atoms_delta": 0,
                "source": "test",
                "confidence": "inferred",
                "liability_status": "",
                "counterparty_address": "",
                "tx_hash": "",
                "notes": "",
                "raw_json": "{}",
                "created_at": "2026-07-03T00:00:00Z",
            }
            self.assertTrue(ledger.insert_event(base_event))
            self.assertTrue(
                ledger.insert_event(
                    {
                        **base_event,
                        "id": "2",
                        "kind": "mining_proposer_reward",
                        "amount_atoms": 200,
                        "balance_atoms_delta": 200,
                    }
                )
            )
            self.assertTrue(
                ledger.insert_event(
                    {
                        **base_event,
                        "id": "3",
                        "kind": "staking_or_committee_reward",
                        "amount_atoms": 300,
                        "balance_atoms_delta": 300,
                    }
                )
            )
            self.assertTrue(
                ledger.insert_event(
                    {
                        **base_event,
                        "id": "4",
                        "kind": "invitation_locked_reward",
                        "amount_atoms": 400,
                        "balance_atoms_delta": 0,
                        "locked_stake_atoms_delta": 400,
                    }
                )
            )
            self.assertTrue(
                ledger.insert_event(
                    {
                        **base_event,
                        "id": "5",
                        "kind": "balance_or_stake_reversal",
                        "direction": "debit",
                        "amount_atoms": -50,
                        "balance_atoms_delta": -50,
                    }
                )
            )
            ledger.conn.commit()
            ledger.close()

            with self.assertRaisesRegex(ValueError, "non-exact eligible reward"):
                RewardLedger(db, read_only=True).export_replay_events()
            exported = RewardLedger(db, read_only=True).export_replay_events(allow_inferred=True)

        self.assertEqual(
            [event["kind"] for event in exported],
            ["Validation", "Proposer", "FinalCommittee"],
        )
        self.assertEqual(exported[0]["idena_address"], "0xabc")
        self.assertEqual(exported[0]["amount_atoms"], 100)

    def test_export_replay_require_exact_rejects_empty_ledger(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            with self.assertRaisesRegex(ValueError, "no exact eligible reward"):
                ledger.export_replay_events(require_exact=True)
            ledger.close()

    def test_export_replay_rejects_mixed_exact_and_inferred_mode(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            with self.assertRaisesRegex(ValueError, "cannot combine"):
                ledger.export_replay_events(require_exact=True, allow_inferred=True)
            ledger.close()

    def test_import_statscollector_replay_exports_without_inferred_override(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            ledger = RewardLedger(db)
            payload = [
                {
                    "idena_address": "0x" + "a" * 40,
                    "epoch": 211,
                    "source_height": 100,
                    "source_hash": "0x" + "1" * 64,
                    "kind": "Validation",
                    "balance": "1.25",
                    "stake": "0.75",
                    "timestamp": 1710000000,
                },
                {
                    "address": "0x" + "b" * 40,
                    "epoch": 211,
                    "block_height": 101,
                    "block_hash": "0x" + "2" * 64,
                    "source_table": "mining_rewards",
                    "proposer": True,
                    "balance": "0.5",
                    "stake": "0",
                },
                {
                    "address": "0x" + "c" * 40,
                    "epoch": 211,
                    "height": 102,
                    "hash": "0x" + "3" * 64,
                    "reward_type": "Invitations",
                    "balance": "0.25",
                    "stake": "0",
                },
            ]
            self.assertEqual(ledger.import_statscollector_replay_events(payload), 3)
            self.assertEqual(ledger.import_statscollector_replay_events(payload), 0)
            exported = ledger.export_replay_events()
            ledger.close()

        self.assertEqual(
            [event["kind"] for event in exported],
            ["Validation", "Proposer"],
        )
        self.assertEqual(exported[0]["amount_atoms"], decimal_to_atoms("2"))
        self.assertEqual(exported[1]["amount_atoms"], decimal_to_atoms("0.5"))

    def test_import_statscollector_replay_maps_non_proposer_mining_to_final_committee(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            ledger = RewardLedger(db)
            self.assertEqual(
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "d" * 40,
                            "epoch": 211,
                            "height": 103,
                            "hash": "0x" + "4" * 64,
                            "source_table": "mining_rewards",
                            "proposer": False,
                            "amount_atoms": "42",
                        }
                    ]
                ),
                1,
            )
            exported = ledger.export_replay_events()
            ledger.close()

        self.assertEqual(exported[0]["kind"], "FinalCommittee")
        self.assertEqual(exported[0]["amount_atoms"], 42)

    def test_import_statscollector_replay_normalizes_postgres_bytea_hashes(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            ledger = RewardLedger(db)
            self.assertEqual(
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "e" * 40,
                            "epoch": 211,
                            "height": 104,
                            "hash": "\\x" + "5" * 64,
                            "tx_hash": "6" * 64,
                            "kind": "Validation",
                            "amount_atoms": "7",
                        }
                    ]
                ),
                1,
            )
            exported = ledger.export_replay_events()
            ledger.close()

        self.assertEqual(exported[0]["source_hash"], "0x" + "5" * 64)

    def test_limited_json_reader_rejects_large_replay_file(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.json"
            path.write_text("[]\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "too large"):
                reward_indexer.read_limited_json_file(path, "StatsCollector replay events", 1)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_limited_json_reader_rejects_symlink_replay_file(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.json"
            link = Path(tmp) / "events.json"
            target.write_text("[]\n", encoding="utf-8")
            os.symlink(target, link)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                reward_indexer.read_limited_json_file(
                    link,
                    "StatsCollector replay events",
                    reward_indexer.MAX_OFFICIAL_INDEXER_EXPORT_BYTES,
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_limited_json_reader_rejects_symlink_ancestor(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real"
            child_dir = real_dir / "child"
            link_dir = base / "link"
            child_dir.mkdir(parents=True)
            os.symlink(real_dir, link_dir)
            replay_file = child_dir / "events.json"
            replay_file.write_text("[]\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unsafe symlink ancestor"):
                reward_indexer.read_limited_json_file(
                    link_dir / "child" / "events.json",
                    "StatsCollector replay events",
                    reward_indexer.MAX_OFFICIAL_INDEXER_EXPORT_BYTES,
                )

    def test_sync_official_indexer_imports_psql_json_without_url_on_argv(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            sql_file = Path(tmp) / "export.sql"
            sql_file.write_text("select '[]';\n", encoding="utf-8")
            ledger = RewardLedger(db)
            database_url = "postgres://user:secret@127.0.0.1:5432/idena_indexer"
            payload = json.dumps(
                [
                    {
                        "address": "0x" + "f" * 40,
                        "epoch": 211,
                        "height": 105,
                        "hash": "0x" + "7" * 64,
                        "kind": "Validation",
                        "amount_atoms": "9",
                    }
                ]
            ).encode("utf-8")

            def fake_run(cmd, **kwargs):
                self.assertNotIn(database_url, cmd)
                self.assertEqual(kwargs["env"]["PGDATABASE"], database_url)
                self.assertIn("-f", cmd)
                return reward_indexer.subprocess.CompletedProcess(cmd, 0, payload, b"")

            with patch.object(reward_indexer.subprocess, "run", side_effect=fake_run):
                result = sync_official_indexer_rewards(
                    ledger=ledger,
                    database_url=database_url,
                    sql_file=sql_file,
                    psql_bin="psql",
                    source="test_exact",
                )
            exported = ledger.export_replay_events(require_exact=True)
            ledger.close()

        self.assertEqual(result["exportedEvents"], 1)
        self.assertEqual(result["importedEvents"], 1)
        self.assertEqual(result["lastExactRewardHeight"], 105)
        self.assertEqual(exported[0]["kind"], "Validation")
        self.assertEqual(exported[0]["amount_atoms"], 9)

    def test_sync_official_indexer_replaces_existing_source_atomically(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            sql_file = Path(tmp) / "export.sql"
            sql_file.write_text("select '[]';\n", encoding="utf-8")
            ledger = RewardLedger(db)
            self.assertEqual(
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "1" * 40,
                            "epoch": 211,
                            "height": 100,
                            "hash": "0x" + "1" * 64,
                            "kind": "Validation",
                            "amount_atoms": "1",
                        }
                    ],
                    source="test_exact",
                ),
                1,
            )
            payload = json.dumps(
                [
                    {
                        "address": "0x" + "2" * 40,
                        "epoch": 211,
                        "height": 110,
                        "hash": "0x" + "2" * 64,
                        "kind": "Proposer",
                        "amount_atoms": "2",
                    }
                ]
            ).encode("utf-8")

            with patch.object(
                reward_indexer.subprocess,
                "run",
                return_value=reward_indexer.subprocess.CompletedProcess(
                    ["psql"], 0, payload, b""
                ),
            ):
                sync_official_indexer_rewards(
                    ledger=ledger,
                    database_url="postgres://user:secret@127.0.0.1:5432/idena_indexer",
                    sql_file=sql_file,
                    source="test_exact",
                )
            exported = ledger.export_replay_events(require_exact=True)
            ledger.close()

        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["idena_address"], "0x" + "2" * 40)
        self.assertEqual(exported[0]["kind"], "Proposer")

    def test_sync_official_indexer_rejects_empty_export_before_replace(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "rewards.sqlite3"
            sql_file = Path(tmp) / "export.sql"
            sql_file.write_text("select '[]';\n", encoding="utf-8")
            ledger = RewardLedger(db)
            self.assertEqual(
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "3" * 40,
                            "epoch": 211,
                            "height": 120,
                            "hash": "0x" + "3" * 64,
                            "kind": "Validation",
                            "amount_atoms": "3",
                        }
                    ],
                    source="test_exact",
                ),
                1,
            )

            with patch.object(
                reward_indexer.subprocess,
                "run",
                return_value=reward_indexer.subprocess.CompletedProcess(
                    ["psql"], 0, b"[]", b""
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "returned no events"):
                    sync_official_indexer_rewards(
                        ledger=ledger,
                        database_url="postgres://user:secret@127.0.0.1:5432/idena_indexer",
                        sql_file=sql_file,
                        source="test_exact",
                    )
            exported = ledger.export_replay_events(require_exact=True)
            ledger.close()

        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["idena_address"], "0x" + "3" * 40)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_database_url_file_rejects_symlink_ancestor(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real"
            child_dir = real_dir / "child"
            link_dir = base / "link"
            child_dir.mkdir(parents=True)
            os.symlink(real_dir, link_dir)
            url_file = child_dir / "idena-indexer-db.url"
            url_file.write_text(
                "postgres://user:secret@127.0.0.1:5432/idena_indexer\n",
                encoding="utf-8",
            )
            url_file.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "unsafe symlink ancestor"):
                reward_indexer.load_official_indexer_database_url(
                    database_url_file=link_dir / "child" / "idena-indexer-db.url",
                    database_url_env="IDENA_INDEXER_DATABASE_URL",
                )

    def test_statscollector_replace_rolls_back_on_invalid_event(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            self.assertEqual(
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "4" * 40,
                            "epoch": 211,
                            "height": 120,
                            "hash": "0x" + "4" * 64,
                            "kind": "Validation",
                            "amount_atoms": "4",
                        }
                    ],
                    source="test_exact",
                ),
                1,
            )

            with self.assertRaisesRegex(ValueError, "invalid Idena address"):
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "5" * 40,
                            "epoch": 211,
                            "height": 130,
                            "hash": "0x" + "5" * 64,
                            "kind": "Proposer",
                            "amount_atoms": "5",
                        },
                        {
                            "address": "0xabc",
                            "epoch": 211,
                            "height": 131,
                            "hash": "0x" + "6" * 64,
                            "kind": "Validation",
                            "amount_atoms": "6",
                        },
                    ],
                    source="test_exact",
                    replace_source=True,
                )
            exported = ledger.export_replay_events(require_exact=True)
            ledger.close()

        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["idena_address"], "0x" + "4" * 40)
        self.assertEqual(exported[0]["kind"], "Validation")

    def test_import_statscollector_replay_rejects_invalid_address(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            with self.assertRaisesRegex(ValueError, "invalid Idena address"):
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0xabc",
                            "epoch": 211,
                            "height": 100,
                            "hash": "0x" + "1" * 64,
                            "kind": "Validation",
                            "amount_atoms": 1,
                        }
                    ]
                )
            ledger.close()

    def test_import_statscollector_replay_rejects_invalid_source_hash(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            with self.assertRaisesRegex(ValueError, "source_hash must be a 32-byte hex hash"):
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "a" * 40,
                            "epoch": 211,
                            "height": 100,
                            "hash": "not-a-hash",
                            "kind": "Validation",
                            "amount_atoms": 1,
                        }
                    ]
                )
            ledger.close()

    def test_import_statscollector_replay_rejects_invalid_tx_hash(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            with self.assertRaisesRegex(ValueError, "tx_hash must be a 32-byte hex hash"):
                ledger.import_statscollector_replay_events(
                    [
                        {
                            "address": "0x" + "a" * 40,
                            "epoch": 211,
                            "height": 100,
                            "hash": "0x" + "1" * 64,
                            "tx_hash": "0x1234",
                            "kind": "Validation",
                            "amount_atoms": 1,
                        }
                    ]
                )
            ledger.close()

    def test_rpc_client_reads_protected_api_key_file(self):
        with TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "api.key"
            key_file.write_text("secret-key\n", encoding="utf-8")
            key_file.chmod(0o600)

            client = IdenaRPCClientMinimal(
                url="http://127.0.0.1:9009",
                api_key_file=str(key_file),
            )

        self.assertEqual(client.api_key, "secret-key")

    def test_rpc_client_ignores_api_key_environment_secret(self):
        with patch.dict("os.environ", {"IDENA_API_KEY": "secret-key"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "IDENA_API_KEY_FILE"):
                IdenaRPCClientMinimal(url="http://127.0.0.1:9009")

    def test_rpc_client_rejects_permissive_api_key_file(self):
        with TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "api.key"
            key_file.write_text("secret-key\n", encoding="utf-8")
            key_file.chmod(0o644)

            with self.assertRaisesRegex(RuntimeError, "too permissive"):
                IdenaRPCClientMinimal(
                    url="http://127.0.0.1:9009",
                    api_key_file=str(key_file),
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_rpc_client_rejects_api_key_file_under_symlink_parent(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real"
            link_dir = base / "link"
            real_dir.mkdir()
            os.symlink(real_dir, link_dir)
            key_file = real_dir / "api.key"
            key_file.write_text("secret-key\n", encoding="utf-8")
            key_file.chmod(0o600)

            with self.assertRaisesRegex(RuntimeError, "parent directory must not be a symlink"):
                IdenaRPCClientMinimal(
                    url="http://127.0.0.1:9009",
                    api_key_file=str(link_dir / "api.key"),
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_rpc_client_rejects_api_key_file_under_symlink_ancestor(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real"
            link_dir = base / "link"
            child_dir = real_dir / "child"
            child_dir.mkdir(parents=True)
            os.symlink(real_dir, link_dir)
            key_file = child_dir / "api.key"
            key_file.write_text("secret-key\n", encoding="utf-8")
            key_file.chmod(0o600)

            with self.assertRaisesRegex(RuntimeError, "unsafe symlink ancestor"):
                IdenaRPCClientMinimal(
                    url="http://127.0.0.1:9009",
                    api_key_file=str(link_dir / "child" / "api.key"),
                )

    def test_rpc_client_rejects_oversized_content_length(self):
        client = IdenaRPCClientMinimal(url="http://127.0.0.1:9009", api_key="secret-key")
        response = FakeRpcResponse(body=b"{}", headers={"Content-Length": "9"})

        with patch.object(idena_rpc_client_minimal, "MAX_IDENA_RPC_RESPONSE_BYTES", 8):
            with patch("urllib.request.urlopen", return_value=response):
                with self.assertRaisesRegex(IdenaRPCError, "too large"):
                    client.call("dna_epoch")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_rolling_import_rejects_symlink_snapshot_file(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            snapshots = base / "snapshots"
            snapshots.mkdir()
            target = base / "target_snapshot.json"
            target.write_text('{"startBlock":1,"identities":{}}\n', encoding="utf-8")
            os.symlink(target, snapshots / "epoch_1_snapshot.json")
            ledger = RewardLedger(base / "rewards.sqlite3")
            indexer = reward_indexer.RewardIndexer(
                ledger=ledger,
                client=None,
                rolling_data_dir=base,
                poll_interval=1,
            )

            try:
                with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                    indexer.import_rolling_epoch(1, with_block_lookup=False)
            finally:
                ledger.close()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_rolling_import_rejects_symlink_delta_file(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            deltas = base / "deltas"
            deltas.mkdir()
            target = base / "target_deltas.jsonl"
            target.write_text("", encoding="utf-8")
            os.symlink(target, deltas / "epoch_1_deltas.jsonl")
            ledger = RewardLedger(base / "rewards.sqlite3")
            indexer = reward_indexer.RewardIndexer(
                ledger=ledger,
                client=None,
                rolling_data_dir=base,
                poll_interval=1,
            )

            try:
                with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                    indexer.import_rolling_epoch(1, with_block_lookup=False)
            finally:
                ledger.close()

    def test_reward_indexer_batch_rejects_oversized_rpc_body(self):
        with TemporaryDirectory() as tmp:
            ledger = RewardLedger(Path(tmp) / "rewards.sqlite3")
            client = IdenaRPCClientMinimal(url="http://127.0.0.1:9009", api_key="secret-key")
            indexer = reward_indexer.RewardIndexer(
                ledger=ledger,
                client=client,
                rolling_data_dir=Path(tmp),
                poll_interval=1,
            )
            response = FakeRpcResponse(body=b"x" * 9)

            try:
                with patch.object(idena_rpc_client_minimal, "MAX_IDENA_RPC_RESPONSE_BYTES", 8):
                    with patch("urllib.request.urlopen", return_value=response):
                        with self.assertRaisesRegex(IdenaRPCError, "too large"):
                            indexer.batch_call([("dna_epoch", [])])
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
