import base64
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-experiment-1-wallet-acceptance.py"
SPEC = importlib.util.spec_from_file_location("pohw_wallet_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def encode_map(entries):
    result = bytearray()
    for key, value in entries:
        result.extend(MODULE.write_compact_size(len(key)))
        result.extend(key)
        result.extend(MODULE.write_compact_size(len(value)))
        result.extend(value)
    result.append(0)
    return bytes(result)


class Experiment1WalletAcceptanceTests(unittest.TestCase):
    inherited = ("11" * 32, 3)
    marker = ("22" * 32, 7)

    def unsigned_transaction(self):
        inputs = [self.inherited, self.marker]
        result = bytearray(bytes.fromhex("02000000"))
        result.extend(MODULE.write_compact_size(len(inputs)))
        for outpoint in inputs:
            result.extend(MODULE.outpoint_bytes(outpoint))
            result.append(0)
            result.extend(bytes.fromhex("fdffffff"))
        result.append(1)
        result.extend((50_000).to_bytes(8, "little"))
        result.extend(b"\x01\x51")
        result.extend(bytes.fromhex("00000000"))
        return bytes(result)

    def psbt(self, input_maps):
        unsigned = self.unsigned_transaction()
        data = bytearray(b"psbt\xff")
        data.extend(encode_map([(b"\x00", unsigned)]))
        for entries in input_maps:
            data.extend(encode_map(entries))
        data.extend(encode_map([]))
        return base64.b64encode(data).decode("ascii")

    def test_extracts_core_finalized_legacy_input_and_empty_marker(self):
        psbt = self.psbt([[(b"\x07", b"\x01\x02")], []])
        raw = bytes.fromhex(
            MODULE.extract_marker_finalized_transaction(
                psbt,
                [self.inherited, self.marker],
                marker_input_index=1,
            )
        )

        self.assertEqual(raw[:4], bytes.fromhex("02000000"))
        self.assertNotEqual(raw[4:6], b"\x00\x01")
        first_outpoint = 5
        first_script_length = first_outpoint + 36
        self.assertEqual(raw[first_script_length : first_script_length + 3], b"\x02\x01\x02")
        second_outpoint = first_script_length + 3 + 4
        second_script_length = second_outpoint + 36
        self.assertEqual(raw[second_script_length], 0)

    def test_extracts_witness_input_without_inventing_marker_witness(self):
        final_witness = b"\x02\x01\xaa\x02\xbb\xcc"
        psbt = self.psbt([[(b"\x08", final_witness)], []])
        raw = bytes.fromhex(
            MODULE.extract_marker_finalized_transaction(
                psbt,
                [self.inherited, self.marker],
                marker_input_index=1,
            )
        )

        self.assertEqual(raw[4:6], b"\x00\x01")
        self.assertIn(final_witness + b"\x00" + bytes.fromhex("00000000"), raw)

    def test_rejects_unfinalized_non_marker_input(self):
        with self.assertRaisesRegex(MODULE.AcceptanceError, "non-marker PSBT input"):
            MODULE.extract_marker_finalized_transaction(
                self.psbt([[], []]),
                [self.inherited, self.marker],
                marker_input_index=1,
            )

    def test_rejects_any_nonempty_marker_final_data(self):
        psbt = self.psbt([[(b"\x07", b"\x51")], [(b"\x07", b"\x00")]])
        with self.assertRaisesRegex(MODULE.AcceptanceError, "marker input"):
            MODULE.extract_marker_finalized_transaction(
                psbt,
                [self.inherited, self.marker],
                marker_input_index=1,
            )

    def test_rejects_reordered_or_replaced_inputs(self):
        psbt = self.psbt([[(b"\x07", b"\x51")], []])
        with self.assertRaisesRegex(MODULE.AcceptanceError, "order or outpoint"):
            MODULE.extract_marker_finalized_transaction(
                psbt,
                [self.marker, self.inherited],
                marker_input_index=1,
            )

    def test_rejects_changed_unsigned_transaction(self):
        psbt = self.psbt([[(b"\x07", b"\x51")], []])
        expected, _ = MODULE.decode_psbt(psbt)
        changed = MODULE.UnsignedTransaction(
            version=expected.version,
            inputs=expected.inputs,
            outputs=(MODULE.TxOutput(value=(49_999).to_bytes(8, "little"), script=b"\x51"),),
            locktime=expected.locktime,
        )
        with self.assertRaisesRegex(MODULE.AcceptanceError, "changed the unsigned"):
            MODULE.extract_marker_finalized_transaction(
                psbt,
                [self.inherited, self.marker],
                marker_input_index=1,
                expected_transaction=changed,
            )

    def test_rejects_nonzero_psbt_version(self):
        unsigned = self.unsigned_transaction()
        data = bytearray(b"psbt\xff")
        data.extend(
            encode_map(
                [
                    (b"\x00", unsigned),
                    (b"\xfb", b"\x02\x00\x00\x00"),
                ]
            )
        )
        data.extend(encode_map([]) * 3)
        with self.assertRaisesRegex(MODULE.AcceptanceError, "PSBTv0"):
            MODULE.decode_psbt(base64.b64encode(data).decode("ascii"))

    def test_psbt_parser_rejects_duplicate_map_keys(self):
        unsigned = self.unsigned_transaction()
        malformed = bytearray(b"psbt\xff")
        malformed.extend(encode_map([(b"\x00", unsigned), (b"\x00", unsigned)]))
        malformed.extend(encode_map([]) * 3)
        value = base64.b64encode(malformed).decode("ascii")
        with self.assertRaisesRegex(MODULE.AcceptanceError, "duplicate PSBT"):
            MODULE.decode_psbt(value)

    def test_compact_size_parser_rejects_noncanonical_encoding(self):
        with self.assertRaisesRegex(MODULE.AcceptanceError, "non-canonical"):
            MODULE.read_compact_size(b"\xfd\xfc\x00", 0)

    def test_amount_conversion_is_exact(self):
        self.assertEqual(MODULE.btc_to_satoshis(MODULE.Decimal("1.00000001"), "value"), 100_000_001)
        self.assertEqual(MODULE.satoshis_to_btc(100_000_001), "1.00000001")
        with self.assertRaisesRegex(MODULE.AcceptanceError, "eight decimal"):
            MODULE.btc_to_satoshis(MODULE.Decimal("0.000000001"), "value")

    def test_sensitive_rpc_arguments_are_passed_on_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "bitcoin-cli"
            cli.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            cli.chmod(0o700)
            client = MODULE.RpcClient(cli, root.resolve(), "fork-wallet")
            completed = subprocess.CompletedProcess([], 0, stdout=b"{}\n", stderr=b"")
            with mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run:
                client.call("walletprocesspsbt", "sensitive-psbt", sensitive=True)

        command = run.call_args.args[0]
        self.assertIn("-stdin", command)
        self.assertNotIn("sensitive-psbt", command)
        self.assertEqual(run.call_args.kwargs["input"], b"sensitive-psbt\n")

    def test_tool_has_no_broadcast_path_or_sensitive_success_output(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("sendrawtransaction", source)
        self.assertNotIn("print(psbt", source)
        self.assertNotIn("print(protected_raw", source)
        self.assertNotIn("--broadcast", source)
        self.assertIn('print("broadcast=false")', source)

    def test_script_is_executable(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
