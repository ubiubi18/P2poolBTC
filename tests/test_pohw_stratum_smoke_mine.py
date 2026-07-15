import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pohw-stratum-smoke-mine.py"
SPEC = importlib.util.spec_from_file_location("pohw_stratum_smoke_mine", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class StratumSmokeMineTests(unittest.TestCase):
    def test_transaction_id_strips_witness_serialization(self):
        version = bytes.fromhex("02000000")
        inputs_and_outputs = bytes.fromhex(
            "01"
            + "00" * 32
            + "ffffffff"
            + "01"
            + "00"
            + "ffffffff"
            + "01"
            + "0000000000000000"
            + "01"
            + "51"
        )
        witness = bytes.fromhex("0120" + "11" * 32)
        locktime = bytes.fromhex("00000000")
        serialized = version + bytes.fromhex("0001") + inputs_and_outputs + witness + locktime
        expected_base = version + inputs_and_outputs + locktime

        actual_base = MODULE.transaction_without_witness(serialized)

        self.assertEqual(actual_base, expected_base)
        self.assertEqual(MODULE.sha256d(actual_base), MODULE.sha256d(expected_base))
        self.assertNotEqual(MODULE.sha256d(actual_base), MODULE.sha256d(serialized))

    def test_non_witness_transaction_is_unchanged(self):
        serialized = bytes.fromhex(
            "02000000"
            + "01"
            + "00" * 32
            + "ffffffff"
            + "01"
            + "00"
            + "ffffffff"
            + "00"
            + "00000000"
        )

        self.assertEqual(MODULE.transaction_without_witness(serialized), serialized)

    def test_transaction_parser_rejects_unsafe_encodings(self):
        with self.assertRaisesRegex(MODULE.SmokeMineError, "truncated"):
            MODULE.transaction_without_witness(b"\x00" * 9)
        with self.assertRaisesRegex(MODULE.SmokeMineError, "unsupported witness flag"):
            MODULE.transaction_without_witness(bytes.fromhex("020000000002") + b"\x00" * 8)
        with self.assertRaisesRegex(MODULE.SmokeMineError, "non-canonical"):
            MODULE.transaction_without_witness(bytes.fromhex("02000000fdfc00") + b"\x00" * 8)

    def test_error_summary_redacts_sensitive_runtime_values(self):
        summary = MODULE._stratum_error_summary(
            [
                20,
                "failed 127.0.0.1:3333 "
                + "ab" * 32
                + " 0x"
                + "cd" * 20
                + " /srv/private/file token=do-not-print",
                None,
            ]
        )

        self.assertIn("code=20", summary)
        self.assertIn("<ip>", summary)
        self.assertIn("<hex>", summary)
        self.assertIn("<address>", summary)
        self.assertIn("<path>", summary)
        self.assertIn("token=<redacted>", summary)
        self.assertNotIn("do-not-print", summary)

    def test_error_summary_is_bounded_and_handles_malformed_errors(self):
        summary = MODULE._stratum_error_summary([True, "x" * 1_000])

        self.assertIn("code=unknown", summary)
        self.assertLessEqual(
            len(summary),
            len("Stratum error code=unknown: ") + MODULE.MAX_ERROR_SUMMARY_CHARS,
        )
        self.assertEqual(
            MODULE._stratum_error_summary({"message": "bad"}),
            "malformed Stratum error",
        )

    def test_allow_no_solution_only_accepts_bounded_exhaustion(self):
        original_argv = sys.argv
        original_mine_one = MODULE.mine_one
        try:
            sys.argv = [str(SCRIPT), "--allow-no-solution"]
            MODULE.mine_one = lambda *_args: (_ for _ in ()).throw(
                MODULE.SmokeMineError(
                    "hash limit reached without a block-valid share"
                )
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(MODULE.main(), 0)
            self.assertIn("completed without an accepted block", output.getvalue())

            MODULE.mine_one = lambda *_args: (_ for _ in ()).throw(
                MODULE.SmokeMineError("Stratum authorization failed")
            )
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(MODULE.main(), 1)
        finally:
            MODULE.mine_one = original_mine_one
            sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
