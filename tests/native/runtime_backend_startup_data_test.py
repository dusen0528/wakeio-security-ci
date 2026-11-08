# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B this file; no controller or workload is started.
"""Original-service startup framing and arithmetic DATA, not live clock qualification."""
from __future__ import annotations

import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-controller"))
from backend_startup_data import ClockProfile, StartupBudget, StartupDataError, cutoff_ns, parse_initialization


class StartupDataTests(unittest.TestCase):
    def test_closed_record_accepts_integer_budget_in_either_key_order(self) -> None:
        cases = ((b'{"v":1,"remainingMs":1}\n', 1),
                 (b'{"remainingMs":900000,"v":1}\n', 900000))
        for packet, expected in cases:
            with self.subTest(packet=packet):
                self.assertEqual(parse_initialization(packet).remaining_ms, expected)

    def test_record_bound_includes_the_only_final_linefeed(self) -> None:
        body = b'{"v":1,"remainingMs":7}'
        exact = body + b" " * (127 - len(body)) + b"\n"
        self.assertEqual(parse_initialization(exact).remaining_ms, 7)
        with self.assertRaises(StartupDataError):
            parse_initialization(body + b" " * (128 - len(body)) + b"\n")

    def test_framing_refuses_truncation_second_records_and_non_ascii(self) -> None:
        record = b'{"v":1,"remainingMs":7}\n'
        for packet in (b"", record[:-1], record + record, record + b"x", record + b"\n",
                       b'{"v":1,\n"remainingMs":7}\n', b'{"v":1,"remainingMs":7,"x":"\xff"}\n'):
            with self.subTest(packet=packet), self.assertRaises(StartupDataError):
                parse_initialization(packet)

    def test_closed_schema_refuses_duplicates_types_and_imported_authority(self) -> None:
        records = (
            b'{"v":1,"v":1}\n', b'{"remainingMs":7,"remainingMs":8}\n',
            b'{"v":1,"v":1,"remainingMs":7}\n', b'{"v":1,"remainingMs":7,"remainingMs":8}\n',
            b'{"v":1,"remainingMs":7,"deadline":9}\n', b'{"v":1,"remainingMs":7,"profile":true}\n',
            b'{"v":true,"remainingMs":7}\n', b'{"v":1.0,"remainingMs":7}\n',
            b'{"v":"1","remainingMs":7}\n', b'{"v":2,"remainingMs":7}\n',
            b'{"v":1,"remainingMs":true}\n', b'{"v":1,"remainingMs":1.0}\n',
            b'{"v":1,"remainingMs":"7"}\n', b'{"v":1,"remainingMs":0}\n',
            b'{"v":1,"remainingMs":-1}\n', b'{"v":1,"remainingMs":900001}\n',
            b'{"v":1,"remainingMs":null}\n', b'{"v":1,"remainingMs":{}}\n',
            b'{"v":1,"remainingMs":NaN}\n', b'{"v":1,"remainingMs":Infinity}\n',
            b'[["v",1],["remainingMs",7]]\n', b'null\n', b'1\n', b'"record"\n',
        )
        for packet in records:
            with self.subTest(packet=packet), self.assertRaises(StartupDataError):
                parse_initialization(packet)

    def test_parsed_budget_cannot_be_rewritten_into_a_renewed_allowance(self) -> None:
        budget = parse_initialization(b'{"v":1,"remainingMs":7}\n')
        with self.assertRaises(FrozenInstanceError):
            setattr(budget, "remaining_ms", 900000)
        self.assertEqual(cutoff_ns(13, budget, ClockProfile(1, 1, 0)), 7000013)

    def test_cutoff_uses_original_anchor_exact_fraction_and_earlier_rounding(self) -> None:
        cases = ((17, 1, ClockProfile(2, 3, 1), 666682),
                 (900, 101, ClockProfile(3, 4, 11), 75750889),
                 (55, 900000, ClockProfile(1, 1, 23), 900000000032),
                 (100, 1, ClockProfile(1, 1000001, 200), -100))
        for anchor, remaining, profile, expected in cases:
            with self.subTest(anchor=anchor, remaining=remaining, profile=profile):
                self.assertEqual(cutoff_ns(anchor, StartupBudget(remaining), profile), expected)

    def test_arithmetic_records_refuse_nonpositive_ratios_and_negative_margin(self) -> None:
        for values in ((0, 1, 0), (1, 0, 0), (-1, 1, 0), (1, 1, -1), (True, 1, 0)):
            with self.subTest(values=values), self.assertRaises(StartupDataError):
                ClockProfile(*values)
        for anchor in (-1, True):
            with self.subTest(anchor=anchor), self.assertRaises(StartupDataError):
                cutoff_ns(anchor, StartupBudget(1), ClockProfile(1, 1, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
