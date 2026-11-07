# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Python3.12 -I -B tests/native/runtime_build_cold_envelope_data_test.py; pure DATA only."""
import configparser
import sys
import unittest
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers/runtime-build"))
from cold_envelope_data import (
    UNIT, ColdDataError, Events, Phase, UnitState, parse_events, parse_unit, slice_name, validated_name,
)

RUN: Final = "ab" * 16
NAME: Final = "wk" + RUN + "b7prepare.slice"
RECORD: Final = (
    b"Id=observed.slice\nNames=observed.slice alias.slice\nLoadState=loaded\n"
    b"ActiveState=active\nSubState=active\nFragmentPath=/units/observed.slice\n"
    b"DropInPaths=\nControlGroup=/user.slice/observed.slice\nInvocationID=0123456789abcdef\n"
    b"CPUQuotaPerSecUSec=2s\nMemoryMax=2147483648\nMemorySwapMax=0\nTasksMax=256\nTransient=no\n"
)


class ColdDataTests(unittest.TestCase):
    def test_names_accept_both_phases_and_generation_edges(self) -> None:
        phases: tuple[Phase, ...] = ("prepare", "offline")
        for phase in phases:
            for generation in (1, 7, 9999999999999999):
                expected = "wk" + RUN + "b" + str(generation) + phase + ".slice"
                with self.subTest(phase=phase, generation=generation):
                    self.assertEqual(slice_name(RUN, generation, phase), expected)
                    self.assertEqual(validated_name(expected), expected)

    def test_names_refuse_parent_expansion_and_noncanonical_shapes(self) -> None:
        cases = (
            "", NAME + "\n", NAME + "\0", NAME + "\r", NAME + "/../foreign",
            NAME.replace("wk", "wk-", 1), NAME.replace(RUN, RUN.upper()),
            NAME.replace("b7", "b0"), NAME.replace("b7", "b07"),
            NAME.replace("b7", "b12345678901234567"), NAME.replace("prepare", "input"),
            NAME.replace(".slice", r"\x2eslice"), NAME.replace(RUN, RUN[:-1]),
            NAME.replace("prepare", "prépare"), "/" + NAME,
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(ColdDataError) as caught:
                    validated_name(raw)
                self.assertEqual(caught.exception.reason, "cold_slice_name")

    def test_name_boundaries_refuse_mismatched_types_and_invalid_components(self) -> None:
        for raw in (None, b"name", 7, True):
            with self.subTest(raw=raw):
                self.assertRaises(ColdDataError, validated_name, raw)
        for run in ("", RUN.upper(), RUN + "a", b"ab" * 16, None):
            with self.subTest(run=run):
                self.assertRaises(ColdDataError, slice_name, run, 7, "prepare")
        for generation in (0, -1, 10000000000000000, True, 7.0, "7", None):
            with self.subTest(generation=generation):
                self.assertRaises(ColdDataError, slice_name, RUN, generation, "prepare")
        for phase in ("input", "prepare\n", b"prepare", None, True):
            with self.subTest(phase=phase):
                self.assertRaises(ColdDataError, slice_name, RUN, 7, phase)

    def test_unit_config_enforces_phase_resource_ceilings_without_execution(self) -> None:
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(UNIT.decode("ascii"))
        self.assertEqual(config.sections(), ["Unit", "Slice"])
        self.assertEqual(set(config["Unit"]), {"description"})
        self.assertEqual(dict(config["Slice"]), {
            "cpuquota": "200%", "memorymax": "2147483648", "memoryswapmax": "0", "tasksmax": "256",
        })

    def test_unit_properties_preserve_data_in_either_order(self) -> None:
        expected = UnitState(
            name="observed.slice", names="observed.slice alias.slice", load="loaded", active="active",
            sub="active", fragment="/units/observed.slice", dropins="", group="/user.slice/observed.slice",
            invocation="0123456789abcdef", quota="2s", memory="2147483648", swap="0", tasks="256",
            transient="no",
        )
        reversed_record = b"\n".join(reversed(RECORD[:-1].split(b"\n"))) + b"\n"
        for raw in (RECORD, reversed_record):
            with self.subTest(raw=raw):
                self.assertEqual(parse_unit(raw), expected)
        self.assertEqual(parse_unit(RECORD.replace(b"LoadState=loaded", b"LoadState=foreign")).load, "foreign")

    def test_unit_records_refuse_missing_duplicate_unknown_and_bad_framing(self) -> None:
        cases = (
            b"", RECORD[:-1], RECORD + b"\n", b"\n" + RECORD,
            RECORD + b"Id=other.slice\n", RECORD + b"Unknown=value\n",
            RECORD.replace(b"Names=observed.slice alias.slice\n", b""),
            RECORD.replace(b"TasksMax=256", b"TasksMax 256"),
            RECORD.replace(b"TasksMax=256", b"TasksMax =256"),
            RECORD.replace(b"Transient=no", b"Transient=no\r"),
            RECORD.replace(b"Id=observed.slice", b"Id=observed\0.slice"),
            RECORD.replace(b"Id=observed.slice", b"Id=observed\xff.slice"),
            RECORD.replace(b"Names=observed.slice alias.slice", b"Names=observed\talias"),
        )
        for raw in cases:
            with self.subTest(raw=raw[:60]):
                self.assertRaises(ColdDataError, parse_unit, raw)

    def test_unit_bound_is_inclusive_and_raw_types_are_strict(self) -> None:
        at_bound = RECORD.replace(b"DropInPaths=", b"DropInPaths=" + b"x" * (65536 - len(RECORD)))
        self.assertEqual(parse_unit(at_bound).dropins, "x" * (65536 - len(RECORD)))
        for raw in (at_bound + b"\n", "Id=text\n", bytearray(RECORD), None, 7):
            with self.subTest(kind=type(raw).__name__):
                self.assertRaises(ColdDataError, parse_unit, raw)

    def test_events_preserve_all_boolean_pairs_in_either_order(self) -> None:
        for populated in (0, 1):
            for frozen in (0, 1):
                lines = (f"populated {populated}", f"frozen {frozen}")
                for ordered in (lines, tuple(reversed(lines))):
                    with self.subTest(populated=populated, frozen=frozen, ordered=ordered):
                        raw = ("\n".join(ordered) + "\n").encode("ascii")
                        self.assertEqual(parse_events(raw), Events(bool(populated), bool(frozen)))

    def test_events_refuse_missing_duplicate_unknown_and_noncanonical_fields(self) -> None:
        valid = b"populated 0\nfrozen 1\n"
        cases = (
            b"", b"populated 0\n", b"frozen 1\n", valid[:-1], valid + b"\n",
            valid + b"populated 0\n", valid + b"frozen 1\n", valid + b"unknown 0\n",
            b"populated 0\npopulated 1\n", b"frozen 0\nfrozen 1\n",
            valid.replace(b"0", b"2"), valid.replace(b"1", b"01"),
            valid.replace(b"0", b"true"), valid.replace(b"populated ", b"populated  "),
            valid.replace(b"populated ", b"populated\t"), valid.replace(b"frozen", b"Frozen"),
            valid.replace(b"0", b"0\r"), valid.replace(b"0", b"0\0"),
            valid.replace(b"0", b"\xff"), valid.replace(b"0", b"0 "),
            b"x" * 64 + b"\n",
        )
        for raw in cases:
            with self.subTest(raw=raw[:60]):
                self.assertRaises(ColdDataError, parse_events, raw)
        for raw in ("populated 0\nfrozen 1\n", bytearray(valid), None, False):
            with self.subTest(kind=type(raw).__name__):
                self.assertRaises(ColdDataError, parse_events, raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
