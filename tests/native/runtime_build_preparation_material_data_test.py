# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Run: pinned Python3.12 -I -B this file. Fixed command DATA only; no child or owner is created."""
from __future__ import annotations

import io
import json
import struct
import sys
import unittest
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "workers/runtime-build"), str(ROOT / "workers/runtime-controller")]
from backend_process import BackendError
from launch import LaunchError, read_selection
from preparation_material_data import MaterialFrame, MaterialKind, Operation, command, parse_frame

RUN: Final = "ab" * 16
ID: Final = "cd" * 32
PREFIX: Final = ("/usr/bin/docker", "--host=unix:///run/user/10001/docker.sock")
IMAGE: Final = "docker.io/library/maven@sha256:65cedfb84cfbb1dc9974c14662d6bf9b20aa6aea274c877fe08952bdfae7992f"


class MaterialDataTests(unittest.TestCase):
    def test_names_and_labels_bind_each_role_and_generation_boundary(self) -> None:
        kinds: tuple[MaterialKind, ...] = ("work", "cache", "output")
        for generation in (1, 7, 9999999999999999):
            frame = MaterialFrame(RUN, generation, "carrier-create", None)
            for kind in kinds:
                with self.subTest(generation=generation, kind=kind):
                    self.assertEqual(frame.name(kind), f"wk-{RUN}-b{generation}-prepare-{kind}")
                    self.assertEqual(frame.labels(kind), {
                        "wakeio.owner": "t6-build", "wakeio.run": RUN, "wakeio.generation": str(generation),
                        "wakeio.scope": "build", "wakeio.role": "prepare-" + kind,
                    })

    def test_fixed_carrier_argv_has_only_three_nocopy_mounts_and_pinned_security(self) -> None:
        expected = (
            *PREFIX, "create", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=65532:65532", "--cpus=2",
            "--memory=2147483648", "--memory-swap=2147483648", "--pids-limit=256",
            "--label=wakeio.owner=t6-build", "--label=wakeio.run=" + RUN, "--label=wakeio.generation=7",
            "--label=wakeio.scope=build", "--label=wakeio.role=prepare-transfer",
            f"--mount=type=volume,src=wk-{RUN}-b7-prepare-work,dst=/work,volume-nocopy",
            f"--mount=type=volume,src=wk-{RUN}-b7-prepare-cache,dst=/cache,volume-nocopy",
            f"--mount=type=volume,src=wk-{RUN}-b7-prepare-output,dst=/output,volume-nocopy",
            "--entrypoint=/bin/false", IMAGE,
        )
        self.assertEqual(command(MaterialFrame(RUN, 7, "carrier-create", None)), expected)

    def test_volume_and_transfer_commands_are_closed_machine_protocol_data(self) -> None:
        cases: tuple[tuple[Operation, str | None, tuple[str, ...]], ...] = (
            ("volume-create-work", None, ("volume", "create", "--driver=local",
             "--label=wakeio.owner=t6-build", "--label=wakeio.run=" + RUN, "--label=wakeio.generation=7",
             "--label=wakeio.scope=build", "--label=wakeio.role=prepare-work", f"wk-{RUN}-b7-prepare-work")),
            ("volume-inspect-cache", None, ("volume", "inspect", f"wk-{RUN}-b7-prepare-cache")),
            ("volume-remove-output", None, ("volume", "rm", f"wk-{RUN}-b7-prepare-output")),
            ("carrier-inspect", ID, ("container", "inspect", ID)),
            ("carrier-remove", ID, ("container", "rm", ID)),
            ("seed", ID, ("cp", "--archive", "-", ID + ":/")),
            ("read-work", ID, ("cp", "--archive", ID + ":/work", "-")),
            ("read-cache", ID, ("cp", "--archive", ID + ":/cache", "-")),
            ("read-output", ID, ("cp", "--archive", ID + ":/output", "-")),
        )
        for selected, container, suffix in cases:
            with self.subTest(operation=selected):
                self.assertEqual(command(MaterialFrame(RUN, 7, selected, container)), (*PREFIX, *suffix))

    def test_exact_operations_separate_cleanup_mutation_and_read_data(self) -> None:
        rows: tuple[tuple[Operation, str | None, bool, bool], ...] = (
            ("volume-create-work", None, False, True), ("volume-inspect-work", None, True, False),
            ("volume-remove-work", None, True, True), ("volume-create-cache", None, False, True),
            ("volume-inspect-cache", None, True, False), ("volume-remove-cache", None, True, True),
            ("volume-create-output", None, False, True), ("volume-inspect-output", None, True, False),
            ("volume-remove-output", None, True, True), ("carrier-create", None, False, True),
            ("carrier-inspect", ID, True, False), ("carrier-remove", ID, True, True),
            ("seed", ID, False, True), ("read-work", ID, False, False),
            ("read-cache", ID, False, False), ("read-output", ID, False, False),
        )
        for selected, container, cleanup, mutation in rows:
            frame = MaterialFrame(RUN, 7, selected, container)
            with self.subTest(operation=selected):
                self.assertEqual((frame.cleanup, frame.mutation), (cleanup, mutation))

    def test_parser_refuses_bad_types_bounds_container_relations_and_injected_fields(self) -> None:
        base = {"run": RUN, "generation": 7, "operation": "carrier-create", "container": None}
        changes = (
            {"run": RUN.upper()}, {"run": RUN + "a"}, {"run": None},
            {"generation": True}, {"generation": 0}, {"generation": 1.0}, {"generation": 10**16},
            {"operation": "exec"}, {"operation": "start"}, {"operation": "wait"}, {"operation": None},
            {"container": ID}, {"operation": "seed"}, {"operation": "read-work", "container": ID.upper()},
            {"operation": "carrier-remove", "container": ID[:-1]}, {"argv": []}, {"path": "/tmp"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(BackendError):
                parse_frame({**base, **change})
        for selected in ("work", "cache", "output"):
            with self.subTest(selected=selected), self.assertRaises(BackendError):
                parse_frame({**base, "operation": "volume-create-" + selected, "container": ID})

    def test_maximum_material_frame_stays_inside_the_unchanged_gate_bound(self) -> None:
        body = json.dumps({"role": "preparation-material", "operand": {
            "run": RUN, "generation": 9999999999999999, "operation": "carrier-inspect", "container": ID,
        }}, separators=(",", ":")).encode()
        raw = struct.pack("!I", len(body)) + body + b"R"
        actual = read_selection(io.BytesIO(raw))
        self.assertEqual(actual.operand, MaterialFrame(RUN, 9999999999999999, "carrier-inspect", ID))
        self.assertLessEqual(len(body), 1024)
        with self.assertRaises(LaunchError):
            read_selection(io.BytesIO(struct.pack("!I", 1025) + body + b"R"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
