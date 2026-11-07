# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Python3.12 -I -B tests/native/runtime_build_launch_test.py; DATA only, never exec or ownership."""
import io
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers/runtime-build"))
from launch import MAX_CONTROL, LaunchError, Selection, encode_selection, read_selection, resource_labels

RUN = "ab" * 16
NAME = "wk-" + RUN + "-b7-input"
CONTAINER = "cd" * 32


def packet(body: bytes) -> bytes:
    return struct.pack("!I", len(body)) + body + b"R"


class Fragmented(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 2))


class LaunchDataTests(unittest.TestCase):
    def test_closed_roles_accept_complete_independent_data_and_fragmented_reads(self) -> None:
        cases = [
            ("image-pull", None), ("image-inspect", None), ("volume-create", NAME),
            ("volume-inspect", NAME), ("volume-remove", NAME), ("carrier-create", NAME),
            ("carrier-inspect", CONTAINER), ("carrier-remove", CONTAINER),
            ("copy-in", CONTAINER), ("copy-out", CONTAINER),
            ("slice-reload", None), ("slice-start", "wk" + RUN + "b7prepare.slice"),
            ("slice-present", "wk" + RUN + "b1offline.slice"),
            ("slice-files", "wk" + RUN + "b9999999999999999prepare.slice"),
            ("slice-inspect", "wk" + RUN + "b7offline.slice"),
            ("slice-stop", "wk" + RUN + "b7prepare.slice"),
        ]
        for role, value in cases:
            body = json.dumps({"role": role, "operand": value}, separators=(",", ":")).encode()
            with self.subTest(role=role):
                actual = read_selection(Fragmented(packet(body)))
                self.assertEqual((actual.role, actual.operand), (role, value))

    def test_encoded_record_has_the_exact_machine_frame_and_single_release_byte(self) -> None:
        selected = Selection("copy-in", CONTAINER)
        body = b'{"role":"copy-in","operand":"' + CONTAINER.encode("ascii") + b'"}'
        self.assertEqual(encode_selection(selected), struct.pack("!I", len(body)) + body + b"R")
        stream = io.BytesIO(packet(body))
        self.assertEqual(read_selection(stream).operand, CONTAINER)
        with self.assertRaises(LaunchError) as caught:
            read_selection(stream)
        self.assertEqual(caught.exception.reason, "launch_truncated")

    def test_incomplete_unreleased_oversized_and_replayed_records_are_refused(self) -> None:
        valid = packet(b'{"role":"image-pull","operand":null}')
        cases = [
            (b"", "launch_truncated"), (valid[:2], "launch_truncated"),
            (struct.pack("!I", 0), "launch_bound"),
            (struct.pack("!I", MAX_CONTROL + 1), "launch_bound"),
            (valid[:-2], "launch_truncated"), (valid[:-1], "launch_truncated"),
            (valid[:-1] + b"X", "launch_release"),
            (valid + b"R", "launch_release"), (valid + valid, "launch_release"),
        ]
        for raw, reason in cases:
            with self.subTest(raw=raw[:12], reason=reason):
                with self.assertRaises(LaunchError) as caught:
                    read_selection(io.BytesIO(raw))
                self.assertEqual(caught.exception.reason, reason)

    def test_arbitrary_commands_fields_operands_and_noncanonical_data_are_refused(self) -> None:
        cases = [
            (b'{"role":"execute","operand":null}', "launch_role"),
            (b'{"role":"slice-execute","operand":null}', "launch_role"),
            (b'{"role":"slice-reload","operand":"anything"}', "launch_operand"),
            (b'{"role":"slice-reload","operand":false}', "launch_operand"),
            (b'{"role":"slice-start","operand":null}', "launch_operand"),
            (b'{"role":"slice-inspect","operand":17}', "launch_operand"),
            (b'{"role":null,"operand":null}', "launch_operand"),
            (b'{"role":"image-pull","operand":"/bin/sh"}', "launch_operand"),
            (b'{"role":"image-inspect","operand":true}', "launch_operand"),
            (b'{"role":"volume-create","operand":7}', "launch_operand"),
            (b'{"role":"copy-in","operand":[]}', "launch_operand"),
            (b'{"role":"copy-in","operand":null}', "launch_operand"),
            (b'{"role":"image-pull","operand":null,"argv":["/bin/sh"]}', "launch_fields"),
            (b'{"role":"image-pull","operand":null,"pid":1}', "launch_fields"),
            (b'{"role":"image-pull"}', "launch_fields"),
            (b'{"operand":null,"role":"image-pull"}', "launch_fields"),
            (b'{"role":"image-pull","role":"image-pull","operand":null}', "launch_canonical"),
            (b'{"role":"image-pull", "operand":null}', "launch_canonical"),
            (b'{"role":"image-pull","operand":null} ', "launch_canonical"),
            (b'\xef\xbb\xbf{"role":"image-pull","operand":null}', "launch_encoding"),
            (b'{"role":"image-\xff","operand":null}', "launch_encoding"),
            (b"[]", "launch_fields"),
        ]
        for body, reason in cases:
            with self.subTest(body=body[:80]):
                with self.assertRaises(LaunchError) as caught:
                    read_selection(io.BytesIO(packet(body)))
                self.assertEqual(caught.exception.reason, reason)

    def test_only_fixed_private_name_and_full_container_data_shapes_are_accepted(self) -> None:
        cases = [
            ("volume-create", "/tmp/input", "launch_volume"),
            ("carrier-create", NAME + "/../other", "launch_volume"),
            ("volume-inspect", NAME.replace("-b7-", "-b0-"), "launch_volume"),
            ("volume-remove", NAME.replace("-b7-", "-b07-"), "launch_volume"),
            ("volume-create", NAME.replace("-b7-", "-b12345678901234567-"), "launch_volume"),
            ("carrier-create", NAME.replace(RUN, RUN.upper()), "launch_volume"),
            ("copy-in", CONTAINER[:-1], "launch_container"),
            ("copy-out", CONTAINER.upper(), "launch_container"),
            ("carrier-inspect", "sha256:" + CONTAINER, "launch_container"),
            ("carrier-remove", CONTAINER + "\0", "launch_container"),
            ("slice-present", NAME, "launch_slice:cold_slice_name"),
            ("slice-files", "wk" + RUN + "b07prepare.slice", "launch_slice:cold_slice_name"),
            ("slice-start", "wk" + RUN + "b0prepare.slice", "launch_slice:cold_slice_name"),
            ("slice-inspect", "wk" + RUN + "b7prepare.slice/../x", "launch_slice:cold_slice_name"),
            ("slice-stop", "wk" + RUN + "b7prepare.slice\0", "launch_slice:cold_slice_name"),
            ("slice-start", "--all", "launch_slice:cold_slice_name"),
        ]
        for role, value, reason in cases:
            body = json.dumps({"role": role, "operand": value}, separators=(",", ":")).encode()
            with self.subTest(role=role, value=value):
                with self.assertRaises(LaunchError) as caught:
                    read_selection(io.BytesIO(packet(body)))
                self.assertEqual(caught.exception.reason, reason)

    def test_labels_are_only_fixed_machine_crosscheck_data(self) -> None:
        expected = {"wakeio.owner": "t6-build", "wakeio.run": RUN, "wakeio.generation": "7",
                    "wakeio.scope": "build", "wakeio.role": "input"}
        self.assertEqual(resource_labels(NAME), expected)
        self.assertEqual(resource_labels(NAME, True), {**expected, "wakeio.role": "input-carrier"})
        with self.assertRaises(LaunchError) as caught:
            resource_labels("foreign-volume")
        self.assertEqual(caught.exception.reason, "launch_volume")


if __name__ == "__main__":
    unittest.main(verbosity=2)
