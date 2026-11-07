# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Run with the granted Python: -I -B tests/native/runtime_build_wire_test.py."""
import hashlib
import hmac
import io
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers/runtime-build"))
from wire import Binding, Reply, canonical, decode, encode, receive
from wire_schema import Json, Operation, WireError

BINDING = Binding("12" * 32, "ab" * 16)
TOKEN = "34" * 32
DIGEST = "56" * 32


def signed(payload: dict[str, Json], domain: str = "build-request:") -> bytes:
    mac = hmac.new(bytes.fromhex(BINDING.nonce), domain.encode() + canonical(payload), hashlib.sha256).hexdigest()
    return canonical({**payload, "mac": mac})


def payload(operation: Operation = "build-begin", body: dict[str, Json] | None = None) -> dict[str, Json]:
    return {"version": 2, "sequence": 1, "challenge": "78" * 32, "run": BINDING.run,
            "operation": operation, "build": None if operation == "build-begin" else TOKEN,
            "body": {"profile": "f01"} if body is None else body}


class Fragmented(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 2))


class WireTests(unittest.TestCase):
    def test_fragmented_frame_matches_independent_mac_and_order(self) -> None:
        request_body = signed(payload())
        request = receive(Fragmented(struct.pack("!I", len(request_body)) + request_body), BINDING, 1)
        frame = encode(request, Reply(TOKEN, {"kind": "allocated", "generation": 1}), BINDING)
        expected = {"version": 2, "sequence": 1, "challenge": "78" * 32, "run": BINDING.run,
                    "operation": "build-begin", "build": TOKEN, "result": {"kind": "allocated", "generation": 1}}
        encoded = signed(expected, "build-response:")
        self.assertEqual(frame, struct.pack("!I", len(encoded)) + encoded)

    def test_authenticated_binding_and_closed_request_grammar(self) -> None:
        changes = [
            {"version": True}, {"version": 1}, {"sequence": True}, {"sequence": 0}, {"sequence": 1025},
            {"sequence": 2**53}, {"sequence": 1.0}, {"challenge": "ff"}, {"run": "cd" * 16},
            {"operation": "execute"}, {"build": TOKEN}, {"body": {"profile": "f05"}},
            {"body": {"profile": "f01", "extra": 1}}, {"extra": 1},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(WireError):
                decode(signed({**payload(), **change}), BINDING, 1)
        for domain in ("request:", "build-response:", "target-request:"):
            with self.subTest(domain=domain), self.assertRaises(WireError):
                decode(signed(payload(), domain), BINDING, 1)
        with self.assertRaises(WireError):
            decode(signed(payload()), BINDING, 2)
        with self.assertRaises(WireError):
            decode(signed(payload()), Binding("ff" * 32, BINDING.run), 1)

    def test_noncanonical_encodings_and_truncation_are_refused(self) -> None:
        raw = signed(payload())
        samples = [raw + b" ", raw.replace(b'"version":2', b'"version":2,"version":2'),
                   raw.replace(b"f01", b"\xff01"), b"NaN", b"{}", b"x" * 65537,
                   raw.replace(b'"sequence":1', b'"sequence":1.0'),
                   raw.replace(b'"profile":"f01"', b'"profile":"\\u006601"')]
        for data in samples:
            with self.subTest(data=data[:80]), self.assertRaises(WireError):
                decode(data, BINDING, 1)
        for data in (b"", b"\0", struct.pack("!I", 0), struct.pack("!I", 65537),
                     struct.pack("!I", len(raw)) + raw[:-1]):
            with self.subTest(data=data[:8]), self.assertRaises(WireError):
                receive(io.BytesIO(data), BINDING, 1)
        unordered = payload()
        unordered = {"sequence": unordered.pop("sequence"), **unordered}
        with self.assertRaises(WireError):
            decode(signed(unordered), BINDING, 1)

    def test_input_bounds_canonical_base64_and_ordered_seal_rows(self) -> None:
        bodies = [
            {"file": -1, "offset": 0, "data": "YQ=="}, {"file": 5, "offset": 0, "data": "YQ=="},
            {"file": True, "offset": 0, "data": "YQ=="}, {"file": 0, "offset": -1, "data": "YQ=="},
            {"file": 0, "offset": 1048576, "data": "YQ=="},
            *({"file": 0, "offset": 0, "data": data} for data in ("", "YQ", "YR==", "YQ==\n", "A" * 32772)),
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(WireError):
                decode(signed(payload("build-input", body)), BINDING, 1)
        rows = [{"file": file, "bytes": 1048576, "sha256": DIGEST} for file in range(5)]
        decode(signed(payload("build-seal", {"files": rows})), BINDING, 1)
        for files in (rows[:-1], rows[::-1], [{**rows[0], "bytes": 1048577}, *rows[1:]],
                      [{**rows[0], "sha256": "FF" * 32}, *rows[1:]]):
            with self.subTest(files=files), self.assertRaises(WireError):
                decode(signed(payload("build-seal", {"files": files})), BINDING, 1)

    def test_all_closed_result_variants_and_their_bounds(self) -> None:
        rows = [
            ("build-begin", {"profile": "f01"}, {"kind": "allocated", "generation": 2**53 - 1}),
            ("build-input", {"file": 4, "offset": 1048575, "data": "YQ=="},
             {"kind": "input-accepted", "file": 4, "nextOffset": 1048576}),
            ("build-seal", {"files": [{"file": file, "bytes": 0, "sha256": DIGEST} for file in range(5)]},
             {"kind": "sealed", "manifestSha256": DIGEST}),
            ("build-prepare", {}, {"kind": "preparation-closed",
             "cache": {"sha256": DIGEST, "bytes": 1073741824, "entries": 16384}, "closureSha256": DIGEST}),
            ("build-offline", {}, {"kind": "offline-closed", "jar": {"bytes": 67108864, "sha256": DIGEST},
             "classes": {"sha256": DIGEST, "bytes": 134217728, "entries": 4096}}),
            ("build-assemble", {}, {"kind": "assembled", "image": {"id": "sha256:" + DIGEST,
             "configSha256": DIGEST, "os": "linux", "architecture": "arm64", "layersSha256": DIGEST},
             "recipeSha256": DIGEST, "gateSha256": DIGEST}),
            ("build-stop", {"reason": "completed"}, {"kind": "stop-requested"}),
            ("build-close", {}, {"kind": "cleanup-state", "state": "confirmed", "reason": None}),
        ]
        for selected, body, observation in rows:
            request = decode(signed(payload(selected, body)), BINDING, 1)
            with self.subTest(selected=selected):
                frame = encode(request, Reply(TOKEN, observation), BINDING)
                self.assertEqual(json.loads(frame[4:])["result"], observation)
                with self.assertRaises(WireError):
                    encode(request, Reply(TOKEN, {**observation, "extra": 1}), BINDING)
                if selected != "build-stop":
                    with self.assertRaises(WireError):
                        encode(request, Reply(TOKEN, {"kind": "stop-requested"}), BINDING)

    def test_response_identity_numeric_platform_and_cleanup_failures(self) -> None:
        samples = [
            ("build-begin", {"kind": "allocated", "generation": 0}),
            ("build-begin", {"kind": "allocated", "generation": 2**53}),
            ("build-prepare", {"kind": "preparation-closed",
             "cache": {"sha256": DIGEST, "bytes": 1073741825, "entries": 1}, "closureSha256": DIGEST}),
            ("build-prepare", {"kind": "preparation-closed",
             "cache": {"sha256": DIGEST, "bytes": 1, "entries": 16385}, "closureSha256": DIGEST}),
            ("build-offline", {"kind": "offline-closed", "jar": {"bytes": 67108865, "sha256": DIGEST},
             "classes": {"sha256": DIGEST, "bytes": 0, "entries": 0}}),
            ("build-offline", {"kind": "offline-closed", "jar": {"bytes": 1, "sha256": DIGEST},
             "classes": {"sha256": DIGEST, "bytes": 134217729, "entries": 4097}}),
            ("build-assemble", {"kind": "assembled", "image": {"id": "sha256:" + DIGEST,
             "configSha256": DIGEST, "os": "linux", "architecture": "amd64", "layersSha256": DIGEST},
             "recipeSha256": DIGEST, "gateSha256": DIGEST}),
            ("build-close", {"kind": "cleanup-state", "state": "confirmed", "reason": "aborted"}),
            ("build-close", {"kind": "cleanup-state", "state": "unconfirmed", "reason": "secret"}),
        ]
        for selected, observation in samples:
            request = decode(signed(payload(selected, None if selected == "build-begin" else {})), BINDING, 1)
            with self.subTest(selected=selected, observation=observation), self.assertRaises(WireError):
                encode(request, Reply(TOKEN, observation), BINDING)
        request = decode(signed(payload("build-close", {})), BINDING, 1)
        with self.assertRaises(WireError):
            encode(request, Reply("ff" * 32, {"kind": "cleanup-state", "state": "confirmed", "reason": None}), BINDING)

    def test_closed_failure_codes_and_begin_reference_introduction(self) -> None:
        request = decode(signed(payload()), BINDING, 1)
        codes = ("input_refused", "identity_changed", "phase_invalid", "operation_failed", "output_bound",
                 "aborted", "deadline", "close_unconfirmed", "allocation_unknown")
        for reason in codes:
            frame = encode(request, Reply(None, {"kind": "failed", "reason": reason}), BINDING)
            self.assertEqual(json.loads(frame[4:])["build"], None)
        for reply in (Reply(None, {"kind": "allocated", "generation": 1}),
                      Reply(TOKEN, {"kind": "failed", "reason": "aborted"}),
                      Reply(None, {"kind": "failed", "reason": "unknown"})):
            with self.subTest(reply=reply), self.assertRaises(WireError):
                encode(request, reply, BINDING)


if __name__ == "__main__":
    unittest.main(verbosity=2)
