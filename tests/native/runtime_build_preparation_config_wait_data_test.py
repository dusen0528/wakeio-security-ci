# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B this file. Only inert HTTP bytes, no socket or clock.
"""Incremental C3 HTTP/chunk/JSON grammar and fragmentation invariance."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from preparation_config_data import ConfigError, Json
from preparation_config_wait_data import WaitParser, wait_request

HEADERS: Final = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
    b"Connection: close\r\n\r\n")


def chunks(parts: tuple[bytes, ...]) -> bytes:
    return b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n" for part in parts) + b"0\r\n\r\n"


def response(value: Json) -> bytes:
    return HEADERS + chunks((json.dumps(value, separators=(",", ":")).encode(),))


class WaitDataTests(unittest.TestCase):
    def test_fixed_request_binds_full_id_and_only_the_selected_api(self) -> None:
        identifier = "ab" * 32
        self.assertEqual(wait_request(identifier), (
            f"POST /v1.30/containers/{identifier}/wait?condition=next-exit HTTP/1.1\r\n"
            "Host: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode())
        for invalid in (identifier.upper(), identifier[:-1], identifier + "/wait", "1", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                wait_request(invalid)

    def test_every_two_way_split_and_byte_fragment_has_identical_terminal_meaning(self) -> None:
        raw = HEADERS + chunks((b'{"Error":', b'null,"StatusCode"', b":255}\n"))
        for split in range(len(raw) + 1):
            parser = WaitParser()
            parser.feed(raw[:split])
            parser.feed(raw[split:])
            with self.subTest(split=split):
                self.assertTrue(parser.headers_ready)
                self.assertFalse(parser.complete)
                self.assertEqual(parser.eof().status_code, 255)
                self.assertTrue(parser.complete)
        parser = WaitParser()
        for byte in raw:
            parser.feed(bytes((byte,)))
        self.assertEqual(parser.eof().status_code, 255)

    def test_headers_ready_only_after_full_validation_and_terminal_still_needs_eof(self) -> None:
        parser = WaitParser()
        parser.feed(HEADERS[:-1])
        self.assertFalse(parser.headers_ready)
        parser.feed(HEADERS[-1:])
        self.assertTrue(parser.headers_ready)
        self.assertIsNone(parser.terminal)
        parser.feed(chunks((b'{"StatusCode":0}\n',)))
        self.assertEqual(parser.terminal.status_code if parser.terminal is not None else None, 0)
        self.assertFalse(parser.complete)
        self.assertEqual(parser.eof().status_code, 0)
        with self.assertRaises(ConfigError):
            parser.feed(b"")

    def test_all_incomplete_prefixes_refuse_eof_without_manufacturing_completion(self) -> None:
        raw = response({"StatusCode": 0})
        for end in range(len(raw)):
            parser = WaitParser()
            parser.feed(raw[:end])
            with self.subTest(end=end), self.assertRaisesRegex(ConfigError, "truncated"):
                parser.eof()
            self.assertFalse(parser.complete)

    def test_header_case_is_insensitive_but_duplicates_controls_and_unknown_forms_refuse(self) -> None:
        parser = WaitParser()
        parser.feed(HEADERS.replace(b"Content-Type", b"cOnTeNt-TyPe") + chunks((b'{"StatusCode":0}',)))
        self.assertEqual(parser.eof().status_code, 0)
        malformed = (
            HEADERS.replace(b"HTTP/1.1 200 OK", b"HTTP/1.0 200 OK"),
            HEADERS.replace(b"200 OK", b"100 Continue"), HEADERS.replace(b"200 OK", b"302 Found"),
            HEADERS.replace(b"\r\n", b"\n"), HEADERS.replace(b"200 OK", b"200 \tOK"),
            HEADERS.replace(b"Content-Type:", b" Content-Type:"),
            HEADERS.replace(b"application/json", b"application/json; charset=utf-8"),
            HEADERS.replace(b"chunked", b"gzip, chunked"), HEADERS.replace(b"chunked", b"Chunked"),
            HEADERS.replace(b"Connection: close", b"Connection: keep-alive"),
            HEADERS.replace(b"Connection: close", b"Connection: upgrade"),
            HEADERS.replace(b"Connection: close", b"Content-Length: 0"),
            HEADERS.replace(b"Connection: close", b"Content-Encoding: identity"),
            HEADERS.replace(b"Connection: close", b"Trailer: Foo"),
            HEADERS.replace(b"Connection: close", b"Upgrade: h2c"),
            HEADERS.replace(b"Connection: close", b"X-Unknown: value"),
            HEADERS.replace(b"Connection: close", b"Server: a\x00b"),
            HEADERS.replace(b"Connection: close", b"Server: a\tb"),
            HEADERS.replace(b"Connection: close", b"Content-Type: application/json"),
        )
        for index, raw in enumerate(malformed):
            with self.subTest(case=index), self.assertRaises(ConfigError):
                parser = WaitParser()
                parser.feed(raw + chunks((b'{"StatusCode":0}',)))
                parser.eof()

    def test_optional_header_observations_are_bounded_not_api_authority(self) -> None:
        optional = (b"Date: Sun, 08 Nov 2026 00:00:00 GMT\r\nServer: Docker/24.0.9\r\n"
                    b"Api-Version: 1.30\r\nDocker-Experimental: false\r\nOstype: linux\r\n")
        parser = WaitParser()
        parser.feed(HEADERS[:-2] + optional + b"\r\n" + chunks((b'{"StatusCode":0}',)))
        self.assertEqual(parser.eof().status_code, 0)
        for raw in (
            HEADERS[:-2] + b"Server: " + b"x" * 2041 + b"\r\n\r\n",
            HEADERS[:-2] + b"Server: x\r\nserver: y\r\n\r\n",
            HEADERS[:-2] + b"Server: x\r\n" * 33 + b"\r\n",
            HEADERS[:-2] + b"Server: " + b"x" * 8192,
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ConfigError):
                parser = WaitParser()
                parser.feed(raw)
                parser.eof()

    def test_chunk_extensions_aliases_trailers_crlf_and_surplus_are_rejected_at_every_split(self) -> None:
        body = b'{"StatusCode":0}'
        canonical = chunks((body,))
        malformed = (
            b"010\r\n" + body + b"\r\n0\r\n\r\n", b"1A\r\n" + body + b" " * 10 + b"\r\n0\r\n\r\n",
            b"10;x=y\r\n" + body + b"\r\n0\r\n\r\n", b"+10\r\n" + body + b"\r\n0\r\n\r\n",
            b" 10\r\n" + body + b"\r\n0\r\n\r\n", b"10\n" + body + b"\r\n0\r\n\r\n",
            canonical.replace(b"}\r\n0", b"}\n0"), canonical[:-2] + b"X: y\r\n\r\n",
            canonical + b"x", canonical + canonical,
        )
        for index, wire in enumerate(malformed):
            raw = HEADERS + wire
            for split in range(len(raw) + 1):
                with self.subTest(case=index, split=split), self.assertRaises(ConfigError):
                    parser = WaitParser()
                    parser.feed(raw[:split])
                    parser.feed(raw[split:])
                    parser.eof()

    def test_json_has_exact_status_error_types_and_utf8_without_duplicate_or_surplus(self) -> None:
        invalid: tuple[Json, ...] = (
            {"StatusCode": True}, {"StatusCode": 1.0}, {"StatusCode": -1}, {"StatusCode": 256},
            {"StatusCode": "0"}, {}, {"StatusCode": 0, "Owner": {}}, [],
            {"StatusCode": 0, "Error": {}}, {"StatusCode": 0, "Error": False},
            {"StatusCode": 0, "Error": {"Message": 1}},
            {"StatusCode": 0, "Error": {"Message": "", "extra": 1}},
            {"StatusCode": 0, "Error": {"Message": "\u00e9" * 513}},
            {"StatusCode": 0, "Error": {"Message": "\ud800"}},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parser = WaitParser()
                parser.feed(response(value))
        for body in (
            b'{"StatusCode":0,"StatusCode":0}', b'{"StatusCode":NaN}', b'{"StatusCode":Infinity}',
            b'\xef\xbb\xbf{"StatusCode":0}', b'{"StatusCode":0}{}', b'{"StatusCode":0}x',
            b'{"StatusCode":0,"Error":{"Message":"\xff"}}',
        ):
            with self.subTest(body=body), self.assertRaises(ConfigError):
                parser = WaitParser()
                parser.feed(HEADERS + chunks((body,)))
        for message in ("", "daemon refused"):
            with self.assertRaisesRegex(ConfigError, "^config_wait_engine_error$"):
                WaitParser().feed(response({"StatusCode": 0, "Error": {"Message": message}}))

    def test_decoded_and_wire_bounds_are_separate_and_failure_is_permanent(self) -> None:
        base = b'{"StatusCode":0}'
        exact = base + b" " * (4096 - len(base))
        parser = WaitParser()
        parser.feed(HEADERS + chunks((exact,)))
        self.assertEqual(parser.eof().status_code, 0)
        for wire in (chunks((exact + b" ",)), b"1001\r\n", b"x" * 32769):
            parser = WaitParser()
            parser.feed(HEADERS)
            with self.subTest(length=len(wire)), self.assertRaises(ConfigError):
                parser.feed(wire)
            with self.assertRaisesRegex(ConfigError, "spent"):
                parser.feed(chunks((base,)))
            self.assertIsNone(parser.terminal)
            self.assertFalse(parser.headers_ready)


if __name__ == "__main__":
    unittest.main(verbosity=2)
