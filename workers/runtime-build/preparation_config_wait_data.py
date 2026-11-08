# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B tests/native/runtime_build_preparation_config_wait_data_test.py
"""Bounded incremental next-exit HTTP DATA; no clock, socket, release mode or ownership."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Final, assert_never

from preparation_config_data import ConfigError, require
from preparation_config_inspect import record, strict_json

OPTIONAL_HEADERS: Final = frozenset((
    "date", "server", "api-version", "docker-experimental", "ostype", "connection",
))


@dataclass(frozen=True, slots=True)
class WaitTerminal:
    status_code: int


class _Stage(Enum):
    HEADERS = auto()
    SIZE = auto()
    DATA = auto()
    CRLF = auto()
    TRAILER = auto()
    DONE = auto()


def wait_request(container: str) -> bytes:
    require(type(container) is str and re.fullmatch("[a-f0-9]{64}", container) is not None, "config_wait_id")
    return (f"POST /v1.30/containers/{container}/wait?condition=next-exit HTTP/1.1\r\n"
            "Host: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode("ascii")


def _headers(raw: bytes) -> tuple[tuple[str, str], ...]:
    lines = raw[:-4].split(b"\r\n")
    require(all(len(line) <= 2048 for line in lines) and len(lines) <= 33, "config_wait_header_bound")
    require(re.fullmatch(rb"HTTP/1\.1 200 [\x20-\x7e]+", lines[0]) is not None, "config_wait_status")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        require(separator == b":" and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is not None,
                "config_wait_header_name")
        require(all(32 <= byte <= 126 for byte in value), "config_wait_header_value")
        key, content = name.decode("ascii").lower(), value.strip(b" ").decode("ascii")
        require(key not in fields and key in OPTIONAL_HEADERS | {"content-type", "transfer-encoding"},
                "config_wait_header_fields")
        fields[key] = content
    require(fields.get("content-type") == "application/json" and fields.get("transfer-encoding") == "chunked",
            "config_wait_framing")
    require(fields.get("connection", "close") == "close", "config_wait_connection")
    return tuple(fields.items())


def _terminal(raw: bytes) -> WaitTerminal:
    fields = record(strict_json(raw, 4096))
    require(set(fields) in ({"StatusCode"}, {"StatusCode", "Error"}), "config_wait_json_fields")
    code = fields["StatusCode"]
    if type(code) is not int or not 0 <= code <= 255:
        raise ConfigError("config_wait_status_code")
    error = fields.get("Error")
    if error is not None:
        message = record(error)
        text = message.get("Message")
        if set(message) != {"Message"} or not isinstance(text, str):
            raise ConfigError("config_wait_error_shape")
        try:
            length = len(text.encode("utf-8"))
        except UnicodeError as failure:
            raise ConfigError("config_wait_error_encoding") from failure
        require(length <= 1024, "config_wait_error_bound")
        raise ConfigError("config_wait_engine_error")
    return WaitTerminal(code)


class WaitParser:
    """Mutable only to accumulate a bounded stream. Any failure permanently poisons this parser."""

    def __init__(self) -> None:
        self.headers: tuple[tuple[str, str], ...] | None = None
        self.terminal: WaitTerminal | None = None
        self.complete = False
        self._failed = False
        self._stage = _Stage.HEADERS
        self._buffer = bytearray()
        self._decoded = bytearray()
        self._wire_body = 0
        self._remaining = 0

    @property
    def headers_ready(self) -> bool:
        return self.headers is not None and not self._failed

    def feed(self, part: bytes) -> None:
        require(not self._failed and not self.complete, "config_wait_spent")
        try:
            require(type(part) is bytes, "config_wait_bytes")
            require(len(part) + len(self._buffer) <= 40960, "config_wait_wire_bound")
            self._buffer.extend(part)
            if self._stage == _Stage.HEADERS:
                self._advance_headers()
            else:
                self._wire_body += len(part)
            if self._stage != _Stage.HEADERS:
                require(self._wire_body <= 32768, "config_wait_wire_bound")
                self._advance_body()
        except ConfigError:
            self._failed = True
            self.terminal = None
            raise

    def _advance_headers(self) -> None:
        end = self._buffer.find(b"\r\n\r\n")
        if end < 0:
            require(len(self._buffer) <= 8192, "config_wait_header_bound")
            lines = bytes(self._buffer).split(b"\r\n")
            require(all(len(line) <= 2048 for line in lines[:-1]) and len(lines[-1]) <= 2050,
                    "config_wait_header_bound")
            return
        require(end + 4 <= 8192, "config_wait_header_bound")
        self.headers = _headers(bytes(self._buffer[:end + 4]))
        del self._buffer[:end + 4]
        self._wire_body = len(self._buffer)
        self._stage = _Stage.SIZE

    def _advance_body(self) -> None:
        while True:
            match self._stage:
                case _Stage.SIZE:
                    end = self._buffer.find(b"\r\n")
                    if end < 0:
                        require(len(self._buffer) <= 5, "config_wait_chunk_size")
                        return
                    size = bytes(self._buffer[:end])
                    require(re.fullmatch(rb"(?:0|[1-9a-f][0-9a-f]{0,3})", size) is not None,
                            "config_wait_chunk_size")
                    self._remaining = int(size, 16)
                    require(len(self._decoded) + self._remaining <= 4096, "config_wait_decoded_bound")
                    del self._buffer[:end + 2]
                    self._stage = _Stage.DATA if self._remaining else _Stage.TRAILER
                case _Stage.DATA:
                    count = min(len(self._buffer), self._remaining)
                    self._decoded.extend(self._buffer[:count])
                    del self._buffer[:count]
                    self._remaining -= count
                    if self._remaining:
                        return
                    self._stage = _Stage.CRLF
                case _Stage.CRLF:
                    if len(self._buffer) < 2:
                        return
                    require(self._buffer[:2] == b"\r\n", "config_wait_chunk_crlf")
                    del self._buffer[:2]
                    self._stage = _Stage.SIZE
                case _Stage.TRAILER:
                    if len(self._buffer) < 2:
                        return
                    require(self._buffer[:2] == b"\r\n", "config_wait_trailer")
                    del self._buffer[:2]
                    self.terminal = _terminal(bytes(self._decoded))
                    self._stage = _Stage.DONE
                case _Stage.DONE:
                    require(not self._buffer, "config_wait_surplus")
                    return
                case _Stage.HEADERS:
                    raise ConfigError("config_wait_internal_stage")
                case unreachable:
                    assert_never(unreachable)

    def eof(self) -> WaitTerminal:
        """EOF is necessary even after valid chunk termination; never a release or CLOSE claim."""
        require(not self._failed and not self.complete, "config_wait_spent")
        if self._stage != _Stage.DONE or self.terminal is None:
            self._failed = True
            raise ConfigError("config_wait_truncated")
        self.complete = True
        return self.terminal
