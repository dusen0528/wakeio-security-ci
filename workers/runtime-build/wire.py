# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Authenticated build-v2 codecs for the future original relay connection owner.

The owner supplies its existing sequence. This module owns no counter, phase
authority, backend, socket listener or build resources.
"""
import hashlib
import hmac
import json
import re
import struct
from dataclasses import dataclass
from typing import BinaryIO

from wire_schema import Json, Operation, WireError, body, digest, integer, operation, record, require, result


@dataclass(frozen=True, slots=True)
class Binding:
    nonce: str
    run: str

    def __post_init__(self) -> None:
        digest(self.nonce)
        require(re.fullmatch("[a-f0-9]{32}", self.run) is not None, "build_run")


@dataclass(frozen=True, slots=True)
class Request:
    sequence: int
    challenge: str
    run: str
    operation: Operation
    build: str | None
    body: dict[str, Json]


@dataclass(frozen=True, slots=True)
class Reply:
    build: str | None
    result: dict[str, Json]


def canonical(value: Json) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def unique(pairs: list[tuple[str, Json]]) -> dict[str, Json]:
    data: dict[str, Json] = {}
    for key, value in pairs:
        require(key not in data, "build_duplicate")
        data[key] = value
    return data


def authenticate(payload: dict[str, Json], binding: Binding, domain: str) -> str:
    return hmac.new(bytes.fromhex(binding.nonce), domain.encode("ascii") + canonical(payload),
                    hashlib.sha256).hexdigest()


def decode(data: bytes, binding: Binding, sequence: int) -> Request:
    """Decode one unframed body, bound to the owner's next original sequence."""
    require(0 < len(data) <= 65536, "build_request_bound")
    try:
        parsed: Json = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
        require(canonical(parsed) == data, "build_noncanonical")
    except (UnicodeError, ValueError, RecursionError) as error:
        raise WireError("build_encoding") from error
    fields = record(parsed, "version,sequence,challenge,run,operation,build,body,mac")
    require(type(fields["version"]) is int and fields["version"] == 2, "build_version")
    require(integer(fields["sequence"], 1024) == sequence and sequence > 0, "build_sequence")
    require(fields["run"] == binding.run, "build_run")
    challenge = digest(fields["challenge"])
    selected = operation(fields["operation"])
    parsed_body = body(selected, fields["build"], fields["body"])
    payload = {key: value for key, value in fields.items() if key != "mac"}
    require(hmac.compare_digest(authenticate(payload, binding, "build-request:"), digest(fields["mac"])),
            "build_request_mac")
    build = None if fields["build"] is None else digest(fields["build"])
    return Request(sequence, challenge, binding.run, selected, build, parsed_body)


def encode(request: Request, reply: Reply, binding: Binding) -> bytes:
    """Produce a length frame; successful begin alone introduces a new correlation token."""
    require(request.run == binding.run, "build_run")
    checked = result(request.operation, request.body, reply.result)
    build = reply.build
    match request.operation, checked["kind"]:
        case "build-begin", "allocated":
            digest(build)
        case "build-begin", _:
            require(build is None, "build_begin_reference")
        case _:
            require(build == request.build, "build_response_reference")
    payload: dict[str, Json] = {
        "version": 2, "sequence": request.sequence, "challenge": request.challenge,
        "run": request.run, "operation": request.operation, "build": build, "result": checked,
    }
    encoded = canonical({**payload, "mac": authenticate(payload, binding, "build-response:")})
    require(len(encoded) <= 1048576, "build_response_bound")
    return struct.pack("!I", len(encoded)) + encoded


def read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        part = stream.read(length - len(chunks))
        require(bool(part), "build_truncated")
        chunks.extend(part)
    return bytes(chunks)


def receive(stream: BinaryIO, binding: Binding, sequence: int) -> Request:
    length = struct.unpack("!I", read_exact(stream, 4))[0]
    require(0 < length <= 65536, "build_request_bound")
    return decode(read_exact(stream, length), binding, sequence)
