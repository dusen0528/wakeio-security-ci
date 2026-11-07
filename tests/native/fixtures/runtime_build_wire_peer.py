# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Synthetic protocol DATA peer. Never a backend, source executor or build oracle."""
import json
import signal
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "workers/runtime-build"))
from wire import Binding, Reply, Request, authenticate, canonical, decode, encode, read_exact
from wire_schema import Json, WireError, integer, require

BINDING = Binding("12" * 32, "ab" * 16)
TOKEN = "34" * 32
DIGEST = "56" * 32


def observation(request: Request) -> dict[str, Json]:
    """Only grammar examples, not assertions about physical resources."""
    match request.operation:
        case "build-begin":
            return {"kind": "allocated", "generation": 1}
        case "build-input":
            from wire_schema import chunk
            return {"kind": "input-accepted", "file": request.body["file"],
                    "nextOffset": integer(request.body["offset"], 1048576) + len(chunk(request.body["data"]))}
        case "build-seal":
            return {"kind": "sealed", "manifestSha256": DIGEST}
        case "build-prepare":
            return {"kind": "preparation-closed",
                    "cache": {"sha256": DIGEST, "bytes": 0, "entries": 0}, "closureSha256": DIGEST}
        case "build-offline":
            return {"kind": "offline-closed", "jar": {"bytes": 0, "sha256": DIGEST},
                    "classes": {"sha256": DIGEST, "bytes": 0, "entries": 0}}
        case "build-assemble":
            return {"kind": "assembled", "image": {"id": "sha256:" + DIGEST,
                    "configSha256": DIGEST, "os": "linux", "architecture": "arm64", "layersSha256": DIGEST},
                    "recipeSha256": DIGEST, "gateSha256": DIGEST}
        case "build-stop":
            return {"kind": "stop-requested"}
        case "build-close":
            return {"kind": "cleanup-state", "state": "confirmed", "reason": None}
    raise WireError("peer_operation")


def corrupt(frame: bytes, mode: str) -> bytes:
    data = json.loads(frame[4:])
    domain = "build-response:"
    match mode:
        case "mac":
            data["mac"] = "00" * 32
        case "sequence":
            data["sequence"] += 1
        case "challenge" | "run" | "build":
            data[mode] = "ff" * (16 if mode == "run" else 32)
        case "operation":
            data["operation"] = "build-offline"
        case "variant":
            data["result"] = {"kind": "stop-requested"}
        case "extra":
            data["result"]["extra"] = 1
        case "domain":
            domain = "response:"
        case "failed":
            data["build"] = None
            data["result"] = {"kind": "failed", "reason": "allocation_unknown"}
        case "order":
            data = {"sequence": data.pop("sequence"), **data}
    if mode != "mac":
        data.pop("mac")
        data["mac"] = authenticate(data, BINDING, domain)
    body = canonical(data)
    if mode == "utf8":
        body = body.replace(b"allocated", b"\xffllocated")
    if mode == "duplicate":
        body = body.replace(b'"version":2', b'"version":2,"version":2')
    if mode == "whitespace":
        body += b" "
    return struct.pack("!I", len(body)) + body


def main() -> None:
    mode = sys.argv[1]
    if mode == "fragment":
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    sequence = 0
    previous = None
    while True:
        header = sys.stdin.buffer.read(4)
        if not header:
            return
        require(len(header) == 4, "peer_header")
        length = struct.unpack("!I", header)[0]
        require(0 < length <= 65536, "peer_bound")
        raw = read_exact(sys.stdin.buffer, length)
        sequence += 1
        parsed = json.loads(raw)
        if parsed["version"] == 1:
            mac = parsed.pop("mac")
            require(list(parsed) == ["version", "sequence", "run", "challenge", "operation"]
                    and parsed["sequence"] == sequence and parsed["run"] == BINDING.run
                    and mac == authenticate(parsed, BINDING, "request:"), "peer_v1")
            payload = {"version": 1, "sequence": sequence, "run": BINDING.run,
                       "challenge": parsed["challenge"], "result": {"observed": "wire-only"}}
            if mode == "utf8-valid-mac":
                payload["result"] = {"observed": "\ufffd"}
            body = canonical({**payload, "mac": authenticate(payload, BINDING, "response:")})
            frame = struct.pack("!I", len(body)) + body
        else:
            request = decode(raw, BINDING, sequence)
            frame = encode(request, Reply(TOKEN, observation(request)), BINDING)
            if mode == "replay" and previous is not None:
                frame = previous
            elif mode not in ("normal", "fragment", "replay", "truncated", "overflow", "bom",
                              "utf8-valid-mac") and not (
                    mode == "build" and request.operation == "build-begin"):
                frame = corrupt(frame, mode)
            previous = frame
        if mode == "bom":
            body = b"\xef\xbb\xbf" + frame[4:]
            frame = struct.pack("!I", len(body)) + body
        if mode == "utf8-valid-mac":
            body = frame[4:].replace(b"\xef\xbf\xbd", b"\xff", 1)
            frame = struct.pack("!I", len(body)) + body
        if mode == "truncated":
            sys.stdout.buffer.write(frame[:-1])
            sys.stdout.buffer.flush()
            return
        if mode == "overflow":
            sys.stdout.buffer.write(struct.pack("!I", 1048577))
        else:
            sys.stdout.buffer.write(frame[:2])
            sys.stdout.buffer.flush()
            if mode == "fragment":
                signal.sigwait({signal.SIGUSR1})
            sys.stdout.buffer.write(frame[2:])
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
