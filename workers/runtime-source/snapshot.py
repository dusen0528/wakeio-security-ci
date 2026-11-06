"""Private host filesystem protocol. No source execution or backend authority."""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
# Run: /usr/bin/python3 -I -S -B workers/runtime-source/snapshot.py
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import signal
import stat
import sys
import uuid
from contextlib import ExitStack
from pathlib import Path
from types import FrameType
from typing import Final, NamedTuple, Union

_spec = importlib.util.spec_from_file_location("source_disposal", Path(__file__).with_name("source_disposal.py"))
if _spec is None or _spec.loader is None:
    sys.exit(2)
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)
from source_disposal import Anchor, Recovery, SnapshotFault, dispose, identity, verify_anchor

FILE_LIMIT: Final = 1024 * 1024
TOTAL_LIMIT: Final = 8 * FILE_LIMIT
DIRECTORY: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
REGULAR: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
SCANNER: Final = frozenset((
    "pom.xml", "src/main/resources/application.properties",
    "src/main/java/io/wakeio/fixtures/Application.java",
    "src/main/java/io/wakeio/jdbcfixtures/Application.java",
))
BUILD: Final = SCANNER | {".dockerignore", "Dockerfile"}
PRIVATE: Final = re.compile(r"(^|[._-])(truth|cases|provenance|evaluator|private|controller)([._-]|$)", re.I)
Wire = Union[None, bool, int, float, str, list["Wire"], dict[str, "Wire"]]


class Request(NamedTuple):
    source: str
    build: tuple[str, ...]
    scanner: tuple[str, ...]


def absolute(value: str) -> str:
    parts = value.split("/")
    if not value.startswith("/") or len(value) > 4096 or any(p in ("", ".", "..") for p in parts[1:]):
        raise SnapshotFault("path")
    for index, part in enumerate(parts[1:]):
        system_private = sys.platform == "darwin" and index == 0 and part == "private"
        if part.casefold() in (".omo", ".handoff", ".git") or PRIVATE.search(part) and not system_private:
            raise SnapshotFault("private_ancestry")
    if sys.platform == "darwin" and parts[1] in ("tmp", "var"):
        alias = "/" + parts[1]
        if os.readlink(alias) != "private" + alias:
            raise SnapshotFault("system_alias")
        return "/private" + value
    return value


def request(value: dict[str, Wire]) -> Request:
    if value.get("executeTargetConsent") is not True:
        raise SnapshotFault("consent")
    if set(value) != {"executeTargetConsent", "sourceRoot", "build", "scanner"}:
        raise SnapshotFault("request")
    source = value["sourceRoot"]
    if not isinstance(source, str):
        raise SnapshotFault("request")
    projections = []
    for role, allowed in (("build", BUILD), ("scanner", SCANNER)):
        paths = value[role]
        if not isinstance(paths, list) or not paths or len(paths) > 5:
            raise SnapshotFault("allowlist")
        if any(not isinstance(path, str) or path not in allowed for path in paths):
            raise SnapshotFault("allowlist")
        names = tuple(path for path in paths if isinstance(path, str))
        if len(set(names)) != len(names):
            raise SnapshotFault("allowlist")
        projections.append(names)
    return Request(source, projections[0], projections[1])


class Capture:
    """Owns retained descriptors and only the entries it actually created."""

    def __init__(self, stack: ExitStack) -> None:
        self.stack = stack
        self.anchors: list[Anchor] = []
        self.owned: list[Anchor] = []
        self.files: dict[tuple[str, str], tuple[Anchor, bytes]] = {}
        self.root = ""
        self.uncertain = False
        self.disposal = Recovery(None, (), False)

    def opened(self, parent: int, name: str, flags: int) -> Anchor:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, flags, dir_fd=parent)
        self.stack.callback(os.close, fd)
        entry = Anchor(parent, name, fd, os.fstat(fd))
        if identity(before) != identity(entry.info):
            raise SnapshotFault("identity")
        self.anchors.append(entry)
        self.check(entry)
        return entry

    def directory(self, path: str) -> int:
        fd = os.open("/", DIRECTORY)
        self.stack.callback(os.close, fd)
        for part in absolute(path).split("/")[1:]:
            fd = self.opened(fd, part, DIRECTORY).fd
        return fd

    def check(self, entry: Anchor) -> None:
        verify_anchor(entry)

    def stable(self) -> None:
        for entry in self.anchors:
            self.check(entry)

    def bytes(self, entry: Anchor) -> bytes:
        self.stable()
        if not stat.S_ISREG(entry.info.st_mode) or entry.info.st_size > FILE_LIMIT:
            raise SnapshotFault("file_bound")
        data = bytearray()
        while len(data) <= FILE_LIMIT:
            chunk = os.pread(entry.fd, min(65536, FILE_LIMIT + 1 - len(data)), len(data))
            if not chunk:
                break
            data.extend(chunk)
        self.stable()
        if len(data) != entry.info.st_size:
            raise SnapshotFault("file_drift")
        return bytes(data)

    def created(self, parent: int, name: str, data: bytes | None) -> Anchor:
        self.stable()
        self.uncertain = True
        if data is None:
            os.mkdir(name, 0o700, dir_fd=parent)
            entry = self.opened(parent, name, DIRECTORY)
        else:
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            self.stack.callback(os.close, fd)
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(data)
                stream.flush()
            entry = Anchor(parent, name, fd, os.fstat(fd))
            self.anchors.append(entry)
        self.owned.append(entry)
        self.uncertain = False
        return entry

    def capture(self, selected: Request) -> None:
        source_fd = self.directory(selected.source)
        payloads: dict[str, bytes] = {}
        for paths in (selected.build, selected.scanner):
            for path in paths:
                if path not in payloads:
                    parent = source_fd
                    for part in path.split("/")[:-1]:
                        parent = self.opened(parent, part, DIRECTORY).fd
                    entry = self.opened(parent, path.split("/")[-1], REGULAR)
                    payloads[path] = self.bytes(entry)
        if sum(len(payloads[path]) for path in (*selected.build, *selected.scanner)) > TOTAL_LIMIT:
            raise SnapshotFault("aggregate_bound")
        temp = "/private/tmp" if sys.platform == "darwin" else "/tmp"
        parent = self.directory(temp)
        name = "wakeio-source-" + uuid.uuid4().hex
        self.root = temp + "/" + name
        root = self.created(parent, name, None)
        for role, paths in (("build", selected.build), ("scanner", selected.scanner)):
            role_fd = self.created(root.fd, role, None).fd
            directories = {"": role_fd}
            for path in paths:
                parts = path.split("/")
                for index in range(1, len(parts)):
                    prefix = "/".join(parts[:index])
                    if prefix not in directories:
                        parent_fd = directories["/".join(parts[:index - 1])]
                        directories[prefix] = self.created(parent_fd, parts[index - 1], None).fd
                entry = self.created(directories["/".join(parts[:-1])], parts[-1], payloads[path])
                self.files[role, path] = entry, payloads[path]
        self.stable()

    def observe(self) -> dict[str, Wire]:
        rows: list[Wire] = []
        for (role, path), (entry, original) in self.files.items():
            data = self.bytes(entry)
            if data != original:
                raise SnapshotFault("projection_drift")
            rows.append({"role": role, "path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        return {"root": self.root, "files": rows}

    def cleanup(self) -> bool:
        self.disposal = dispose(self.owned, self.uncertain)
        return self.disposal.clean


def emit(value: dict[str, Wire]) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def receive() -> dict[str, Wire]:
    line = sys.stdin.buffer.readline(65537)
    if not line.endswith(b"\n") or len(line) > 65536:
        raise SnapshotFault("protocol")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise SnapshotFault("protocol")
    return value


def interrupted(number: int, frame: FrameType | None) -> None:
    raise SnapshotFault("interrupted")


def main() -> int:
    signal.signal(signal.SIGTERM, interrupted)
    with ExitStack() as stack:
        capture = Capture(stack)
        try:
            capture.capture(request(receive()))
            emit(capture.observe())
            while True:
                command = receive()
                if command == {"op": "close"}:
                    break
                capture.observe()
                if command == {"op": "observe"}:
                    emit(capture.observe())
                elif set(command) == {"op", "role", "path"} and command["op"] == "read":
                    entry, data = capture.files[command["role"], command["path"]]
                    emit({"data": base64.b64encode(capture.bytes(entry)).decode("ascii")})
                else:
                    raise SnapshotFault("protocol")
        except (OSError, SnapshotFault, ValueError, KeyError, TypeError):
            emit({"error": "snapshot_refused"})
        finally:
            clean = capture.cleanup()
            emit({"closed": clean, "root": capture.root, "retained": capture.disposal.directory})
    return 0 if clean else 2


if __name__ == "__main__":
    sys.exit(main())
