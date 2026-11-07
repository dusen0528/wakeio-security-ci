"""Fixed BUILD byte progression. These copies and receipts confer no resource authority."""
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict

MAX_CHUNK: Final = 24576
MAX_FILE: Final = 1048576
MAX_PROJECTION: Final = 8388608
PROFILE_SHA256: Final = "ba9a3778518ad6fbed4e25cffc5f7c9c9701b14c32bd2da041cb5fae7dc0b53a"


@dataclass(frozen=True, slots=True)
class InputError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise InputError(reason)


class _ProfileRow(TypedDict):
    id: str
    root: str
    files: list[int]


class _BindingRow(TypedDict):
    path: str
    bytes: int
    sha256: str
    roles: list[str]


class _Metadata(TypedDict):
    profiles: list[_ProfileRow]
    bindings: list[_BindingRow]


class Receipt(TypedDict):
    file: int
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Binding:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Profile:
    identifier: str
    root: str
    files: tuple[Binding, ...]


def profile(identifier: str) -> Profile:
    """Select only the hash-bound controller metadata, never a caller path or root."""
    require(type(identifier) is str and identifier in ("f01", "f02", "f03", "f04"), "profile")
    with Path(__file__).with_name("profiles.json").open("rb") as source:
        raw = source.read(65537)
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == PROFILE_SHA256, "profile_binding")
    metadata: _Metadata = json.loads(raw)
    selected = next(row for row in metadata["profiles"] if row["id"] == identifier)
    bindings = tuple(metadata["bindings"][index] for index in selected["files"])
    files = tuple(Binding(row["path"], row["bytes"], row["sha256"]) for row in bindings if "BUILD" in row["roles"])
    require(len(files) == 5 and all(0 < row.size <= MAX_FILE for row in files)
            and sum(row.size for row in files) <= MAX_PROJECTION, "profile_bounds")
    return Profile(identifier, selected["root"], files)


@dataclass(frozen=True, slots=True)
class Chunk:
    file: int
    offset: int
    data: bytes


@dataclass(frozen=True, slots=True)
class InputCopy:
    """Immutable, profile-checked DATA, not a sealed volume or a build eligibility token."""
    identifier: str
    bodies: tuple[bytes, ...]

    def __post_init__(self) -> None:
        selected = profile(self.identifier)
        require(type(self.bodies) is tuple and len(self.bodies) == 5, "copy_count")
        for binding, body in zip(selected.files, self.bodies, strict=True):
            require(type(body) is bytes and len(body) == binding.size, "copy_length")
            require(hashlib.sha256(body).hexdigest() == binding.sha256, "copy_digest")

    def manifest(self) -> bytes:
        rows = [{"file": index, "path": binding.path, "bytes": len(body),
                 "sha256": hashlib.sha256(body).hexdigest()}
                for index, (binding, body) in enumerate(zip(profile(self.identifier).files, self.bodies, strict=True))]
        return json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class InputData:
    """Mutable one-way byte accumulator; any refusal consumes its remaining DATA transitions."""
    __slots__ = ("_profile", "_bodies", "_active", "_file", "_open")

    def __init__(self, identifier: str) -> None:
        self._profile = profile(identifier)
        self._bodies: list[bytes] = []
        self._active = bytearray()
        self._file = 0
        self._open = True

    def append(self, chunk: Chunk) -> int:
        """Accept exactly the next nonempty decoded chunk; a full file advances the ordinal."""
        require(self._open, "input_state")
        self._open = False
        require(type(chunk) is Chunk, "chunk_shape")
        require(type(chunk.file) is int and chunk.file == self._file and self._file < 5, "file_order")
        require(type(chunk.offset) is int and chunk.offset == len(self._active), "offset_order")
        require(type(chunk.data) is bytes and 0 < len(chunk.data) <= MAX_CHUNK, "chunk_bound")
        binding = self._profile.files[self._file]
        end = len(self._active) + len(chunk.data)
        require(end <= binding.size and end <= MAX_FILE, "file_bound")
        self._active.extend(chunk.data)
        if end == binding.size:
            body = bytes(self._active)
            require(hashlib.sha256(body).hexdigest() == binding.sha256, "input_digest")
            self._bodies.append(body)
            self._active.clear()
            self._file += 1
        self._open = True
        return end

    def finish(self, receipts: Sequence[Receipt]) -> InputCopy:
        """Join retained bytes to the original host's exact ordered five receipt rows once."""
        require(self._open, "input_state")
        self._open = False
        require(self._file == 5 and not self._active, "input_incomplete")
        require(len(receipts) == 5, "receipt_count")
        for index, (row, binding, body) in enumerate(
                zip(receipts, self._profile.files, self._bodies, strict=True)):
            require(type(row) is dict and set(row) == {"file", "bytes", "sha256"}, "receipt_shape")
            require(type(row["file"]) is int and row["file"] == index, "receipt_order")
            require(type(row["bytes"]) is int and row["bytes"] == len(body) == binding.size, "receipt_length")
            require(type(row["sha256"]) is str
                    and row["sha256"] == hashlib.sha256(body).hexdigest() == binding.sha256, "receipt_digest")
        return InputCopy(self._profile.identifier, tuple(self._bodies))
