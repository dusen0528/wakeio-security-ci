"""Bounded local descriptor observations, never original volume membership or sealing."""
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import BinaryIO, Final

BLOCK: Final = 65536
MAX_METADATA: Final = 16 * 1024 * 1024
MAX_DIRECTORIES: Final = 32768
DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(slots=True)
class OutputError(Exception):
    """Tracebacks are interpreter-owned mutable exception state, including during context exit."""
    reason: str

    def __str__(self) -> str:
        return self.reason


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise OutputError(reason)


def relative_path(value: str) -> str:
    require(type(value) is str and value and not value.startswith("/") and "\\" not in value, "output_path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise OutputError("output_path") from error
    parts = value.split("/")
    require(len(encoded) <= 4096 and len(parts) <= 64
            and all(part not in ("", ".", "..") and len(part.encode("utf-8")) <= 255 for part in parts)
            and all(ord(char) >= 32 and ord(char) != 127 for char in value), "output_path")
    return value


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True, slots=True)
class Binding:
    path: str
    bytes: int
    sha256: str

    def __post_init__(self) -> None:
        relative_path(self.path)
        require(type(self.bytes) is int and self.bytes >= 0, "output_length")
        require(type(self.sha256) is str and re.fullmatch(r"[a-f0-9]{64}", self.sha256) is not None,
                "output_digest")


def bindings_digest(rows: tuple[Binding, ...]) -> str:
    values = [{"path": row.path, "bytes": row.bytes, "sha256": row.sha256}
              for row in sorted(rows, key=lambda row: row.path)]
    return hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Limits:
    bytes: int
    files: int

    def __post_init__(self) -> None:
        require(type(self.bytes) is int and self.bytes >= 0
                and type(self.files) is int and self.files >= 0, "output_limits")


@dataclass(frozen=True, slots=True)
class File:
    binding: Binding
    metadata: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Directory:
    path: str
    metadata: tuple[int, ...]
    names: tuple[str, ...]


@contextmanager
def _opened(parent: int, name: str, expected: tuple[int, ...]) -> Iterator[BinaryIO]:
    """Keep the same regular single-link descriptor and name throughout its read interval."""
    opened = os.open(name, FILE_FLAGS, dir_fd=parent)
    with os.fdopen(opened, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "output_file_type")
        require(info.st_nlink == 1, "output_file_links")
        require(identity(info) == expected
                and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected,
                "output_file_changed")
        yield stream
        require(identity(os.fstat(stream.fileno())) == expected
                and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected,
                "output_file_changed")


def _hash(stream: BinaryIO, size: int) -> str:
    digest = hashlib.sha256()
    position = 0
    while position < size:
        chunk = os.pread(stream.fileno(), min(BLOCK, size - position), position)
        require(bool(chunk), "output_file_short")
        digest.update(chunk)
        position += len(chunk)
    require(not os.pread(stream.fileno(), 1, size), "output_file_grew")
    return digest.hexdigest()


class _Walk:
    """Mutable bounded traversal accumulator; it owns no borrowed descriptor."""
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.total = 0
        self.metadata = 0
        self.files: list[File] = []
        self.directories: list[Directory] = []

    def charge(self, path: str) -> None:
        self.metadata += len(path.encode("utf-8")) + 256
        require(self.metadata <= MAX_METADATA, "output_metadata_bound")

    def file(self, fd: int, name: str, path: str) -> None:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode), "output_file_type")
        require(0 <= info.st_size <= self.limits.bytes - self.total, "output_tree_bytes")
        require(len(self.files) < self.limits.files, "output_tree_files")
        with _opened(fd, name, identity(info)) as stream:
            digest = _hash(stream, info.st_size)
        self.total += info.st_size
        self.files.append(File(Binding(path, info.st_size, digest), identity(info)))

    def walk(self, fd: int, path: str) -> None:
        before = identity(os.fstat(fd))
        require(stat.S_ISDIR(before[2]), "output_directory_type")
        self.charge(path)
        require(len(self.directories) < MAX_DIRECTORIES, "output_directory_bound")
        names: list[str] = []
        folded: set[str] = set()
        self.directories.append(Directory(path, before, ()))
        slot = len(self.directories) - 1
        with os.scandir(fd) as entries:
            for entry in entries:
                relative = relative_path((path + "/" if path else "") + entry.name)
                self.charge(relative)
                require(entry.name.casefold() not in folded, "output_name_collision")
                folded.add(entry.name.casefold())
                names.append(entry.name)
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    with ExitStack() as stack:
                        child = os.open(entry.name, DIRECTORY_FLAGS, dir_fd=fd)
                        stack.callback(os.close, child)
                        require(identity(os.fstat(child)) == identity(info), "output_directory_changed")
                        self.walk(child, relative)
                        require(identity(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) == identity(info),
                                "output_directory_changed")
                else:
                    self.file(fd, entry.name, relative)
        require(identity(os.fstat(fd)) == before, "output_directory_changed")
        self.directories[slot] = Directory(path, before, tuple(sorted(names)))


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Read-only observations. The caller still owns the root and exclusion of all writers."""
    root: int
    limits: Limits
    files: tuple[File, ...]
    directories: tuple[Directory, ...]
    parents: Mapping[str, tuple[int, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "parents",
                           MappingProxyType({directory.path: directory.metadata for directory in self.directories}))

    def check(self) -> None:
        require(scan(self.root, self.limits) == self, "output_tree_changed")

    @contextmanager
    def open(self, file: File) -> Iterator[BinaryIO]:
        parts = relative_path(file.binding.path).split("/")
        with ExitStack() as stack:
            parent = self.root
            require(identity(os.fstat(parent)) == self.parents[""], "output_directory_changed")
            for index, name in enumerate(parts[:-1]):
                parent = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
                stack.callback(os.close, parent)
                require(identity(os.fstat(parent)) == self.parents["/".join(parts[:index + 1])],
                        "output_directory_changed")
            with _opened(parent, parts[-1], file.metadata) as stream:
                yield stream


def scan(root_fd: int, limits: Limits) -> Snapshot:
    """Borrow an open directory and produce bounded, reconciliable descriptor observations."""
    require(type(root_fd) is int and stat.S_ISDIR(os.fstat(root_fd).st_mode), "output_root")
    walk = _Walk(limits)
    walk.walk(root_fd, "")
    return Snapshot(root_fd, limits, tuple(sorted(walk.files, key=lambda file: file.binding.path)),
                    tuple(sorted(walk.directories, key=lambda directory: directory.path)))
