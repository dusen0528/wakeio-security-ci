"""Original open-file anchors, adapted from M1 read_file/namedFile/owned_directory."""
import hashlib
import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from seal_types import require


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def safe_parent(path: str) -> tuple[tuple[str, tuple[int, ...]], ...]:
    require(os.path.isabs(path) and os.path.normpath(path) == path, "canonical_path")
    result = []
    for parent in reversed(Path(path).parents):
        info = os.lstat(parent)
        require(stat.S_ISDIR(info.st_mode), "parent_symlink")
        require(info.st_uid in (0, os.geteuid()), "parent_owner")
        require(not info.st_mode & 0o022 or bool(info.st_mode & stat.S_ISVTX), "parent_mode")
        # Ancestor link counts can change when unrelated siblings are created.
        # Exact entry sets/nlink/timestamps belong to explicitly sealed directories.
        result.append((str(parent), identity(info)[:5]))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class Anchor:
    path: str
    fd: int
    metadata: tuple[int, ...]
    parents: tuple[tuple[str, tuple[int, ...]], ...]
    sha256: str
    size: int

    def read(self) -> bytes:
        require(safe_parent(self.path) == self.parents, "ancestor_replaced")
        require(identity(os.lstat(self.path)) == self.metadata, "name_replaced")
        require(identity(os.fstat(self.fd)) == self.metadata, "fd_replaced")
        body = bytearray()
        while len(body) <= self.size:
            chunk = os.pread(self.fd, min(65536, self.size + 1 - len(body)), len(body))
            if not chunk:
                break
            body.extend(chunk)
        require(len(body) == self.size, "file_size")
        require(identity(os.fstat(self.fd)) == self.metadata, "read_race")
        require(identity(os.lstat(self.path)) == self.metadata, "name_race")
        require(hashlib.sha256(body).hexdigest() == self.sha256, "file_bytes")
        return bytes(body)


class Files:
    """Mutable original-operation owner; descriptors live until context exit."""
    def __init__(self) -> None:
        self._stack = ExitStack()
        self.anchors: list[Anchor] = []
        self.directories: list[tuple[str, tuple[int, ...], tuple[str, ...]]] = []
        self.closed = False

    def __enter__(self) -> "Files":
        return self

    def __exit__(self, *unused: BaseException | None) -> None:
        self.closed = True
        self._stack.close()

    def capture(self, path: str, limit: int) -> Anchor:
        require(not self.closed and all(a.path != path for a in self.anchors), "capture_once")
        parents = safe_parent(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self._stack.callback(os.close, fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid(), "file_owner_type")
        require(info.st_nlink == 1 and not info.st_mode & 0o022, "file_links_mode")
        require(0 <= info.st_size <= limit, "file_bound")
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            chunk = os.pread(fd, min(65536, info.st_size - offset), offset)
            require(bool(chunk), "short_file")
            digest.update(chunk)
            offset += len(chunk)
        anchor = Anchor(path, fd, identity(info), parents, digest.hexdigest(), info.st_size)
        anchor.read()
        self.anchors.append(anchor)
        return anchor

    def directory(self, path: str) -> None:
        require(not self.closed and all(d[0] != path for d in self.directories), "directory_once")
        safe_parent(path)
        info = os.lstat(path)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), "directory_owner")
        require(info.st_mode & 0o777 == 0o700, "directory_mode")
        self.directories.append((path, identity(info), tuple(sorted(os.listdir(path)))))

    def check(self, mutable_status: bool = False) -> None:
        require(not self.closed, "closed_files")
        for anchor in self.anchors:
            if not mutable_status or anchor.path != "/var/lib/dpkg/status":
                anchor.read()
        for path, metadata, names in self.directories:
            require(identity(os.lstat(path)) == metadata, "directory_replaced")
            require(tuple(sorted(os.listdir(path))) == names, "directory_entries")

    def digest(self) -> str:
        self.check()
        body = repr([(a.path, a.metadata, a.sha256) for a in self.anchors] + self.directories)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


def write_new(path: str, body: bytes) -> None:
    safe_parent(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
