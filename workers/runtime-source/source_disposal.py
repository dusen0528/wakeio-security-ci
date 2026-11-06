"""Original-entry disposal in a helper-private, unpublished namespace.

The namespace excludes public-path mutators, not an arbitrary same-UID process
which discovers it or retains directory descriptors into it.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from contextlib import ExitStack
from typing import Literal, NamedTuple, Sequence


class SnapshotFault(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Anchor(NamedTuple):
    parent: int
    name: str
    fd: int
    info: os.stat_result


class Pending(NamedTuple):
    name: str
    device: str
    inode: str
    slot: str | None
    location: Literal["original", "operation_pending", "unknown"]


class Recovery(NamedTuple):
    directory: str | None
    pending: tuple[Pending, ...]
    uncertain: bool

    @property
    def clean(self) -> bool:
        return not self.uncertain and not self.pending and self.directory is None


def identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode


def stamp(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (*identity(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify_anchor(entry: Anchor, strict: bool = True) -> None:
    named = os.stat(entry.name, dir_fd=entry.parent, follow_symlinks=False)
    current = os.fstat(entry.fd)
    if identity(named) != identity(entry.info) or identity(current) != identity(entry.info):
        raise SnapshotFault("identity")
    if stat.S_ISREG(entry.info.st_mode):
        if current.st_nlink != 1 or stamp(named) != stamp(current):
            raise SnapshotFault("file_drift")
        if strict and stamp(current) != stamp(entry.info):
            raise SnapshotFault("file_drift")
        if not strict and (current.st_size != entry.info.st_size or current.st_mtime_ns != entry.info.st_mtime_ns):
            raise SnapshotFault("file_drift")
    elif not stat.S_ISDIR(current.st_mode):
        raise SnapshotFault("file_type")


def publish(recovery: Recovery) -> None:
    print(json.dumps({"cleanup": {
        "directory": recovery.directory, "pending": [entry._asdict() for entry in recovery.pending],
        "uncertain": recovery.uncertain,
    }}, separators=(",", ":")), flush=True)


def retire(entry: Anchor, destination: int, slot: str) -> None:
    verify_anchor(entry)
    if stat.S_ISDIR(entry.info.st_mode) and os.listdir(entry.fd):
        raise SnapshotFault("nonempty")
    os.rename(entry.name, slot, src_dir_fd=entry.parent, dst_dir_fd=destination)
    claimed = Anchor(destination, slot, entry.fd, entry.info)
    # Rename may change ctime. It does not establish the detached entry's identity.
    verify_anchor(claimed, strict=False)
    if stat.S_ISDIR(entry.info.st_mode):
        os.rmdir(slot, dir_fd=destination)
    else:
        os.unlink(slot, dir_fd=destination)


def dispose(owned: Sequence[Anchor], uncertain: bool) -> Recovery:
    if not owned:
        return Recovery(None, (), uncertain)
    directory = tempfile.mkdtemp(prefix="wakeio-source-cleanup-",
                                 dir="/private/tmp" if sys.platform == "darwin" else "/tmp")
    pending = {
        index: Pending(entry.name, str(entry.info.st_dev), str(entry.info.st_ino), None, "original")
        for index, entry in enumerate(owned)
    }
    # The original session receives this journal independently of a pending API read.
    publish(Recovery(directory, tuple(pending.values()), uncertain))
    with ExitStack() as stack:
        expected = os.stat(directory, follow_symlinks=False)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        actual = os.fstat(fd)
        if identity(expected) != identity(actual) or stat.S_IMODE(actual.st_mode) != 0o700:
            raise SnapshotFault("quarantine_identity")
        for index in reversed(range(len(owned))):
            pending[index] = pending[index]._replace(slot=str(index), location="operation_pending")
            publish(Recovery(directory, tuple(pending.values()), uncertain))
            try:
                retire(owned[index], fd, str(index))
            except (OSError, SnapshotFault):
                uncertain = True
                pending[index] = pending[index]._replace(location="unknown")
            else:
                del pending[index]
            publish(Recovery(directory, tuple(pending.values()), uncertain))
        if not uncertain:
            try:
                os.rmdir(directory)
            except OSError:
                uncertain = True
            else:
                directory = None
        result = Recovery(directory, tuple(pending.values()), uncertain)
        publish(result)
        return result
