# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: only through the original controller startup; never accepts a supplied descriptor.
"""Original service-input and negative-control descriptor custody, not an ownership adapter."""
from __future__ import annotations

import os
import select
import stat
from typing import TYPE_CHECKING, Literal, assert_never

from backend_process import BackendError, require
from backend_startup_data import INITIAL_BOUND, STARTUP_READY, StartupBudget, parse_initialization

if TYPE_CHECKING:
    from backend_startup import OriginalStartup

type Identity = tuple[int, int, int]


def descriptor_identity(descriptor: int) -> Identity:
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


class StartupIO:
    """Mutable original FD ledger; its actual Startup retains it before the first pipe allocation."""

    def __init__(self, source: OriginalStartup) -> None:
        self.source = source
        self.descriptors: dict[str, int] = {}
        self.identities: dict[str, Identity] = {}
        self.started = False
        self.closed = False
        self.close_unknown = False

    def original(self) -> None:
        from backend_startup import OriginalStartup
        require(type(self) is StartupIO and type(self.source) is OriginalStartup
                and self.source.io is self, "startup_io_original")

    def check(self) -> None:
        self.original()
        require(not self.closed and not self.close_unknown, "startup_io_retired")
        for name, descriptor in self.descriptors.items():
            require(self.identities.get(name) == descriptor_identity(descriptor), "startup_descriptor_changed")

    def initialize(self) -> StartupBudget:
        self.original()
        require(not self.started, "startup_initialization_replay")
        self.started = True
        self.source.raise_if_failed()
        reader, writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.descriptors.update({"input": 0, "control": reader, "writer": writer})
        for name, descriptor in self.descriptors.items():
            self.identities[name] = descriptor_identity(descriptor)
        require(self.identities["input"][2] in (stat.S_IFIFO, stat.S_IFSOCK), "startup_input_type")
        os.set_blocking(0, False)
        self.source.raise_if_failed()
        require(os.write(1, STARTUP_READY) == len(STARTUP_READY), "startup_marker_short")
        events = select.poll()
        events.register(0, select.POLLIN)
        events.register(reader, select.POLLIN)
        body = bytearray()
        while b"\n" not in body:
            self.check()
            self.source.raise_if_failed()
            batch = tuple(events.poll())
            require(len({fd for fd, _ in batch}) == len(batch), "startup_duplicate_event")
            for descriptor, flags in batch:
                require(descriptor in (0, reader) and flags != 0
                        and not flags & ~(select.POLLIN | select.POLLHUP | select.POLLERR),
                        "startup_initial_event")
            if any(flags & (select.POLLHUP | select.POLLERR) for _, flags in batch):
                self.source.revoke("startup_initial_channel_closed")
                self.source.raise_if_failed()
            self.check()
            self.source.raise_if_failed()
            for descriptor, _ in batch:
                if descriptor == reader:
                    self.consume("control")
                    self.source.raise_if_failed()
                else:
                    try:
                        chunk = os.read(0, INITIAL_BOUND + 1 - len(body))
                    except BlockingIOError:
                        continue
                    require(bool(chunk), "startup_initial_eof")
                    body.extend(chunk)
                    require(len(body) <= INITIAL_BOUND, "startup_initial_bound")
        self.check()
        self.source.raise_if_failed()
        budget = parse_initialization(bytes(body))
        self.consume("input")
        self.source.raise_if_failed()
        return budget

    def wake(self) -> None:
        writer = self.descriptors.get("writer")
        if writer is not None and not self.closed:
            try:
                require(not self.close_unknown and self.identities.get("writer") == descriptor_identity(writer),
                        "startup_wake_replaced")
                require(os.write(writer, b"!") == 1, "startup_wake_short")
            except BlockingIOError:
                return

    def consume(self, name: Literal["input", "control"]) -> None:
        self.check()
        descriptor = self.descriptors[name]
        try:
            body = os.read(descriptor, 65536)
        except BlockingIOError:
            return
        self.check()
        match name:
            case "input":
                self.source.revoke("backend_owner_revoked" if not body else "startup_extra_record")
            case "control":
                require(bool(body) and not body.strip(b"!"), "startup_control_lost")
                require(self.source.failure is not None, "startup_unbound_wake")
            case unreachable:
                assert_never(unreachable)

    def close(self) -> None:
        self.original()
        if self.closed:
            return
        require(not self.close_unknown, "startup_close_unknown")
        for name, descriptor in tuple(self.descriptors.items()):
            try:
                require(self.identities.get(name) == descriptor_identity(descriptor), "startup_close_replaced")
                os.close(descriptor)
            except (BackendError, OSError) as error:
                self.close_unknown = True
                raise BackendError("startup_close_unconfirmed:" + str(error)) from error
            del self.descriptors[name]
        self.closed = True
