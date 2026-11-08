# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: created only by the original guest main before Backend construction.
"""Original startup allowance and retained clock observer; no caller can supply live clock support."""
from __future__ import annotations

import sys
import time
from threading import Event, RLock, Thread, TIMEOUT_MAX
from typing import TYPE_CHECKING, Final, Literal, assert_never

from backend_process import BackendError, require
from backend_startup_data import ClockProfile, StartupBudget, cutoff_ns
from backend_startup_io import StartupIO

if TYPE_CHECKING:
    from build import BuildSession
    from relay import Backend
    from backend_service import OriginalConnection

QUALIFIED_CLOCKS: Final[tuple[ClockProfile, ...]] = ()


class OriginalStartup:
    """Mutable original lifetime: one G0/R, one Backend and one actual service connection."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.anchor_ns: int | None = None
        self.budget: StartupBudget | None = None
        self.profile: ClockProfile | None = None
        self.cutoff_ns: int | None = None
        self.backend: Backend | None = None
        self.session: BuildSession | None = None
        self.connection: OriginalConnection | None = None
        self.failure: BackendError | None = None
        self.notification_error: OSError | BackendError | None = None
        self.thread: Thread | None = None
        self.arm_attempted = False
        self.observers_retired = False
        self._stop = Event()
        self._lock = RLock()
        self.io = StartupIO(self)

    def initialize(self) -> None:
        require(sys.platform == "linux" and self.anchor_ns is None, "startup_original_platform")
        self.anchor_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        self.budget = self.io.initialize()

    def original(self) -> Backend:
        from relay import Backend
        backend = self.backend
        require(type(self) is OriginalStartup and type(backend) is Backend, "startup_original_backend")
        if backend is None:
            raise BackendError("startup_original_backend")
        require(backend._startup is self and backend.run_id == self.run_id, "startup_backend_changed")
        return backend

    def bind(self, backend: Backend) -> None:
        from relay import Backend
        require(type(backend) is Backend and backend._startup is self and backend.run_id == self.run_id
                and self.backend is None and self.budget is not None and self.anchor_ns is not None,
                "startup_backend_replay")
        self.backend = backend

    def bind_session(self) -> None:
        from build import BuildSession
        backend = self.original()
        require(self.session is None and type(backend.build) is BuildSession, "startup_session_replay")
        backend.build._original()
        self.session = backend.build

    def arm(self) -> None:
        self.original()
        require(not self.arm_attempted and not self.observers_retired, "startup_clock_replay")
        self.arm_attempted = True
        require(len(QUALIFIED_CLOCKS) <= 1, "startup_clock_profile_ambiguous")
        self.profile = next(iter(QUALIFIED_CLOCKS), None)
        profile, budget, anchor = self.profile, self.budget, self.anchor_ns
        if profile is None:
            return
        if budget is None or anchor is None:
            raise BackendError("startup_original_allowance")
        self.cutoff_ns = cutoff_ns(anchor, budget, profile)
        self.observe_deadline()
        self.raise_if_failed()
        self.thread = Thread(target=self._observe, name="wakeio-original-deadline", daemon=False)
        self.thread.start()

    def _observe(self) -> None:
        cutoff = self.cutoff_ns
        if cutoff is None:
            self.revoke("startup_original_cutoff_missing")
            return
        try:
            while not self._stop.is_set():
                remaining = cutoff - time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                if remaining <= 0:
                    self.revoke("backend_deadline")
                    return
                self._stop.wait(min(remaining / 1000000000, TIMEOUT_MAX))
        except (OSError, OverflowError, ValueError) as error:
            self.revoke("startup_clock_observation:" + str(error))

    def revoke(self, reason: str) -> None:
        with self._lock:
            if self.failure is not None:
                return
            self.failure = BackendError(reason)
            try:
                self.io.wake()
            except (OSError, BackendError) as error:
                self.notification_error = error

    def raise_if_failed(self) -> None:
        with self._lock:
            failure = self.failure
        if failure is not None:
            raise failure

    def work(self) -> None:
        self.original()
        self.raise_if_failed()
        require(not self.observers_retired and self.profile is not None and self.cutoff_ns is not None
                and self.thread is not None and self.thread.is_alive(), "backend_clock_unqualified")
        self.io.consume("input")
        connection = self.connection
        if connection is None:
            raise BackendError("backend_original_connection_unavailable")
        connection.work()
        if self.cutoff_ns is None:
            raise BackendError("startup_original_cutoff_missing")
        self.observe_deadline()
        self.raise_if_failed()

    def sources(self) -> tuple[tuple[Literal["input", "control", "connection"], int], ...]:
        self.original()
        self.io.check()
        if self.failure is not None:
            return ()
        connection = self.connection
        if connection is None:
            raise BackendError("backend_original_connection_unavailable")
        connection.check()
        return (("input", self.io.descriptors["input"]), ("control", self.io.descriptors["control"]),
                ("connection", connection.descriptor()))

    def consume(self, role: Literal["input", "control", "connection"]) -> None:
        match role:
            case "input" | "control":
                self.io.consume(role)
            case "connection":
                connection = self.connection
                if connection is None:
                    raise BackendError("backend_original_connection_unavailable")
                connection.observe()
            case unreachable:
                assert_never(unreachable)

    def observe_deadline(self) -> None:
        cutoff = self.cutoff_ns
        if cutoff is not None and time.clock_gettime_ns(time.CLOCK_MONOTONIC) >= cutoff:
            self.revoke("backend_deadline")

    def timeout_ms(self) -> int | None:
        if self.failure is not None:
            return None
        cutoff = self.cutoff_ns
        if cutoff is None:
            raise BackendError("startup_original_cutoff_missing")
        return max(0, min((cutoff - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) // 1000000, 2147483647))

    def retire_observers(self) -> None:
        if self.observers_retired:
            return
        if self.session is not None:
            backend = self.original()
            self.session._original()
            require(self.session._drained and not backend._mutation_unknown
                    and all(not item.private for item in backend._observations.attachments.values()),
                    "startup_borrowers_retained")
        self._stop.set()
        thread = self.thread
        if thread is not None and thread.ident is not None:
            thread.join()
        self.io.close()
        self.observers_retired = True

    def close_connection(self) -> None:
        if self.connection is not None:
            self.connection.close()
