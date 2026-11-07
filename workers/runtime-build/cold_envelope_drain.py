# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""The original cold drain stays on stack; subscriptions own no resource or disposition."""
from __future__ import annotations

import os
import select
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Never

from backend_process import BackendError, require
from cold_envelope import ColdEnvelope
from cold_envelope_data import ColdDataError, parse_events
from launch import LaunchError

if TYPE_CHECKING:
    from build import BuildSession


@dataclass(frozen=True, slots=True)
class _Watch:
    envelope: ColdEnvelope
    identity: tuple[int, int]
    read: tuple[bytes] | None


class _Subscriptions:
    """Mutable subscription bookkeeping only; all cleanup remains in the original owners."""

    def __init__(self, session: BuildSession) -> None:
        self.session = session
        self.wake = session.backend._wake_read
        value = os.fstat(self.wake)
        self.wake_identity = (value.st_dev, value.st_ino)
        self.events = select.poll()
        self.watching: dict[int, _Watch] = {}
        self._wake_check()

    def _wake_check(self) -> None:
        self.session._original()
        value = os.fstat(self.wake)
        require(self.session.backend._wake_read == self.wake and stat.S_ISFIFO(value.st_mode)
                and (value.st_dev, value.st_ino) == self.wake_identity
                and not os.get_blocking(self.wake), "cold_wake_lost")

    def _member(self, envelope: ColdEnvelope) -> None:
        self.session._original()
        require(type(envelope) is ColdEnvelope and self.session._cold.get(envelope.phase) is envelope
                and envelope.session is self.session and envelope.backend is self.session.backend
                and envelope.daemon is self.session.daemon and envelope.generation == self.session._generation
                and envelope.input is self.session._copy, "cold_subscription_owner")

    def _identity(self, descriptor: int, watch: _Watch) -> None:
        self._member(watch.envelope)
        require(watch.envelope.armed and not watch.envelope.drained
                and watch.envelope.descriptors.get("cgroup.events") == descriptor, "cold_subscription_changed")
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and (value.st_dev, value.st_ino) == watch.identity
                == watch.envelope.identities["cgroup.events"], "cold_subscription_replaced")

    def arm(self) -> None:
        self._wake_check()
        self.events = select.poll()
        self.watching.clear()
        self.events.register(self.wake, select.POLLIN)
        for envelope in self.session._cold.values():
            if envelope is None or envelope.drained:
                continue
            self._member(envelope)
            if envelope.armed:
                descriptor = envelope.descriptors["cgroup.events"]
                watch = _Watch(envelope, envelope.identities["cgroup.events"], envelope.observation)
                self._identity(descriptor, watch)
                require(descriptor != self.wake and descriptor not in self.watching, "cold_subscription_duplicate")
                self.events.register(descriptor, select.POLLPRI | select.POLLERR)
                self.watching[descriptor] = watch

    def consume_wake(self) -> bool:
        self._wake_check()
        try:
            body = os.read(self.wake, 65536)
        except BlockingIOError:
            return False
        require(bool(body), "cold_wake_eof")
        return True

    def prune(self) -> None:
        for descriptor, watch in tuple(self.watching.items()):
            envelope = watch.envelope
            self._member(envelope)
            keep = not envelope.drained and envelope.armed and "cgroup.events" in envelope.descriptors
            if keep:
                self._identity(descriptor, watch)
                raw = envelope.observation
                keep = raw is not None and raw is not watch.read
                if keep and raw is not None:
                    try:
                        parse_events(raw[0])
                    except ColdDataError:
                        keep = False
            if not keep:
                self.events.unregister(descriptor)
                del self.watching[descriptor]

    def wait(self) -> None:
        ready = self.events.poll()
        require(bool(ready), "cold_observer_empty")
        wake = False
        for descriptor, flags in ready:
            if descriptor == self.wake:
                self._wake_check()
                require(bool(flags & select.POLLIN) and not flags & ~select.POLLIN, "cold_wake_invalid")
                wake = True
            else:
                require(descriptor in self.watching, "cold_observer_foreign")
                self._identity(descriptor, self.watching[descriptor])
                require(bool(flags & (select.POLLPRI | select.POLLERR))
                        and not flags & ~(select.POLLPRI | select.POLLERR), "cold_observer_invalid")
        if wake:
            require(self.consume_wake(), "cold_wake_unconfirmed")


def _join_children(session: BuildSession) -> None:
    for pending in session._pending:
        if pending.process is not None and not pending.process.drained:
            pending.process.stop()
    for pending in session._pending:
        if pending.process is not None and not pending.process.drained:
            pending.process.join()
    require(all(pending.process is not None and pending.process.drained
                for pending in session._pending), "cold_children_retained")


def _certain(session: BuildSession) -> None:
    require(not session._uncertainty() and not session.backend._mutation_unknown
            and all(envelope is None or not envelope.close_unknown for envelope in session._cold.values()),
            "cold_cleanup_uncertain")


def _attempt(session: BuildSession) -> None:
    try:
        _join_children(session)
        _certain(session)
        session._cleaning = True
        session._resources.remove()
        for envelope in session._cold.values():
            if envelope is None or envelope.drained:
                continue
            try:
                envelope.remove()
            except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
                session._fail("cold_cleanup_failed:" + str(error))
                _join_children(session)
                _certain(session)
        _certain(session)
        session._drained = all(pending.process is not None and pending.process.drained
                               for pending in session._pending) and all(
                                   envelope is None or envelope.drained for envelope in session._cold.values())
    except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
        session._fail("cold_drain_failed:" + str(error))
        session._uncertainty()
    finally:
        session._cleaning = False


def _hold(session: BuildSession, reason: str) -> Never:
    """Terminal missing facts have no recovery transition; keep Backend.close prerequisites alive."""
    session._fail(reason)
    try:
        _join_children(session)
    except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
        session._fail("cold_terminal_join_failed:" + str(error))
    while True:
        session._wake.clear()
        session._wake.wait()


def drain(session: BuildSession) -> None:
    """Drive only the actual original session; never return from unfinished or uncertain cleanup."""
    from build import BuildSession
    require(type(session) is BuildSession, "cold_drain_owner_type")
    with session.backend._mutation_lock:
        try:
            subscriptions = _Subscriptions(session)
            while not session._drained:
                subscriptions.arm()
                subscriptions.consume_wake()
                _attempt(session)
                _join_children(session)
                _certain(session)
                subscriptions.prune()
                if session._drained:
                    return
                subscriptions.wait()
        except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
            _hold(session, "cold_drain_observer_lost:" + str(error))
