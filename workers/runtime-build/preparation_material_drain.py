# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Same-stack material-first disposal; only actual original pipe reads permit retry."""
from __future__ import annotations

import os
import select
import stat
from typing import TYPE_CHECKING

from backend_process import BackendError, require
from cold_envelope_drain import _hold, _join_children, drain as cold_drain
from launch import LaunchError
from preparation_materials import PreparationMaterials

if TYPE_CHECKING:
    from build import BuildSession


class _Wake:
    """Mutable subscription association only; this class neither owns nor closes the pipe."""

    def __init__(self, session: BuildSession) -> None:
        self.session = session
        self.descriptor = session.backend._wake_read
        value = os.fstat(self.descriptor)
        self.identity = (value.st_dev, value.st_ino)
        self.events = select.poll()
        self.arm()

    def check(self) -> None:
        self.session._original()
        value = os.fstat(self.descriptor)
        require(self.session.backend._wake_read == self.descriptor and stat.S_ISFIFO(value.st_mode)
                and (value.st_dev, value.st_ino) == self.identity and not os.get_blocking(self.descriptor),
                "material_wake_lost")

    def arm(self) -> None:
        self.check()
        self.events.register(self.descriptor, select.POLLIN)

    def consume(self) -> bool:
        self.check()
        try:
            body = os.read(self.descriptor, 65536)
        except BlockingIOError:
            return False
        require(bool(body), "material_wake_eof")
        return True

    def wait(self) -> None:
        ready = self.events.poll()
        require(bool(ready), "material_wake_empty")
        self.check()
        for descriptor, flags in ready:
            require(descriptor == self.descriptor and flags == select.POLLIN, "material_wake_invalid")
        require(self.consume(), "material_wake_unconfirmed")


def _certain(session: BuildSession, materials: PreparationMaterials) -> None:
    configuration = session._preparation_config
    require(configuration is None or configuration.drained, "material_config_retained")
    require(not session._uncertainty() and not session.backend._mutation_unknown
            and not materials.close_unknown and not materials.identity_unknown, "material_cleanup_uncertain")
    input_close_unknown = session._resources.mount_fd is not None and any(
        pending.resources is session._resources and pending.selection.role == "volume-remove" and pending.settled
        for pending in session._pending)
    require(not input_close_unknown, "material_input_close_unknown")


def _attempt(session: BuildSession, materials: PreparationMaterials) -> None:
    try:
        configuration = session._preparation_config
        if configuration is not None and not configuration.drained:
            from preparation_config_drain import drain as config_drain
            config_drain(configuration)
        _join_children(session)
        _certain(session, materials)
        session._cleaning = True
        if not materials.drained:
            session.backend.check()
            materials.remove()
        if materials.drained and not session._cold:
            session._resources.remove()
            _certain(session, materials)
            session._drained = all(pending.process is not None and pending.process.drained
                                   for pending in session._pending)
    except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        session._fail("material_drain_failed:" + str(error))
        session._uncertainty()
        if not materials.drained:
            materials.state = "RETAINED"
    finally:
        session._cleaning = False


def drain(session: BuildSession) -> None:
    """Never unwind unfinished material/input/Process custody to Backend prerequisite teardown."""
    from build import BuildSession

    with session.backend._mutation_lock:
        try:
            require(type(session) is BuildSession, "material_drain_owner")
            materials = session._preparation_materials
            require(type(materials) is PreparationMaterials, "material_drain_owner")
            if materials is None:
                raise BackendError("material_drain_owner")
            wake = _Wake(session)
            wake.consume()
            while not session._drained:
                _attempt(session, materials)
                _join_children(session)
                _certain(session, materials)
                if materials.drained and session._cold:
                    cold_drain(session)
                if session._drained:
                    return
                wake.arm()
                wake.wait()
                wake.arm()
        except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            if session._preparation_materials is not None and not session._preparation_materials.drained:
                session._preparation_materials.state = "NEGATIVE_HOLD"
            _hold(session, "material_drain_observer_lost:" + str(error))
