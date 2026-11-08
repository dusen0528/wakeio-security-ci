# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Fixed original producer/verifier observation loop; no supplied poller, event or deadline exists."""
from __future__ import annotations

import os
import select
from typing import TYPE_CHECKING, Protocol

from backend_process import BackendError, require
from cold_envelope_data import ColdDataError
from launch import LaunchError
from preparation_config_data import ConfigError
from input_resources import checked

if TYPE_CHECKING:
    from preparation_config_tool import ConfigurationTool
    from preparation_config import PreparationConfiguration
    from process import Process


class PollContext(Protocol):
    """Typing for the standard poll object, never runtime owner recognition or an accepted input."""
    def register(self, descriptor: int, flags: int) -> None: ...
    def modify(self, descriptor: int, flags: int) -> None: ...
    def unregister(self, descriptor: int) -> None: ...
    def poll(self, timeout: int | None = None) -> list[tuple[int, int]]: ...


class StopHistory:
    """Original request and first attempt are separate monotone facts, not permission by themselves."""
    def __init__(self) -> None:
        self.requested = False
        self.attempted = False


def _process(tool: ConfigurationTool) -> Process:
    tool.original()
    pending = tool.attach
    if pending is None or pending.process is None or tool.events is None:
        raise BackendError("config_poll_original_missing")
    tool.configuration.session._member(pending, pending.process)
    require(tool.events is pending.process.events, "config_poll_replaced")
    return pending.process


def _foreign(tool: ConfigurationTool) -> tuple[tuple[str, int, int], ...]:
    wake = tool.configuration.wake
    if wake is None:
        raise BackendError("config_wake_missing")
    wake.check()
    sources = [("backend-wake", wake.descriptor, select.POLLIN)]
    if tool.wait is not None and not tool.wait.drained and not tool.wait.complete:
        tool.wait.original()
        value = os.fstat(tool.wait.descriptor)
        require((value.st_dev, value.st_ino) == tool.wait.allocation.identity, "config_wait_source_replaced")
        sources.append(("wait", tool.wait.descriptor, tool.wait.flags))
    if tool.envelope is not None and tool.envelope.armed and not tool.envelope.stopped:
        tool.envelope.original()
        descriptor = tool.envelope.descriptors["cgroup.events"]
        value = os.fstat(descriptor)
        require(tool.envelope.observation is not None and (value.st_dev, value.st_ino)
                == tool.envelope.identities["cgroup.events"], "config_group_read_missing")
        sources.append(("group", tool.envelope.descriptors["cgroup.events"], select.POLLPRI | select.POLLERR))
    return tuple(sources)


def _sync(tool: ConfigurationTool) -> None:
    events = _process(tool).events
    sources = _foreign(tool)
    current = {name: descriptor for name, descriptor, _ in sources}
    for name, descriptor in tuple(tool.foreign.items()):
        if name not in current:
            events.unregister(descriptor)
            del tool.foreign[name]
        else:
            require(current[name] == descriptor, "config_foreign_replacement")
    for name, descriptor, flags in sources:
        if name in tool.foreign:
            events.modify(descriptor, flags)
        else:
            events.register(descriptor, flags)
            tool.foreign[name] = descriptor
        tool.poll_generation += 1


def _validate(tool: ConfigurationTool, batch: tuple[tuple[int, int], ...]) -> None:
    process = _process(tool)
    permitted = set(process.armed) | set(tool.foreign.values())
    require(len({descriptor for descriptor, _ in batch}) == len(batch), "config_duplicate_event")
    for descriptor, flags in batch:
        require(type(descriptor) is int and type(flags) is int and descriptor in permitted
                and flags != 0 and not flags & select.POLLNVAL, "config_event_membership")
        if descriptor == tool.foreign.get("group"):
            require(not flags & ~(select.POLLPRI | select.POLLERR), "config_group_event_flags")
        elif descriptor in (tool.foreign.get("backend-wake"), process.descriptors.get("wake-read"),
                            process.descriptors.get("pidfd")):
            require(flags == select.POLLIN, "config_event_flags")
        else:
            wait = tool.wait
            writable = (wait is not None and descriptor == tool.foreign.get("wait")
                        and wait.flags == select.POLLOUT) or (process.child is not None
                        and process.streams.get(descriptor) is process.child.stdin)
            expected = select.POLLOUT if writable else select.POLLIN
            require(not flags & ~(expected | select.POLLHUP | select.POLLERR), "config_stream_event_flags")


def _dispatch(tool: ConfigurationTool, batch: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], bytes] | None:
    process = _process(tool)
    exceptional: tuple[tuple[int, int], bytes] | None = None
    for descriptor, flags in batch:
        if descriptor == tool.foreign.get("backend-wake"):
            wake = tool.configuration.wake
            if wake is None:
                raise BackendError("config_wake_missing")
            wake.read()
        elif descriptor == tool.foreign.get("wait"):
            if tool.wait is None:
                raise BackendError("config_wait_missing")
            tool.wait.ready(flags)
        elif descriptor == tool.foreign.get("group"):
            if tool.envelope is None:
                raise BackendError("config_group_missing")
            tool.envelope.observe()
            exceptional = tool.envelope.observation
        else:
            process._ready(descriptor, flags)
    return exceptional


def _poll(tool: ConfigurationTool) -> tuple[tuple[int, int], bytes] | None:
    _sync(tool)
    batch = tool.configuration.backend._configuration_poll(tool)
    _validate(tool, batch)
    return _dispatch(tool, batch)


def arm_tool(tool: ConfigurationTool) -> None:
    from preparation_config_wait import ConfigurationWait
    pending = tool.attach
    if pending is None or pending.process is None:
        raise BackendError("config_process_missing")
    tool.events = pending.process.events
    tool.wait = ConfigurationWait(tool)
    tool.wait.prepare()
    _sync(tool)
    tool.configuration.backend._configuration_arm(tool)
    while not tool.wait.headers_acknowledged:
        _poll(tool)
        tool.configuration.admit()
    tool.configuration.admit()


def _kill_once(tool: ConfigurationTool) -> None:
    if (not tool.stop.requested or tool.stop.attempted or tool.closed or not tool.released
            or tool.wait is None or tool.wait.complete):
        return
    tool.stop.attempted = True
    session = tool.configuration.session
    prior = session._cleaning
    session._cleaning = True
    try:
        pending = tool.configuration.call(tool.frame("container-kill"))
        require(checked(pending) == (tool.container + "\n").encode("ascii"), "config_kill_response")
        session._settle(pending)
    finally:
        session._cleaning = prior


def observe_tool(tool: ConfigurationTool) -> None:
    from phase_factory import begin_configuration_attach
    from preparation_config_drain import negative_hold
    tool.original()
    tool.observing = True
    session = tool.configuration.session
    previous = session._cleaning
    try:
        if tool.attach is None:
            begin_configuration_attach(tool)
        blocked = False
        while not tool.closed:
            exceptional = _poll(tool)
            fresh_wake = tool.configuration.take_cleanup_observation()
            if session._failure is not None or session._closing:
                tool.request_stop(_process(tool))
                session._cleaning = True
            before = len(tool.history)
            try:
                _kill_once(tool)
                if not blocked or exceptional is not None or fresh_wake is not None:
                    tool.configuration.backend._observations.prepare_join(tool)
                    tool.reconcile()
                    blocked = False
            except (BackendError, ConfigError, ColdDataError, LaunchError, OSError, ValueError, KeyError,
                    TypeError, RecursionError) as error:
                last = tool.history[-1]
                require(len(tool.history) > before and last.process is not None and last.process.drained
                        and not last.process.released, "config_reconcile_observation_lost:" + str(error))
                blocked = True
                session._fail("config_reconcile_prerequisite:" + str(error))
    except (BackendError, ConfigError, ColdDataError, LaunchError, OSError, ValueError, KeyError,
            TypeError, RecursionError) as error:
        if tool.released:
            negative_hold(tool.configuration, "config_tool_observer_lost:" + str(error))
        raise
    finally:
        tool.observing = False
        session._cleaning = previous


class ConfigurationSubscriptions:
    """Configuration-only cleanup polling begins after the tool loop yields; no concurrent reader exists."""

    def __init__(self, configuration: PreparationConfiguration) -> None:
        self.configuration = configuration
        self.events = select.poll()
        self.watching: dict[int, ConfigurationTool] = {}
        self.previous: dict[ConfigurationTool, tuple[tuple[int, int], bytes]] = {}

    def arm(self) -> None:
        wake = self.configuration.wake
        if wake is None:
            raise BackendError("config_wake_missing")
        wake.check()
        self.events = select.poll()
        self.watching.clear()
        self.events.register(wake.descriptor, select.POLLIN)
        for tool in (self.configuration.producer, self.configuration.verifier):
            if tool is None or tool.envelope is None:
                continue
            envelope = tool.envelope
            envelope.original()
            raw = envelope.observation
            if envelope.armed and not envelope.drained and raw is not None and raw is not self.previous.get(tool):
                descriptor = envelope.descriptors["cgroup.events"]
                self.identity(tool, descriptor)
                require(descriptor != wake.descriptor and descriptor not in self.watching, "config_source_duplicate")
                self.events.register(descriptor, select.POLLPRI | select.POLLERR)
                self.watching[descriptor] = tool
                self.previous[tool] = raw

    def identity(self, tool: ConfigurationTool, descriptor: int) -> None:
        tool.original()
        envelope = tool.envelope
        if envelope is None:
            raise BackendError("config_group_missing")
        envelope.paths.check()
        value = os.fstat(descriptor)
        require(envelope.armed and not envelope.drained and envelope.descriptors.get("cgroup.events") == descriptor
                and (value.st_dev, value.st_ino) == envelope.identities["cgroup.events"], "config_source_replaced")

    def wait(self) -> tuple[tuple[int, int], bytes] | None:
        wake = self.configuration.wake
        if wake is None:
            raise BackendError("config_wake_missing")
        batch = self.events.poll()
        wake.check()
        require(bool(batch) and len({fd for fd, _ in batch}) == len(batch), "config_cleanup_batch")
        for descriptor, flags in batch:
            if descriptor == wake.descriptor:
                require(flags == select.POLLIN, "config_cleanup_wake_flags")
            else:
                require(descriptor in self.watching and flags != 0
                        and not flags & ~(select.POLLPRI | select.POLLERR), "config_cleanup_group_flags")
                self.identity(self.watching[descriptor], descriptor)
        fresh: tuple[tuple[int, int], bytes] | None = None
        for descriptor, _ in batch:
            if descriptor == wake.descriptor:
                wake.read()
            else:
                envelope = self.watching[descriptor].envelope
                if envelope is None:
                    raise BackendError("config_group_missing")
                envelope.observe()
                fresh = envelope.observation
        return fresh


def unwatch_foreign(tool: ConfigurationTool) -> None:
    tool.configuration.backend._observations.detach(tool)
    if tool.events is not None:
        events = _process(tool).events
        for name, descriptor in tuple(tool.foreign.items()):
            events.unregister(descriptor)
            del tool.foreign[name]
