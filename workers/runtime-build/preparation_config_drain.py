# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original serialized configuration continuation; borrowed wake reads never declare CLOSE."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Never

from backend_process import BackendError, require
from cold_envelope_data import ColdDataError
from cold_envelope_drain import _hold
from launch import LaunchError
from preparation_config_data import ConfigError
from preparation_config_bindings import verify_original_result
from preparation_config_tool import ConfigurationTool
from preparation_config_observe import ConfigurationSubscriptions, arm_tool, observe_tool, unwatch_foreign

if TYPE_CHECKING:
    from preparation_config import PreparationConfiguration
    from preparation_config_volumes import ConfigurationVolume


@dataclass(frozen=True, slots=True)
class ConfigurationWakeRead:
    descriptor: int
    identity: tuple[int, int]
    sequence: int
    body: bytes


class ConfigurationWake:
    """One mutable borrowed read view; it never creates, replaces, closes or accepts a pipe."""

    def __init__(self, configuration: PreparationConfiguration) -> None:
        self.configuration = configuration
        self.descriptor = configuration.backend._wake_read
        value = os.fstat(self.descriptor)
        self.identity = (value.st_dev, value.st_ino)
        self.sequence = 0
        self.last_read: ConfigurationWakeRead | None = None
        self.pending_read: ConfigurationWakeRead | None = None
        self.last_spent: ConfigurationWakeRead | None = None
        self.last_discarded: ConfigurationWakeRead | None = None

    def check(self) -> None:
        self.configuration.original()
        value = os.fstat(self.descriptor)
        require(self.configuration.wake is self and self.configuration.backend._wake_read == self.descriptor
                and stat.S_ISFIFO(value.st_mode) and not os.get_blocking(self.descriptor)
                and (value.st_dev, value.st_ino) == self.identity, "config_wake_replaced")

    def read(self) -> None:
        self.check()
        self.discard()
        try:
            body = os.read(self.descriptor, 65536)
        except BlockingIOError:
            return
        require(bool(body), "config_wake_eof")
        self.sequence += 1
        self.last_read = ConfigurationWakeRead(self.descriptor, self.identity, self.sequence, body)
        self.pending_read = self.last_read

    def take(self) -> ConfigurationWakeRead | None:
        self.check()
        value, self.pending_read = self.pending_read, None
        if value is not None:
            require(value.descriptor == self.descriptor and value.identity == self.identity and bool(value.body)
                    and (self.last_spent is None or value.sequence > self.last_spent.sequence), "config_wake_replay")
            self.last_spent = value
        return value

    def discard(self) -> None:
        if self.pending_read is not None:
            self.last_discarded = self.pending_read
            self.pending_read = None


def _retire(tool: ConfigurationTool) -> None:
    session = tool.configuration.session
    previous = session._cleaning
    session._cleaning = True
    try:
        tool.remove()
    finally:
        session._cleaning = previous




def prepare(configuration: PreparationConfiguration) -> None:
    configuration.admit()
    require(not configuration.started, "config_prepare_replay")
    configuration.started = True
    configuration.wake = ConfigurationWake(configuration)
    configuration.state = "ALLOCATING"
    configuration.result.allocate()
    configuration.inputs.allocate()
    configuration.state = "SEEDING"
    configuration.input_seed = ConfigurationTool(configuration, "input-seed")
    configuration.input_seed.create()
    configuration.input_seed.seed()
    _retire(configuration.input_seed)
    configuration.inputs_sealed = True
    configuration.seed = ConfigurationTool(configuration, "seed")
    configuration.seed.create()
    configuration.seed.seed()
    _retire(configuration.seed)
    configuration.state = "PRODUCING"
    configuration.producer = ConfigurationTool(configuration, "producer")
    configuration.producer.create()
    configuration.producer.read("read-helper")
    configuration.producer.read("read-certificate")
    observe_tool(configuration.producer)
    process = configuration.producer.attach.process
    require(process is not None and configuration.producer.exit_code == 0 and not process.output
            and not process.errors and not process.output_overflow, "config_producer_failed")
    _retire(configuration.producer)
    configuration.writers_removed = True
    configuration.state = "VERIFYING"
    configuration.verifier = ConfigurationTool(configuration, "verifier")
    configuration.verifier.create()
    configuration.verifier.read("read-helper")
    configuration.verifier.read("read-certificate")
    configuration.verifier.read("read-config")
    observe_tool(configuration.verifier)
    verify_original_result(configuration)
    _retire(configuration.verifier)
    previous = configuration.session._cleaning
    configuration.session._cleaning = True
    try:
        configuration.inputs.remove()
    finally:
        configuration.session._cleaning = previous
    configuration.admit()
    require(configuration.inputs.removed and not configuration.inputs.descriptors
            and configuration.verification is not None and not configuration.uncertain(), "config_hold_incomplete")
    configuration.held = True
    configuration.state = "CONFIGURATION_HELD"


def _volume_disposed(volume: ConfigurationVolume) -> bool:
    pending = volume.creation
    absent = pending is None or (pending.process is not None and pending.process.drained
                                 and not pending.process.released and not volume.returned)
    return (absent or volume.removed) and not volume.descriptors and not volume.close_unknown


def _dispose(configuration: PreparationConfiguration) -> None:
    session = configuration.session
    configuration.held = False
    configuration.state = "DISPOSING"
    configuration.preparation_burned = True
    configuration.offline_burned = True
    tools = (configuration.seed, configuration.input_seed, configuration.producer, configuration.verifier)
    for pending in tuple(configuration.pending):
        if (not any(tool is not None and tool.attach is pending for tool in tools)
                and pending.process is not None and not pending.process.drained):
            session._member(pending, pending.process)
            pending.process.stop()
            pending.process.join()
    for borrower in (configuration.preparation_borrow, configuration.offline_borrow):
        if borrower is not None and not borrower.drained:
            borrower.drain()
    for tool in (configuration.seed, configuration.input_seed, configuration.producer, configuration.verifier):
        if tool is None or tool.drained:
            continue
        if tool.attach is not None and tool.attach.process is not None and tool.released and not tool.closed:
            tool.request_stop(tool.attach.process)
            observe_tool(tool)
        if not tool.released:
            unwatch_foreign(tool)
        for pending in tool.history:
            if pending.process is not None and not pending.process.drained:
                pending.process.stop()
                pending.process.join()
        require(not session._uncertainty() and not configuration.uncertain(), "config_cleanup_uncertain")
        tool.remove()
    require(not configuration.uncertain(), "config_cleanup_uncertain")
    for volume in (configuration.inputs, configuration.result):
        if not _volume_disposed(volume):
            volume.remove()
    configuration.drained = (all(_volume_disposed(volume) for volume in (configuration.inputs, configuration.result))
                             and all(p.process is not None and p.process.drained for p in configuration.pending)
                             and not configuration.uncertain())
    if configuration.drained:
        configuration.state = "DISPOSED"


def drain(configuration: PreparationConfiguration) -> None:
    session = configuration.session
    with configuration.backend._mutation_lock:
        try:
            configuration.original()
            if configuration.wake is None:
                configuration.wake = ConfigurationWake(configuration)
            wake = configuration.wake
            subscriptions = ConfigurationSubscriptions(configuration)
            subscriptions.arm()
            wake.read()
            initial = not configuration.cleanup_started
            exceptional: tuple[tuple[int, int], bytes] | None = None
            while not configuration.drained:
                observation = configuration.take_cleanup_observation() or exceptional
                exceptional = None
                if initial or observation is not None:
                    configuration.cleanup_started = True
                    initial = False
                    previous = session._cleaning
                    session._cleaning = True
                    configuration.retry_observation = observation
                    try:
                        _dispose(configuration)
                    except (BackendError, ConfigError, ColdDataError, LaunchError, OSError,
                            ValueError, KeyError, TypeError, RecursionError) as error:
                        session._fail("config_cleanup:" + str(error))
                        session._uncertainty()
                    finally:
                        configuration.retry_observation = None
                        session._cleaning = previous
                    require(not configuration.uncertain(), "config_cleanup_negative_hold")
                if configuration.drained:
                    return
                subscriptions.arm()
                exceptional = subscriptions.wait()
        except (BackendError, ConfigError, ColdDataError, LaunchError, OSError,
                ValueError, KeyError, TypeError, RecursionError) as error:
            negative_hold(configuration, "config_cleanup_retained:" + str(error))


def dispose_tool_observers(tool: ConfigurationTool) -> None:
    unwatch_foreign(tool)
    if tool.wait is not None and not tool.wait.drained:
        tool.wait.dispose()
    if tool.envelope is not None and not tool.envelope.drained:
        tool.envelope.remove()

def settle_configuration_attach(tool: ConfigurationTool) -> None:
    pending = tool.attach
    if pending is None or pending.process is None or pending.process.child is None:
        raise BackendError("config_attach_missing")
    session = tool.configuration.session
    session._member(pending, pending.process)
    require(tool.closed and pending.process.drained and pending.process.released
            and not pending.settled and pending.mutation and tool.exit_code is not None
            and tool.exit_code >= 0 and pending.process.child.returncode == tool.exit_code,
            "config_start_effect_unconfirmed")
    pending.settled = True


def negative_hold(configuration: PreparationConfiguration, reason: str) -> Never:
    """Detach only subscriptions before existing best-effort joins; preserve every original resource."""
    configuration.state = "NEGATIVE_HOLD"
    if configuration.wake is not None:
        configuration.wake.discard()
    for tool in (configuration.producer, configuration.verifier):
        if tool is None or tool.events is None:
            continue
        try:
            unwatch_foreign(tool)
        except (BackendError, OSError, ValueError, KeyError) as error:
            configuration.session._fail("config_terminal_unwatch:" + str(error))
    _hold(configuration.session, reason)
