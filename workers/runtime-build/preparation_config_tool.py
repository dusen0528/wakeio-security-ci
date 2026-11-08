# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original fixed configuration tools, read histories and independently reconciled physical closure."""
from __future__ import annotations

import re
import preparation_config_observe as observe
from typing import TYPE_CHECKING

from backend_process import BackendError, require
from input_resources import checked
from preparation_config_archive import (
    ArchiveObservation, inspect_certificate, inspect_config, inspect_helper, inspect_helpers, inspect_seed,
)
from preparation_config_data import ConfigFrame, Operation, ToolRole
from preparation_config_inspect import ContainerObservation
from preparation_config_bindings import inspect_tool

if TYPE_CHECKING:
    from build import Pending
    from preparation_config import PreparationConfiguration
    from preparation_config_envelope import ConfigurationEnvelope
    from preparation_config_wait import ConfigurationWait
    from process import Process


class ConfigurationRead:
    """An original one-use slot is burned before its own Pending or Process can exist."""

    def __init__(self) -> None:
        self.burned = False
        self.pending: Pending | None = None
        self.accepted: ArchiveObservation | None = None


class ConfigurationTool:
    """Mutable fixed-role history; never a generic container executor or externally issued owner."""

    def __init__(self, configuration: PreparationConfiguration, role: ToolRole) -> None:
        self.configuration, self.role = configuration, role
        self.events: observe.PollContext | None = None
        self.foreign: dict[str, int] = {}
        self.poll_generation = 0
        self.container = ""
        self.creation: ContainerObservation | None = None
        self.history: list[Pending] = []
        self.controls: dict[tuple[Operation, bool], Pending] = {}
        self.attach: Pending | None = None
        self.envelope: ConfigurationEnvelope | None = None
        self.wait: ConfigurationWait | None = None
        self.seed_read = ConfigurationRead()
        self.input_read = ConfigurationRead()
        self.helper_read = ConfigurationRead()
        self.certificate_read = ConfigurationRead()
        self.pre_read = ConfigurationRead()
        self.terminal_read = ConfigurationRead()
        self.active_read: ConfigurationRead | None = None
        self.exit_code: int | None = None
        self.observing = False
        self.stop = observe.StopHistory()
        self.container_removed = False
        self.closed = False
        self.identity_unknown = False
        self.drained = False

    @property
    def released(self) -> bool:
        return self.attach is not None and self.attach.process is not None and self.attach.process.released

    @property
    def never_created(self) -> bool:
        pending = self.controls.get((Operation.CONTAINER_CREATE, False))
        return not self.container and (pending is None or (pending.process is not None
                and pending.process.drained and not pending.process.released))

    def original(self) -> None:
        self.configuration.original()
        require(type(self) is ConfigurationTool and self.configuration.tool(self.role) is self,
                "config_tool_original")

    def frame(self, operation: str) -> ConfigFrame:
        op = Operation(operation)
        container = None if op is Operation.CONTAINER_CREATE or op.value.startswith("envelope-") else self.container
        return ConfigFrame(self.configuration.run, self.configuration.generation, op, self.role, container)

    def retain(self, pending: Pending) -> None:
        self.original()
        frame = pending.selection.configuration()
        require(pending.resources is self.configuration and pending.session is self.configuration.session,
                "config_tool_pending")
        if frame.operation.value.startswith("read-"):
            slot = self.active_read
            require(slot is not None and slot.burned and slot.pending is None, "config_read_original")
            if slot is None:
                raise BackendError("config_read_slot")
            slot.pending = pending
        elif frame.mutation:
            final_reload = frame.operation is Operation.ENVELOPE_RELOAD and self.envelope is not None and (
                self.envelope.file_removed)
            key = (frame.operation, final_reload)
            prior = self.controls.get(key)
            require(prior is None or (pending.cleanup and self.configuration.retry_observation is not None
                    and not prior.settled and prior.process is not None and prior.process.drained
                    and not prior.process.released), "config_control_replay")
            self.controls[key] = pending
        if frame.operation is Operation.ATTACH_START:
            require(self.attach is None, "config_attach_replay")
            self.attach = pending
        self.history.append(pending)

    def eligible(self, frame: ConfigFrame) -> None:
        self.original()
        require(not self.drained and not self.identity_unknown and (not self.container_removed or (
            self.configuration.session._cleaning and self.envelope is not None and not self.envelope.drained
            and frame.operation in (Operation.ENVELOPE_INSPECT, Operation.ENVELOPE_STOP, Operation.ENVELOPE_RELOAD))),
            "config_tool_retired")
        match frame.operation:
            case Operation.CONTAINER_CREATE:
                self.configuration.creation_eligible(self)
                require(not self.container and self.creation is None, "config_tool_create_replay")
            case Operation.ATTACH_START:
                require(not self.released and self.envelope is not None and self.envelope.ready
                        and self.wait is not None and self.wait.headers_acknowledged
                        and not self.wait.complete and self.wait.parser.terminal is None
                        and self.helper_read.accepted is not None and self.certificate_read.accepted is not None,
                        "config_release_prerequisites")
                require(self.role != "verifier" or self.pre_read.accepted is not None, "config_verifier_pre_read")
            case Operation.CONTAINER_REMOVE:
                require(self.creation is not None and (self.closed if self.released else True)
                        and all(item.process is not None and item.process.drained for item in self.history
                                if item is not self.configuration.session._active), "config_tool_children_retained")
                require(self.role != "verifier" or self.configuration.session._failure is not None
                        or self.terminal_read.accepted is not None or not self.released, "config_terminal_read_missing")
            case Operation.CONTAINER_KILL:
                require(self.released and self.stop.requested and not self.closed
                        and self.wait is not None and not self.wait.complete, "config_stop_ineligible")
            case Operation.READ_CONFIG | Operation.READ_INPUTS | Operation.READ_HELPER | Operation.READ_CERTIFICATE:
                require(self.active_read is not None and self.active_read.burned
                        and self.active_read.pending is self.configuration.session._active, "config_read_gate")
            case Operation.SEED_VOLUME | Operation.SEED_INPUTS:
                require(self.creation is not None and not self.released and self.role in ("seed", "input-seed"),
                        "config_seed_state")
            case Operation.CONTAINER_INSPECT:
                require(bool(self.container), "config_tool_identity_missing")
            case (Operation.ENVELOPE_PRESENT | Operation.ENVELOPE_FILES | Operation.ENVELOPE_INSPECT
                  | Operation.ENVELOPE_RELOAD | Operation.ENVELOPE_START | Operation.ENVELOPE_STOP):
                require(self.envelope is not None, "config_envelope_missing")
                self.envelope.original()
            case _:
                raise BackendError("config_tool_operation")

    def inspect(self) -> ContainerObservation:
        return inspect_tool(self)

    def create(self) -> None:
        self.original()
        if self.role in ("producer", "verifier"):
            from preparation_config_envelope import ConfigurationEnvelope
            self.envelope = ConfigurationEnvelope(self)
            self.envelope.prepare()
        pending = self.configuration.call(self.frame("container-create"))
        identifier = checked(pending).decode("ascii")
        require(re.fullmatch(r"[a-f0-9]{64}\n", identifier) is not None, "config_create_response")
        self.container = identifier[:-1]
        self.creation = self.inspect()
        require(self.creation.status == "created", "config_tool_started_early")
        self.configuration.session._settle(pending)

    def select_read(self, operation: str) -> ConfigurationRead:
        require(self.configuration.session._failure is None, "config_failed_read")
        match operation, self.role:
            case "read-config", "seed":
                require(not self.released, "config_seed_released")
                return self.seed_read
            case "read-config", "verifier":
                if not self.released:
                    return self.pre_read
                require(self.closed and not self.container_removed and self.pre_read.accepted is not None,
                        "config_terminal_read_state")
                return self.terminal_read
            case "read-inputs", "input-seed":
                return self.input_read
            case "read-helper", "producer" | "verifier":
                require(not self.released, "config_post_release_input_read")
                return self.helper_read
            case "read-certificate", "producer" | "verifier":
                require(not self.released, "config_post_release_input_read")
                return self.certificate_read
            case _:
                raise BackendError("config_read_role")

    def read(self, operation: str) -> ArchiveObservation:
        self.original()
        slot = self.select_read(operation)
        require(not slot.burned and self.active_read is None, "config_read_replay")
        slot.burned, self.active_read = True, slot
        try:
            pending = self.configuration.call(self.frame(operation))
            raw = checked(pending)
            inputs = self.configuration.helper_inputs
            if inputs is None:
                raise BackendError("config_original_inputs_missing")
            match operation:
                case "read-config":
                    value = inspect_seed(raw) if self.role == "seed" else inspect_config(raw)
                case "read-inputs":
                    value = inspect_helpers(inputs, raw)
                case "read-helper":
                    value = inspect_helper(inputs, self.role, raw)
                case "read-certificate":
                    value = inspect_certificate(inputs, raw)
                case _:
                    raise BackendError("config_read_operation")
            require(slot is not self.terminal_read or value == self.pre_read.accepted, "config_terminal_changed")
            slot.accepted = value
            self.configuration.session._settle(pending)
            return value
        finally:
            self.active_read = None

    def seed(self) -> None:
        operation = "seed-inputs" if self.role == "input-seed" else "seed-volume"
        pending = self.configuration.call(self.frame(operation))
        checked(pending)
        self.read("read-inputs" if self.role == "input-seed" else "read-config")
        self.configuration.session._settle(pending)

    def request_stop(self, process: Process) -> bool:
        pending = self.attach
        if pending is None or pending.process is not process or process.pending is not pending:
            return False
        if not process.released or process.observation_failed:
            return False
        self.original()
        if not self.stop.requested:
            self.stop.requested = True
            process.wake()
        return True

    def reconcile(self) -> None:
        pending = self.attach
        if pending is None or pending.process is None or pending.process.child is None:
            raise BackendError("config_attach_missing")
        process = pending.process
        if not (self.wait is not None and self.wait.complete and process.exit_observed
                and process.stdout_eof and process.stderr_eof and not process.streams):
            return
        process.join()
        require(process.drained and self.wait is not None and self.wait.complete
                and self.wait.terminal is not None and self.envelope is not None, "config_physical_join_missing")
        terminal = self.inspect()
        require(terminal.status == "exited" and terminal.exit_code == process.child.returncode
                == self.wait.terminal.status_code and terminal.exit_code >= 0
                and not self.envelope.observe().populated, "config_physical_terminal_mismatch")
        self.exit_code, self.closed = terminal.exit_code, True
        from preparation_config_drain import settle_configuration_attach
        settle_configuration_attach(self)

    def remove(self) -> None:
        self.original()
        if not self.container_removed and not self.never_created:
            self.inspect()
            pending = self.configuration.call(self.frame("container-remove"))
            require(checked(pending) == (self.container + "\n").encode("ascii"), "config_remove_response")
            self.configuration.session._settle(pending)
            self.container_removed = True
        from preparation_config_drain import dispose_tool_observers
        dispose_tool_observers(self)
        self.drained = (self.container_removed or self.never_created) and (
            self.wait is None or self.wait.drained) and (self.envelope is None or self.envelope.drained) and all(
            item.process is not None and item.process.drained
            for item in self.history)
