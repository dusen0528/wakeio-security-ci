# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: only through the same original Backend's fixed configuration hooks.
"""Fixed original poll subscriptions; private failures never consume the borrowed cleanup wake."""
from __future__ import annotations

import select
from typing import IO, TYPE_CHECKING, Literal

from backend_process import BackendError, require
from backend_startup_io import Identity, descriptor_identity

if TYPE_CHECKING:
    from preparation_config import PreparationConfiguration
    from preparation_config_tool import ConfigurationTool
    from preparation_materials import PreparationMaterials
    from process import Process
    from relay import Backend

type PrivateRole = Literal["input", "control", "connection"]
type Watch = tuple[Identity, IO[bytes] | None]


def _process(tool: ConfigurationTool) -> Process:
    from preparation_config_tool import ConfigurationTool
    from preparation_config_observe import _process as original_process
    require(type(tool) is ConfigurationTool, "backend_configuration_tool")
    return original_process(tool)


class ConfigurationObservations:
    """Mutable fixed attachment ledger on the original Backend; it issues no owner or work token."""

    def __init__(self, backend: Backend) -> None:
        self.backend = backend
        self.attachments: dict[ConfigurationTool, Attachment] = {}
        self.notified: BackendError | None = None

    def notify(self) -> None:
        failure = self.backend._startup.failure
        if failure is not None and self.notified is None:
            self.notified = failure
            self.backend.build._fail(failure.code)

    def detach(self, tool: ConfigurationTool) -> None:
        attachment = self.attachments.get(tool)
        try:
            require(_state(tool.configuration.backend) is self, "backend_detach_owner")
            if attachment is not None:
                attachment.detach()
        except (BackendError, OSError, ValueError, KeyError):
            if attachment is not None:
                attachment.polluted = True
            raise

    def prepare_join(self, tool: ConfigurationTool) -> None:
        require(_state(tool.configuration.backend) is self, "backend_join_owner")
        process = _process(tool)
        if (tool.wait is not None and tool.wait.complete and process.exit_observed
                and process.stdout_eof and process.stderr_eof and not process.streams):
            attachment = self.attachments.get(tool)
            if attachment is not None:
                attachment.original()
                require(not attachment.polluted, "backend_poll_unknown")
                for descriptor in tuple(attachment.private):
                    attachment._unregister(descriptor)


def _state(backend: Backend) -> ConfigurationObservations:
    from relay import Backend
    require(type(backend) is Backend, "backend_observation_owner")
    state = backend._observations
    require(type(state) is ConfigurationObservations and state.backend is backend, "backend_observation_changed")
    backend.build._original()
    backend._startup.original()
    return state


class Attachment:
    """Actual poll ownership and generations remain retained even after partial arming or failed detach."""

    def __init__(self, backend: Backend, tool: ConfigurationTool) -> None:
        self.backend, self.tool = backend, tool
        self.process = _process(tool)
        self.events = self.process.events
        self.private: dict[int, tuple[PrivateRole, Identity]] = {}
        self.watching: dict[int, Watch] = {}
        self.child = self.process.child
        self.generation = tool.poll_generation
        self.detached = False
        self.polluted = False

    def original(self) -> None:
        if self.process.events is not self.events or self.tool.events is not self.events:
            self.polluted = True
            raise BackendError("backend_poll_replaced")
        require(_state(self.backend).attachments.get(self.tool) is self
                and _process(self.tool) is self.process and not self.detached, "backend_attachment_original")
        if self.child is None:
            self.child = self.process.child
        if self.child is not self.process.child:
            self.polluted = True
            raise BackendError("backend_child_replaced")

    def sync(self) -> None:
        self.original()
        process, tool = self.process, self.tool
        foreign = set(tool.foreign.values())
        require(len(foreign) == len(tool.foreign) and not foreign & process.armed, "backend_source_collision")
        live = set(process.armed) | foreign
        for descriptor in tuple(self.watching):
            if descriptor not in live:
                del self.watching[descriptor]
        for descriptor in live:
            snapshot = descriptor_identity(descriptor), process.streams.get(descriptor)
            prior = self.watching.get(descriptor)
            if prior is not None and (prior[0] != snapshot[0] or prior[1] is not snapshot[1]):
                self.polluted = True
                raise BackendError("backend_tool_descriptor_reused")
            self.watching[descriptor] = snapshot
        sources = self.backend._startup.sources()
        desired = {descriptor: role for role, descriptor in sources}
        require(len(desired) == len(sources), "backend_private_source_duplicate")
        require(not live & set(desired), "backend_private_source_collision")
        for descriptor in tuple(self.private):
            if descriptor not in desired:
                self._unregister(descriptor)
        for descriptor, role in desired.items():
            identity = descriptor_identity(descriptor)
            prior = self.private.get(descriptor)
            if prior is not None:
                require(prior == (role, identity), "backend_private_source_reused")
                continue
            self.private[descriptor] = role, identity
            try:
                self.events.register(descriptor, select.POLLIN)
            except (OSError, ValueError, KeyError):
                self.polluted = True
                raise
        self.generation = tool.poll_generation

    def validate(self, batch: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
        from preparation_config_observe import _validate
        self.original()
        require(self.generation == self.tool.poll_generation, "backend_poll_generation_changed")
        require(len({fd for fd, _ in batch}) == len(batch), "backend_duplicate_event")
        for descriptor, flags in batch:
            require(type(descriptor) is int and type(flags) is int and flags != 0
                    and descriptor in (self.watching.keys() | self.private.keys())
                    and not flags & select.POLLNVAL, "backend_event_membership")
            if descriptor in self.private:
                require(not flags & ~(select.POLLIN | select.POLLHUP | select.POLLERR),
                        "backend_private_event_flags")
        for descriptor, (identity, stream) in self.watching.items():
            if descriptor_identity(descriptor) != identity or self.process.streams.get(descriptor) is not stream:
                self.polluted = True
                raise BackendError("backend_tool_descriptor_changed")
        for descriptor, (_, identity) in self.private.items():
            require(descriptor_identity(descriptor) == identity, "backend_private_descriptor_changed")
        subset = tuple((fd, flags) for fd, flags in batch if fd not in self.private)
        _validate(self.tool, subset)
        return subset

    def _unregister(self, descriptor: int) -> None:
        if descriptor in self.process.armed or descriptor in self.tool.foreign.values():
            self.polluted = True
            raise BackendError("backend_unregister_collision")
        try:
            self.events.unregister(descriptor)
        except (OSError, ValueError, KeyError):
            self.polluted = True
            raise
        del self.private[descriptor]

    def detach(self) -> None:
        if self.detached:
            return
        self.original()
        require(not self.polluted, "backend_poll_unknown")
        for descriptor in tuple(self.private):
            self._unregister(descriptor)
        self.detached = True


def preflight(backend: Backend, materials: PreparationMaterials) -> None:
    from preparation_materials import PreparationMaterials
    _state(backend)
    session = backend.build
    require(type(materials) is PreparationMaterials and session._preparation_materials is materials
            and materials.session is session and materials.backend is backend
            and materials.daemon is backend.daemon and materials.network is backend.network
            and materials.mirror is backend.mirror and materials.input is session._resources
            and materials.copy is session._copy and materials.run == backend.run_id
            and materials.generation == session._generation and materials.held
            and materials.state == "MATERIALS_HELD" and not materials.identity_unknown
            and not materials.close_unknown and not materials.drained
            and session._failure is None and not session._closing and not backend._mutation_unknown
            and not backend.refused and not backend._interrupted and not backend.closed,
            "backend_configuration_preflight")
    backend._startup.work()


def arm(backend: Backend, tool: ConfigurationTool) -> None:
    state = _state(backend)
    _process(tool)
    require(tool.configuration.backend is backend and tool.role in ("producer", "verifier")
            and tool not in state.attachments, "backend_configuration_arm")
    backend._startup.work()
    attachment = Attachment(backend, tool)
    state.attachments[tool] = attachment
    attachment.sync()


def poll(backend: Backend, tool: ConfigurationTool) -> tuple[tuple[int, int], ...]:
    state = _state(backend)
    attachment = state.attachments.get(tool)
    if attachment is None:
        raise BackendError("backend_configuration_unarmed")
    source = backend._startup
    try:
        with source._lock:
            source.observe_deadline()
            state.notify()
            attachment.sync()
            state.notify()
            timeout = source.timeout_ms()
            process = attachment.process
            require(source.failure is None or process.drained or (state.notified is source.failure
                    and process.wake_error is None and not process.observation_failed
                    and "wake-write" in process.descriptors
                    and process.descriptors.get("wake-read") in process.armed), "backend_notification_unconfirmed")
        batch = tuple(attachment.events.poll(timeout))
        subset = attachment.validate(batch)
        source.observe_deadline()
        for descriptor, flags in batch:
            private = attachment.private.get(descriptor)
            if private is not None:
                if flags & (select.POLLHUP | select.POLLERR):
                    source.revoke("backend_private_source_closed")
                source.consume(private[0])
        state.notify()
        return subset
    except (BackendError, OSError, ValueError) as error:
        source.revoke("backend_configuration_observation:" + str(error))
        state.notify()
        raise


def terminal_hold(configuration: PreparationConfiguration, reason: str) -> None:
    state = _state(configuration.backend)
    retained = tuple(item for item in state.attachments.values()
                     if item.tool.configuration is configuration)
    for item in retained:
        if not item.detached and (item.process.events is not item.events or item.tool.events is not item.events):
            item.polluted = True
    polluted = tuple(item for item in retained if item.polluted)
    if not polluted:
        return
    session = configuration.session
    session._fail(reason)
    for item in polluted:
        item.process._fault("backend_poll_context_lost")
        if item.child is item.process.child:
            item.process.stop()
    while True:
        session._wake.clear()
        session._wake.wait()
