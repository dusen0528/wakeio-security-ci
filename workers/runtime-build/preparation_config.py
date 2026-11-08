# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original configuration custody; allocation records never confer executable admission."""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal, assert_never

from backend_process import BackendError, require
from launch import Selection
from preparation_config_data import ConfigFrame, Operation
from preparation_config_inspect import ImageObservation, Verification
from preparation_config_volumes import ConfigurationBorrow, ConfigurationVolume
from preparation_config_archive import ArchiveObservation, HelperInputs, helpers_archive, seed_archive
from preparation_config_bindings import Helper, HelperRead, inspect_parent, load_helpers
from preparation_material_archive import Transfer
from process import LOG_BOUND

if TYPE_CHECKING:
    from build import BuildSession, Pending
    from process import Process
    from preparation_config_drain import ConfigurationWake, ConfigurationWakeRead
    from preparation_config_tool import ConfigurationTool
    from preparation_materials import PreparationMaterials


class PreparationConfiguration:
    """Original parent, helper, certificate and allocation histories survive revocation."""

    def __init__(self, materials: PreparationMaterials) -> None:
        from preparation_materials import PreparationMaterials

        require(type(materials) is PreparationMaterials, "config_materials_type")
        self.materials, self.session = materials, materials.session
        self.backend, self.daemon = materials.backend, materials.daemon
        self.network, self.mirror = materials.network, materials.mirror
        self.resources, self.input, self.copy = self.backend.resources, materials.input, materials.copy
        self.run, self.generation = materials.run, materials.generation
        self.boot, self.helper_hash, self.files = self.backend.boot, self.backend.helper_hash, self.backend.files
        self.image = materials.image
        self.parent_volumes = tuple(materials.volumes.items())
        self.parent_anchors = tuple(materials.identities.items())
        self.certificate = self.mirror.certificate
        self.helpers: tuple[Helper, Helper] | None = None
        self.helper_reads: list[HelperRead] = []
        self.result = ConfigurationVolume(self, False)
        self.inputs = ConfigurationVolume(self, True)
        self.seed: ConfigurationTool | None = None
        self.input_seed: ConfigurationTool | None = None
        self.producer: ConfigurationTool | None = None
        self.verifier: ConfigurationTool | None = None
        self.pending: list[Pending] = []
        self.started = self.held = self.drained = self.identity_unknown = False
        self.state = "RESERVED"
        self.helper_inputs: HelperInputs | None = None
        self.tool_image: ImageObservation | None = None
        self.close_unknown = False
        self.inputs_sealed = False
        self.writers_removed = False
        self.wake: ConfigurationWake | None = None
        self.retry_observation: ConfigurationWakeRead | tuple[tuple[int, int], bytes] | None = None
        self.cleanup_started = False
        self.verification: Verification | None = None
        self.config_observation: ArchiveObservation | None = None
        self.preparation_borrow: ConfigurationBorrow | None = None
        self.offline_borrow: ConfigurationBorrow | None = None
        self.preparation_burned = False
        self.offline_burned = False

    def original(self) -> None:
        session = self.session
        session._original()
        require(type(self) is PreparationConfiguration and session._preparation_config is self
                and session._config_consumed and session._preparation_materials is self.materials
                and self.materials.session is session and session.backend is self.backend
                and session.daemon is self.daemon and session.network is self.network
                and session.mirror is self.mirror and self.backend.resources is self.resources
                and self.resources.daemon is self.daemon and self.mirror.resources is self.resources
                and self.mirror.network is self.network and session._resources is self.input
                and session._copy is self.copy and self.copy is not None
                and session._generation == self.generation and self.backend.run_id == self.run
                and self.backend.boot == self.boot and self.backend.helper_hash == self.helper_hash
                and self.backend.files is self.files and self.materials.image is self.image,
                "config_original_owner")

    def bindings(self) -> None:
        self.original()
        try:
            require(not self.identity_unknown and self.materials.held
                    and self.materials.state == "MATERIALS_HELD" and self.input.sealed
                    and self.materials.carrier_known and self.materials.carrier_removed
                    and not self.materials.close_unknown and not self.materials.identity_unknown
                    and tuple(self.materials.volumes.items()) == self.parent_volumes
                    and tuple(self.materials.identities.items()) == self.parent_anchors,
                    "config_materials_changed")
            self.materials._input_anchor()
            self.materials._anchors()
            require(self.mirror.certificate is self.certificate and 0 < len(self.certificate) <= 16384
                    and self.network.phase == "BUILD" and self.network.installed
                    and self.mirror.container in self.resources.containers and bool(self.mirror.build),
                    "config_mirror_changed")
            for helper in self.helpers or ():
                require(any(path == helper.path and inode == helper.inode and digest == helper.digest
                            for path, inode, digest in self.files), "config_helper_binding")
        except (BackendError, OSError) as error:
            self.identity_unknown = True
            raise BackendError("config_binding_lost:" + str(error)) from error

    def load_helpers(self) -> None:
        load_helpers(self)

    def inspect_parent(self) -> None:
        inspect_parent(self)

    def accept(self, selection: Selection) -> ConfigFrame:
        self.original()
        frame = selection.configuration()
        require(frame.run == self.run and frame.generation == self.generation, "config_origin")
        if frame.tool is not None:
            tool = self.tool(frame.tool)
            require(tool is not None and (frame.container is None or frame.container == tool.container),
                    "config_tool_origin")
        return frame

    def tool(self, role: Literal["seed", "input-seed", "producer", "verifier"]) -> ConfigurationTool | None:
        match role:
            case "seed":
                return self.seed
            case "input-seed":
                return self.input_seed
            case "producer":
                return self.producer
            case "verifier":
                return self.verifier
            case unreachable:
                assert_never(unreachable)

    def retain(self, pending: Pending) -> None:
        frame = self.accept(pending.selection)
        require(pending.session is self.session and pending.resources is self, "config_pending_owner")
        self.pending.append(pending)
        if frame.tool is not None:
            tool = self.tool(frame.tool)
            if tool is None:
                raise BackendError("config_tool_missing")
            tool.retain(pending)
            return
        volume = self.inputs if frame.operation.value.startswith("input-") else self.result
        if frame.operation.value.endswith("-create"):
            require(volume.creation is None, "config_volume_create_replay")
            volume.creation = pending
        if frame.operation.value.endswith("-remove"):
            prior = volume.removal
            require(prior is None or (pending.cleanup and self.retry_observation is not None
                    and not prior.settled and prior.process is not None and prior.process.drained
                    and not prior.process.released), "config_volume_remove_replay")
            volume.removal = pending

    def call(self, frame: ConfigFrame) -> Pending:
        self.admit()
        selection = Selection("preparation-config", frame)
        return self.session._run(self, selection)

    def volume_unborrowed(self, volume: ConfigurationVolume) -> None:
        self.original()
        require(volume is self.result or volume is self.inputs, "config_foreign_volume")
        roles = (self.input_seed, self.producer, self.verifier) if volume is self.inputs else (
            self.seed, self.producer, self.verifier)
        require(all(tool is None or tool.drained for tool in roles), "config_tool_retained")
        require(all(pending.process is not None and pending.process.drained
                    for pending in self.pending if pending is not self.session._active), "config_children_retained")
        require(not self.held, "config_borrowing_not_revoked")
        if volume is self.result:
            for borrower in (self.preparation_borrow, self.offline_borrow):
                if borrower is not None:
                    borrower.original()
                    require(borrower.drained, "config_borrower_retained")

    def admit(self) -> None:
        self.original()
        if not self.session._cleaning:
            self.backend._configuration_preflight(self.materials)
            self.session._check()
        else:
            self.backend.check()
        self.bindings()

    def eligible(self, selection: Selection) -> None:
        frame = self.accept(selection)
        require(not self.drained and not self.uncertain(), "config_effect_uncertain")
        require(not self.session._cleaning or frame.cleanup, "config_cleanup_role")
        self.admit()
        if frame.tool is not None:
            tool = self.tool(frame.tool)
            if tool is None:
                raise BackendError("config_tool_missing")
            tool.eligible(frame)
            return
        volume = self.inputs if frame.operation.value.startswith("input-") else self.result
        require(not volume.removed, "config_volume_removed")
        if frame.operation.value.endswith("-create"):
            require(self.state == "ALLOCATING" and not self.session._cleaning
                    and volume.creation is self.session._active, "config_volume_create_state")
        if frame.operation.value.endswith("-remove"):
            require(self.session._cleaning, "config_volume_remove_state")
            self.volume_unborrowed(volume)

    def payload(self, frame: ConfigFrame) -> Transfer:
        match frame.operation:
            case Operation.SEED_VOLUME:
                return Transfer(seed_archive(), LOG_BOUND, False)
            case Operation.SEED_INPUTS:
                if self.helper_inputs is None:
                    raise BackendError("config_helper_inputs_missing")
                return Transfer(helpers_archive(self.helper_inputs), LOG_BOUND, False)
            case _:
                archive = frame.operation.value.startswith("read-")
                return Transfer(b"", 131072 if archive else LOG_BOUND, archive)

    def creation_eligible(self, tool: ConfigurationTool) -> None:
        require(self.tool(tool.role) is tool and self.result.returned and self.inputs.returned,
                "config_tool_volume_prerequisites")
        match tool.role:
            case "input-seed":
                require(self.state == "SEEDING" and not self.inputs_sealed, "config_inputs_seed_state")
            case "seed":
                require(self.state == "SEEDING" and self.inputs_sealed and self.input_seed is not None
                        and self.input_seed.drained, "config_seed_state")
            case "producer":
                require(self.state == "PRODUCING" and self.inputs_sealed and self.seed is not None
                        and self.seed.drained, "config_producer_writer_state")
            case "verifier":
                require(self.state == "VERIFYING" and self.writers_removed and self.producer is not None
                        and self.producer.drained, "config_verifier_writer_state")
            case unreachable:
                assert_never(unreachable)

    def inflight(self, pending: Pending) -> bool:
        return any(tool is not None and tool.attach is pending and tool.observing
                   and not tool.identity_unknown and pending.process is not None
                   and not pending.process.observation_failed for tool in (self.producer, self.verifier))

    def stop_process(self, process: Process) -> bool:
        from phase_factory import configuration_stop
        return configuration_stop(self.session, process)

    def uncertain(self) -> bool:
        volumes = (self.result, self.inputs)
        tools = (self.seed, self.input_seed, self.producer, self.verifier)
        return (self.identity_unknown or self.close_unknown or self.backend._mutation_unknown
                or any(volume.identity_unknown or volume.close_unknown or volume.paths.identity_unknown
                       or volume.paths.close_unknown for volume in volumes)
                or any(tool is not None and (tool.identity_unknown
                       or (tool.wait is not None and (tool.wait.identity_unknown or tool.wait.close_unknown
                           or tool.wait.paths.identity_unknown or tool.wait.paths.close_unknown))
                       or (tool.envelope is not None and (tool.envelope.identity_unknown
                           or tool.envelope.close_unknown or tool.envelope.paths.close_unknown
                           or tool.envelope.paths.identity_unknown))) for tool in tools))

    def take_cleanup_observation(self) -> ConfigurationWakeRead | None:
        return None if self.wake is None else self.wake.take()

    def prepare(self) -> None:
        from preparation_config_drain import prepare
        prepare(self)


    def _borrow_preparation(self, creator: BuildSession) -> None:
        with self.backend._mutation_lock:
            ConfigurationBorrow.require_preparation(self, creator)
            self.preparation_burned = True
            self.preparation_borrow = ConfigurationBorrow(self, creator, False)

    def _borrow_offline(self, creator: BuildSession) -> None:
        with self.backend._mutation_lock:
            ConfigurationBorrow.require_offline(self, creator)
            self.offline_burned = True
            self.offline_borrow = ConfigurationBorrow(self, creator, True)
