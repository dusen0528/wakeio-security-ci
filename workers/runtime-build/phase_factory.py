# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Guarded original phase factories; one consumed reservation survives all failures."""
from __future__ import annotations

import os
from importlib import import_module
from typing import TYPE_CHECKING, Final, Literal

from backend_process import BackendError, require
from input import InputError
from input_resources import checked, inspection
from launch import LaunchError, Selection

if TYPE_CHECKING:
    from build import BuildSession, Origin, Pending
    from process import Process
    from preparation_materials import PreparationMaterials
    from preparation_config_tool import ConfigurationTool
    from preparation_material_data import MaterialFrame
    from preparation_config_data import ConfigFrame

COLD: Final = ("cold_envelope", "cold_envelope_data", "cold_envelope_drain")
MATERIAL: Final = (
    "phase_factory", "preparation_materials", "preparation_material_data",
    "preparation_material_inspect", "preparation_material_archive", "preparation_material_drain",
)


CONFIGURATION: Final = (
    "preparation_config", "preparation_config_volumes", "preparation_config_data",
    "preparation_config_bindings",
    "preparation_config_archive", "preparation_config_inspect", "preparation_config_tool",
    "preparation_config_envelope", "preparation_config_wait", "preparation_config_wait_data",
    "preparation_config_drain", "preparation_config_observe",
)


def phase_origin(session: BuildSession, resources: Origin, selection: Selection) -> None:
    """Pure historical checks for products of these guarded factories; no control or eligibility work."""
    if resources is session._preparation_config and session._preparation_config is not None:
        session._preparation_config.accept(selection)
        return
    if resources is session._preparation_materials and session._preparation_materials is not None:
        session._preparation_materials.accept(selection)
        return
    origin = next((item for item in session._cold.values() if item is resources), None)
    if origin is None:
        raise BackendError("build_operation_owner")
    from cold_envelope import ColdEnvelope

    require(type(origin) is ColdEnvelope and origin.session is session and origin.backend is session.backend
            and origin.daemon is session.daemon and origin.generation == session._generation
            and origin.input is session._copy and origin.input is not None and selection.role in (
                "slice-present", "slice-files", "slice-reload", "slice-start", "slice-inspect", "slice-stop")
            and selection.operand == (None if selection.role == "slice-reload" else origin.name),
            "build_cold_origin")


def _helpers(session: BuildSession, names: tuple[str, ...]) -> None:
    session._check()
    for name in names:
        require(any(path == session.backend.root / "build" / (name + ".py")
                    for path, _, _ in session.backend.files), "build_phase_helper_unavailable")
    session.backend.check()
    for name in names:
        import_module(name)


def _reserve(session: BuildSession, phase: Literal["prepare", "offline"]) -> None:
    session._check()
    require(session._resources.sealed and session._copy is not None and session._generation > 0
            and session.backend.qualified and session.network.phase == "BUILD", "build_phase_input")
    require(type(phase) is str and phase in ("prepare", "offline") and phase not in session._phase_reservations,
            "build_phase_replay")
    descriptor = session._resources.mount_fd
    if descriptor is None:
        raise BackendError("build_phase_input_anchor")
    value = os.fstat(descriptor)
    require((value.st_dev, value.st_ino) == session._resources.mount_identity, "build_phase_input_replaced")
    session._phase_reservations.add(phase)


def prepare_cold(session: BuildSession, phase: Literal["prepare", "offline"]) -> None:
    with session.backend._mutation_lock:
        _helpers(session, COLD)
        from cold_envelope import ColdEnvelope
        from cold_envelope_data import ColdDataError

        _reserve(session, phase)
        session._cold[phase] = None
        try:
            envelope = ColdEnvelope(session, phase)
            session._cold[phase] = envelope
            envelope.prepare()
        except (BackendError, ColdDataError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
            session._fail("build_cold_failed:" + str(error))
            session._uncertainty()
            raise


def prepare_materials(session: BuildSession) -> None:
    with session.backend._mutation_lock:
        _helpers(session, (*MATERIAL, *COLD))
        from preparation_material_inspect import image_observation
        from preparation_materials import PreparationMaterials

        _reserve(session, "prepare")
        try:
            materials = PreparationMaterials(session)
            session._preparation_materials = materials
            original = session._resources
            require(original._volume() == original.volume, "material_input_volume_changed")
            raw = checked(original._call("image-inspect"))
            require(inspection(raw) == original.image, "material_original_image_changed")
            materials.image = image_observation(raw)
            materials.prepare()
        except (BackendError, InputError, LaunchError, OSError, ValueError,
                KeyError, TypeError, RecursionError) as error:
            session._fail("build_material_failed:" + str(error))
            session._uncertainty()
            retained = session._preparation_materials
            if retained is not None:
                retained.state = ("NEGATIVE_HOLD" if session.backend._mutation_unknown
                                  or retained.identity_unknown or retained.close_unknown else "RETAINED")
            raise
def phase_payload(pending: Pending) -> None:
    """Fill only the two fixed original phase payload families; no effect or owner registration."""
    frame: MaterialFrame | ConfigFrame
    match pending.selection.role:
        case "preparation-material":
            from preparation_material_archive import transfer
            frame = pending.selection.material()
            payload = transfer(frame, pending.session._copy)
        case "preparation-config":
            configuration = pending.session._preparation_config
            if configuration is None:
                raise BackendError("config_owner_missing")
            frame = pending.selection.configuration()
            payload = configuration.payload(frame)
        case _:
            raise BackendError("build_phase_payload_role")
    pending.mutation = frame.mutation
    require(not pending.cleanup or frame.cleanup, "build_cleanup_copy")
    pending.body, pending.output_bound, pending.archive_output = payload.body, payload.bound, payload.archive


def phase_retain(pending: Pending) -> None:
    session = pending.session
    if pending.resources is session._preparation_materials and session._preparation_materials is not None:
        session._preparation_materials.retain(pending)
    elif pending.resources is session._preparation_config and session._preparation_config is not None:
        session._preparation_config.retain(pending)
    else:
        raise BackendError("build_phase_origin")


def phase_eligible(pending: Pending) -> None:
    session = pending.session
    match pending.selection.role:
        case "preparation-material":
            owner = session._preparation_materials
        case "preparation-config":
            owner = session._preparation_config
        case _:
            raise BackendError("build_phase_role")
    require(owner is not None and pending.resources is owner, "build_phase_origin")
    if owner is None:
        raise BackendError("build_phase_missing")
    owner.eligible(pending.selection)


def prepare_configuration(materials: PreparationMaterials | None) -> None:
    from preparation_materials import PreparationMaterials
    require(type(materials) is PreparationMaterials, "config_original_materials")
    if materials is None:
        raise BackendError("config_original_materials")
    session = materials.session
    with session.backend._mutation_lock:
        session._original()
        require(session._preparation_materials is materials, "config_original_materials")
        session.backend._configuration_preflight(materials)
        session._check()
        for name in ("PrepConfigProduce.java", "PrepConfigVerify.java"):
            require(any(path == session.backend.root / "build" / name
                        for path, _, _ in session.backend.files), "config_helper_unavailable")
        session.backend.check()
        _helpers(session, (*MATERIAL, *COLD, *CONFIGURATION))
        require(session._preparation_materials is materials and materials.held
                and materials.state == "MATERIALS_HELD" and materials.carrier_known
                and materials.carrier_removed and len(materials.volumes) == 3
                and not materials.identity_unknown and not materials.close_unknown
                and "prepare" in session._phase_reservations and not session._config_consumed
                and session._preparation_config is None, "config_predecessor_unavailable")
        materials._input_anchor()
        materials._anchors()
        for kind, observed in tuple(materials.volumes.items()):
            require(materials._volume(kind) == observed, "config_parent_volume_changed")
        require(all(pending.process is not None and pending.process.drained
                    and (not pending.mutation or pending.settled) for pending in session._pending
                    if pending.resources is materials), "config_parent_children_retained")
        from preparation_config import PreparationConfiguration
        from preparation_config_data import ConfigError
        session._config_consumed = True
        try:
            configuration = PreparationConfiguration(materials)
            session._preparation_config = configuration
            configuration.load_helpers()
            configuration.inspect_parent()
            configuration.prepare()
        except (BackendError, ConfigError, LaunchError, OSError, ValueError,
                KeyError, TypeError, RecursionError) as error:
            session._fail("config_failed:" + str(error))
            session._uncertainty()
            retained = session._preparation_config
            if retained is not None:
                retained.state = "NEGATIVE_HOLD" if retained.uncertain() else "RETAINED"
            raise


def configuration_stop(session: BuildSession, process: Process) -> bool:
    """Historical relationship dispatch remains available after work revocation."""
    configuration = session._preparation_config
    pending = process.pending
    if (configuration is None or pending.resources is not configuration
            or pending.selection.role != "preparation-config" or process.observation_failed):
        return False
    session._member(pending, process)
    frame = pending.selection.configuration()
    if frame.operation.value != "attach-start" or frame.tool is None:
        return False
    tool = configuration.tool(frame.tool)
    return tool is not None and tool.request_stop(process)


def begin_configuration_attach(tool: ConfigurationTool) -> Pending:
    """Retain the actual attach through the same ledger and clear only its launch-gate activity."""
    from build import Pending
    from process import Process
    session, configuration = tool.configuration.session, tool.configuration
    session._check()
    require(session._active is None, "build_operation_owner")
    selection = Selection("preparation-config", tool.frame("attach-start"))
    session._origin(configuration, selection)
    pending = Pending(session, configuration, selection)
    session._pending.append(pending)
    configuration.retain(pending)
    pending.process = Process(pending)
    from preparation_config_drain import arm_tool
    arm_tool(tool)
    session._active = pending
    try:
        pending.process._start_gated()
        if not pending.process.released:
            if session._failure is not None:
                raise session._failure
            raise BackendError("config_attach_unreleased")
    finally:
        session._active = None
    return pending


class ConfigurationObservationBoundary:
    """Fixed consumer dependency only; the current Backend supplies no positive observation authority."""

    def _configuration_preflight(self, materials: PreparationMaterials) -> None:
        raise BackendError("config_original_observations_unavailable")

    def _configuration_arm(self, tool: ConfigurationTool) -> None:
        raise BackendError("config_original_observations_unavailable")

    def _configuration_poll(self, tool: ConfigurationTool) -> tuple[tuple[int, int], ...]:
        raise BackendError("config_original_observations_unavailable")




class ConfigurationBorrowCreatorBoundary:
    """Same original session dependency only; no genuine future consumer supplier exists yet."""

    def _require_preparation_configuration_creator(self) -> None:
        raise BackendError("config_original_consumer_unavailable")

    def _require_offline_configuration_creator(self) -> None:
        raise BackendError("config_original_consumer_unavailable")

    def _require_preparation_configuration_closed(self) -> None:
        raise BackendError("config_original_consumer_unavailable")

    def _require_offline_configuration_closed(self) -> None:
        raise BackendError("config_original_consumer_unavailable")
