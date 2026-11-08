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
    from build import BuildSession, Origin

COLD: Final = ("cold_envelope", "cold_envelope_data", "cold_envelope_drain")
MATERIAL: Final = (
    "phase_factory", "preparation_materials", "preparation_material_data",
    "preparation_material_inspect", "preparation_material_archive", "preparation_material_drain",
)


def phase_origin(session: BuildSession, resources: Origin, selection: Selection) -> None:
    """Pure historical checks for products of these guarded factories; no control or eligibility work."""
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
