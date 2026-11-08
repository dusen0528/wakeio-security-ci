# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Inactive original input owner. No guest dispatcher or executable admission is exposed."""
from __future__ import annotations

from collections.abc import Sequence
from threading import Event
from typing import TYPE_CHECKING, Literal, assert_never

from backend_process import BackendError, require
from input import Chunk, InputCopy, InputData, InputError, Receipt
from input_archive import MAX_METADATA, build_archive
from input_resources import InputResources
from launch import LaunchError, Selection
from process import LOG_BOUND, Process

if TYPE_CHECKING:
    from cold_envelope import ColdEnvelope
    from preparation_materials import PreparationMaterials
    from relay import Backend
    type Origin = InputResources | ColdEnvelope | PreparationMaterials


class Pending:
    """Mutable original continuation; DATA cannot register or settle this record."""

    def __init__(self, session: BuildSession, resources: Origin, selection: Selection) -> None:
        self.session = session
        self.resources = resources
        self.selection = selection
        self.body = b""
        self.output_bound = LOG_BOUND
        self.archive_output = False
        self.cleanup = session._cleaning
        self.process: Process | None = None
        self.settled = False
        match selection.role:
            case "preparation-material":
                from preparation_material_archive import transfer
                frame = selection.material()
                self.mutation = frame.mutation
                require(not self.cleanup or frame.cleanup, "build_cleanup_copy")
                payload = transfer(frame, session._copy)
                self.body, self.output_bound, self.archive_output = payload.body, payload.bound, payload.archive
            case "copy-in" | "copy-out":
                data = session._copy
                if data is None:
                    raise BackendError("build_copy_missing")
                require(not self.cleanup, "build_cleanup_copy")
                self.mutation = selection.role == "copy-in"
                if self.mutation:
                    self.body = build_archive(data)
                else:
                    self.output_bound = sum(len(part) for part in data.bodies) + MAX_METADATA
                    self.archive_output = True
            case ("image-inspect" | "volume-inspect" | "carrier-inspect"
                  | "slice-present" | "slice-files" | "slice-inspect"):
                self.mutation = False
            case ("image-pull" | "volume-create" | "volume-remove" | "carrier-create" | "carrier-remove"
                  | "slice-reload" | "slice-start" | "slice-stop"):
                self.mutation = True
            case unreachable:
                assert_never(unreachable)


class BuildSession:
    """One Backend-retained ledger; construction allocates no external resources."""

    def __init__(self, backend: Backend) -> None:
        from relay import Backend
        require(type(backend) is Backend, "build_backend_type")
        self.backend = backend
        self.daemon = backend.daemon
        self.network = backend.network
        self.mirror = backend.mirror
        self._resources = InputResources(self)
        self._cold: dict[Literal["prepare", "offline"], ColdEnvelope | None] = {}
        self._phase_reservations: set[Literal["prepare", "offline"]] = set()
        self._preparation_materials: PreparationMaterials | None = None
        self._pending: list[Pending] = []
        self._active: Pending | None = None
        self._input: InputData | None = None
        self._copy: InputCopy | None = None
        self._generation = 0
        self._failure: BackendError | None = None
        self._closing = False
        self._cleaning = False
        self._drained = False
        self._wake = Event()

    def _original(self) -> None:
        require(type(self) is BuildSession and type(self._resources) is InputResources
                and self.backend.build is self and self.backend.daemon is self.daemon
                and self.backend.network is self.network and self.backend.mirror is self.mirror
                and self._resources.session is self, "build_original_owner")

    def _check(self) -> None:
        self._original()
        if self._failure is not None:
            raise self._failure
        require(not self._closing and not self.backend._mutation_unknown, "build_revoked")
        self.backend.check()
        if self._failure is not None:
            raise self._failure

    def _member(self, pending: Pending, process: Process) -> None:
        self._original()
        require(type(pending) is Pending and type(process) is Process
                and pending.session is self and any(item is pending for item in self._pending)
                and pending.process is process and process.pending is pending, "build_foreign_process")
        self._origin(pending.resources, pending.selection)

    def _origin(self, resources: Origin, selection: Selection) -> None:
        if resources is self._resources:
            require(not selection.role.startswith("slice-") and selection.role != "preparation-material",
                    "build_input_role")
        else:
            require(resources is not None and (resources is self._preparation_materials
                    or any(item is resources for item in self._cold.values())), "build_operation_owner")
            from phase_factory import phase_origin
            phase_origin(self, resources, selection)

    def _eligible(self, pending: Pending, process: Process) -> None:
        self._member(pending, process)
        require(self._active is pending and not pending.settled and not process.stopped
                and not process.released and not self.backend._mutation_unknown, "build_operation_revoked")
        if pending.cleanup:
            require(self._cleaning and (pending.selection.role in (
                "image-inspect", "volume-inspect", "volume-remove", "carrier-inspect", "carrier-remove",
                "slice-present", "slice-files", "slice-inspect", "slice-stop", "slice-reload")
                or (pending.selection.role == "preparation-material" and pending.selection.material().cleanup)),
                    "build_cleanup_role")
        else:
            require(self._failure is None and not self._closing, "build_revoked")
        if pending.resources is self._preparation_materials and self._preparation_materials is not None:
            self._preparation_materials.eligible(pending.selection)
        require(not process.stopped, "build_operation_revoked")

    def _fail(self, reason: str) -> None:
        if self._failure is None:
            self._failure = BackendError(reason)
        self.backend.refused = True
        self._wake.set()
        for pending in self._pending:
            if pending.process is not None and not pending.process.drained:
                if not pending.cleanup:
                    pending.process.stopped = True
                pending.process.wake()

    def _select(self, identifier: str) -> None:
        """Internal DATA accumulation only; there is no corresponding v1 RPC."""
        self._check()
        require(self._generation == 0 and self._input is None, "build_input_replay")
        self._generation += 1
        try:
            self._input = InputData(identifier)
        except InputError as error:
            self._fail(str(error))
            raise

    def _append(self, chunk: Chunk) -> int:
        self._check()
        if self._input is None:
            raise BackendError("build_input_missing")
        try:
            return self._input.append(chunk)
        except InputError as error:
            self._fail(str(error))
            raise

    def _finish(self, receipts: Sequence[Receipt]) -> None:
        """Only this session's retained accumulator can supply its physical transfer."""
        self._check()
        if self._input is None:
            raise BackendError("build_input_missing")
        require(self._copy is None, "build_finish_replay")
        with self.backend._mutation_lock:
            try:
                self._check()
                self._copy = self._input.finish(receipts)
                self._resources.prepare()
            except (BackendError, InputError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
                self._fail("build_input_failed:" + str(error))
                self._uncertainty()
                raise

    def _prepare_cold(self, phase: Literal["prepare", "offline"]) -> None:
        self._factory_available()
        from phase_factory import prepare_cold
        prepare_cold(self, phase)

    def _prepare_materials(self) -> None:
        self._factory_available()
        from phase_factory import prepare_materials
        prepare_materials(self)

    def _factory_available(self) -> None:
        self._check()
        require(any(path == self.backend.root / "build/phase_factory.py" for path, _, _ in self.backend.files),
                "build_phase_factory_unavailable")

    def _run(self, resources: Origin, selection: Selection) -> Pending:
        self._original()
        require(self._active is None, "build_operation_owner")
        self._origin(resources, selection)
        if self._cleaning:
            self.backend.check()
        else:
            self._check()
        pending = Pending(self, resources, selection)
        self._pending.append(pending)
        if resources is self._preparation_materials and self._preparation_materials is not None:
            self._preparation_materials.retain(pending)
        pending.process = Process(pending)
        self._active = pending
        try:
            pending.process.start()
            require(pending.process.drained and pending.process.child is not None, "build_process_unclosed")
            if not pending.mutation and not pending.archive_output:
                pending.settled = True
            return pending
        finally:
            self._active = None

    def _settle(self, pending: Pending) -> None:
        if pending.process is None or pending.process.child is None:
            raise BackendError("build_process_missing")
        self._member(pending, pending.process)
        require((pending.mutation or pending.archive_output) and not pending.settled and pending.process.drained
                and pending.process.child.returncode == 0, "build_effect_unconfirmed")
        pending.settled = True

    def _uncertainty(self) -> bool:
        unknown = any(pending.mutation and not pending.settled
                      and pending.process is not None
                      and pending.process.released for pending in self._pending)
        if unknown:
            self.backend._mutation_unknown = True
        return unknown

    def drain(self) -> None:
        """Keep this original synchronous owner alive until physical cleanup can finish."""
        if self._drained and not self.backend._mutation_unknown:
            return
        self._drained = False
        self._original()
        self._closing = True
        self._fail("build_closed")
        if self._preparation_materials is not None:
            from preparation_material_drain import drain
            drain(self)
            return
        if self._cold:
            from cold_envelope_drain import drain
            drain(self)
            return
        with self.backend._mutation_lock:
            try:
                for pending in self._pending:
                    if pending.process is not None and not pending.process.drained:
                        pending.process.stop()
                        pending.process.join()
                require(all(pending.process is not None and pending.process.drained
                            for pending in self._pending), "build_children_retained")
                if not self._uncertainty() and not self.backend._mutation_unknown:
                    self._cleaning = True
                    self._resources.remove()
                    self._drained = all(pending.process is not None and pending.process.drained
                                        for pending in self._pending)
            except (BackendError, LaunchError, OSError, ValueError, KeyError, TypeError) as error:
                self._fail("build_drain_failed:" + str(error))
                self._uncertainty()
            finally:
                self._cleaning = False
        while not self._drained:
            self._wake.wait()
            self._wake.clear()
