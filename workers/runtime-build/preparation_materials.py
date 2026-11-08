# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original preparation material custody; no workload, wait or public build result."""
from __future__ import annotations

import os
import re
import stat
from typing import TYPE_CHECKING, Literal, assert_never

from backend_process import BackendError, require
from input_resources import checked
from launch import Selection
from preparation_material_archive import inspect_archive
from preparation_material_data import KINDS, MaterialFrame, MaterialKind, Operation, operation
from preparation_material_inspect import ImageObservation, VolumeObservation, carrier_observation, volume_observation

if TYPE_CHECKING:
    from build import BuildSession, Pending


class PreparationMaterials:
    """Mutable original allocations, creation Pending records and close tombstones survive failure."""

    def __init__(self, session: BuildSession) -> None:
        from build import BuildSession
        require(type(session) is BuildSession, "material_session_type")
        self.session = session
        self.backend, self.daemon = session.backend, session.daemon
        self.network, self.mirror = session.network, session.mirror
        self.input, self.copy = session._resources, session._copy
        self.input_fd, self.input_identity, self.input_volume = (
            self.input.mount_fd, self.input.mount_identity, self.input.volume)
        self.run, self.generation = self.backend.run_id, session._generation
        self.image: ImageObservation | None = None
        self.volumes: dict[MaterialKind, VolumeObservation] = {}
        self.creation_pending: dict[Operation, Pending] = {}
        self.descriptors: dict[str, int] = {}
        self.identities: dict[str, tuple[int, int]] = {}
        self.removed: set[MaterialKind] = set()
        self.carrier = ""
        self.carrier_known = self.carrier_removed = False
        self.started = self.held = self.drained = False
        self.close_unknown = self.identity_unknown = False
        self.state: Literal["RESERVED", "ALLOCATING", "SEEDING", "MATERIALS_HELD",
                            "DISPOSING", "DISPOSED", "RETAINED", "NEGATIVE_HOLD"] = "RESERVED"

    def accept(self, selection: Selection) -> MaterialFrame:
        """Historical membership is pure; it never launches nested control processes."""
        self.session._original()
        require(type(self) is PreparationMaterials and self.session._preparation_materials is self
                and self.session.backend is self.backend and self.session.daemon is self.daemon
                and self.session.network is self.network and self.session.mirror is self.mirror
                and self.session._resources is self.input and self.session._copy is self.copy
                and self.copy is not None and self.generation == self.session._generation
                and self.run == self.backend.run_id, "material_original_owner")
        frame = selection.material()
        require(frame.run == self.run and frame.generation == self.generation
                and (frame.container is None or frame.container == self.carrier), "material_origin")
        return frame

    def eligible(self, selection: Selection) -> None:
        frame = self.accept(selection)
        require(not self.drained and not self.close_unknown and not self.identity_unknown, "material_revoked")
        require(not self.session._cleaning or frame.cleanup, "material_cleanup_role")
        self._input_anchor()
        self._anchors()
        if frame.kind is not None:
            require(frame.kind not in self.removed, "material_volume_removed")
        match frame.operation:
            case "volume-create-work" | "volume-create-cache" | "volume-create-output":
                require(frame.kind not in self.volumes and not self.carrier, "material_volume_replay")
            case "carrier-create":
                require(len(self.volumes) == 3 and not self.carrier, "material_carrier_replay")
            case "seed" | "read-work" | "read-cache" | "read-output":
                require(self.carrier_known and not self.carrier_removed and self.state == "SEEDING",
                        "material_transfer_state")
            case "carrier-inspect" | "carrier-remove":
                require(bool(self.carrier) and not self.carrier_removed, "material_carrier_removed")
            case "volume-remove-work" | "volume-remove-cache" | "volume-remove-output":
                require(frame.kind in self.volumes and (not self.carrier or self.carrier_removed),
                        "material_borrower_retained")
            case "volume-inspect-work" | "volume-inspect-cache" | "volume-inspect-output":
                require(self.started, "material_not_started")
            case unreachable:
                assert_never(unreachable)

    def _input_anchor(self) -> None:
        try:
            descriptor = self.input_fd
            if descriptor is None:
                raise BackendError("material_input_lost")
            require(self.input.sealed and self.input.mount_fd == descriptor
                    and self.input.mount_identity == self.input_identity
                    and self.input.volume is self.input_volume, "material_input_replaced")
            value = os.fstat(descriptor)
            path = "/home/wakeio-m1/.local/share/docker/volumes/" + self.input.name + "/_data"
            linked = os.stat(path, follow_symlinks=False)
            require(stat.S_ISDIR(value.st_mode) and stat.S_ISDIR(linked.st_mode)
                    and (value.st_dev, value.st_ino) == (linked.st_dev, linked.st_ino) == self.input_identity,
                    "material_input_replaced")
        except (BackendError, OSError) as error:
            self.identity_unknown = True
            raise BackendError("material_input_identity_lost:" + str(error)) from error

    def retain(self, pending: Pending) -> None:
        frame = self.accept(pending.selection)
        if frame.mutation or frame.operation.startswith("read-"):
            prior = self.creation_pending.get(frame.operation)
            require(prior is None or (not prior.settled and prior.process is not None
                                      and prior.process.drained and not prior.process.released), "material_replay")
            self.creation_pending[frame.operation] = pending

    def _call(self, selected: Operation) -> Pending:
        container = self.carrier if selected in (
            "carrier-inspect", "carrier-remove", "seed", "read-work", "read-cache", "read-output") else None
        selection = Selection("preparation-material", MaterialFrame(self.run, self.generation, selected, container))
        self.eligible(selection)
        return self.session._run(self, selection)

    def _anchors(self) -> None:
        try:
            for path, descriptor in self.descriptors.items():
                value = os.fstat(descriptor)
                require(stat.S_ISDIR(value.st_mode) and value.st_nlink > 0
                        and (value.st_dev, value.st_ino) == self.identities[path], "material_descriptor_replaced")
                if path != "/":
                    parent, name = path.rsplit("/", 1)
                    linked = os.stat(name, dir_fd=self.descriptors[parent or "/"], follow_symlinks=False)
                    require((linked.st_dev, linked.st_ino) == self.identities[path], "material_namespace_replaced")
        except (OSError, BackendError) as error:
            self.identity_unknown = True
            raise BackendError("material_identity_lost:" + str(error)) from error

    def _directory(self, path: str) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for current in ("/", *("/" + "/".join(path.split("/")[1:index])
                               for index in range(2, len(path.split("/")) + 1))):
            if current not in self.descriptors:
                parent, name = current.rsplit("/", 1)
                self.descriptors[current] = (os.open("/", flags) if current == "/" else
                                             os.open(name, flags, dir_fd=self.descriptors[parent or "/"]))
                value = os.fstat(self.descriptors[current])
                self.identities[current] = (value.st_dev, value.st_ino)
        self._anchors()

    def _close(self, path: str) -> None:
        descriptor = self.descriptors.pop(path)
        try:
            os.close(descriptor)
        except OSError:
            self.close_unknown = True
            raise

    def _volume(self, kind: MaterialKind) -> VolumeObservation:
        pending = self._call(operation("volume-inspect-" + kind))
        raw = checked(pending)
        try:
            value = volume_observation(pending.selection.material(), raw)
        except (BackendError, ValueError, TypeError, RecursionError) as error:
            self.identity_unknown = True
            raise BackendError("material_volume_observer_lost:" + str(error)) from error
        previous = self.volumes.get(kind)
        if previous is not None and previous != value:
            self.identity_unknown = True
            raise BackendError("material_volume_replaced")
        self._directory(value.mountpoint)
        return value

    def _allocate_volume(self, kind: MaterialKind) -> None:
        absent = self._call(operation("volume-inspect-" + kind))
        process = absent.process
        if process is None or process.child is None:
            raise BackendError("material_absence_process")
        name = absent.selection.material().name(kind)
        expected = ("Error response from daemon: get " + name + ": no such volume\n").encode("ascii")
        require(not process.output_overflow and process.child.returncode == 1 and bytes(process.errors) == expected
                and bytes(process.output) in (b"", b"[]\n"), "material_volume_preexisting_or_unknown")
        creation = self._call(operation("volume-create-" + kind))
        require(checked(creation) == (name + "\n").encode("ascii"), "material_volume_response")
        self.volumes[kind] = self._volume(kind)
        self.session._settle(creation)

    def _carrier(self) -> None:
        if self.image is None:
            raise BackendError("material_image_missing")
        for kind in KINDS:
            self._volume(kind)
        pending = self._call("carrier-inspect")
        try:
            carrier_observation(pending.selection.material(), self.image, checked(pending))
        except (BackendError, ValueError, TypeError, RecursionError) as error:
            self.identity_unknown = True
            raise BackendError("material_carrier_observer_lost:" + str(error)) from error

    def _remove_carrier(self) -> None:
        require(self.carrier_known, "material_carrier_unknown")
        self._carrier()
        pending = self._call("carrier-remove")
        require(checked(pending) == (self.carrier + "\n").encode("ascii"), "material_carrier_removal")
        self.session._settle(pending)
        self.carrier_removed = True

    def prepare(self) -> None:
        copied = self.copy
        if copied is None:
            raise BackendError("material_copy_missing")
        require(not self.started, "material_prepare_replay")
        self.started = True
        self.state = "ALLOCATING"
        for kind in KINDS:
            self._allocate_volume(kind)
        creation = self._call("carrier-create")
        identifier = checked(creation).decode("ascii")
        require(re.fullmatch(r"[a-f0-9]{64}\n", identifier) is not None, "material_carrier_response")
        self.carrier = identifier[:-1]
        self._carrier()
        self.carrier_known = True
        self.session._settle(creation)
        self.state = "SEEDING"
        seed = self._call("seed")
        checked(seed)
        self.session._settle(seed)
        for kind in KINDS:
            readback = self._call(operation("read-" + kind))
            inspect_archive(copied, kind, checked(readback))
            self.session._settle(readback)
        self._remove_carrier()
        self.session._check()
        self.held = True
        self.state = "MATERIALS_HELD"

    def remove(self) -> None:
        """Dispose the original carrier before output/cache/work and close original FDs only once."""
        self.accept(Selection("preparation-material", MaterialFrame(self.run, self.generation,
                                                                  "volume-inspect-work", None)))
        require(self.session._cleaning and not self.close_unknown and not self.identity_unknown,
                "material_cleanup_unavailable")
        self.held = False
        self.state = "DISPOSING"
        if self.carrier and not self.carrier_removed:
            self._remove_carrier()
        for kind in reversed(KINDS):
            if kind not in self.volumes or kind in self.removed:
                continue
            volume = self._volume(kind)
            removal = self._call(operation("volume-remove-" + kind))
            require(checked(removal) == (volume.name + "\n").encode("ascii"), "material_volume_removal")
            self.session._settle(removal)
            self.removed.add(kind)
            self._close(volume.mountpoint)
            self._close(volume.mountpoint.rsplit("/", 1)[0])
        for path in reversed(tuple(self.descriptors)):
            self._close(path)
        self.drained = not self.descriptors and not self.close_unknown and set(self.volumes) == self.removed
        if self.drained:
            self.state = "DISPOSED"
