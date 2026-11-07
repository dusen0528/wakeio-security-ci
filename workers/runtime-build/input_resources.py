"""Original fixed-image, volume and never-started carrier producer."""
from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, TypeAlias

from backend_process import BackendError, require
from input_archive import inspect_archive
from launch import Role, Selection, build_image, resource_labels

if TYPE_CHECKING:
    from build import BuildSession, Pending

Json: TypeAlias = str | int | float | bool | None | list["Json"] | dict[str, "Json"]


def record(value: Json) -> Mapping[str, Json]:
    match value:
        case dict() as fields:
            return fields
        case _:
            raise BackendError("build_inspection_record")


def inspection(raw: bytes) -> Mapping[str, Json]:
    value: Json = json.loads(raw)
    match value:
        case [dict() as fields]:
            return fields
        case _:
            raise BackendError("build_inspection_shape")


def checked(pending: Pending) -> bytes:
    process = pending.process
    if process is None or process.child is None:
        raise BackendError("build_process_missing")
    pending.session._member(pending, process)
    require(process.drained and not process.output_overflow
            and process.child.returncode == 0, "build_command_failed")
    return bytes(process.output)


class InputResources:
    """Only original successful creation continuations establish these mutable bindings."""

    def __init__(self, session: BuildSession) -> None:
        from build import BuildSession
        require(type(session) is BuildSession, "build_resource_owner_type")
        self.session = session
        self.name = ""
        self.image: Mapping[str, Json] | None = None
        self.volume: Mapping[str, Json] | None = None
        self.mount_identity: tuple[int, int] | None = None
        self.mount_fd: int | None = None
        self.carrier = ""
        self.carrier_known = False
        self.sealed = False
        self.started = False

    def _call(self, role: Role, operand: str | None = None) -> Pending:
        cleaning = self.session._cleaning
        if self.session._failure is not None and role in ("image-inspect", "volume-inspect", "carrier-inspect"):
            self.session._cleaning = True
        try:
            return self.session._run(self, Selection(role, operand))
        finally:
            self.session._cleaning = cleaning

    def _image(self) -> None:
        pull = self._call("image-pull")
        checked(pull)
        self.session._settle(pull)
        image = inspection(checked(self._call("image-inspect")))
        reference, config = build_image()
        require(image.get("Id") == config and image.get("Os") == "linux"
                and image.get("Architecture") == "arm64", "build_image_binding")
        digests = image.get("RepoDigests")
        require(type(digests) is list and reference in digests, "build_image_manifest")
        self.image = image
        configuration = record(image.get("Config"))
        require(configuration.get("Volumes") in (None, {}, {"/work": {}})
                and configuration.get("Healthcheck") is None, "build_image_allocations")

    def _volume(self) -> Mapping[str, Json]:
        value = inspection(checked(self._call("volume-inspect", self.name)))
        mount = "/home/wakeio-m1/.local/share/docker/volumes/" + self.name + "/_data"
        require(value.get("Name") == self.name and value.get("Driver") == "local"
                and value.get("Scope") == "local" and value.get("Options") in (None, {})
                and value.get("Labels") == resource_labels(self.name)
                and value.get("Mountpoint") == mount, "build_volume_binding")
        require(type(value.get("CreatedAt")) is str and bool(value["CreatedAt"]), "build_volume_creation")
        original = self.mount_fd
        require(self.volume is None or original is not None, "build_volume_anchor_missing")
        descriptor = self._open_volume(mount)
        retained = False
        try:
            observed = os.fstat(descriptor)
            identity = (observed.st_dev, observed.st_ino)
            if original is None:
                self.mount_fd = descriptor
                self.mount_identity = identity
                retained = True
            else:
                anchor = os.fstat(original)
                require(identity == (anchor.st_dev, anchor.st_ino) == self.mount_identity,
                        "build_volume_replaced")
            if self.volume is not None:
                require(value.get("CreatedAt") == self.volume.get("CreatedAt"), "build_volume_replaced")
        finally:
            if not retained:
                os.close(descriptor)
        return value

    def _open_volume(self, mount: str) -> int:
        flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open("/", flags)
        try:
            for part in mount.split("/")[1:]:
                following = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = following
            return descriptor
        except OSError:
            os.close(descriptor)
            raise

    def _carrier(self) -> None:
        if self.volume is None or self.image is None:
            raise BackendError("build_resources_missing")
        value = inspection(checked(self._call("carrier-inspect", self.carrier)))
        config = record(value.get("Config"))
        host = record(value.get("HostConfig"))
        state = record(value.get("State"))
        image_config = record(self.image.get("Config"))
        require(value.get("Id") == self.carrier and value.get("Image") == build_image()[1]
                and config.get("Image") == build_image()[0]
                and config.get("Labels") == resource_labels(self.name, True), "build_carrier_binding")
        require(config.get("Entrypoint") == ["/bin/false"] and config.get("User") == "65532:65532"
                and config.get("Cmd") == image_config.get("Cmd") and config.get("Env") == image_config.get("Env")
                and config.get("Healthcheck") is None
                and config.get("Volumes") in (None, {}, {"/work": {}}), "build_carrier_configuration")
        require(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True
                and host.get("Privileged") is False and host.get("CapDrop") == ["ALL"]
                and host.get("SecurityOpt") == ["no-new-privileges"] and host.get("Runtime") == "runc"
                and host.get("PidMode") == "" and host.get("IpcMode") == "private", "build_carrier_boundary")
        require(host.get("NanoCpus") == 2000000000 and host.get("Memory") == 2147483648
                and host.get("MemorySwap") == 2147483648 and host.get("PidsLimit") == 256,
                "build_carrier_limits")
        require(all(host.get(key) in (None, [], {}) for key in (
            "Binds", "VolumesFrom", "Devices", "DeviceRequests", "ExtraHosts", "Dns", "DnsSearch",
            "CapAdd", "PortBindings", "Tmpfs")), "build_carrier_extra_allocations")
        mounts = value.get("Mounts")
        require(type(mounts) is list and len(mounts) == 1, "build_carrier_mount_count")
        match mounts:
            case [dict() as mount]:
                require(mount.get("Type") == "volume" and mount.get("Name") == self.name
                        and mount.get("Source") == self.volume.get("Mountpoint")
                        and mount.get("Destination") == "/work" and mount.get("Driver") == "local"
                        and mount.get("RW") is True and mount.get("Propagation") == "",
                        "build_carrier_mount")
            case _:
                raise BackendError("build_carrier_mount_shape")
        match host.get("Mounts"):
            case [dict() as mount]:
                require(mount.get("Type") == "volume" and mount.get("Source") == self.name
                        and mount.get("Target") == "/work" and mount.get("ReadOnly") is False,
                        "build_carrier_declared_mount")
            case _:
                raise BackendError("build_carrier_declared_mount_shape")
        require(state.get("Status") == "created" and state.get("Running") is False
                and state.get("Paused") is False and state.get("Restarting") is False
                and state.get("Dead") is False and type(state.get("Pid")) is int and state.get("Pid") == 0,
                "build_carrier_started")
        self._volume()

    def prepare(self) -> None:
        self.session._check()
        require(not self.started, "build_resource_replay")
        self.started = True
        self.name = "wk-" + self.session.backend.run_id + "-b" + str(self.session._generation) + "-input"
        self._image()
        absent = self._call("volume-inspect", self.name)
        process = absent.process
        if process is None or process.child is None:
            raise BackendError("build_absence_process")
        expected = ("Error response from daemon: get " + self.name + ": no such volume\n").encode("ascii")
        require(not process.output_overflow and process.child.returncode == 1 and bytes(process.errors) == expected
                and bytes(process.output) in (b"", b"[]\n"), "build_volume_preexisting_or_unknown")
        creation = self._call("volume-create", self.name)
        require(checked(creation) == (self.name + "\n").encode("ascii"), "build_volume_response")
        self.volume = self._volume()
        self.session._settle(creation)
        self.session._check()
        creation = self._call("carrier-create", self.name)
        identifier = checked(creation).decode("ascii")
        require(re.fullmatch(r"[a-f0-9]{64}\n", identifier) is not None, "build_carrier_response")
        self.carrier = identifier[:-1]
        self._carrier()
        self.carrier_known = True
        self.session._settle(creation)
        self.session._check()
        copied = self._call("copy-in", self.carrier)
        checked(copied)
        self.session._settle(copied)
        self.session._check()
        readback = self._call("copy-out", self.carrier)
        data = self.session._copy
        if data is None:
            raise BackendError("build_copy_missing")
        inspect_archive(data, checked(readback))
        self.session._settle(readback)
        copies = [pending for pending in self.session._pending if pending.selection.role in ("copy-in", "copy-out")]
        require(len(copies) == 2 and all(pending.process is not None and pending.process.drained
                                        for pending in copies), "build_copy_borrowers")
        self._remove_carrier()
        self.session._check()
        self.sealed = True

    def _remove_carrier(self) -> None:
        require(self.carrier_known, "build_carrier_unknown")
        self._carrier()
        removal = self._call("carrier-remove", self.carrier)
        require(checked(removal) == (self.carrier + "\n").encode("ascii"), "build_carrier_removal")
        self.session._settle(removal)
        self.carrier_known = False
        self.carrier = ""

    def remove(self) -> None:
        """Remove only these original known resources, never an image or discovered replacement."""
        if self.carrier_known:
            self._remove_carrier()
        if self.volume is not None:
            require(not self.carrier, "build_carrier_retained")
            self._volume()
            removal = self._call("volume-remove", self.name)
            require(checked(removal) == (self.name + "\n").encode("ascii"), "build_volume_removal")
            self.session._settle(removal)
            if self.mount_fd is None:
                raise BackendError("build_volume_anchor_missing")
            os.close(self.mount_fd)
            self.mount_fd = None
            self.volume = None
            self.mount_identity = None
