# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Exact material inspection DATA; valid observations never register original ownership."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from backend_process import BackendError, require
from input_resources import Json, inspection, record
from launch import build_image
from preparation_material_data import KINDS, MaterialFrame, MaterialKind

VOLUME_ROOT: Final = "/home/wakeio-m1/.local/share/docker/volumes"
ZERO_TIME: Final = "0001-01-01T00:00:00Z"


@dataclass(frozen=True, slots=True)
class VolumeObservation:
    kind: MaterialKind
    name: str
    created: str
    mountpoint: str


@dataclass(frozen=True, slots=True)
class ImageObservation:
    reference: str
    config: str
    command: tuple[str, ...] | None
    environment: tuple[str, ...] | None


def _strings(raw: Json) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise BackendError("material_image_strings")
    require(len(raw) <= 256, "material_image_strings")
    result: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise BackendError("material_image_string")
        require(len(value) <= 4096 and "\0" not in value, "material_image_string")
        result.append(value)
    return tuple(result)


def image_observation(raw: bytes) -> ImageObservation:
    value = inspection(raw)
    reference, configuration = build_image()
    require(value.get("Id") == configuration and value.get("Os") == "linux"
            and value.get("Architecture") == "arm64", "material_image_binding")
    digests = value.get("RepoDigests")
    require(type(digests) is list and reference in digests, "material_image_manifest")
    config = record(value.get("Config"))
    require(config.get("Volumes") in (None, {}, {"/work": {}})
            and config.get("Healthcheck") is None, "material_image_allocations")
    return ImageObservation(reference, configuration, _strings(config.get("Cmd")), _strings(config.get("Env")))


def volume_observation(frame: MaterialFrame, raw: bytes) -> VolumeObservation:
    kind = frame.kind
    if kind is None:
        raise BackendError("material_volume_kind")
    name = frame.name(kind)
    value = inspection(raw)
    mountpoint = VOLUME_ROOT + "/" + name + "/_data"
    require(value.get("Name") == name and value.get("Driver") == "local" and value.get("Scope") == "local"
            and value.get("Options") in (None, {}) and value.get("Labels") == frame.labels(kind)
            and value.get("Mountpoint") == mountpoint, "material_volume_binding")
    created = value.get("CreatedAt")
    if not isinstance(created, str):
        raise BackendError("material_volume_creation")
    require(0 < len(created) <= 128 and all(32 <= ord(char) <= 126 for char in created),
            "material_volume_creation")
    return VolumeObservation(kind, name, created, mountpoint)


def _mount_map(raw: list[Json], target: Literal["Destination", "Target"]) -> Mapping[str, Mapping[str, Json]]:
    result: dict[str, Mapping[str, Json]] = {}
    for item in raw:
        fields = record(item)
        name = fields.get(target)
        if not isinstance(name, str):
            raise BackendError("material_mount_targets")
        require(name in ("/work", "/cache", "/output") and name not in result, "material_mount_targets")
        result[name] = fields
    return result


def _mounts(frame: MaterialFrame, value: Mapping[str, Json], host: Mapping[str, Json]) -> None:
    actual, declared = value.get("Mounts"), host.get("Mounts")
    if not isinstance(actual, list) or not isinstance(declared, list):
        raise BackendError("material_mount_shape")
    require(len(actual) == len(declared) == 3, "material_mount_count")
    actual_by_target = _mount_map(actual, "Destination")
    declared_by_target = _mount_map(declared, "Target")
    require(set(actual_by_target) == set(declared_by_target) == {"/work", "/cache", "/output"},
            "material_mount_targets")
    for kind in KINDS:
        name = frame.name(kind)
        mount, declaration = actual_by_target["/" + kind], declared_by_target["/" + kind]
        require(mount.get("Type") == "volume" and mount.get("Name") == name
                and mount.get("Source") == VOLUME_ROOT + "/" + name + "/_data"
                and mount.get("Destination") == "/" + kind and mount.get("Driver") == "local"
                and mount.get("RW") is True and mount.get("Propagation") == "", "material_mount")
        require(declaration == {"Type": "volume", "Source": name, "Target": "/" + kind,
                                "ReadOnly": False, "VolumeOptions": {"NoCopy": True}},
                "material_declared_mount")
        require(declaration.get("ReadOnly") is False
                and record(declaration.get("VolumeOptions")).get("NoCopy") is True,
                "material_declared_mount")


def carrier_observation(frame: MaterialFrame, image: ImageObservation, raw: bytes) -> None:
    value = inspection(raw)
    config, host, state = (record(value.get(key)) for key in ("Config", "HostConfig", "State"))
    require(value.get("Id") == frame.container and value.get("Image") == image.config
            and config.get("Image") == image.reference and config.get("Labels") == frame.labels("transfer"),
            "material_carrier_binding")
    require(config.get("Entrypoint") == ["/bin/false"] and config.get("User") == "65532:65532"
            and _strings(config.get("Cmd")) == image.command and _strings(config.get("Env")) == image.environment
            and config.get("Healthcheck") is None and config.get("Volumes") in (None, {}, {"/work": {}}),
            "material_carrier_configuration")
    require(all(config.get(key) is False for key in ("Tty", "OpenStdin", "StdinOnce", "AttachStdin")),
            "material_carrier_interactive")
    require(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False and host.get("CapDrop") == ["ALL"]
            and host.get("SecurityOpt") == ["no-new-privileges"] and host.get("Runtime") == "runc"
            and host.get("PidMode") == "" and host.get("IpcMode") == "private"
            and host.get("CgroupParent") == "" and host.get("UsernsMode") in ("", "private"),
            "material_carrier_boundary")
    for key, expected in (("NanoCpus", 2000000000), ("Memory", 2147483648),
                          ("MemorySwap", 2147483648), ("PidsLimit", 256)):
        require(type(host.get(key)) is int and host.get(key) == expected, "material_carrier_limits")
    require(host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0}
            and type(record(host.get("RestartPolicy")).get("MaximumRetryCount")) is int
            and host.get("AutoRemove") is False, "material_carrier_restart")
    require(all(host.get(key) in (None, [], {}) for key in (
        "Binds", "VolumesFrom", "Devices", "DeviceRequests", "ExtraHosts", "Dns", "DnsSearch",
        "DnsOptions", "CapAdd", "PortBindings", "Tmpfs", "Links")), "material_carrier_extra_allocations")
    _mounts(frame, value, host)
    require(state.get("Status") == "created"
            and all(state.get(key) is False for key in ("Running", "Paused", "Restarting", "Dead", "OOMKilled"))
            and type(state.get("Pid")) is int and state.get("Pid") == 0
            and type(state.get("ExitCode")) is int and state.get("ExitCode") == 0
            and state.get("Error") == "" and state.get("StartedAt") == state.get("FinishedAt") == ZERO_TIME
            and type(value.get("RestartCount")) is int and value.get("RestartCount") == 0,
            "material_carrier_started")
