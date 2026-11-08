# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B tests/native/runtime_build_preparation_config_inspect_test.py
"""Strict inspection and verifier DATA. Observations never issue or register owners."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from preparation_config_data import (
    GLOBAL_SETTINGS, IMAGE, IMAGE_CONFIG, TMPFS, USER_SETTINGS, ConfigError, ConfigFrame,
    Json, Operation, environment, java_command, require,
)

VOLUME_ROOT: Final = "/home/wakeio-m1/.local/share/docker/volumes"
ZERO_TIME: Final = "0001-01-01T00:00:00Z"


@dataclass(frozen=True, slots=True)
class VolumeObservation:
    kind: Literal["config", "config-input"]
    name: str
    created: str
    mountpoint: str


@dataclass(frozen=True, slots=True)
class ImageObservation:
    reference: str
    config: str
    command: tuple[str, ...] | None
    environment: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContainerObservation:
    identifier: str
    created: str
    status: Literal["created", "exited"]
    exit_code: int
    started: str
    finished: str


@dataclass(frozen=True, slots=True)
class Verification:
    certificate_der_sha256: str
    store_sha256: str


def _pairs(pairs: list[tuple[str, Json]]) -> dict[str, Json]:
    fields: dict[str, Json] = {}
    for key, value in pairs:
        require(key not in fields, "config_json_duplicate")
        fields[key] = value
    return fields


def _constant(value: str) -> Json:
    raise ConfigError("config_json_constant:" + value)


def strict_json(raw: bytes, bound: int) -> Json:
    require(type(raw) is bytes and 0 < len(raw) <= bound, "config_json_bound")
    try:
        text = raw.decode("utf-8")
        require(not text.startswith("\ufeff"), "config_json_bom")
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ConfigError("config_json_encoding") from error


def record(value: Json) -> Mapping[str, Json]:
    if not isinstance(value, dict):
        raise ConfigError("config_record")
    return value


def _inspection(raw: bytes) -> Mapping[str, Json]:
    value = strict_json(raw, 131072)
    if not isinstance(value, list) or len(value) != 1:
        raise ConfigError("config_inspection_shape")
    return record(value[0])


def _strings(raw: Json) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ConfigError("config_strings")
    require(len(raw) <= 256, "config_strings")
    result: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise ConfigError("config_string")
        require(len(value) <= 4096 and all(32 <= ord(char) <= 126 for char in value), "config_string")
        result.append(value)
    return tuple(result)


def _env(raw: Json) -> tuple[str, ...]:
    values = _strings(raw)
    if values is None:
        raise ConfigError("config_env")
    keys = tuple(item.partition("=")[0] for item in values)
    require(all("=" in item for item in values) and len(keys) == len(set(keys)), "config_env")
    return tuple(sorted(values))


def image_observation(raw: bytes) -> ImageObservation:
    value = _inspection(raw)
    require(value.get("Id") == IMAGE_CONFIG and value.get("Os") == "linux"
            and value.get("Architecture") == "arm64", "config_image_binding")
    digests = value.get("RepoDigests")
    require(type(digests) is list and IMAGE in digests, "config_image_manifest")
    config = record(value.get("Config"))
    require(config.get("Volumes") in (None, {}) and config.get("Healthcheck") is None, "config_image_allocations")
    env = _env(config.get("Env"))
    require({item.partition("=")[0] for item in env} == {
        "PATH", "JAVA_HOME", "LANG", "LANGUAGE", "LC_ALL", "JAVA_VERSION", "MAVEN_HOME", "MAVEN_CONFIG"},
        "config_image_env")
    return ImageObservation(IMAGE, IMAGE_CONFIG, _strings(config.get("Cmd")), env)


def volume_observation(frame: ConfigFrame, raw: bytes) -> VolumeObservation:
    require(frame.operation in (Operation.VOLUME_INSPECT, Operation.INPUT_VOLUME_INSPECT), "config_volume_operation")
    auxiliary = frame.operation == Operation.INPUT_VOLUME_INSPECT
    kind = "config-input" if auxiliary else "config"
    name = frame.name(auxiliary)
    value = _inspection(raw)
    mountpoint = VOLUME_ROOT + "/" + name + "/_data"
    require(value.get("Name") == name and value.get("Driver") == value.get("Scope") == "local"
            and value.get("Options") in (None, {}) and value.get("Labels") == frame.labels(kind)
            and value.get("Mountpoint") == mountpoint, "config_volume_binding")
    created = value.get("CreatedAt")
    if not isinstance(created, str):
        raise ConfigError("config_volume_creation")
    require(0 < len(created) <= 128 and all(32 <= ord(char) <= 126 for char in created), "config_volume_creation")
    return VolumeObservation(kind, name, created, mountpoint)


def _mounts(frame: ConfigFrame, value: Mapping[str, Json], host: Mapping[str, Json]) -> None:
    started = frame.tool in ("producer", "verifier")
    expected = (("/build-config", False, frame.tool == "verifier"), ("/config-input", True, True)) if started else (
        (("/config-input", True, False),) if frame.tool == "input-seed" else (("/build-config", False, False),))
    actual, declared = value.get("Mounts"), host.get("Mounts")
    if not isinstance(actual, list) or not isinstance(declared, list):
        raise ConfigError("config_mount_shape")
    require(len(actual) == len(declared) == len(expected), "config_mount_count")
    for raw, target_key in ((actual, "Destination"), (declared, "Target")):
        mapped: dict[str, Mapping[str, Json]] = {}
        for item in raw:
            fields = record(item)
            target = fields.get(target_key)
            if not isinstance(target, str):
                raise ConfigError("config_mount_targets")
            require(target not in mapped, "config_mount_targets")
            mapped[target] = fields
        require(len(mapped) == len(expected) and set(mapped) == {row[0] for row in expected}, "config_mount_targets")
        for target, auxiliary, readonly in expected:
            mount = mapped[target]
            name = frame.name(auxiliary)
            if target_key == "Destination":
                require(mount.get("Type") == "volume" and mount.get("Name") == name
                        and mount.get("Source") == VOLUME_ROOT + "/" + name + "/_data"
                        and mount.get("Driver") == "local" and mount.get("RW") is (not readonly)
                        and mount.get("Propagation") == "", "config_mount")
            else:
                require(dict(mount) == {"Type": "volume", "Source": name, "Target": target,
                                       "ReadOnly": readonly, "VolumeOptions": {"NoCopy": True}}
                        and mount.get("ReadOnly") is readonly
                        and record(mount.get("VolumeOptions")).get("NoCopy") is True, "config_declared_mount")


def container_observation(frame: ConfigFrame, image: ImageObservation, raw: bytes) -> ContainerObservation:
    if frame.operation != Operation.CONTAINER_INSPECT or frame.tool is None:
        raise ConfigError("config_inspect_operation")
    value = _inspection(raw)
    config, host, state = (record(value.get(key)) for key in ("Config", "HostConfig", "State"))
    started = frame.tool in ("producer", "verifier")
    require(value.get("Id") == frame.container and value.get("Image") == image.config == IMAGE_CONFIG
            and config.get("Image") == image.reference == IMAGE
            and config.get("Labels") == frame.labels("config-" + frame.tool), "config_container_binding")
    expected_cmd = java_command(frame.tool) if started else image.command
    expected_env = tuple(sorted(environment(frame.tool))) if started else image.environment
    require(_strings(config.get("Cmd")) == expected_cmd and _env(config.get("Env")) == expected_env
            and config.get("Entrypoint") == ["/opt/java/openjdk/bin/java" if started else "/bin/false"]
            and config.get("User") == "65532:65532" and config.get("WorkingDir") == "/tmp"
            and config.get("Healthcheck") is None and config.get("Volumes") in (None, {}), "config_tool_config")
    require(not started or config.get("Hostname") == "wakeio-config-" + frame.tool, "config_hostname")
    require(all(config.get(key) is False for key in ("Tty", "OpenStdin", "StdinOnce", "AttachStdin")),
            "config_interactive")
    require(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False and host.get("CapDrop") == ["ALL"]
            and host.get("SecurityOpt") == ["no-new-privileges"] and host.get("Runtime") == "runc"
            and host.get("PidMode") == "" and host.get("IpcMode") == "private"
            and host.get("UsernsMode") in ("", "private")
            and host.get("CgroupParent") == (frame.slice_name() if started else ""), "config_security")
    for key, expected in (("NanoCpus", 2000000000), ("Memory", 2147483648),
                          ("MemorySwap", 2147483648), ("PidsLimit", 256)):
        require(type(host.get(key)) is int and host.get(key) == expected, "config_limits")
    require(host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0}
            and type(record(host.get("RestartPolicy")).get("MaximumRetryCount")) is int
            and host.get("AutoRemove") is False, "config_restart")
    require(all(host.get(key) in (None, [], {}) for key in (
        "Binds", "VolumesFrom", "Devices", "DeviceRequests", "ExtraHosts", "Dns", "DnsSearch", "DnsOptions",
        "CapAdd", "PortBindings", "Links", "GroupAdd", "DeviceCgroupRules", "LxcConf", "Sysctls", "Ulimits")),
        "config_extra_allocations")
    require(host.get("UTSMode") == "" and host.get("PublishAllPorts") is False
            and config.get("ExposedPorts") in (None, {}), "config_extra_namespaces_ports")
    require(set(record(record(value.get("NetworkSettings")).get("Networks"))) == {"none"}, "config_networks")
    require(host.get("Tmpfs") == {"/tmp": TMPFS} if started else host.get("Tmpfs") in (None, {}), "config_tmpfs")
    _mounts(frame, value, host)
    return _state(frame, value, state)


def _state(frame: ConfigFrame, value: Mapping[str, Json], state: Mapping[str, Json]) -> ContainerObservation:
    status, code = state.get("Status"), state.get("ExitCode")
    created, began, finished = value.get("Created"), state.get("StartedAt"), state.get("FinishedAt")
    if status not in ("created", "exited") or not isinstance(status, str):
        raise ConfigError("config_state")
    require(status == "created" or frame.tool in ("producer", "verifier"), "config_state")
    if type(code) is not int or not 0 <= code <= 255 or (status == "created" and code != 0):
        raise ConfigError("config_exit")
    require(all(state.get(key) is False for key in ("Running", "Paused", "Restarting", "Dead", "OOMKilled"))
            and type(state.get("Pid")) is int and state.get("Pid") == 0 and state.get("Error") == ""
            and type(value.get("RestartCount")) is int and value.get("RestartCount") == 0, "config_terminal")
    if not isinstance(created, str) or not isinstance(began, str) or not isinstance(finished, str):
        raise ConfigError("config_timestamp")
    for timestamp in (created, began, finished):
        require(1 <= len(timestamp) <= 128 and all(32 <= ord(char) <= 126 for char in timestamp), "config_timestamp")
    require((began == finished == ZERO_TIME) if status == "created" else (
        began != ZERO_TIME and finished != ZERO_TIME), "config_history")
    return ContainerObservation(frame.container or "", created, "created" if status == "created" else "exited",
                                code, began, finished)


def semantic_observation(raw: bytes, expected: Verification) -> Verification:
    value = record(strict_json(raw, 2048))
    require(raw.startswith(b"{") and raw.endswith(b"}\n") and raw.count(b"\n") == 1, "config_verify_record")
    require(list(value) == ["schema", "storeType", "storeProvider", "aliases", "trustedCertificateEntries",
                            "keyEntries", "certificateDerSha256", "storeSha256", "userSettingsSha256",
                            "globalSettingsSha256"], "config_verify_fields")
    require(value["schema"] == "wakeio.prep-config.verify/v1" and value["storeType"] == "PKCS12"
            and value["storeProvider"] == "SUN" and value["aliases"] == ["wakeio-build-mirror"]
            and type(value["trustedCertificateEntries"]) is int and value["trustedCertificateEntries"] == 1
            and type(value["keyEntries"]) is int and value["keyEntries"] == 0, "config_verify_semantics")
    for key in ("certificateDerSha256", "storeSha256", "userSettingsSha256", "globalSettingsSha256"):
        digest = value[key]
        require(type(digest) is str and re.fullmatch("[a-f0-9]{64}", digest) is not None, "config_verify_digest")
    require(value["certificateDerSha256"] == expected.certificate_der_sha256
            and value["storeSha256"] == expected.store_sha256
            and value["userSettingsSha256"] == hashlib.sha256(USER_SETTINGS).hexdigest()
            and value["globalSettingsSha256"] == hashlib.sha256(GLOBAL_SETTINGS).hexdigest(), "config_verify_binding")
    certificate, store = value["certificateDerSha256"], value["storeSha256"]
    if not isinstance(certificate, str) or not isinstance(store, str):
        raise ConfigError("config_verify_digest")
    return Verification(certificate, store)
