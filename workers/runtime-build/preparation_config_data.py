# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B tests/native/runtime_build_preparation_config_data_test.py
"""Closed C3 command DATA. No allocation, launch import, release slot or ownership."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal, TypedDict, assert_never

type Json = str | int | float | bool | None | list[Json] | dict[str, Json]
ToolRole = Literal["seed", "input-seed", "producer", "verifier"]
DOCKER: Final = ("/usr/bin/docker", "--host=unix:///run/user/10001/docker.sock")
IMAGE: Final = "docker.io/library/maven@sha256:65cedfb84cfbb1dc9974c14662d6bf9b20aa6aea274c877fe08952bdfae7992f"
IMAGE_CONFIG: Final = "sha256:fe1f0cef06dadb4b4e7b613be22c806414f48f3357c9728e659f7bc0baab7326"
USER_SETTINGS: Final = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">\n'
    b'  <localRepository>/tmp/wakeio-m2</localRepository>\n'
    b'  <interactiveMode>false</interactiveMode>\n'
    b'  <mirrors>\n    <mirror>\n      <id>wakeio-build-mirror</id>\n'
    b'      <mirrorOf>*</mirrorOf>\n      <url>https://wakeio-maven:8443/maven2/</url>\n'
    b'    </mirror>\n  </mirrors>\n</settings>\n'
)
GLOBAL_SETTINGS: Final = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"/>\n'
)
TMPFS: Final = "rw,nosuid,nodev,noexec,size=268435456,mode=1777"


class ConfigError(Exception):
    """Typed boundary failure with normal mutable Exception traceback semantics."""
    reason: str

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)

    def __str__(self) -> str:
        return self.reason


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ConfigError(reason)


class Operation(StrEnum):
    VOLUME_INSPECT = "volume-inspect"
    VOLUME_CREATE = "volume-create"
    VOLUME_REMOVE = "volume-remove"
    INPUT_VOLUME_INSPECT = "input-volume-inspect"
    INPUT_VOLUME_CREATE = "input-volume-create"
    INPUT_VOLUME_REMOVE = "input-volume-remove"
    CONTAINER_CREATE = "container-create"
    CONTAINER_INSPECT = "container-inspect"
    CONTAINER_REMOVE = "container-remove"
    SEED_VOLUME = "seed-volume"
    SEED_INPUTS = "seed-inputs"
    READ_INPUTS = "read-inputs"
    READ_CONFIG = "read-config"
    READ_HELPER = "read-helper"
    READ_CERTIFICATE = "read-certificate"
    ATTACH_START = "attach-start"
    CONTAINER_KILL = "container-kill"
    ENVELOPE_PRESENT = "envelope-present"
    ENVELOPE_FILES = "envelope-files"
    ENVELOPE_INSPECT = "envelope-inspect"
    ENVELOPE_RELOAD = "envelope-reload"
    ENVELOPE_START = "envelope-start"
    ENVELOPE_STOP = "envelope-stop"


class FrameData(TypedDict):
    run: str
    generation: int
    operation: str
    tool: str | None
    container: str | None


@dataclass(frozen=True, slots=True)
class ConfigFrame:
    run: str
    generation: int
    operation: Operation
    tool: ToolRole | None
    container: str | None

    def __post_init__(self) -> None:
        require(type(self.run) is str and re.fullmatch("[a-f0-9]{32}", self.run) is not None, "config_run")
        require(type(self.generation) is int and 1 <= self.generation <= 9999999999999999, "config_generation")
        require(type(self.operation) is Operation, "config_operation")
        op = self.operation
        volume = op.value.startswith(("volume-", "input-volume-"))
        match op:
            case Operation.SEED_VOLUME:
                roles = ("seed",)
            case Operation.SEED_INPUTS | Operation.READ_INPUTS:
                roles = ("input-seed",)
            case Operation.READ_CONFIG:
                roles = ("seed", "verifier")
            case Operation.CONTAINER_CREATE | Operation.CONTAINER_INSPECT | Operation.CONTAINER_REMOVE:
                roles = ("seed", "input-seed", "producer", "verifier")
            case (Operation.READ_HELPER | Operation.READ_CERTIFICATE | Operation.ATTACH_START
                  | Operation.CONTAINER_KILL | Operation.ENVELOPE_PRESENT | Operation.ENVELOPE_FILES
                  | Operation.ENVELOPE_INSPECT | Operation.ENVELOPE_RELOAD | Operation.ENVELOPE_START
                  | Operation.ENVELOPE_STOP):
                roles = ("producer", "verifier")
            case (Operation.VOLUME_INSPECT | Operation.VOLUME_CREATE | Operation.VOLUME_REMOVE
                  | Operation.INPUT_VOLUME_INSPECT | Operation.INPUT_VOLUME_CREATE | Operation.INPUT_VOLUME_REMOVE):
                roles = ()
            case unreachable:
                assert_never(unreachable)
        require(self.tool is None if volume else type(self.tool) is str and self.tool in roles, "config_tool")
        needs_id = not volume and op != Operation.CONTAINER_CREATE and not op.value.startswith("envelope-")
        require((type(self.container) is str and re.fullmatch("[a-f0-9]{64}", self.container) is not None)
                if needs_id else self.container is None, "config_container")

    @property
    def mutation(self) -> bool:
        return self.operation in (
            Operation.VOLUME_CREATE, Operation.VOLUME_REMOVE, Operation.INPUT_VOLUME_CREATE,
            Operation.INPUT_VOLUME_REMOVE, Operation.CONTAINER_CREATE, Operation.CONTAINER_REMOVE,
            Operation.SEED_VOLUME, Operation.SEED_INPUTS, Operation.ATTACH_START, Operation.CONTAINER_KILL,
            Operation.ENVELOPE_RELOAD, Operation.ENVELOPE_START, Operation.ENVELOPE_STOP)

    @property
    def cleanup(self) -> bool:
        return self.operation in (
            Operation.VOLUME_INSPECT, Operation.VOLUME_REMOVE, Operation.INPUT_VOLUME_INSPECT,
            Operation.INPUT_VOLUME_REMOVE, Operation.CONTAINER_INSPECT, Operation.CONTAINER_REMOVE,
            Operation.CONTAINER_KILL, Operation.ENVELOPE_PRESENT, Operation.ENVELOPE_FILES,
            Operation.ENVELOPE_INSPECT, Operation.ENVELOPE_RELOAD, Operation.ENVELOPE_STOP)

    def data(self) -> FrameData:
        return {"run": self.run, "generation": self.generation, "operation": self.operation.value,
                "tool": self.tool, "container": self.container}

    def name(self, auxiliary: bool = False) -> str:
        return f"wk-{self.run}-b{self.generation}-prepare-config" + ("-input" if auxiliary else "")

    def labels(self, role: str) -> dict[str, str]:
        require(role in ("config", "config-input", "config-seed", "config-input-seed",
                         "config-producer", "config-verifier"), "config_label_role")
        return {"wakeio.owner": "t6-build", "wakeio.run": self.run, "wakeio.generation": str(self.generation),
                "wakeio.scope": "build", "wakeio.role": "prepare-" + role}

    def slice_name(self) -> str:
        require(self.tool in ("producer", "verifier"), "config_envelope_role")
        suffix = "produce" if self.tool == "producer" else "verify"
        return f"wk{self.run}b{self.generation}config{suffix}.slice"


def parse_frame(raw: Mapping[str, Json]) -> ConfigFrame:
    require(type(raw) is dict and list(raw) == ["run", "generation", "operation", "tool", "container"],
            "config_fields")
    match (raw["run"], raw["generation"], raw["operation"], raw["container"]):
        case (str() as run, int() as generation, str() as selected, (str() | None) as container):
            require(type(selected) is str, "config_fields")
            try:
                operation = Operation(selected)
            except ValueError as error:
                raise ConfigError("config_operation") from error
            return ConfigFrame(run, generation, operation, _tool(raw["tool"]), container)
        case _:
            raise ConfigError("config_fields")


def _tool(raw: Json) -> ToolRole | None:
    match raw:
        case "seed" | "input-seed" | "producer" | "verifier" | None:
            return raw
        case _:
            raise ConfigError("config_tool")


def environment(role: ToolRole) -> tuple[str, ...]:
    require(role in ("producer", "verifier"), "config_java_role")
    return ("PATH=/opt/java/openjdk/bin:/usr/bin:/bin", "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LANGUAGE=C",
            "LC_ALL=C", "JAVA_VERSION=jdk-21.0.12.1+1", "MAVEN_HOME=/usr/share/maven",
            "MAVEN_CONFIG=/tmp/unused-maven-home", "HOME=/tmp", "TMPDIR=/tmp", "HOSTNAME=wakeio-config-" + role)


def java_command(role: ToolRole) -> tuple[str, ...]:
    require(role in ("producer", "verifier"), "config_java_role")
    name = "PrepConfigProduce.java" if role == "producer" else "PrepConfigVerify.java"
    return ("-Djava.io.tmpdir=/tmp", "-Duser.home=/tmp", "-Dfile.encoding=UTF-8", "--class-path",
            "/config-input/" + role, "--source", "21", "/config-input/" + role + "/" + name)


def unit_bytes(frame: ConfigFrame) -> bytes:
    frame.slice_name()
    description = b"producer" if frame.tool == "producer" else b"verifier"
    return (b"[Unit]\nDescription=Wakeio configuration " + description
            + b"\n[Slice]\nCPUQuota=200%\nMemoryMax=2147483648\nMemorySwapMax=0\nTasksMax=256\n")


def _create(frame: ConfigFrame) -> tuple[str, ...]:
    role = frame.tool
    if role is None:
        raise ConfigError("config_tool")
    started = role in ("producer", "verifier")
    labels = tuple("--label=" + key + "=" + value for key, value in frame.labels("config-" + role).items())
    targets = (("/build-config", False, role == "verifier"), ("/config-input", True, True)) if started else (
        (("/config-input", True, False),) if role == "input-seed" else (("/build-config", False, False),))
    mounts = tuple("--mount=type=volume,src=" + frame.name(auxiliary) + ",dst=" + target
                   + ",volume-nocopy" + (",readonly" if readonly else "") for target, auxiliary, readonly in targets)
    extra = ("--hostname=wakeio-config-" + role, "--cgroup-parent=" + frame.slice_name(),
             "--tmpfs=/tmp:" + TMPFS, *("--env=" + item for item in environment(role))) \
        if started else ()
    return (*DOCKER, "create", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=65532:65532", "--cpus=2",
            "--memory=2147483648", "--memory-swap=2147483648", "--pids-limit=256", "--runtime=runc",
            "--ipc=private", "--restart=no", "--workdir=/tmp", *labels, *mounts, *extra,
            "--entrypoint=" + ("/opt/java/openjdk/bin/java" if started else "/bin/false"),
            IMAGE, *(java_command(role) if started else ()))


def command(frame: ConfigFrame) -> tuple[str, ...]:
    """Encode only fixed operations; the caller still needs original resource authority."""
    op, identifier = frame.operation, frame.container or ""
    match op:
        case Operation.VOLUME_CREATE | Operation.INPUT_VOLUME_CREATE:
            auxiliary = op == Operation.INPUT_VOLUME_CREATE
            flags = tuple("--label=" + key + "=" + value
                          for key, value in frame.labels("config-input" if auxiliary else "config").items())
            return (*DOCKER, "volume", "create", "--driver=local", *flags, frame.name(auxiliary))
        case (Operation.VOLUME_INSPECT | Operation.VOLUME_REMOVE
              | Operation.INPUT_VOLUME_INSPECT | Operation.INPUT_VOLUME_REMOVE):
            action = "inspect" if op in (Operation.VOLUME_INSPECT, Operation.INPUT_VOLUME_INSPECT) else "rm"
            return (*DOCKER, "volume", action, frame.name(op.value.startswith("input-")))
        case Operation.CONTAINER_CREATE:
            return _create(frame)
        case Operation.CONTAINER_INSPECT | Operation.CONTAINER_REMOVE | Operation.CONTAINER_KILL:
            action = {Operation.CONTAINER_INSPECT: "inspect", Operation.CONTAINER_REMOVE: "rm",
                      Operation.CONTAINER_KILL: "kill"}[op]
            return (*DOCKER, "container", action, identifier)
        case Operation.SEED_VOLUME | Operation.SEED_INPUTS:
            target = "/build-config" if op == Operation.SEED_VOLUME else "/config-input"
            return (*DOCKER, "cp", "--archive", "-", identifier + ":" + target)
        case Operation.READ_INPUTS | Operation.READ_CONFIG | Operation.READ_HELPER | Operation.READ_CERTIFICATE:
            target = {Operation.READ_INPUTS: "/config-input", Operation.READ_CONFIG: "/build-config",
                      Operation.READ_HELPER: "/config-input/" + (frame.tool or ""),
                      Operation.READ_CERTIFICATE: "/config-input/mirror.crt"}[op]
            return (*DOCKER, "cp", "--archive", identifier + ":" + target, "-")
        case Operation.ATTACH_START:
            return (*DOCKER, "start", "--attach", identifier)
        case (Operation.ENVELOPE_PRESENT | Operation.ENVELOPE_FILES | Operation.ENVELOPE_INSPECT
              | Operation.ENVELOPE_RELOAD | Operation.ENVELOPE_START | Operation.ENVELOPE_STOP):
            return _envelope_command(frame)
        case unreachable:
            assert_never(unreachable)


def _envelope_command(frame: ConfigFrame) -> tuple[str, ...]:
    from cold_envelope_data import UNIT_PROPERTIES

    suffix = {
        Operation.ENVELOPE_PRESENT: ("list-units", "--all", "--plain", "--no-legend", "--no-pager"),
        Operation.ENVELOPE_FILES: ("list-unit-files", "--no-legend", "--no-pager"),
        Operation.ENVELOPE_INSPECT: ("show",),
        Operation.ENVELOPE_RELOAD: ("daemon-reload",),
        Operation.ENVELOPE_START: ("start",), Operation.ENVELOPE_STOP: ("stop",),
    }[frame.operation]
    tail = () if frame.operation == Operation.ENVELOPE_RELOAD else (frame.slice_name(),)
    properties = ("--property=" + UNIT_PROPERTIES,) if frame.operation == Operation.ENVELOPE_INSPECT else ()
    return ("/usr/bin/systemctl", "--user", *suffix, *tail, *properties)
