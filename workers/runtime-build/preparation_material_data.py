# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Closed preparation transfer command DATA, not allocation or execution authority."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal, TypedDict, assert_never

from backend_process import BackendError, require

MaterialKind = Literal["work", "cache", "output"]
Operation = Literal[
    "volume-create-work", "volume-inspect-work", "volume-remove-work",
    "volume-create-cache", "volume-inspect-cache", "volume-remove-cache",
    "volume-create-output", "volume-inspect-output", "volume-remove-output",
    "carrier-create", "carrier-inspect", "carrier-remove", "seed", "read-work", "read-cache", "read-output",
]
OPERATIONS: Final[tuple[Operation, ...]] = (
    "volume-create-work", "volume-inspect-work", "volume-remove-work",
    "volume-create-cache", "volume-inspect-cache", "volume-remove-cache",
    "volume-create-output", "volume-inspect-output", "volume-remove-output",
    "carrier-create", "carrier-inspect", "carrier-remove", "seed", "read-work", "read-cache", "read-output",
)
KINDS: Final[tuple[MaterialKind, ...]] = ("work", "cache", "output")
type Json = str | int | float | bool | None | list[Json] | dict[str, Json]


class FrameData(TypedDict):
    run: str
    generation: int
    operation: str
    container: str | None


def operation(raw: str) -> Operation:
    for selected in OPERATIONS:
        if raw == selected:
            return selected
    raise BackendError("material_operation")


@dataclass(frozen=True, slots=True)
class MaterialFrame:
    run: str
    generation: int
    operation: Operation
    container: str | None

    def __post_init__(self) -> None:
        require(type(self.run) is str and re.fullmatch(r"[a-f0-9]{32}", self.run) is not None, "material_run")
        require(type(self.generation) is int and 1 <= self.generation <= 9999999999999999,
                "material_generation")
        require(type(self.operation) is str and self.operation in OPERATIONS, "material_operation")
        needs_container = self.operation in (
            "carrier-inspect", "carrier-remove", "seed", "read-work", "read-cache", "read-output")
        require((type(self.container) is str and re.fullmatch(r"[a-f0-9]{64}", self.container) is not None)
                if needs_container else self.container is None, "material_container")

    def data(self) -> FrameData:
        return {"run": self.run, "generation": self.generation,
                "operation": self.operation, "container": self.container}

    def name(self, kind: MaterialKind) -> str:
        require(type(kind) is str and kind in KINDS, "material_kind")
        return f"wk-{self.run}-b{self.generation}-prepare-{kind}"

    def labels(self, kind: MaterialKind | Literal["transfer"]) -> dict[str, str]:
        require(kind in (*KINDS, "transfer"), "material_kind")
        return {"wakeio.owner": "t6-build", "wakeio.run": self.run, "wakeio.generation": str(self.generation),
                "wakeio.scope": "build", "wakeio.role": "prepare-" + kind}

    @property
    def kind(self) -> MaterialKind | None:
        match self.operation:
            case "volume-create-work" | "volume-inspect-work" | "volume-remove-work" | "read-work":
                return "work"
            case "volume-create-cache" | "volume-inspect-cache" | "volume-remove-cache" | "read-cache":
                return "cache"
            case "volume-create-output" | "volume-inspect-output" | "volume-remove-output" | "read-output":
                return "output"
            case "carrier-create" | "carrier-inspect" | "carrier-remove" | "seed":
                return None
            case unreachable:
                assert_never(unreachable)

    @property
    def cleanup(self) -> bool:
        return self.operation in (
            "volume-inspect-work", "volume-remove-work", "volume-inspect-cache", "volume-remove-cache",
            "volume-inspect-output", "volume-remove-output", "carrier-inspect", "carrier-remove")

    @property
    def mutation(self) -> bool:
        return self.operation in (
            "volume-create-work", "volume-remove-work", "volume-create-cache", "volume-remove-cache",
            "volume-create-output", "volume-remove-output", "carrier-create", "carrier-remove", "seed")


def parse_frame(raw: Json) -> MaterialFrame:
    if not isinstance(raw, dict):
        raise BackendError("material_fields")
    require(list(raw) == ["run", "generation", "operation", "container"], "material_fields")
    run, generation, selected, container = raw["run"], raw["generation"], raw["operation"], raw["container"]
    if (not isinstance(run, str) or not isinstance(generation, int) or not isinstance(selected, str)
            or (container is not None and not isinstance(container, str))):
        raise BackendError("material_fields")
    return MaterialFrame(run, generation, operation(selected), container)


def command(frame: MaterialFrame) -> tuple[str, ...]:
    from daemon import DOCKER
    from launch import build_image

    match frame.operation:
        case "volume-create-work" | "volume-create-cache" | "volume-create-output":
            kind = frame.kind
            if kind is None:
                raise BackendError("material_kind")
            labels = tuple("--label=" + key + "=" + value for key, value in frame.labels(kind).items())
            return (*DOCKER, "volume", "create", "--driver=local", *labels, frame.name(kind))
        case ("volume-inspect-work" | "volume-inspect-cache" | "volume-inspect-output"
              | "volume-remove-work" | "volume-remove-cache" | "volume-remove-output"):
            kind = frame.kind
            if kind is None:
                raise BackendError("material_kind")
            action = "inspect" if frame.operation.startswith("volume-inspect-") else "rm"
            return (*DOCKER, "volume", action, frame.name(kind))
        case "carrier-create":
            labels = tuple("--label=" + key + "=" + value for key, value in frame.labels("transfer").items())
            mounts = tuple("--mount=type=volume,src=" + frame.name(kind) + ",dst=/" + kind + ",volume-nocopy"
                           for kind in KINDS)
            return (*DOCKER, "create", "--network=none", "--read-only", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--user=65532:65532", "--cpus=2",
                    "--memory=2147483648", "--memory-swap=2147483648", "--pids-limit=256", *labels,
                    *mounts, "--entrypoint=/bin/false", build_image()[0])
        case "carrier-inspect" | "carrier-remove" | "seed" | "read-work" | "read-cache" | "read-output":
            return _carrier_command(frame)
        case unreachable:
            assert_never(unreachable)


def _carrier_command(frame: MaterialFrame) -> tuple[str, ...]:
    from daemon import DOCKER

    identifier = frame.container
    if identifier is None:
        raise BackendError("material_container")
    match frame.operation:
        case "carrier-inspect":
            return (*DOCKER, "container", "inspect", identifier)
        case "carrier-remove":
            return (*DOCKER, "container", "rm", identifier)
        case "seed":
            return (*DOCKER, "cp", "--archive", "-", identifier + ":/")
        case "read-work" | "read-cache" | "read-output":
            return (*DOCKER, "cp", "--archive", identifier + ":/" + frame.operation.removeprefix("read-"), "-")
        case ("volume-create-work" | "volume-inspect-work" | "volume-remove-work"
              | "volume-create-cache" | "volume-inspect-cache" | "volume-remove-cache"
              | "volume-create-output" | "volume-inspect-output" | "volume-remove-output" | "carrier-create"):
            raise BackendError("material_carrier_operation")
        case unreachable:
            assert_never(unreachable)
