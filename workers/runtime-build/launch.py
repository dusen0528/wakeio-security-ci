# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Closed private launch DATA and the fixed Linux child release gate."""
import hashlib
import json
import os
import re
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, Literal, TypedDict, assert_never

Role = Literal["image-pull", "image-inspect", "volume-create", "volume-inspect", "volume-remove",
               "carrier-create", "carrier-inspect", "carrier-remove", "copy-in", "copy-out"]
MAX_CONTROL: Final = 1024
VOLUME: Final = re.compile(r"wk-([a-f0-9]{32})-b([1-9][0-9]{0,15})-input")
IDENTIFIER: Final = re.compile(r"[a-f0-9]{64}")


@dataclass(frozen=True, slots=True)
class LaunchError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise LaunchError(reason)


def selected_role(raw: str) -> Role:
    roles: tuple[Role, ...] = ("image-pull", "image-inspect", "volume-create", "volume-inspect",
                              "volume-remove", "carrier-create", "carrier-inspect", "carrier-remove",
                              "copy-in", "copy-out")
    for value in roles:
        if raw == value:
            return value
    raise LaunchError("launch_role")


@dataclass(frozen=True, slots=True)
class Selection:
    """Validated command DATA; never a resource or release-authority registration."""
    role: Role
    operand: str | None

    def __post_init__(self) -> None:
        match self.role:
            case "image-pull" | "image-inspect":
                require(self.operand is None, "launch_operand")
            case "volume-create" | "volume-inspect" | "volume-remove" | "carrier-create":
                require(VOLUME.fullmatch(operand(self)) is not None, "launch_volume")
            case "carrier-inspect" | "carrier-remove" | "copy-in" | "copy-out":
                require(IDENTIFIER.fullmatch(operand(self)) is not None, "launch_container")
            case unreachable:
                assert_never(unreachable)


def operand(selection: Selection) -> str:
    match selection.operand:
        case str() as value:
            return value
        case None:
            raise LaunchError("launch_operand")
        case unreachable:
            assert_never(unreachable)


class _SelectionData(TypedDict):
    role: str
    operand: str | None


class _Platform(TypedDict):
    manifestDigest: str
    configDigest: str


class _Image(TypedDict):
    repository: str
    platforms: dict[str, _Platform]


class _Pins(TypedDict):
    baseImages: dict[str, _Image]


class _Metadata(TypedDict):
    pins: _Pins


def build_image() -> tuple[str, str]:
    from input import PROFILE_SHA256

    with Path(__file__).with_name("profiles.json").open("rb") as source:
        raw = source.read(65537)
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == PROFILE_SHA256, "launch_profile")
    metadata: _Metadata = json.loads(raw)
    image = metadata["pins"]["baseImages"]["build"]
    platform = image["platforms"]["linux/arm64"]
    return image["repository"] + "@" + platform["manifestDigest"], platform["configDigest"]


def encode_selection(selection: Selection) -> bytes:
    body = json.dumps({"role": selection.role, "operand": selection.operand},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    require(0 < len(body) <= MAX_CONTROL, "launch_bound")
    return struct.pack("!I", len(body)) + body + b"R"


def _exact(stream: BinaryIO, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = stream.read(length - len(result))
        require(bool(part), "launch_truncated")
        result.extend(part)
    return bytes(result)


def read_selection(stream: BinaryIO) -> Selection:
    length = struct.unpack("!I", _exact(stream, 4))[0]
    require(0 < length <= MAX_CONTROL, "launch_bound")
    body = _exact(stream, length)
    try:
        text = body.decode("utf-8")
        data: _SelectionData = json.loads(text)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise LaunchError("launch_encoding") from error
    require(type(data) is dict and list(data) == ["role", "operand"], "launch_fields")
    require(json.dumps(data, ensure_ascii=False, separators=(",", ":")) == text, "launch_canonical")
    require(type(data["role"]) is str and (data["operand"] is None or type(data["operand"]) is str),
            "launch_operand")
    selection = Selection(selected_role(data["role"]), data["operand"])
    require(_exact(stream, 1) == b"R" and stream.read(1) == b"", "launch_release")
    return selection


def resource_labels(name: str, carrier: bool = False) -> dict[str, str]:
    matched = VOLUME.fullmatch(name)
    if matched is None:
        raise LaunchError("launch_volume")
    return {"wakeio.owner": "t6-build", "wakeio.run": matched[1], "wakeio.generation": matched[2],
            "wakeio.scope": "build", "wakeio.role": "input-carrier" if carrier else "input"}


def command(selection: Selection) -> tuple[str, ...]:
    from daemon import DOCKER

    match selection.role:
        case "image-pull":
            return (*DOCKER, "pull", "--platform=linux/arm64", build_image()[0])
        case "image-inspect":
            return (*DOCKER, "image", "inspect", build_image()[0])
        case "volume-create":
            name = operand(selection)
            labels = tuple("--label=" + key + "=" + value for key, value in resource_labels(name).items())
            return (*DOCKER, "volume", "create", "--driver=local", *labels, name)
        case "volume-inspect":
            return (*DOCKER, "volume", "inspect", operand(selection))
        case "volume-remove":
            return (*DOCKER, "volume", "rm", operand(selection))
        case "carrier-create":
            name = operand(selection)
            labels = tuple("--label=" + key + "=" + value for key, value in resource_labels(name, True).items())
            return (*DOCKER, "create", "--network=none", "--read-only", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--user=65532:65532", "--cpus=2",
                    "--memory=2147483648", "--memory-swap=2147483648", "--pids-limit=256", *labels,
                    "--mount=type=volume,src=" + name + ",dst=/work", "--entrypoint=/bin/false", build_image()[0])
        case "carrier-inspect":
            return (*DOCKER, "container", "inspect", operand(selection))
        case "carrier-remove":
            return (*DOCKER, "container", "rm", operand(selection))
        case "copy-in":
            return (*DOCKER, "cp", "--archive", "-", operand(selection) + ":/")
        case "copy-out":
            return (*DOCKER, "cp", "--archive", operand(selection) + ":/work", "-")
        case unreachable:
            assert_never(unreachable)


def main() -> None:
    require(sys.platform == "linux" and os.geteuid() == 10001 and os.getegid() == 10001
            and not os.getgroups(), "launch_platform")
    sys.path.insert(0, "/usr/local/lib/wakeio-controller")
    sys.path.insert(0, "/usr/local/lib/wakeio-controller/build")
    from backend_process import USER_ENV

    require(len(sys.argv) == 2 and re.fullmatch(r"[0-9]{1,10}", sys.argv[1]) is not None, "launch_ingress")
    descriptor = int(sys.argv[1])
    require(stat.S_ISFIFO(os.fstat(descriptor).st_mode), "launch_channel")
    with os.fdopen(descriptor, "rb") as channel:
        selection = read_selection(channel)
    argv = command(selection)
    os.execve(argv[0], argv, USER_ENV)


if __name__ == "__main__":
    try:
        main()
    except (LaunchError, OSError, ValueError):
        sys.stderr.write("BUILD_LAUNCH_REFUSED\n")
        sys.exit(125)
