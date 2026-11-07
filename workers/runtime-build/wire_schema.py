# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Closed build-v2 DATA grammar. No resources, dispatcher or authority registry."""
import base64
import binascii
import re
from typing import Final, Literal, TypeAlias, assert_never

Json: TypeAlias = None | bool | int | str | list["Json"] | dict[str, "Json"]
Operation = Literal[
    "build-begin", "build-input", "build-seal", "build-prepare",
    "build-offline", "build-assemble", "build-stop", "build-close",
]
REASONS: Final = frozenset((
    "input_refused", "identity_changed", "phase_invalid", "operation_failed", "output_bound",
    "aborted", "deadline", "close_unconfirmed", "allocation_unknown",
))


class WireError(Exception):
    """A redacted, closed protocol refusal."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(value: bool, code: str) -> None:
    if not value:
        raise WireError(code)


def record(raw: Json, keys: str) -> dict[str, Json]:
    require(type(raw) is dict, "build_record")
    match raw:
        case dict():
            require(",".join(raw) == keys, "build_keys")
            return raw
        case _:
            raise WireError("build_record")


def integer(raw: Json, maximum: int) -> int:
    require(type(raw) is int, "build_integer")
    match raw:
        case int():
            require(0 <= raw <= maximum, "build_integer")
            return raw
        case _:
            raise WireError("build_integer")


def digest(raw: Json) -> str:
    match raw:
        case str():
            require(re.fullmatch("[a-f0-9]{64}", raw) is not None, "build_digest")
            return raw
        case _:
            raise WireError("build_digest")


def chunk(raw: Json) -> bytes:
    match raw:
        case str():
            require(0 < len(raw) <= 32768, "build_base64")
            try:
                result = base64.b64decode(raw, validate=True)
            except (ValueError, binascii.Error) as error:
                raise WireError("build_base64") from error
            require(base64.b64encode(result).decode("ascii") == raw, "build_base64")
            return result
        case _:
            raise WireError("build_base64")


def operation(raw: Json) -> Operation:
    match raw:
        case ("build-begin" | "build-input" | "build-seal" | "build-prepare"
              | "build-offline" | "build-assemble" | "build-stop" | "build-close"):
            return raw
        case _:
            raise WireError("build_operation")


def body(selected: Operation, build: Json, raw: Json) -> dict[str, Json]:
    if selected != "build-begin":
        digest(build)
    match selected:
        case "build-begin":
            data = record(raw, "profile")
            require(build is None and data["profile"] in ("f01", "f02", "f03", "f04"), "build_begin")
        case "build-input":
            data = record(raw, "file,offset,data")
            integer(data["file"], 4)
            offset = integer(data["offset"], 1048576)
            require(offset + len(chunk(data["data"])) <= 1048576, "build_file_bound")
        case "build-seal":
            data = record(raw, "files")
            match data["files"]:
                case list() as files:
                    require(len(files) == 5, "build_files")
                    for index, raw_row in enumerate(files):
                        row = record(raw_row, "file,bytes,sha256")
                        require(integer(row["file"], 4) == index, "build_ordinal")
                        integer(row["bytes"], 1048576)
                        digest(row["sha256"])
                case _:
                    raise WireError("build_files")
        case "build-stop":
            data = record(raw, "reason")
            require(data["reason"] in ("aborted", "deadline", "failure", "completed"), "build_stop")
        case "build-prepare" | "build-offline" | "build-assemble" | "build-close":
            data = record(raw, "")
        case unreachable:
            assert_never(unreachable)
    return data


def reason(raw: Json) -> None:
    require(type(raw) is str and raw in REASONS, "build_reason")


def tree(raw: Json, bounds: tuple[int, int]) -> None:
    data = record(raw, "sha256,bytes,entries")
    digest(data["sha256"])
    integer(data["bytes"], bounds[0])
    integer(data["entries"], bounds[1])


def result(selected: Operation, request: dict[str, Json], raw: Json) -> dict[str, Json]:
    require(type(raw) is dict, "build_result")
    match raw:
        case {"kind": "failed"}:
            data = record(raw, "kind,reason")
            reason(data["reason"])
            return data
    match selected:
        case "build-begin":
            data = record(raw, "kind,generation")
            require(data["kind"] == "allocated" and integer(data["generation"], 2**53 - 1) > 0, "build_result")
        case "build-input":
            data = record(raw, "kind,file,nextOffset")
            require(data["kind"] == "input-accepted" and integer(data["file"], 4) == request["file"]
                    and integer(data["nextOffset"], 1048576)
                    == integer(request["offset"], 1048576) + len(chunk(request["data"])), "build_input_result")
        case "build-seal":
            data = record(raw, "kind,manifestSha256")
            require(data["kind"] == "sealed", "build_result")
            digest(data["manifestSha256"])
        case "build-prepare":
            data = record(raw, "kind,cache,closureSha256")
            require(data["kind"] == "preparation-closed", "build_result")
            tree(data["cache"], (1073741824, 16384))
            digest(data["closureSha256"])
        case "build-offline":
            data = record(raw, "kind,jar,classes")
            require(data["kind"] == "offline-closed", "build_result")
            jar = record(data["jar"], "bytes,sha256")
            integer(jar["bytes"], 67108864)
            digest(jar["sha256"])
            tree(data["classes"], (134217728, 4096))
        case "build-assemble":
            data = record(raw, "kind,image,recipeSha256,gateSha256")
            require(data["kind"] == "assembled", "build_result")
            image = record(data["image"], "id,configSha256,os,architecture,layersSha256")
            require(type(image["id"]) is str and re.fullmatch("sha256:[a-f0-9]{64}", image["id"]) is not None
                    and image["os"] == "linux" and image["architecture"] == "arm64", "build_image")
            for key in ("configSha256", "layersSha256"):
                digest(image[key])
            digest(data["recipeSha256"])
            digest(data["gateSha256"])
        case "build-stop":
            data = record(raw, "kind")
            require(data["kind"] == "stop-requested", "build_result")
        case "build-close":
            data = record(raw, "kind,state,reason")
            require(data["kind"] == "cleanup-state", "build_result")
            match data["state"]:
                case "confirmed":
                    require(data["reason"] is None, "build_cleanup")
                case "unconfirmed":
                    reason(data["reason"])
                case _:
                    raise WireError("build_cleanup")
        case unreachable:
            assert_never(unreachable)
    return data
