# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Closed material USTAR DATA. These bytes neither seal a cache nor establish custody."""
from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from typing import Literal, assert_never

from input import MAX_FILE, InputCopy, InputError, profile, require
from input_archive import BLOCK, MAX_METADATA, RECORD, _directories
from preparation_material_data import MaterialFrame, MaterialKind


@dataclass(frozen=True, slots=True)
class Transfer:
    body: bytes
    bound: int
    archive: bool


def transfer(frame: MaterialFrame, data: InputCopy | None) -> Transfer:
    """Select only the original fixed seed/read DATA payload, with separate archive and log bounds."""
    from process import LOG_BOUND

    if data is None:
        raise InputError("material_copy_missing")
    match frame.operation:
        case "seed":
            return Transfer(build_archive(data), LOG_BOUND, False)
        case "read-work" | "read-cache" | "read-output":
            kind = frame.kind
            if kind is None:
                raise InputError("material_read_kind")
            return Transfer(b"", output_bound(data, kind), True)
        case ("volume-create-work" | "volume-inspect-work" | "volume-remove-work"
              | "volume-create-cache" | "volume-inspect-cache" | "volume-remove-cache"
              | "volume-create-output" | "volume-inspect-output" | "volume-remove-output"
              | "carrier-create" | "carrier-inspect" | "carrier-remove"):
            return Transfer(b"", LOG_BOUND, False)
        case unreachable:
            assert_never(unreachable)


def _members(data: InputCopy, selected: MaterialKind | Literal["seed"]) -> tuple[tuple[str, bytes | None], ...]:
    match selected:
        case "cache" | "output":
            return ((selected, None),)
        case "work" | "seed":
            source = profile(data.identifier)
            directories = {*_directories(source), "work/target"}
            if selected == "seed":
                directories.update(("cache", "output"))
            return (*((name, None) for name in sorted(directories, key=lambda name: (name.count("/"), name))),
                    *(("work/" + binding.path, body)
                      for binding, body in zip(source.files, data.bodies, strict=True)))
        case unreachable:
            assert_never(unreachable)


def build_archive(data: InputCopy) -> bytes:
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, body in _members(data, "seed"):
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 65532
                info.mtime = 0
                if body is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o700 if name in ("cache", "output") else 0o500
                    archive.addfile(info)
                else:
                    info.mode = 0o400
                    info.size = len(body)
                    with io.BytesIO(body) as content:
                        archive.addfile(info, content)
        return buffer.getvalue()


def output_bound(data: InputCopy, kind: MaterialKind) -> int:
    match kind:
        case "work":
            return sum(len(body) for body in data.bodies) + MAX_METADATA
        case "cache" | "output":
            return MAX_METADATA
        case unreachable:
            assert_never(unreachable)


def _header(block: bytes) -> tarfile.TarInfo:
    require(len(block) == BLOCK, "material_archive_truncated")
    require(block[156:157] in (tarfile.DIRTYPE, tarfile.REGTYPE), "material_archive_type")
    try:
        info = tarfile.TarInfo.frombuf(block, "ascii", "strict")
    except (tarfile.HeaderError, UnicodeError, ValueError) as error:
        raise InputError("material_archive_header") from error
    require(0 <= info.size <= MAX_FILE, "material_archive_length")
    require(not info.linkname and not info.uname and not info.gname and info.devmajor == info.devminor == 0,
            "material_archive_metadata")
    require(info.uid == info.gid == 65532 and info.mtime == 0, "material_archive_ownership")
    require(block == info.tobuf(tarfile.USTAR_FORMAT, "ascii", "strict"), "material_archive_noncanonical")
    return info


def inspect_archive(data: InputCopy, kind: MaterialKind, raw: bytes) -> str:
    """Inspect the actual bounded stream, not a re-encoded surrogate; never extract anything."""
    require(type(raw) is bytes and len(raw) <= output_bound(data, kind), "material_archive_bound")
    seen: set[str] = set()
    folded: set[str] = set()
    position = 0
    for expected, body in _members(data, kind):
        block = raw[position:position + BLOCK]
        require(block != bytes(BLOCK), "material_archive_missing")
        info = _header(block)
        name = info.name
        require("\\" not in name and not name.startswith("/")
                and all(part not in ("", ".", "..") for part in name.split("/")), "material_archive_path")
        require(name not in seen, "material_archive_duplicate")
        require(name.casefold() not in folded, "material_archive_case_collision")
        require(name == expected, "material_archive_membership")
        seen.add(name)
        folded.add(name.casefold())
        directory = body is None
        require(info.isdir() == directory, "material_archive_member_type")
        mode = (0o700 if name in ("cache", "output") else 0o500) if directory else 0o400
        require(info.mode == mode, "material_archive_mode")
        size = 0 if body is None else len(body)
        require(info.size == size, "material_archive_length")
        start = position + BLOCK
        end = start + size
        position = end + (-size % BLOCK)
        require(position <= len(raw), "material_archive_truncated")
        require(not any(raw[end:position]), "material_archive_padding")
        if body is not None:
            require(raw[start:end] == body, "material_archive_content")
    framed = ((position + 2 * BLOCK + RECORD - 1) // RECORD) * RECORD
    require(len(raw) == framed and not any(raw[position:]), "material_archive_trailing")
    return hashlib.sha256(raw).hexdigest()
