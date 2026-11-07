"""Fixed input archive DATA only; readback observation never seals an owned resource."""
import hashlib
import io
import tarfile
from typing import Final

from input import MAX_FILE, InputCopy, InputError, Profile, profile, require

MAX_METADATA: Final = 16 * 1024 * 1024
BLOCK: Final = tarfile.BLOCKSIZE
RECORD: Final = tarfile.RECORDSIZE


def _directories(selected: Profile) -> tuple[str, ...]:
    directories = {"work"}
    for binding in selected.files:
        parts = ("work/" + binding.path).split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return tuple(sorted(directories, key=lambda path: (path.count("/"), path)))


def build_archive(data: InputCopy) -> bytes:
    """Reuse Resources.seed's directory-first pattern, with explicit plain USTAR framing."""
    selected = profile(data.identifier)
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in _directories(selected):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.uid = info.gid = 65532
                info.mode = 0o500
                info.mtime = 0
                archive.addfile(info)
            for binding, body in zip(selected.files, data.bodies, strict=True):
                info = tarfile.TarInfo("work/" + binding.path)
                info.uid = info.gid = 65532
                info.mode = 0o400
                info.mtime = 0
                info.size = len(body)
                with io.BytesIO(body) as content:
                    archive.addfile(info, content)
        return buffer.getvalue()


def _header(block: bytes) -> tarfile.TarInfo:
    """Parse one header only; never let TarFile process extension payloads."""
    require(len(block) == BLOCK, "archive_truncated")
    require(block[156:157] in (tarfile.DIRTYPE, tarfile.REGTYPE), "archive_type")
    try:
        info = tarfile.TarInfo.frombuf(block, "ascii", "strict")
    except (tarfile.HeaderError, UnicodeError, ValueError) as error:
        raise InputError("archive_header") from error
    require(0 <= info.size <= MAX_FILE, "archive_length")
    require(not info.linkname and not info.uname and not info.gname
            and info.devmajor == 0 and info.devminor == 0, "archive_metadata")
    require(info.uid == 65532 and info.gid == 65532 and info.mtime == 0, "archive_ownership")
    require(info.mode == (0o500 if info.isdir() else 0o400), "archive_mode")
    require(block == info.tobuf(tarfile.USTAR_FORMAT, "ascii", "strict"), "archive_noncanonical")
    return info


def inspect_archive(data: InputCopy, raw: bytes) -> str:
    """Inspect bounded readback bytes independently, without extraction or physical-state claims."""
    selected = profile(data.identifier)
    require(type(raw) is bytes and len(raw) <= sum(row.size for row in selected.files) + MAX_METADATA,
            "archive_bound")
    directories = _directories(selected)
    names = (*directories, *("work/" + row.path for row in selected.files))
    files = {"work/" + binding.path: (binding, body)
             for binding, body in zip(selected.files, data.bodies, strict=True)}
    seen: set[str] = set()
    folded: set[str] = set()
    position = 0
    for expected in names:
        block = raw[position:position + BLOCK]
        require(block != bytes(BLOCK), "archive_missing")
        info = _header(block)
        name = info.name
        require("\\" not in name and not name.startswith("/")
                and all(part not in ("", ".", "..") for part in name.split("/")), "archive_path")
        require(name not in seen, "archive_duplicate")
        require(name.casefold() not in folded, "archive_case_collision")
        require(name == expected, "archive_membership")
        seen.add(name)
        folded.add(name.casefold())
        directory = name in directories
        require(info.isdir() == directory, "archive_member_type")
        size = 0 if directory else files[name][0].size
        require(info.size == size, "archive_length")
        start = position + BLOCK
        end = start + size
        position = end + (-size % BLOCK)
        require(position <= len(raw), "archive_truncated")
        require(not any(raw[end:position]), "archive_padding")
        if not directory:
            binding, body = files[name]
            content = raw[start:end]
            require(hashlib.sha256(content).hexdigest() == binding.sha256 and content == body, "archive_content")
    framed = ((position + 2 * BLOCK + RECORD - 1) // RECORD) * RECORD
    require(len(raw) == framed and not any(raw[position:]), "archive_trailing")
    return hashlib.sha256(data.manifest()).hexdigest()
