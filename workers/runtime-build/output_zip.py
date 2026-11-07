"""Bounded ZIP32 framing and actual streamed expansion; no extraction or artifact execution."""
import os
import stat
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from typing import Final, assert_never

from output_files import BLOCK, MAX_METADATA, OutputError, relative_path, require

MAX_JAR: Final = 64 * 1024 * 1024
MAX_EXPANDED: Final = 208 * 1024 * 1024
MAX_RECORDS: Final = 32768


class Compression(IntEnum):
    STORED = 0
    DEFLATED = 8


def _number(raw: bytes, offset: int, width: int) -> int:
    return int.from_bytes(raw[offset:offset + width], "little")


def _read(fd: int, offset: int, size: int) -> bytes:
    require(offset >= 0 and 0 <= size <= MAX_METADATA, "zip_read_bound")
    raw = os.pread(fd, size, offset)
    require(len(raw) == size, "zip_truncated")
    return raw


def _extras(raw: bytes) -> None:
    position = 0
    seen: set[int] = set()
    while position < len(raw):
        require(position + 4 <= len(raw), "zip_extra")
        kind = _number(raw, position, 2)
        length = _number(raw, position + 2, 2)
        position += 4
        require(kind not in seen and position + length <= len(raw), "zip_extra")
        seen.add(kind)
        payload = raw[position:position + length]
        require((kind == 0xCAFE and length == 0)
                or (kind == 0x5455 and length in (5, 9, 13) and payload[0] in (1, 3, 7)
                    and length == 1 + 4 * payload[0].bit_count()), "zip_extra")
        position += length


@dataclass(frozen=True, slots=True)
class Member:
    path: str
    size: int
    compressed: int
    crc: int
    method: Compression
    flags: int
    local: int
    data: int
    end: int
    directory: bool


def _local(fd: int, central: bytes, name: bytes) -> tuple[int, int]:
    offset = _number(central, 42, 4)
    local = _read(fd, offset, 30)
    require(local[:4] == b"PK\x03\x04" and local[4:14] == central[6:16], "zip_local")
    name_size = _number(local, 26, 2)
    extra_size = _number(local, 28, 2)
    require(name_size == len(name) and extra_size <= 4096, "zip_local")
    require(_read(fd, offset + 30, name_size) == name, "zip_local")
    _extras(_read(fd, offset + 30 + name_size, extra_size))
    data = offset + 30 + name_size + extra_size
    compressed = _number(central, 20, 4)
    end = data + compressed
    expected = central[16:28]
    if _number(central, 8, 2) & 8:
        require(local[14:26] in (bytes(12), expected), "zip_descriptor")
        descriptor = _read(fd, end, 12)
        descriptor_size = 12
        if descriptor != expected:
            require(descriptor[:4] == b"PK\x07\x08"
                    and _read(fd, end + 4, 12) == expected, "zip_descriptor")
            descriptor_size = 16
        end += descriptor_size
    else:
        require(local[14:26] == expected, "zip_local")
    return data, end


def _member(fd: int, offset: int) -> tuple[Member, int, int]:
    central = _read(fd, offset, 46)
    require(central[:4] == b"PK\x01\x02" and _number(central, 6, 2) <= 20, "zip_central")
    flags = _number(central, 8, 2)
    try:
        method = Compression(_number(central, 10, 2))
    except ValueError as error:
        raise OutputError("zip_encoding") from error
    require(flags & ~0x080E == 0
            and (method != Compression.STORED or flags & 6 == 0), "zip_encoding")
    name_size = _number(central, 28, 2)
    extra_size = _number(central, 30, 2)
    require(0 < name_size <= 4096 and extra_size <= 4096
            and _number(central, 32, 2) == 0 and _number(central, 34, 2) == 0, "zip_metadata")
    name = _read(fd, offset + 46, name_size)
    require(bool(flags & 0x800) or name.isascii(), "zip_encoding")
    try:
        decoded = name.decode("utf-8", "strict")
    except UnicodeError as error:
        raise OutputError("zip_encoding") from error
    directory = decoded.endswith("/")
    path = relative_path(decoded[:-1] if directory else decoded)
    mode = _number(central, 38, 4) >> 16
    kind = stat.S_IFMT(mode)
    require(kind in (0, stat.S_IFDIR if directory else stat.S_IFREG)
            and mode & 0o7000 == 0 and (directory or _number(central, 38, 4) & 0x10 == 0), "zip_type")
    _extras(_read(fd, offset + 46 + name_size, extra_size))
    size = _number(central, 24, 4)
    compressed = _number(central, 20, 4)
    require(size <= MAX_EXPANDED and compressed <= MAX_JAR
            and (method != Compression.STORED or size == compressed) and (not directory or size == 0), "zip_size")
    data, end = _local(fd, central, name)
    return (Member(path, size, compressed, _number(central, 16, 4), method, flags,
                   _number(central, 42, 4), data, end, directory),
            offset + 46 + name_size + extra_size, 30 + name_size + extra_size)


def _paths(member: Member, hierarchy: dict[str, tuple[str, bool]], metadata: int) -> int:
    parts = member.path.split("/")
    for depth in range(1, len(parts) + 1):
        prefix = "/".join(parts[:depth])
        directory = depth < len(parts) or member.directory
        key = prefix.casefold()
        previous = hierarchy.get(key)
        require(previous is None or previous == (prefix, directory), "zip_hierarchy")
        if previous is None:
            metadata += len(prefix.encode("utf-8")) + 128
            require(metadata <= MAX_METADATA, "zip_expansion_bound")
            hierarchy[key] = (prefix, directory)
    return metadata


def members(fd: int) -> tuple[Member, ...]:
    """Preflight all framing and bounds before a payload decoder can allocate or yield."""
    size = os.fstat(fd).st_size
    require(22 <= size <= MAX_JAR, "zip_jar_bound")
    end = _read(fd, size - 22, 22)
    require(end[:4] == b"PK\x05\x06" and end[4:8] == bytes(4) and end[20:22] == bytes(2),
            "zip_end")
    count = _number(end, 10, 2)
    require(count <= MAX_RECORDS and _number(end, 8, 2) == count, "zip_count")
    central_size = _number(end, 12, 4)
    central = _number(end, 16, 4)
    require(central_size <= MAX_METADATA and central + central_size == size - 22
            and central_size >= count * 46, "zip_central_bound")
    position = central
    metadata = central_size
    expanded = 0
    result: list[Member] = []
    folded: set[str] = set()
    hierarchy: dict[str, tuple[str, bool]] = {}
    for _ in range(count):
        require(position + 46 <= central + central_size, "zip_central")
        member, position, local_metadata = _member(fd, position)
        require(position <= central + central_size and member.end <= central, "zip_range")
        require(member.path.casefold() not in folded, "zip_duplicate")
        folded.add(member.path.casefold())
        metadata += local_metadata
        expanded += member.size
        require(metadata <= MAX_METADATA and expanded <= MAX_EXPANDED, "zip_expansion_bound")
        metadata = _paths(member, hierarchy, metadata)
        result.append(member)
    require(position == central + central_size, "zip_central")
    cursor = 0
    for member in sorted(result, key=lambda row: row.local):
        require(member.local == cursor and member.data <= member.end, "zip_range")
        cursor = member.end
    require(cursor == central, "zip_range")
    return tuple(result)


def chunks(fd: int, member: Member) -> Iterator[bytes]:
    """Charge actual expansion before yielding; declared ZIP size never truncates a stream."""
    match member.method:
        case Compression.STORED:
            decoder = None
        case Compression.DEFLATED:
            decoder = zlib.decompressobj(-15)
        case unreachable:
            assert_never(unreachable)
    position = member.data
    remaining = member.compressed
    expanded = 0
    crc = 0
    while remaining:
        encoded = _read(fd, position, min(BLOCK, remaining))
        position += len(encoded)
        remaining -= len(encoded)
        pending = encoded
        drain = False
        while pending or drain:
            before = len(pending)
            try:
                decoded = pending if decoder is None else decoder.decompress(pending, BLOCK)
            except zlib.error as error:
                raise OutputError("zip_deflate") from error
            pending = b"" if decoder is None else decoder.unconsumed_tail
            drain = decoder is not None and len(decoded) == BLOCK and not decoder.eof
            require(bool(decoded) or len(pending) < before or not pending, "zip_deflate_progress")
            expanded += len(decoded)
            require(expanded <= member.size, "zip_actual_expansion")
            crc = zlib.crc32(decoded, crc)
            if decoded:
                yield decoded
            require(decoder is None or not decoder.unused_data, "zip_deflate_trailing")
    require(decoder is None or decoder.eof, "zip_deflate_end")
    require(expanded == member.size and crc == member.crc, "zip_content")
