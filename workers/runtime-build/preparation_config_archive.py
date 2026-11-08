# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B tests/native/runtime_build_preparation_config_archive_test.py
"""Closed C3 USTAR DATA, never extracted. Readback retains actual bytes and metadata."""
from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from typing import Final

from preparation_config_data import ConfigError, GLOBAL_SETTINGS, USER_SETTINGS, require

BOUND: Final = 131072
BLOCK: Final = tarfile.BLOCKSIZE
RECORD: Final = tarfile.RECORDSIZE
SETTINGS: Final = (("user-settings.xml", USER_SETTINGS), ("global-settings.xml", GLOBAL_SETTINGS))


@dataclass(frozen=True, slots=True)
class HelperInputs:
    producer: bytes
    verifier: bytes
    certificate: bytes

    def __post_init__(self) -> None:
        for value, bound in ((self.producer, 32768), (self.verifier, 32768), (self.certificate, 16384)):
            require(type(value) is bytes and 1 <= len(value) <= bound, "config_input_bound")


@dataclass(frozen=True, slots=True)
class Entry:
    name: str
    body: bytes | None
    mode: int
    mtime: int = 0

    @property
    def sha256(self) -> str | None:
        return None if self.body is None else hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True, slots=True)
class ArchiveObservation:
    raw: bytes
    entries: tuple[Entry, ...]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


def _settings(root: str, final: bool) -> tuple[Entry, ...]:
    return (Entry(root, None, 0o500 if final else 0o700),
            *(Entry(root + "/" + name, body, 0o400) for name, body in SETTINGS))


def _helpers(inputs: HelperInputs, root: str) -> tuple[Entry, ...]:
    return (Entry(root, None, 0o500), Entry(root + "/producer", None, 0o500),
            Entry(root + "/verifier", None, 0o500),
            Entry(root + "/producer/PrepConfigProduce.java", inputs.producer, 0o400),
            Entry(root + "/verifier/PrepConfigVerify.java", inputs.verifier, 0o400),
            Entry(root + "/mirror.crt", inputs.certificate, 0o400))


def _encode(entries: tuple[Entry, ...]) -> bytes:
    """Use stdlib USTAR encoding, not the independent raw-block acceptance path."""
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for entry in entries:
                info = tarfile.TarInfo(entry.name)
                info.uid = info.gid = 65532
                info.mode, info.mtime = entry.mode, entry.mtime
                if entry.body is None:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                else:
                    info.size = len(entry.body)
                    with io.BytesIO(entry.body) as content:
                        archive.addfile(info, content)
        result = buffer.getvalue()
    require(len(result) <= BOUND, "config_archive_bound")
    return result


def seed_archive() -> bytes:
    """The root '.' addresses the fixed cp destination; it is not an accepted readback alias."""
    return _encode(_settings(".", False))


def helpers_archive(inputs: HelperInputs) -> bytes:
    return _encode(_helpers(inputs, "."))


def _header(block: bytes) -> tarfile.TarInfo:
    require(len(block) == BLOCK, "config_archive_truncated")
    require(block[156:157] in (tarfile.DIRTYPE, tarfile.REGTYPE), "config_archive_type")
    try:
        info = tarfile.TarInfo.frombuf(block, "ascii", "strict")
    except (tarfile.HeaderError, UnicodeError, ValueError) as error:
        raise ConfigError("config_archive_header") from error
    require(0 <= info.size <= 65536, "config_archive_length")
    require(info.uid == info.gid == 65532 and type(info.mtime) is int
            and 0 <= info.mtime <= 8589934591, "config_archive_ownership")
    require(not info.linkname and not info.uname and not info.gname
            and info.devmajor == info.devminor == 0, "config_archive_metadata")
    require(block == info.tobuf(tarfile.USTAR_FORMAT, "ascii", "strict"), "config_archive_noncanonical")
    return info


def _inspect(raw: bytes, expected: tuple[Entry, ...], store: bool = False) -> ArchiveObservation:
    require(type(raw) is bytes and 0 < len(raw) <= BOUND, "config_archive_bound")
    position = 0
    accepted: list[Entry] = []
    for entry in expected:
        block = raw[position:position + BLOCK]
        require(block != bytes(BLOCK), "config_archive_missing")
        info = _header(block)
        require(info.name == entry.name, "config_archive_membership")
        is_store = store and entry.name == "build-config/mirror-trust.p12"
        require(info.isdir() == (entry.body is None), "config_archive_member_type")
        require(info.mode == entry.mode, "config_archive_mode")
        if is_store:
            require(1 <= info.size <= 65536, "config_archive_length")
        else:
            require(info.size == (0 if entry.body is None else len(entry.body)), "config_archive_length")
            if not (store and entry.name == "build-config"):
                require(info.mtime == entry.mtime, "config_archive_mtime")
        start = position + BLOCK
        end = start + info.size
        position = end + (-info.size % BLOCK)
        require(position <= len(raw), "config_archive_truncated")
        require(not any(raw[end:position]), "config_archive_padding")
        content = None if entry.body is None else raw[start:end]
        if not is_store:
            require(content == entry.body, "config_archive_content")
        accepted.append(Entry(info.name, content, info.mode, info.mtime))
    framed = ((position + 2 * BLOCK + RECORD - 1) // RECORD) * RECORD
    require(len(raw) == framed and not any(raw[position:]), "config_archive_trailing")
    return ArchiveObservation(raw, tuple(accepted))


def inspect_seed(raw: bytes) -> ArchiveObservation:
    return _inspect(raw, _settings("build-config", False))


def inspect_config(raw: bytes) -> ArchiveObservation:
    """Store bytes are opaque here; semantic PKCS12 acceptance belongs to the separate JVM."""
    entries = (*_settings("build-config", True), Entry("build-config/mirror-trust.p12", b"", 0o400))
    return _inspect(raw, entries, store=True)


def inspect_helpers(inputs: HelperInputs, raw: bytes) -> ArchiveObservation:
    return _inspect(raw, _helpers(inputs, "config-input"))


def inspect_helper(inputs: HelperInputs, role: str, raw: bytes) -> ArchiveObservation:
    """Independent cp output for exactly one tool directory, before tool release."""
    require(role in ("producer", "verifier"), "config_helper_role")
    name = "PrepConfigProduce.java" if role == "producer" else "PrepConfigVerify.java"
    body = inputs.producer if role == "producer" else inputs.verifier
    return _inspect(raw, (Entry(role, None, 0o500), Entry(role + "/" + name, body, 0o400)))


def inspect_certificate(inputs: HelperInputs, raw: bytes) -> ArchiveObservation:
    return _inspect(raw, (Entry("mirror.crt", inputs.certificate, 0o400),))
