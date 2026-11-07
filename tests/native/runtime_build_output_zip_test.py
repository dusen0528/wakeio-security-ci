# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# How to run: python3.12 tests/native/runtime_build_output_zip_test.py
"""Inert ZIP32 controls over real local FDs; no artifact is extracted or executed."""
from __future__ import annotations

import io
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from output_files import OutputError
from output_zip import chunks, members


@dataclass(frozen=True, slots=True)
class Entry:
    """Independent ZIP32 wire fields; overrides isolate malformed properties."""
    name: bytes = b"a"
    body: bytes = b"inert"
    method: int = 0
    flags: int = 0
    extra: bytes = b""
    mode: int = 0o100644
    size: int | None = None
    crc: int | None = None
    encoded: bytes | None = None
    signed: bool = True


def archive(entries: tuple[Entry, ...]) -> bytes:
    local = bytearray()
    central = bytearray()
    for entry in entries:
        encoded = entry.encoded
        if encoded is None:
            compressor = zlib.compressobj(wbits=-15)
            encoded = (compressor.compress(entry.body) + compressor.flush()
                       if entry.method == 8 else entry.body)
        size = len(entry.body) if entry.size is None else entry.size
        crc = zlib.crc32(entry.body) if entry.crc is None else entry.crc
        values = (crc, len(encoded), size)
        name_size, extra_size = len(entry.name), len(entry.extra)
        central.extend(struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 788, 20, entry.flags, entry.method,
                                   0, 0, *values, name_size, extra_size, 0, 0, 0,
                                   entry.mode << 16, len(local)))
        central.extend(entry.name + entry.extra)
        local.extend(struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, entry.flags, entry.method, 0, 0,
                                 *((0, 0, 0) if entry.flags & 8 else values), name_size, extra_size))
        local.extend(entry.name + entry.extra + encoded)
        if entry.flags & 8:
            local.extend((b"PK\x07\x08" if entry.signed else b"") + struct.pack("<3I", *values))
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, len(entries), len(entries),
                      len(central), len(local), 0)
    return bytes(local + central) + end


def altered(raw: bytes, changes: tuple[tuple[int, bytes], ...]) -> bytes:
    result = bytearray(raw)
    for offset, value in changes:
        result[offset:offset + len(value)] = value
    return bytes(result)


@contextmanager
def descriptor(raw: bytes) -> Iterator[int]:
    with tempfile.TemporaryDirectory(prefix="output-zip-") as temporary:
        path = Path(temporary) / "inert.zip"
        path.write_bytes(raw)
        with path.open("rb") as stream:
            yield stream.fileno()


class ZipTests(unittest.TestCase):
    def test_stdlib_producers_roundtrip_stored_and_large_compressible_deflate(self) -> None:
        body = b"inert-data\n" * 20000
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(method=method):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w", compression=method) as producer:
                    producer.writestr("dir/", b"")
                    producer.writestr("dir/data", body)
                with descriptor(buffer.getvalue()) as fd:
                    rows = members(fd)
                    self.assertEqual([(row.path, row.directory) for row in rows],
                                     [("dir", True), ("dir/data", False)])
                    self.assertEqual(b"".join(chunks(fd, rows[0])), b"")
                    self.assertEqual(b"".join(chunks(fd, rows[1])), body)

    def test_zip32_descriptors_and_harmless_extras_preserve_exact_bytes(self) -> None:
        for method in (0, 8):
            for signed in (False, True):
                with self.subTest(method=method, signed=signed):
                    entry = Entry(name="é".encode(), method=method, flags=0x808, signed=signed,
                                  extra=b"\xfe\xca\x00\x00\x55\x54\x05\x00\x01\x00\x00\x00\x00")
                    with descriptor(archive((entry,))) as fd:
                        self.assertEqual(b"".join(chunks(fd, members(fd)[0])), entry.body)

    def test_actual_expansion_is_charged_before_any_oversized_yield(self) -> None:
        body = b"A" * 200000
        for declared in (1, 65536, 65537):
            with self.subTest(declared=declared), descriptor(archive((
                Entry(body=body, method=8, size=declared, crc=zlib.crc32(body[:declared])),
            ))) as fd:
                row = members(fd)[0]
                yielded = 0
                with self.assertRaises(OutputError) as failure:
                    for block in chunks(fd, row):
                        yielded += len(block)
                        self.assertLessEqual(yielded, declared)
                self.assertEqual(failure.exception.reason, "zip_actual_expansion")

    def test_stream_crc_eof_and_exact_compressed_consumption(self) -> None:
        compressor = zlib.compressobj(wbits=-15)
        encoded = compressor.compress(b"inert") + compressor.flush()
        cases = (
            (Entry(crc=0), "zip_content"),
            (Entry(method=8, crc=0), "zip_content"),
            (Entry(method=8, size=6), "zip_content"),
            (Entry(method=8, encoded=encoded[:-1]), "zip_deflate_end"),
            (Entry(method=8, encoded=encoded + b"junk"), "zip_deflate_trailing"),
            (Entry(method=8, encoded=encoded + encoded), "zip_deflate_trailing"),
            (Entry(method=8, encoded=b"\x07"), "zip_deflate"),
        )
        for entry, reason in cases:
            with self.subTest(entry=entry), descriptor(archive((entry,))) as fd:
                row = members(fd)[0]
                with self.assertRaises(OutputError) as failure:
                    tuple(chunks(fd, row))
                self.assertEqual(failure.exception.reason, reason)

    def test_unsafe_names_types_flags_and_extra_fields_refuse_at_preflight(self) -> None:
        cases = (
            *(Entry(name=name) for name in (b"/a", b"../a", b"a/../b", b"a//b", b"a\\b",
                                           b"a\x00b", b"a\nb", b"", b"a" * 256,
                                           b"/".join([b"a"] * 65), b"a" * 4097)),
            Entry(name=b"\xff", flags=0x800), Entry(name="é".encode()),
            *(Entry(mode=mode) for mode in (0o120777, 0o010644, 0o020644, 0o104644)),
            Entry(name=b"a/", mode=0o100644, body=b""),
            Entry(name=b"a/", mode=0o040755),
            *(Entry(flags=flags) for flags in (1, 0x10, 0x40, 0x2000, 2)),
            Entry(method=99), Entry(size=4),
            *(Entry(extra=extra) for extra in (b"x", b"\xfe\xca\x01\x00x",
                b"\xfe\xca\x00\x00" * 2, b"\x01\x00\x00\x00", b"\x75\x70\x00\x00",
                b"\x55\x54\x05\x00\x03" + bytes(4), b"x" * 4097)),
        )
        for entry in cases:
            with self.subTest(entry=entry), descriptor(archive((entry,))) as fd:
                with self.assertRaises(OutputError):
                    members(fd)

    def test_duplicate_and_hierarchical_collisions_refuse_without_directory_records(self) -> None:
        with descriptor(archive((Entry(name=b"a/one"), Entry(name=b"a/two")))) as fd:
            self.assertEqual([row.path for row in members(fd)], ["a/one", "a/two"])
        for names in ((b"a", b"a"), (b"A", b"a"), (b"A/one", b"a/two"), (b"a", b"a/b"),
                      (b"a/b", b"a"), (b"A/one", b"a/")):
            entries = tuple(Entry(name=name, body=b"" if name.endswith(b"/") else b"inert",
                                  mode=0o040755 if name.endswith(b"/") else 0o100644) for name in names)
            with self.subTest(names=names), descriptor(archive(entries)) as fd:
                with self.assertRaises(OutputError):
                    members(fd)

    def test_local_central_and_end_record_disagreements_refuse(self) -> None:
        raw = archive((Entry(),))
        central = raw.index(b"PK\x01\x02")
        end = len(raw) - 22
        changes = (
            (0, b"BAD!"), (4, b"\x15\x00"), (6, b"\x00\x08"), (8, b"\x08\x00"),
            (10, b"\x01\x00"), (14, bytes(4)), (18, b"\x04\x00\x00\x00"),
            (22, b"\x04\x00\x00\x00"), (26, b"\x02\x00"), (30, b"b"),
            (central, b"BAD!"), (central + 6, b"\x2d\x00"),
            (central + 32, b"\x01\x00"), (central + 34, b"\x01\x00"),
            (central + 20, struct.pack("<I", 64 * 1024 * 1024 + 1)),
            (central + 38, b"\x10"), (central + 42, b"\x01\x00\x00\x00"),
            (central + 42, b"\xff\xff\xff\x7f"),
            (end, b"BAD!"), (end + 4, b"\x01\x00"), (end + 6, b"\x01\x00"),
            (end + 8, b"\x02\x00"), (end + 12, bytes(4)), (end + 16, bytes(4)),
            (end + 20, b"\x01\x00"),
        )
        for change in changes:
            with self.subTest(change=change), descriptor(altered(raw, (change,))) as fd:
                with self.assertRaises(OutputError):
                    members(fd)

    def test_descriptors_must_agree_with_central_crc_and_both_sizes(self) -> None:
        for signed in (False, True):
            raw = archive((Entry(method=8, flags=8, signed=signed),))
            central = raw.index(b"PK\x01\x02")
            for offset in (14, central - 12, central - 8, central - 4):
                with self.subTest(signed=signed, offset=offset):
                    with descriptor(altered(raw, ((offset, b"\xff"),))) as fd:
                        with self.assertRaises(OutputError):
                            members(fd)

    def test_truncation_prefix_gaps_overlap_and_trailing_structures_refuse(self) -> None:
        raw = archive((Entry(),))
        central = raw.index(b"PK\x01\x02")
        inner = archive((Entry(name=b"b"),))
        pair = archive((Entry(body=inner[:inner.index(b"PK\x01\x02")]), Entry(name=b"b")))
        second = pair.index(b"PK\x01\x02") + 47
        gap = raw[:central] + b"x" + raw[central:]
        gap = altered(gap, ((len(gap) - 6, struct.pack("<I", central + 1)),))
        cases = (b"", raw[:21], raw[:-1], raw + b"x", b"x" + raw, gap,
                 raw[:33] + raw[34:],
                 altered(pair, ((second + 42, struct.pack("<I", 31)),)))
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), descriptor(candidate) as fd:
                with self.assertRaises(OutputError):
                    members(fd)

    def test_record_metadata_declared_expansion_and_archive_size_bounds(self) -> None:
        raw = archive((Entry(body=b"", method=8, size=208 * 1024 * 1024),))
        with descriptor(raw) as fd:
            self.assertEqual(members(fd)[0].size, 208 * 1024 * 1024)
        cases = (
            altered(raw, ((len(raw) - 14, struct.pack("<HH", 32769, 32769)),)),
            altered(raw, ((len(raw) - 10, struct.pack("<I", 16 * 1024 * 1024 + 1)),)),
            archive((Entry(body=b"", method=8, size=208 * 1024 * 1024 + 1),)),
            archive((Entry(body=b"", method=8, size=208 * 1024 * 1024), Entry(name=b"b", body=b"x"))),
        )
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), descriptor(candidate) as fd:
                with self.assertRaises(OutputError):
                    members(fd)
        names = tuple(Entry(name=(("a" * 250 + "/") * 16 + str(i)).encode(), body=b"")
                      for i in range(2100))
        with descriptor(archive(names)) as fd:
            with self.assertRaises(OutputError) as failure:
                members(fd)
            self.assertEqual(failure.exception.reason, "zip_expansion_bound")
        with tempfile.TemporaryFile() as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
            with self.assertRaises(OutputError) as failure:
                members(stream.fileno())
            self.assertEqual(failure.exception.reason, "zip_jar_bound")


if __name__ == "__main__":
    unittest.main(verbosity=2)
