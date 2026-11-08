# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Run: pinned Python3.12 -I -B this file; only inert fixture bytes and bounded USTAR DATA."""
from __future__ import annotations

import copy
import hashlib
import sys
import tarfile
import unittest
from pathlib import Path
from typing import Final, Literal

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "workers/runtime-build"), str(ROOT / "workers/runtime-controller"),
               str(ROOT / "tests/native")]
from input import InputCopy, InputError
from preparation_material_archive import build_archive, inspect_archive, output_bound, transfer
from preparation_material_data import MaterialFrame, MaterialKind, Operation
from runtime_build_input_test import control, entries, fixture


def material_entries(identifier: str, kind: MaterialKind | Literal["seed"]) -> list[tuple[tarfile.TarInfo, bytes]]:
    source = entries(identifier) if kind in ("work", "seed") else []
    extras = ("work/target",) if kind == "work" else (
        ("cache", "output", "work/target") if kind == "seed" else (kind,))
    for name in extras:
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.uid = info.gid = 65532
        info.mode = 0o500 if name == "work/target" else 0o700
        source.append((info, b""))
    return sorted((row for row in source if row[0].isdir()), key=lambda row: (
        row[0].name.count("/"), row[0].name)) + [row for row in source if row[0].isreg()]


def input_copy(identifier: str = "f01") -> InputCopy:
    return InputCopy(identifier, tuple(body for _, body in fixture(identifier)))


class MaterialArchiveTests(unittest.TestCase):
    def test_fixed_payload_selection_keeps_archive_bytes_out_of_log_bounds(self) -> None:
        data = input_copy()
        rows: tuple[tuple[Operation, str | None, int, bool], ...] = (
            ("seed", "cd" * 32, 1048576, False),
            ("read-work", "cd" * 32, sum(len(body) for _, body in fixture("f01")) + 16777216, True),
            ("read-cache", "cd" * 32, 16777216, True), ("read-output", "cd" * 32, 16777216, True),
            ("carrier-create", None, 1048576, False), ("volume-inspect-work", None, 1048576, False),
        )
        for selected, container, bound, archive in rows:
            payload = transfer(MaterialFrame("ab" * 16, 7, selected, container), data)
            expected = control(material_entries("f01", "seed")) if selected == "seed" else b""
            with self.subTest(operation=selected):
                self.assertEqual((payload.body, payload.bound, payload.archive), (expected, bound, archive))

    def test_seed_and_three_separate_readbacks_match_independent_inert_ustar(self) -> None:
        kinds: tuple[MaterialKind, ...] = ("work", "cache", "output")
        for identifier in ("f01", "f02", "f03", "f04"):
            data = input_copy(identifier)
            with self.subTest(profile=identifier):
                self.assertEqual(build_archive(data), control(material_entries(identifier, "seed")))
                for kind in kinds:
                    raw = control(material_entries(identifier, kind))
                    self.assertEqual(inspect_archive(data, kind, raw), hashlib.sha256(raw).hexdigest())
                self.assertEqual(output_bound(data, "work"), sum(len(body) for _, body in fixture(identifier))
                                 + 16 * 1024 * 1024)
                self.assertEqual(output_bound(data, "cache"), 16 * 1024 * 1024)
                self.assertEqual(output_bound(data, "output"), 16 * 1024 * 1024)

    def test_modes_ownership_and_nonempty_target_cache_output_are_refused(self) -> None:
        data = input_copy()
        cases: tuple[tuple[MaterialKind, int, str, int, str], ...] = (
            ("cache", 0, "mode", 0o500, "material_archive_mode"),
            ("output", 0, "mode", 0o500, "material_archive_mode"),
            ("work", -1, "mode", 0o600, "material_archive_mode"),
            ("work", 0, "mode", 0o700, "material_archive_mode"),
            ("work", -1, "uid", 0, "material_archive_ownership"),
            ("work", -1, "gid", 0, "material_archive_ownership"),
            ("work", -1, "mtime", 1, "material_archive_ownership"),
        )
        for kind, index, field, value, reason in cases:
            members = material_entries("f01", kind)
            setattr(members[index][0], field, value)
            with self.subTest(kind=kind, field=field), self.assertRaisesRegex(InputError, "^" + reason + "$"):
                inspect_archive(data, kind, control(members))
        for kind, path in (("work", "work/target/extra"), ("cache", "cache/extra"), ("output", "output/extra")):
            members = material_entries("f01", kind)
            info = tarfile.TarInfo(path)
            info.uid = info.gid = 65532
            info.mode = 0o400
            members.append((info, b""))
            with self.subTest(path=path), self.assertRaisesRegex(InputError, "^material_archive_trailing$"):
                inspect_archive(data, kind, control(members))

    def test_ustar_refuses_links_extensions_paths_duplicates_and_noncanonical_metadata(self) -> None:
        data = input_copy()
        original = material_entries("f01", "work")
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE,
                     tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE):
            members = copy.deepcopy(original)
            members[-1][0].type = kind
            with self.subTest(type=kind), self.assertRaisesRegex(InputError, "^material_archive_type$"):
                inspect_archive(data, "work", control(members))
        for name, reason in (
                ("/work/file", "path"), ("../work/file", "path"), ("work/../file", "path"),
                ("work\\file", "path"), ("work", "duplicate"), ("WORK", "case_collision"),
                ("work/compose.json", "membership")):
            members = copy.deepcopy(original)
            members[1][0].name = name
            with self.subTest(name=name), self.assertRaisesRegex(InputError, "^material_archive_" + reason + "$"):
                inspect_archive(data, "work", control(members))
        for field, value in (("uname", "root"), ("gname", "root"), ("linkname", "work/other"),
                             ("devmajor", 1), ("devminor", 1)):
            members = copy.deepcopy(original)
            setattr(members[-1][0], field, value)
            with self.subTest(field=field), self.assertRaisesRegex(InputError, "^material_archive_metadata$"):
                inspect_archive(data, "work", control(members))

    def test_contents_header_padding_termination_member_types_and_bounds_are_checked(self) -> None:
        data = input_copy()
        members = material_entries("f01", "work")
        raw = control(members)
        file_index = len(members) - 5
        start = 512 * file_index + 512
        changed = bytearray(raw)
        changed[start] ^= 1
        padding = bytearray(raw)
        padding[start + len(members[file_index][1])] = 1
        checksum = bytearray(raw)
        checksum[0] ^= 1
        noncanonical = bytearray(raw)
        noncanonical[500] = 1
        noncanonical[148:156] = b"        "
        noncanonical[148:156] = f"{sum(noncanonical[:512]):06o}\0 ".encode()
        wrong_type = copy.deepcopy(members)
        wrong_type[0][0].type = tarfile.REGTYPE
        cases = (
            (bytes(changed), "content"), (bytes(padding), "padding"), (bytes(checksum), "header"),
            (bytes(noncanonical), "noncanonical"), (control(members[:-1]), "missing"),
            (raw + bytes(10240), "trailing"), (raw + raw, "trailing"), (raw[:-1], "trailing"),
            (raw[:511], "truncated"), (raw[:start + 1], "truncated"), (control(wrong_type), "member_type"),
            (b"x" * (sum(len(body) for _, body in fixture("f01")) + 16 * 1024 * 1024 + 1), "bound"),
        )
        for malformed, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(InputError, "^material_archive_" + reason + "$"):
                inspect_archive(data, "work", malformed)
        for kind in ("cache", "output"):
            with self.subTest(kind=kind), self.assertRaisesRegex(InputError, "^material_archive_bound$"):
                inspect_archive(data, kind, b"x" * (16 * 1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
