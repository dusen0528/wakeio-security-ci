# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Run: granted Python -I -B tests/native/runtime_build_input_test.py (inert fixture bytes only)."""
import copy
import hashlib
import io
import json
import sys
import tarfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from input import MAX_CHUNK, Chunk, InputCopy, InputData, InputError, Receipt, profile
from input_archive import MAX_METADATA, build_archive, inspect_archive

ROOTS = ("spring-sqli/vulnerable", "spring-sqli/fixed", "spring-sqli-jdbc/vulnerable", "spring-sqli-jdbc/fixed")


def fixture(identifier: str) -> tuple[tuple[str, bytes], ...]:
    number = int(identifier[1:]) - 1
    package = "fixtures" if number < 2 else "jdbcfixtures"
    paths = (".dockerignore", "Dockerfile", "pom.xml",
             f"src/main/java/io/wakeio/{package}/Application.java", "src/main/resources/application.properties")
    root = ROOT / "examples/runtime" / ROOTS[number]
    return tuple((path, (root / path).read_bytes()) for path in paths)


def ingest(identifier: str) -> tuple[InputData, list[Receipt]]:
    pending = InputData(identifier)
    rows: list[Receipt] = []
    for index, (_, body) in enumerate(fixture(identifier)):
        for offset in range(0, len(body), 17):
            pending.append(Chunk(index, offset, body[offset:offset + 17]))
        rows.append({"file": index, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
    return pending, rows


def entries(identifier: str) -> list[tuple[tarfile.TarInfo, bytes]]:
    files = fixture(identifier)
    directories = {str(parent) for path, _ in files for parent in PurePosixPath("work", path).parents}
    directories.remove(".")
    result: list[tuple[tarfile.TarInfo, bytes]] = []
    for name in sorted(directories, key=lambda path: (path.count("/"), path)):
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.uid = info.gid = 65532
        info.mode = 0o500
        result.append((info, b""))
    for path, body in files:
        info = tarfile.TarInfo("work/" + path)
        info.uid = info.gid = 65532
        info.mode = 0o400
        info.size = len(body)
        result.append((info, body))
    return result


def control(members: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    raw = bytearray()
    for info, body in members:
        header = bytearray(info.tobuf(tarfile.USTAR_FORMAT, "ascii", "strict"))
        if info.devmajor or info.devminor:
            header[329:337] = tarfile.itn(info.devmajor, 8, tarfile.USTAR_FORMAT)
            header[337:345] = tarfile.itn(info.devminor, 8, tarfile.USTAR_FORMAT)
            header[148:156] = b"        "
            header[148:156] = f"{sum(header):06o}\0 ".encode()
        raw.extend(header)
        raw.extend(body)
        raw.extend(bytes(-len(body) % 512))
    raw.extend(bytes(1024))
    raw.extend(bytes(-len(raw) % 10240))
    return bytes(raw)


class InputTests(unittest.TestCase):
    def test_four_actual_profiles_match_host_receipts_manifest_and_ustar(self) -> None:
        for identifier in ("f01", "f02", "f03", "f04"):
            with self.subTest(profile=identifier):
                pending, rows = ingest(identifier)
                accepted = pending.finish(rows)
                files = fixture(identifier)
                manifest = [{"file": index, "path": path, "bytes": len(body),
                             "sha256": hashlib.sha256(body).hexdigest()}
                            for index, (path, body) in enumerate(files)]
                expected = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode()
                self.assertEqual(accepted.manifest(), expected)
                raw = build_archive(accepted)
                self.assertEqual(build_archive(accepted), raw)
                self.assertEqual(inspect_archive(accepted, raw), hashlib.sha256(expected).hexdigest())
                self.assertEqual(inspect_archive(accepted, control(entries(identifier))),
                                 hashlib.sha256(expected).hexdigest())
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                    observed = archive.getmembers()
                    self.assertEqual([member.name for member in observed],
                                     [info.name for info, _ in entries(identifier)])
                    for member in observed:
                        self.assertEqual((member.uid, member.gid, member.mtime), (65532, 65532, 0))
                        self.assertEqual(member.mode, 0o500 if member.isdir() else 0o400)
                    for path, body in files:
                        stream = archive.extractfile("work/" + path)
                        assert stream is not None
                        with stream:
                            self.assertEqual(stream.read(len(body) + 1), body)
                print(json.dumps({"profile": identifier, "files": manifest,
                                  "manifestBytes": len(expected),
                                  "manifestSha256": hashlib.sha256(expected).hexdigest(),
                                  "archiveBytes": len(raw), "archiveSha256": hashlib.sha256(raw).hexdigest()}))
                with self.assertRaisesRegex(InputError, "^input_state$"):
                    pending.finish(rows)
                with self.assertRaisesRegex(InputError, "^input_state$"):
                    pending.append(Chunk(4, 0, b"x"))

    def test_foreign_order_offsets_chunk_bounds_and_digest_refuse_stickily(self) -> None:
        body = fixture("f01")[0][1]
        cases = [
            (Chunk(1, 0, b"a"), "file_order"), (Chunk(5, 0, b"a"), "file_order"),
            (Chunk(-1, 0, b"a"), "file_order"), (Chunk(True, 0, b"a"), "file_order"),
            (Chunk(0, 1, b"a"), "offset_order"), (Chunk(0, -1, b"a"), "offset_order"),
            (Chunk(0, True, b"a"), "offset_order"), (Chunk(0, 0, b""), "chunk_bound"),
            (Chunk(0, 0, b"a" * (MAX_CHUNK + 1)), "chunk_bound"),
            (Chunk(0, 0, body + b"x"), "file_bound"),
            (Chunk(0, 0, bytes([body[0] ^ 1]) + body[1:]), "input_digest"),
        ]
        for chunk, reason in cases:
            with self.subTest(reason=reason, file=chunk.file):
                pending = InputData("f01")
                with self.assertRaisesRegex(InputError, "^" + reason + "$"):
                    pending.append(chunk)
                with self.assertRaisesRegex(InputError, "^input_state$"):
                    pending.append(Chunk(0, 0, body))
        for first in (body[:1], body):
            pending = InputData("f01")
            pending.append(Chunk(0, 0, first))
            reason = "offset_order" if len(first) == 1 else "file_order"
            with self.subTest(replay=len(first)), self.assertRaisesRegex(InputError, "^" + reason + "$"):
                pending.append(Chunk(0, 0, first))
        with self.assertRaisesRegex(InputError, "^profile$"):
            InputData("f05")
        with self.assertRaisesRegex(InputError, "^input_incomplete$"):
            InputData("f01").finish([])

    def test_receipts_cannot_replace_retained_bytes_or_profile_agreement(self) -> None:
        changes = [({"file": 1}, "receipt_order"), ({"file": True}, "receipt_order"),
                   ({"bytes": 25}, "receipt_length"), ({"bytes": True}, "receipt_length"),
                   ({"sha256": "0" * 64}, "receipt_digest"), ({"extra": 0}, "receipt_shape")]
        for change, reason in changes:
            pending, rows = ingest("f01")
            raw = json.loads(json.dumps(rows))
            raw[0].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(InputError, "^" + reason + "$"):
                pending.finish(raw)
            with self.assertRaisesRegex(InputError, "^input_state$"):
                pending.finish(rows)
        for count in (4, 6):
            pending, rows = ingest("f01")
            malformed = rows[:count] if count == 4 else [*rows, rows[0]]
            with self.subTest(count=count), self.assertRaisesRegex(InputError, "^receipt_count$"):
                pending.finish(malformed)
        pending = InputData("f01")
        pending.append(Chunk(0, 0, fixture("f01")[0][1][:-1]))
        with self.assertRaisesRegex(InputError, "^input_incomplete$"):
            pending.finish([])
        bodies = tuple(body for _, body in fixture("f01"))
        with self.assertRaisesRegex(InputError, "^copy_length$"):
            InputCopy("f02", bodies)
        changed = (bytes([bodies[0][0] ^ 1]) + bodies[0][1:], *bodies[1:])
        with self.assertRaisesRegex(InputError, "^copy_digest$"):
            InputCopy("f01", changed)

    def test_archive_rejects_isolated_header_type_path_metadata_and_length_faults(self) -> None:
        pending, rows = ingest("f01")
        accepted = pending.finish(rows)
        original = entries("f01")
        index = len(original) - 5
        changes = [("uid", 0, "archive_ownership"), ("gid", 0, "archive_ownership"),
                   ("mtime", 1, "archive_ownership"), ("mode", 0o600, "archive_mode"),
                   ("uname", "root", "archive_metadata"), ("gname", "root", "archive_metadata"),
                   ("linkname", "work/other", "archive_metadata"), ("devmajor", 1, "archive_metadata"),
                   ("devminor", 1, "archive_metadata"),
                   ("size", 25, "archive_length"), ("size", 1048577, "archive_length"),
                   *[("name", name, "archive_path") for name in
                     ("/work/.dockerignore", "../work/.dockerignore", "work/../.dockerignore", "work\\file")],
                   ("name", "work/compose.json", "archive_membership")]
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE,
                     tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                     tarfile.GNUTYPE_SPARSE, b"Z"):
            changes.append(("type", kind, "archive_type"))
        for field, value, reason in changes:
            members = copy.deepcopy(original)
            setattr(members[index][0], field, value)
            if field == "size":
                info, body = members[index]
                members[index] = (info, body[:info.size] + bytes(max(0, info.size - len(body))))
            with self.subTest(field=field, value=value), self.assertRaisesRegex(InputError, "^" + reason + "$"):
                inspect_archive(accepted, control(members))
        for name, reason in (("work", "archive_duplicate"), ("WORK", "archive_case_collision")):
            members = copy.deepcopy(original)
            members[1][0].name = name
            with self.subTest(name=name), self.assertRaisesRegex(InputError, "^" + reason + "$"):
                inspect_archive(accepted, control(members))

    def test_archive_rejects_content_framing_padding_membership_and_overflow(self) -> None:
        pending, rows = ingest("f01")
        accepted = pending.finish(rows)
        members = entries("f01")
        raw = control(members)
        index = len(members) - 5
        start = sum(512 + ((len(body) + 511) // 512) * 512 for _, body in members[:index]) + 512
        content = bytearray(raw)
        content[start] ^= 1
        padding = bytearray(raw)
        padding[start + members[index][0].size] = 1
        header = bytearray(raw)
        header[0] ^= 1
        noncanonical = bytearray(raw)
        noncanonical[500] = 1
        noncanonical[148:156] = b"        "
        noncanonical[148:156] = f"{sum(noncanonical[:512]):06o}\0 ".encode()
        extra = copy.deepcopy(members)
        extra.append(copy.deepcopy(members[-1]))
        extra[-1][0].name = "work/extra"
        directory_type = copy.deepcopy(members)
        directory_type[0][0].type = tarfile.REGTYPE
        directory_type[0][0].mode = 0o400
        cases = [(bytes(content), "archive_content"), (bytes(padding), "archive_padding"),
                 (bytes(header), "archive_header"), (bytes(noncanonical), "archive_noncanonical"),
                 (control(members[:-1]), "archive_missing"), (control(extra), "archive_trailing"),
                 (control(directory_type), "archive_member_type"), (raw + bytes(10240), "archive_trailing"),
                 (raw + b"x", "archive_trailing"), (raw[:-1], "archive_trailing"),
                 (raw[:start + 1], "archive_truncated"), (raw[:511], "archive_truncated"),
                 (b"x" * (sum(row.size for row in profile("f01").files) + MAX_METADATA + 1), "archive_bound")]
        for data, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(InputError, "^" + reason + "$"):
                inspect_archive(accepted, data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
