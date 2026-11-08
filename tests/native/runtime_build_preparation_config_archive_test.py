# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B this file. Inert USTAR bytes never reach a filesystem extractor.
"""Independent raw USTAR controls, not a production encoder round-trip oracle."""
from __future__ import annotations

import hashlib
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from preparation_config_archive import (
    HelperInputs, helpers_archive, inspect_certificate, inspect_config, inspect_helper,
    inspect_helpers, inspect_seed, seed_archive,
)
from preparation_config_data import ConfigError

USER: Final = b"""<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <localRepository>/tmp/wakeio-m2</localRepository>
  <interactiveMode>false</interactiveMode>
  <mirrors>
    <mirror>
      <id>wakeio-build-mirror</id>
      <mirrorOf>*</mirrorOf>
      <url>https://wakeio-maven:8443/maven2/</url>
    </mirror>
  </mirrors>
</settings>
"""
GLOBAL: Final = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"/>\n')
INPUTS: Final = HelperInputs(b"inert producer\n", b"inert verifier\n", b"inert certificate\n")
STORE: Final = b"\x30\x03\x02\x01\x03"


@dataclass(frozen=True, slots=True)
class Member:
    name: str
    body: bytes | None
    mode: int
    mtime: int = 0


def checksum(block: bytearray) -> None:
    block[148:156] = b"        "
    block[148:156] = f"{sum(block):06o}\0 ".encode("ascii")


def header(row: Member) -> bytes:
    block = bytearray(512)
    name = row.name + ("/" if row.body is None else "")
    block[:len(name)] = name.encode("ascii")
    for start, width, value in ((100, 8, row.mode), (108, 8, 65532), (116, 8, 65532),
                                (124, 12, 0 if row.body is None else len(row.body)), (136, 12, row.mtime)):
        block[start:start + width] = f"{value:0{width - 1}o}\0".encode("ascii")
    block[156:157] = b"5" if row.body is None else b"0"
    block[257:265] = b"ustar\x0000"
    checksum(block)
    return bytes(block)


def control(rows: tuple[Member, ...]) -> bytes:
    result = b"".join(header(row) + (b"" if row.body is None else row.body + bytes(-len(row.body) % 512))
                      for row in rows)
    result += bytes(1024)
    return result + bytes(-len(result) % 10240)


def settings(final: bool = False) -> tuple[Member, ...]:
    return (Member("build-config", None, 0o500 if final else 0o700),
            Member("build-config/user-settings.xml", USER, 0o400),
            Member("build-config/global-settings.xml", GLOBAL, 0o400))


def inputs(root: str = "config-input") -> tuple[Member, ...]:
    return (Member(root, None, 0o500), Member(root + "/producer", None, 0o500),
            Member(root + "/verifier", None, 0o500),
            Member(root + "/producer/PrepConfigProduce.java", INPUTS.producer, 0o400),
            Member(root + "/verifier/PrepConfigVerify.java", INPUTS.verifier, 0o400),
            Member(root + "/mirror.crt", INPUTS.certificate, 0o400))


def changed_header(raw: bytes, offset: int, payload: bytes) -> bytes:
    block = bytearray(raw[:512])
    block[offset:offset + len(payload)] = payload
    checksum(block)
    return bytes(block) + raw[512:]


class ConfigArchiveTests(unittest.TestCase):
    def test_seed_encoders_target_destination_dot_without_changing_readback_namespace(self) -> None:
        rows = (Member(".", None, 0o700), Member("./user-settings.xml", USER, 0o400),
                Member("./global-settings.xml", GLOBAL, 0o400))
        self.assertEqual(seed_archive(), control(rows))
        self.assertEqual(helpers_archive(INPUTS), control(inputs(".")))
        with self.assertRaisesRegex(ConfigError, "membership"):
            inspect_seed(control(rows))

    def test_independent_readbacks_return_actual_bytes_hashes_and_store_metadata(self) -> None:
        raw = control(settings())
        accepted = inspect_seed(raw)
        self.assertEqual((accepted.raw, accepted.sha256), (raw, hashlib.sha256(raw).hexdigest()))
        final = (*settings(True), Member("build-config/mirror-trust.p12", STORE, 0o400, 1730000000))
        result = inspect_config(control(final))
        self.assertEqual((result.entries[-1].body, result.entries[-1].mtime, result.entries[-1].sha256),
                         (STORE, 1730000000, hashlib.sha256(STORE).hexdigest()))
        helper_raw = control(inputs())
        helper_result = inspect_helpers(INPUTS, helper_raw)
        self.assertEqual(helper_result.raw, helper_raw)
        self.assertEqual([entry.body for entry in helper_result.entries],
                         [None, None, None, INPUTS.producer, INPUTS.verifier, INPUTS.certificate])
        for role, body, filename in (("producer", INPUTS.producer, "PrepConfigProduce.java"),
                                     ("verifier", INPUTS.verifier, "PrepConfigVerify.java")):
            rows = (Member(role, None, 0o500), Member(role + "/" + filename, body, 0o400))
            self.assertEqual(inspect_helper(INPUTS, role, control(rows)).entries[-1].body, body)
        cert = control((Member("mirror.crt", INPUTS.certificate, 0o400),))
        self.assertEqual(inspect_certificate(INPUTS, cert).entries[0].sha256,
                         hashlib.sha256(INPUTS.certificate).hexdigest())

    def test_aliases_links_extensions_and_metadata_are_not_accepted_as_regular_members(self) -> None:
        raw = control(settings())
        changes = (
            (0, b"Build-config"), (0, b"../config"), (0, b"/build-config"), (0, b"./build-config"),
            (0, b"build\\config"), (100, b"0000701\0"), (108, b"0000000\0"),
            (116, b"0000000\0"), (136, b"00000000001\0"), (157, b"alias"), (265, b"root"),
            (297, b"group"), (329, b"0000001\0"), (337, b"0000001\0"), (500, b"x"),
        )
        for offset, payload in changes:
            with self.subTest(offset=offset, payload=payload), self.assertRaises(ConfigError):
                inspect_seed(changed_header(raw, offset, payload))
        for typeflag in (b"0", b"1", b"2", b"3", b"4", b"6", b"x", b"g", b"L", b"S", b"\0"):
            with self.subTest(type=typeflag), self.assertRaises(ConfigError):
                inspect_seed(changed_header(raw, 156, typeflag))

    def test_content_order_duplicates_padding_checksum_truncation_and_extra_members_refuse(self) -> None:
        raw = control(settings())
        changed = bytearray(raw)
        changed[1024] ^= 1
        padding = bytearray(raw)
        padding[1024 + len(USER)] = 1
        bad_checksum = bytearray(raw)
        bad_checksum[0] ^= 1
        surplus = bytearray(raw)
        surplus[-1] = 1
        rows = settings()
        cases = (bytes(changed), bytes(padding), bytes(bad_checksum), bytes(surplus), raw[:511],
                 raw[:1025], raw[:-1], raw + bytes(10240), raw + raw, b"x" * 131073,
                 control(rows[:-1]), control((rows[0], rows[2], rows[1])),
                 control((*rows, Member("build-config/extra", b"x", 0o400))),
                 control((rows[0], rows[1], rows[1])))
        for index, malformed in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ConfigError):
                inspect_seed(malformed)

    def test_helpers_bind_original_content_and_closed_six_entry_tree(self) -> None:
        rows = inputs()
        for index in range(len(rows)):
            row = rows[index]
            changed = Member(row.name, row.body, row.mode ^ 0o100)
            with self.subTest(index=index), self.assertRaises(ConfigError):
                inspect_helpers(INPUTS, control((*rows[:index], changed, *rows[index + 1:])))
            if row.body is not None:
                changed = Member(row.name, b"other", row.mode)
                with self.subTest(content=index), self.assertRaisesRegex(ConfigError, "length|content"):
                    inspect_helpers(INPUTS, control((*rows[:index], changed, *rows[index + 1:])))
        with self.assertRaises(ConfigError):
            inspect_helpers(HelperInputs(b"replacement", INPUTS.verifier, INPUTS.certificate), control(rows))
        with self.assertRaises(ConfigError):
            inspect_helpers(INPUTS, control((*rows, Member("config-input/sibling.class", b"x", 0o400))))

    def test_store_lengths_and_times_and_input_size_edges_are_bounded(self) -> None:
        for size in (1, 65536):
            raw = control((*settings(True), Member("build-config/mirror-trust.p12", bytes(size), 0o400, 8589934591)))
            self.assertEqual(len(inspect_config(raw).entries[-1].body or b""), size)
        for size in (0, 65537):
            with self.subTest(size=size), self.assertRaises(ConfigError):
                inspect_config(control((*settings(True), Member("build-config/mirror-trust.p12", bytes(size), 0o400))))
        for producer, verifier, certificate in (
            (b"", b"v", b"c"), (b"p" * 32769, b"v", b"c"), (b"p", b"v" * 32769, b"c"),
            (b"p", b"v", b""), (b"p", b"v", b"c" * 16385),
        ):
            with self.subTest(size=(len(producer), len(verifier), len(certificate))), self.assertRaises(ConfigError):
                HelperInputs(producer, verifier, certificate)
        bounded = HelperInputs(b"p" * 32768, b"v" * 32768, b"c" * 16384)
        self.assertLessEqual(len(helpers_archive(bounded)), 131072)


if __name__ == "__main__":
    unittest.main(verbosity=2)
