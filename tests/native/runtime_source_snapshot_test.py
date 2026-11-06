"""Distinct descriptor/ancestry tests; node:test owns producer lifecycle and policy."""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
# Run: /usr/bin/python3 -I -S -B tests/native/runtime_source_snapshot_test.py
from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers/runtime-source"))
from snapshot import Capture, REGULAR, SnapshotFault


class DescriptorTests(unittest.TestCase):
    def test_retained_ancestor_refuses_replacement_before_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-fd-") as directory, ExitStack() as stack:
            top = Path(directory).resolve()
            source = top / "source"
            source.mkdir()
            (source / "pom.xml").write_bytes(b"original")
            capture = Capture(stack)
            parent = capture.directory(str(source))
            entry = capture.opened(parent, "pom.xml", REGULAR)
            source.rename(top / "moved")
            source.mkdir()
            (source / "pom.xml").write_bytes(b"replacement secret")

            with self.assertRaises(SnapshotFault):
                capture.bytes(entry)

            self.assertEqual((top / "moved/pom.xml").read_bytes(), b"original")
            self.assertEqual((source / "pom.xml").read_bytes(), b"replacement secret")
            descriptor = entry.fd
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptor)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_fifo_is_rejected_without_waiting_for_writer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-fd-") as directory, ExitStack() as stack:
            root = Path(directory).resolve()
            os.mkfifo(root / "pom.xml")
            capture = Capture(stack)
            parent = capture.directory(str(root))

            with self.assertRaises(SnapshotFault):
                capture.opened(parent, "pom.xml", REGULAR)

            self.assertTrue((root / "pom.xml").is_fifo())

    def test_source_mutation_invalidates_capture_without_modifying_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-fd-") as directory, ExitStack() as stack:
            root = Path(directory).resolve()
            source = root / "pom.xml"
            source.write_bytes(b"before")
            capture = Capture(stack)
            parent = capture.directory(str(root))
            entry = capture.opened(parent, "pom.xml", REGULAR)
            source.write_bytes(b"after")

            with self.assertRaises(SnapshotFault):
                capture.bytes(entry)

            self.assertEqual(source.read_bytes(), b"after")

    def test_renamed_output_root_keeps_foreign_replacement_and_reports_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-fd-") as directory, ExitStack() as stack:
            top = Path(directory).resolve()
            capture = Capture(stack)
            parent = capture.directory(str(top))
            root = capture.created(parent, "projection", None)
            capture.created(root.fd, "pom.xml", b"original")
            (top / "projection").rename(top / "moved")
            (top / "projection").mkdir()
            (top / "projection/pom.xml").write_bytes(b"foreign")

            clean = capture.cleanup()
            if capture.disposal.directory:
                stack.callback(shutil.rmtree, capture.disposal.directory)
            self.assertFalse(clean)

            self.assertEqual((top / "projection/pom.xml").read_bytes(), b"foreign")
            self.assertEqual(list((top / "moved").iterdir()), [])

    def test_system_tmp_alias_is_narrow_and_user_alias_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-fd-") as directory, ExitStack() as stack:
            top = Path(directory).resolve()
            (top / "real").mkdir()
            (top / "alias").symlink_to(top / "real")
            capture = Capture(stack)
            with self.assertRaises(OSError):
                capture.directory(str(top / "alias"))
            actual = os.fstat(capture.directory("/tmp"))
            expected = os.stat("/tmp")
            self.assertEqual((actual.st_dev, actual.st_ino), (expected.st_dev, expected.st_ino))

    def test_cleanup_preserves_replacement_at_unlink_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-boundary-") as directory, ExitStack() as stack:
            top = Path(directory).resolve()
            capture = Capture(stack)
            parent = capture.directory(str(top))
            projection = capture.created(parent, "projection", None)
            capture.created(projection.fd, "pom.xml", b"original")
            public_file = top / "projection/pom.xml"
            real_unlink = os.unlink
            injected = False

            def boundary(name: str, *, dir_fd: int | None = None) -> None:
                nonlocal injected
                if not injected:
                    if public_file.exists():
                        public_file.rename(top / "parked-original")
                    public_file.parent.mkdir(parents=True, exist_ok=True)
                    public_file.write_bytes(b"foreign replacement")
                    injected = True
                real_unlink(name, dir_fd=dir_fd)

            with patch("os.unlink", boundary):
                clean = capture.cleanup()
            if capture.disposal.directory:
                stack.callback(shutil.rmtree, capture.disposal.directory)

            self.assertTrue(injected)
            self.assertTrue(public_file.exists(), "cleanup deleted the foreign replacement")
            self.assertEqual(public_file.read_bytes(), b"foreign replacement")
            self.assertFalse(clean, "cleanup claimed success after pathname ownership changed")

    def test_cleanup_retains_foreign_entry_captured_at_rename_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-claim-") as directory, ExitStack() as stack:
            top = Path(directory).resolve()
            capture = Capture(stack)
            parent = capture.directory(str(top))
            projection = capture.created(parent, "projection", None)
            capture.created(projection.fd, "pom.xml", b"original")
            public_file = top / "projection/pom.xml"
            parked = top / "parked-original"
            real_rename = os.rename
            injected = False

            def boundary(
                source: str, destination: str, *, src_dir_fd: int | None = None, dst_dir_fd: int | None = None
            ) -> None:
                nonlocal injected
                if source == "pom.xml" and not injected:
                    real_rename(public_file, parked)
                    public_file.write_bytes(b"foreign captured during detach")
                    injected = True
                real_rename(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            with patch("os.rename", boundary):
                clean = capture.cleanup()
            recovery = capture.disposal
            assert recovery.directory is not None
            stack.callback(shutil.rmtree, recovery.directory)
            self.assertTrue(injected)
            self.assertFalse(clean)
            pending = next(entry for entry in recovery.pending if entry.name == "pom.xml")
            assert pending.slot is not None
            self.assertEqual((Path(recovery.directory) / pending.slot).read_bytes(), b"foreign captured during detach")
            self.assertEqual(parked.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main(verbosity=2)
