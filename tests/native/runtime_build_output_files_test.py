# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Local descriptor tests only; no original volume, workload or native backend is exercised."""
import errno
import hashlib
import os
import sys
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from enum import StrEnum
from pathlib import Path
from typing import assert_never

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from output_files import DIRECTORY_FLAGS, Limits, OutputError, relative_path, scan


class EntryKind(StrEnum):
    SYMLINK = "symlink"
    FIFO = "fifo"


@contextmanager
def tree() -> Iterator[tuple[Path, int]]:
    with tempfile.TemporaryDirectory(prefix="output-files-") as temporary, ExitStack() as stack:
        root = Path(temporary) / "view"
        root.mkdir(mode=0o700)
        fd = os.open(root, DIRECTORY_FLAGS)
        stack.callback(os.close, fd)
        yield root, fd


class FileTests(unittest.TestCase):
    def test_real_bytes_sorted_bindings_and_owned_close_preserve_the_borrowed_root(self) -> None:
        with tree() as (root, fd):
            (root / "classes").mkdir()
            (root / "z").write_bytes(b"last")
            (root / "classes/a").write_bytes(b"first")
            captured = scan(fd, Limits(9, 2))
            self.assertEqual([(row.binding.path, row.binding.bytes, row.binding.sha256) for row in captured.files],
                             [("classes/a", 5, hashlib.sha256(b"first").hexdigest()),
                              ("z", 4, hashlib.sha256(b"last").hexdigest())])
            with captured.open(captured.files[0]) as stream:
                opened = stream.fileno()
                self.assertEqual(stream.read(), b"first")
            self.assertTrue(stream.closed)
            with self.assertRaises(OSError) as closed:
                os.fstat(opened)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            self.assertTrue(os.fstat(fd).st_ino)
            captured.check()

    def test_real_boundary_error_survives_context_unwinding_and_owned_descriptor_closes(self) -> None:
        with tree() as (root, fd):
            (root / "a").write_bytes(b"a")
            captured = scan(fd, Limits(1, 1))
            with self.assertRaisesRegex(OutputError, "^output_path$"):
                with captured.open(captured.files[0]) as stream:
                    opened = stream.fileno()
                    relative_path("../escape")
            self.assertTrue(stream.closed)
            with self.assertRaises(OSError) as closed:
                os.fstat(opened)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            self.assertTrue(os.fstat(fd).st_ino)

    def test_symlink_and_fifo_are_refused_without_reading_their_targets(self) -> None:
        for kind in EntryKind:
            with self.subTest(kind=kind), tree() as (root, fd):
                target = root.parent / "foreign"
                target.write_bytes(b"outside")
                match kind:
                    case EntryKind.SYMLINK:
                        (root / "entry").symlink_to(target)
                    case EntryKind.FIFO:
                        os.mkfifo(root / "entry")
                    case unexpected:
                        assert_never(unexpected)
                with self.assertRaisesRegex(OutputError, "^output_file_type$"):
                    scan(fd, Limits(100, 2))
                self.assertEqual(target.read_bytes(), b"outside")

    def test_single_visible_hardlink_refuses_before_it_can_be_an_accepted_file(self) -> None:
        with tree() as (root, fd):
            outside = root.parent / "outside"
            outside.write_bytes(b"linked")
            os.link(outside, root / "entry")
            self.assertEqual(os.stat(root / "entry").st_nlink, 2)
            with self.assertRaisesRegex(OutputError, "^output_file_links$"):
                scan(fd, Limits(100, 2))

    def test_exact_counts_and_bytes_accept_then_each_one_over_bound_refuses(self) -> None:
        with tree() as (root, fd):
            (root / "a").write_bytes(b"1234")
            (root / "b").write_bytes(b"123456")
            self.assertEqual(len(scan(fd, Limits(10, 2)).files), 2)
            with self.assertRaisesRegex(OutputError, "^output_tree_bytes$"):
                scan(fd, Limits(9, 2))
            (root / "c").write_bytes(b"")
            with self.assertRaisesRegex(OutputError, "^output_tree_files$"):
                scan(fd, Limits(10, 2))

    def test_same_length_file_substitution_invalidates_its_retained_observation(self) -> None:
        with tree() as (root, fd):
            original = root / "a"
            original.write_bytes(b"original")
            captured = scan(fd, Limits(100, 2))
            replacement = root.parent / "replacement"
            replacement.write_bytes(b"replaced")
            os.replace(replacement, original)
            with self.assertRaisesRegex(OutputError, "^output_tree_changed$"):
                captured.check()
            with self.assertRaisesRegex(OutputError, "^output_directory_changed$"):
                with captured.open(captured.files[0]):
                    self.fail("A substituted name must not yield an accepted descriptor")

    def test_canonical_paths_refuse_escapes_controls_and_excess_depth(self) -> None:
        for path in ("/absolute", "../escape", "a/../b", "a//b", "a\\b", "a\x00b", "a\nb",
                     "/".join(["a"] * 65), "a" * 256):
            with self.subTest(path=path), self.assertRaisesRegex(OutputError, "^output_path$"):
                relative_path(path)
        self.assertEqual(relative_path("a/b.class"), "a/b.class")


if __name__ == "__main__":
    unittest.main(verbosity=2)
