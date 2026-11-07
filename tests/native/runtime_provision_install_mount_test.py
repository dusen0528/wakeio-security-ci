# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Native only: /usr/bin/python3 -I -B runtime_provision_install_mount_test.py.

Requires a separately authorized disposable Ubuntu arm64 guest, installed reviewed
helpers and an otherwise empty wakeio-install-* service with CPU2/4GiB/PIDs256.
No source/evidence mount, platform skip, simulated mount or guest Node is used.
"""
import errno
import fcntl
import hashlib
import os
import selectors
import shutil
import signal
import socket
import sys
import traceback
import unittest
from contextlib import ExitStack

sys.path.insert(0, "/usr/local/lib/wakeio-install")
from install_process import Deadline
from install_sandbox import sandbox
from install_supervisor import prerequisite
from seal_files import Files, identity, write_new
from seal_process import drain_service, own_service
from seal_types import BASE, InstallError, require


class NativeMountTest(unittest.TestCase):
    def test_final_consumed_paths_survive_original_namespace_writes(self) -> None:
        require(sys.version_info >= (3, 11) and sys.platform == "linux", "native_linux_python")
        require(os.geteuid() == os.getegid() == 0, "native_root")
        with Files() as files:
            prerequisite(files)
            service = own_service()
            os.mkdir(BASE, 0o700)
            root_identity = identity(os.lstat(BASE))[:5]
            try:
                for directory in ("empty", "lists", "archives"):
                    os.mkdir(BASE + "/" + directory, 0o700)
                for name, body in (("lists/index", b"sealed-index"), ("archives/package.deb", b"sealed-deb"),
                                   ("apt.conf", b"sealed-config"), ("lists/lock", b""), ("archives/lock", b"")):
                    write_new(BASE + "/" + name, body)
                    files.capture(BASE + "/" + name, 64)
                for directory in ("empty", "lists", "archives"):
                    files.directory(BASE + "/" + directory)
                files.directory(BASE)
                self.exercise(files)
            finally:
                drain_service(service, Deadline(30))
                require(identity(os.lstat(BASE))[:5] == root_identity, "native_cleanup_identity")
                shutil.rmtree(BASE)

    def exercise(self, files: Files) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with left, right, ExitStack() as lifetime, selectors.DefaultSelector() as events:
            left.settimeout(15)
            right.settimeout(15)
            events.register(left, selectors.EVENT_READ)
            pid = os.fork()
            if pid == 0:
                left.close()
                os.setsid()
                code = 125
                try:
                    self.child_view(files, right)
                    code = 0
                except (AssertionError, InstallError, OSError, UnicodeError, ValueError):
                    traceback.print_exc()
                right.close()
                os._exit(code)
            right.close()
            pidfd = os.pidfd_open(pid)
            lifetime.callback(os.close, pidfd)
            events.register(pidfd, selectors.EVENT_READ)
            deadline = Deadline(30)
            try:
                left.sendall(b"START")
                ready = events.select(deadline.remaining())
                self.assertIn(left.fileno(), {key.fd for key, _ in ready})
                self.assertEqual(left.recv(32), b"FINAL_VIEW")
                files.check()  # Last original check; child has finished ALL sandbox mounts.
                for name, original in (("lists/index", b"sealed-index"), ("archives/package.deb", b"sealed-deb")):
                    path = BASE + "/" + name
                    with open(path, "r+b") as stream:
                        self.assertEqual(stream.write(b"X" * len(original)), len(original))
                        stream.flush()
                        os.fsync(stream.fileno())
                    with open(path, "rb") as stream:
                        self.assertEqual(stream.read(), b"X" * len(original))
                left.sendall(b"ORIGINALS_CHANGED")
                self.assertEqual(left.recv(32), b"SEALED_AND_LOCKED")
                events.unregister(left)
                self.assertTrue(events.select(deadline.remaining()))
                status = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT)
                self.assertEqual((status.si_code, status.si_status), (os.CLD_EXITED, 0))
            finally:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                os.waitpid(pid, 0)

    def child_view(self, files: Files, channel: socket.socket) -> None:
        self.assertEqual(channel.recv(16), b"START")
        sandbox(files)
        channel.sendall(b"FINAL_VIEW")
        self.assertEqual(channel.recv(32), b"ORIGINALS_CHANGED")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        for name, expected in (("lists/index", b"sealed-index"), ("archives/package.deb", b"sealed-deb"),
                               ("apt.conf", b"sealed-config")):
            path = BASE + "/" + name
            anchor = next(value for value in files.anchors if value.path == path)
            with open(path, "rb") as stream:
                actual = stream.read()
                self.assertEqual(actual, expected)
                self.assertEqual(hashlib.sha256(actual).hexdigest(), anchor.sha256)
                self.assertNotEqual(identity(os.fstat(stream.fileno()))[:2], anchor.metadata[:2])
                self.assertEqual(fcntl.fcntl(stream, fcntl.F_GET_SEALS), seals)
                self.assertTrue(os.fstatvfs(stream.fileno()).f_flag & os.ST_RDONLY)
            with self.assertRaises(OSError) as refused:
                with open(path, "r+b") as stream:
                    stream.write(b"unsafe")
            self.assertIn(refused.exception.errno, (errno.EROFS, errno.EPERM))
        for directory in ("empty", "lists", "archives"):
            path = BASE + "/" + directory
            self.assertTrue(os.statvfs(path).f_flag & os.ST_RDONLY)
            with self.assertRaises(OSError) as refused:
                with open(path + "/unexpected", "xb"):
                    self.fail("protected directory was writable")
            self.assertEqual(refused.exception.errno, errno.EROFS)
        for name in ("lists/lock", "archives/lock"):
            path = BASE + "/" + name
            anchor = next(value for value in files.anchors if value.path == path)
            with open(path, "r+b") as stream:
                self.assertEqual(identity(os.fstat(stream.fileno()))[:2], anchor.metadata[:2])
                self.assertEqual(stream.read(), b"")
                self.assertFalse(os.fstatvfs(stream.fileno()).f_flag & os.ST_RDONLY)
                fcntl.lockf(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(stream, fcntl.LOCK_UN)
        channel.sendall(b"SEALED_AND_LOCKED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
