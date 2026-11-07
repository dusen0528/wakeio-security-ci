# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Native only: /usr/bin/python3 -I -B runtime_provision_install_apt_test.py.

Future execution requires explicit authenticated PREPARE/network consent in a fresh
source-free Ubuntu arm64 guest and an otherwise empty constrained installer service.
stdin must be a live controller pipe, held open without data for the entire test.
Production prepare obtains and anchors the real signed closure; absent/expired
inputs fail, never load a serialized Prepared or synthesize headers. The hook is
always denied before ACCEPT. Owned rootful masks last until outer VM destruction.
"""
import hashlib
import json
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
from install_audit import Autostart
from install_config import apt
from install_prepare import prepare
from install_process import Deadline, checked
from install_sandbox import peer, sandbox
from install_supervisor import prerequisite
from install_transaction import installer
from seal_files import Files, identity, write_new
from seal_hook import hook_config, validate_install_hook
from seal_operation import Operation
from seal_process import drain_service, own_service
from seal_types import BASE, ENV, InstallError, require


class NativeAptTest(unittest.TestCase):
    def setUp(self) -> None:
        require(sys.version_info >= (3, 11) and sys.platform == "linux", "native_linux_python")
        require(os.geteuid() == os.getegid() == 0, "native_root")
        self.lifetime = ExitStack()
        self.addCleanup(self.lifetime.close)
        self.files = self.lifetime.enter_context(Files())
        prerequisite(self.files)
        self.service = own_service()
        with selectors.DefaultSelector() as events:
            events.register(0, selectors.EVENT_READ)
            require(not events.select(0), "live_controller_stdin_required")
        self.policy = Autostart()
        self.root_identity: tuple[int, ...] | None = None
        self.marker_identity: tuple[int, ...] | None = None
        self.marker = f"/etc/apt/apt.conf.d/90wakeio-native-seal-{os.getpid()}.conf"
        self.addCleanup(self.finish)
        os.mkdir(BASE, 0o700)
        self.root_identity = identity(os.lstat(BASE))[:5]
        write_new(self.marker, b'Wakeio::Native::Inherited "must-not-load";\n')
        self.marker_identity = identity(os.lstat(self.marker))
        self.files.capture(self.marker, 128)
        self.policy.install(self.files, Deadline(30))
        self.left, self.right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.lifetime.enter_context(self.left)
        self.lifetime.enter_context(self.right)
        self.left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.left.settimeout(15)
        self.right.settimeout(15)
        self.prepared = prepare(self.files, Deadline(300), self.right.fileno())
        require(4 <= len(self.prepared.packages) <= 48, "native_authenticated_closure_required")

    def finish(self) -> None:
        drain_service(self.service, Deadline(30))
        if self.policy.policy is not None:
            self.policy.cleanup_policy()  # Production masks intentionally await VM teardown.
        if self.marker_identity is not None:
            require(identity(os.lstat(self.marker)) == self.marker_identity, "native_marker_replaced")
            os.unlink(self.marker)
        if self.root_identity is not None:
            require(identity(os.lstat(BASE))[:5] == self.root_identity, "native_cleanup_identity")
            shutil.rmtree(BASE)

    def test_native_single_load_and_duplicate_refusal_before_dpkg(self) -> None:
        owner = Operation(self.files, Deadline(300))
        try:
            owner.prepared(self.prepared)
            owner.consume()
            payload = self.capture(False)
            actual = self.loaded_header(payload)
            self.assertEqual([value for key, value in actual if key == "apt::keep-fds::"],
                             [str(self.right.fileno())])
            self.assertEqual(owner.hook(payload), hashlib.sha256(payload).hexdigest())
            # Original argv is replayed through native APT, not a manually duplicated dump.
            duplicate = self.capture(True)
            actual = self.loaded_header(duplicate)
            self.assertEqual([value for key, value in actual if key == "apt::keep-fds::"],
                             [str(self.right.fileno()), str(self.right.fileno())])
            with self.assertRaises(InstallError) as refused:
                validate_install_hook(duplicate, self.prepared.packages, self.prepared.configuration)
            self.assertEqual(refused.exception.code, "hook_option:apt::keep-fds::")
            self.files.check()  # Includes original dpkg status: no accepted hook or install.
            self.assertEqual(checked(("/usr/bin/dpkg", "--audit"), Deadline(30)), b"")
        finally:
            owner.close()  # Never complete an install owner for a deliberately denied hook.

    def loaded_header(self, payload: bytes) -> tuple[tuple[str, str], ...]:
        lines = payload.decode("ascii").splitlines()
        self.assertEqual(lines[0], "VERSION 3")
        self.assertIn("", lines)
        actual = hook_config(lines[1:lines.index("")])
        self.assertNotIn("wakeio::native::inherited", {key for key, _ in actual})
        print(json.dumps({"nativeInfoFD": payload.decode("ascii")}), flush=True)
        return actual

    def capture(self, duplicate: bool) -> bytes:
        argv = apt(("--no-download", "install", *(p.name + "=" + p.new.version for p in self.prepared.packages)))
        if duplicate:
            argv = (argv[0], "-c", BASE + "/apt.conf", *argv[1:])
        env = {**ENV, "WAKEIO_INSTALL_FD": str(self.right.fileno())}
        print(json.dumps({"duplicateLoad": duplicate, "argv": argv, "env": env}), flush=True)
        with ExitStack() as lifetime, selectors.DefaultSelector() as events:
            events.register(self.left, selectors.EVENT_READ, "channel")
            pid = os.fork()
            if pid == 0:
                self.left.close()
                code = 125
                try:
                    self.assertEqual(self.right.recv(16), b"START")
                    if duplicate:
                        self.replay_child(argv, env)
                    else:
                        installer(self.files, self.right, self.prepared)
                except (AssertionError, InstallError, OSError, UnicodeError, ValueError):
                    traceback.print_exc()
                self.right.close()
                os._exit(code)
            pidfd = os.pidfd_open(pid)
            lifetime.callback(os.close, pidfd)
            events.register(pidfd, selectors.EVENT_READ, "exit")
            deadline = Deadline(30)
            try:
                self.left.sendall(b"START")
                self.await_channel(events, deadline)
                self.assertEqual(self.left.recv(16), b"READY")
                self.files.check()
                self.left.sendall(b"GO")
                self.await_channel(events, deadline)
                payload = peer(self.left, pid)
                self.left.sendall(b"DENY")  # No ACCEPT can reach install_hook.py.
                events.unregister(self.left)
                self.assertTrue(events.select(deadline.remaining()))
                status = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT)
                self.assertEqual((status.si_code, status.si_status), (os.CLD_EXITED, 100))
                return payload
            finally:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                os.waitpid(pid, 0)
                drain_service(self.service, Deadline(30))

    def await_channel(self, events: selectors.BaseSelector, deadline: Deadline) -> None:
        ready = events.select(deadline.remaining())
        self.assertIn(self.left.fileno(), {key.fd for key, _ in ready}, "native hook/READY missing")

    def replay_child(self, argv: tuple[str, ...], env: dict[str, str]) -> None:
        """Same production install boundary with the original double-load argv."""
        os.setsid()
        sandbox(self.files)
        self.right.sendall(b"READY")
        self.assertEqual(self.right.recv(8), b"GO")
        os.set_inheritable(self.right.fileno(), True)
        with open("/dev/null", "r+b") as sink:
            for fd in (0, 1, 2):
                os.dup2(sink.fileno(), fd)
        os.execve(argv[0], argv, env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
