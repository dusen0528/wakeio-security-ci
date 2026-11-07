"""Original Linux launch-child custody; physical process closure is not daemon closure."""
from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
from typing import IO, TYPE_CHECKING, Final

from backend_process import BackendError, USER_ENV, require
from launch import LaunchError, encode_selection

if TYPE_CHECKING:
    from build import Pending

LOG_BOUND: Final = 1024 * 1024


class Process:
    """Mutable custodian retained by its original pending operation before any effect."""

    def __init__(self, pending: Pending) -> None:
        from build import BuildSession, Pending
        require(type(pending) is Pending and type(pending.session) is BuildSession, "build_pending_type")
        self.pending = pending
        self.child: subprocess.Popen[bytes] | None = None
        self.descriptors: dict[str, int] = {}
        self.streams: dict[int, IO[bytes]] = {}
        self.events = select.poll()
        self.output = bytearray()
        self.errors = bytearray()
        self.output_overflow = False
        self.offset = 0
        self.exit_observed = False
        self.reaped = False
        self.stdout_eof = False
        self.stderr_eof = False
        self.released = False
        self.stopped = False
        self.stop_raced = False
        self.wake_error: OSError | None = None
        self.drained = False

    def _dispose(self, name: str) -> None:
        descriptor = self.descriptors.pop(name, None)
        if descriptor is not None:
            os.close(descriptor)

    def wake(self) -> None:
        try:
            if self.stopped:
                self._dispose("gate-write")
            if "wake-write" in self.descriptors:
                os.write(self.descriptors["wake-write"], b"!")
        except BlockingIOError:
            self.stopped = True
        except OSError as error:
            self.wake_error = error
            self.stopped = True

    def stop(self) -> None:
        self.stopped = True
        self._dispose("gate-write")
        child = self.child
        if child is not None and not self.reaped:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                self.stop_raced = True

    def start(self) -> None:
        session = self.pending.session
        session._member(self.pending, self)
        require(self.child is None and not self.descriptors, "build_process_replay")
        require(sys.platform == "linux", "build_process_platform")
        try:
            reader, writer = os.pipe2(os.O_CLOEXEC)
            self.descriptors.update({"gate-read": reader, "gate-write": writer})
            reader, writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            self.descriptors.update({"wake-read": reader, "wake-write": writer})
            self.child = subprocess.Popen(
                ("/usr/bin/python3", "-I", "-B", "/usr/local/lib/wakeio-controller/build/launch.py",
                 str(self.descriptors["gate-read"])),
                env=USER_ENV, user=10001, group=10001, extra_groups=(), start_new_session=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                pass_fds=(self.descriptors["gate-read"],))
            self._dispose("gate-read")
            self._arm()
            session._eligible(self.pending, self)
            packet = encode_selection(self.pending.selection)
            writer = self.descriptors["gate-write"]
            session._eligible(self.pending, self)
            cancellation = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
            try:
                require(not self.stopped and not signal.sigpending().intersection(cancellation),
                        "build_gate_interrupted")
                self.released = True
                require(os.write(writer, packet) == len(packet), "build_gate_short")
                self._dispose("gate-write")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except (OSError, ValueError, BackendError, LaunchError) as error:
            session._fail("build_process_setup:" + str(error))
            self.stop()
        self.join()

    def _arm(self) -> None:
        child = self.child
        if child is None:
            raise BackendError("build_child_missing")
        if child.stdin is None or child.stdout is None or child.stderr is None:
            raise BackendError("build_pipe_missing")
        self.descriptors["pidfd"] = os.pidfd_open(child.pid)
        self.events.register(self.descriptors["pidfd"], select.POLLIN)
        self.events.register(self.descriptors["wake-read"], select.POLLIN)
        for stream in (child.stdout, child.stderr, child.stdin):
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            self.streams[descriptor] = stream
            self.events.register(descriptor, select.POLLOUT if stream is child.stdin else select.POLLIN)

    def _close_stream(self, descriptor: int) -> None:
        stream = self.streams[descriptor]
        self.events.unregister(descriptor)
        stream.close()
        del self.streams[descriptor]

    def _input(self, descriptor: int) -> None:
        if self.stopped or self.offset == len(self.pending.body):
            self._close_stream(descriptor)
            return
        try:
            self.offset += os.write(descriptor, self.pending.body[self.offset:self.offset + 65536])
        except BlockingIOError:
            return
        except BrokenPipeError:
            self.pending.session._fail("build_input_pipe")
            self.stop()
            self._close_stream(descriptor)

    def _output(self, descriptor: int) -> None:
        child = self.child
        if child is None:
            raise BackendError("build_child_missing")
        stream = self.streams[descriptor]
        try:
            chunk = os.read(descriptor, 65536)
        except BlockingIOError:
            return
        stdout = stream is child.stdout
        if not chunk:
            if stdout:
                self.stdout_eof = True
            else:
                self.stderr_eof = True
            self._close_stream(descriptor)
            return
        target = self.output if stdout else self.errors
        bound = self.pending.output_bound if stdout else LOG_BOUND
        used = len(target) if self.pending.archive_output else len(self.output) + len(self.errors)
        if len(chunk) > bound - used:
            self.output_overflow = True
            self.pending.session._fail("build_output_bound")
            self.stop()
        if not self.output_overflow:
            target.extend(chunk)

    def _join_arming(self) -> None:
        """Re-arm only drainage of this same child; this path never releases its gate."""
        child = self.child
        if child is None:
            return
        self.events = select.poll()
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                descriptor = stream.fileno()
                os.set_blocking(descriptor, False)
                self.streams[descriptor] = stream
                self.events.register(descriptor, select.POLLOUT if stream is child.stdin else select.POLLIN)
        if "pidfd" in self.descriptors and not self.exit_observed:
            self.events.register(self.descriptors["pidfd"], select.POLLIN)
        if "wake-read" in self.descriptors:
            self.events.register(self.descriptors["wake-read"], select.POLLIN)

    def join(self) -> None:
        """Drain bounded chunks through both real EOFs and reap the retained Popen."""
        if self.drained:
            return
        child = self.child
        self._dispose("gate-read")
        self._dispose("gate-write")
        if child is not None:
            if self.stopped:
                self.stop()
            self._join_arming()
            while self.streams or ("pidfd" in self.descriptors and not self.exit_observed):
                for descriptor, flags in self.events.poll():
                    require(not flags & select.POLLNVAL, "build_descriptor_invalid")
                    if descriptor == self.descriptors.get("wake-read"):
                        os.read(descriptor, 65536)
                        if self.stopped:
                            self.stop()
                    elif descriptor == self.descriptors.get("pidfd"):
                        require(bool(flags & select.POLLIN), "build_pidfd_observation")
                        self.exit_observed = True
                        self.events.unregister(descriptor)
                    elif descriptor in self.streams:
                        if self.streams[descriptor] is child.stdin:
                            self._input(descriptor)
                        else:
                            self._output(descriptor)
            child.wait()
            self.reaped = True
        for name in tuple(self.descriptors):
            self._dispose(name)
        self.drained = self.wake_error is None and (child is None or (
            self.exit_observed and self.reaped and self.stdout_eof and self.stderr_eof
            and child.stdin is not None and child.stdin.closed
            and child.stdout is not None and child.stdout.closed
            and child.stderr is not None and child.stderr.closed and not self.descriptors))
