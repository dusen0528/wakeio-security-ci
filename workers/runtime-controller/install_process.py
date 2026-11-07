"""Bounded native tools; no shell, inherited environment, retry or polling."""
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

from seal_types import ENV, InstallError, require


@dataclass(frozen=True, slots=True)
class Result:
    code: int
    stdout: bytes
    stderr: bytes


class Deadline:
    def __init__(self, seconds: float):
        require(0 < seconds <= 900, "deadline_bound")
        self.end = time.monotonic() + seconds

    def remaining(self) -> float:
        value = self.end - time.monotonic()
        require(value > 0, "deadline_expired")
        return value


def run(argv: tuple[str, ...], deadline: Deadline, limit: int = 1024 * 1024) -> Result:
    require(argv[0].startswith("/"), "absolute_tool")
    deadline.remaining()
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=ENV, start_new_session=True) as child:
        require(child.stdout is not None and child.stderr is not None, "process_pipes")
        streams = (child.stdout, child.stderr)
        buffers = [bytearray(), bytearray()]
        pidfd = os.pidfd_open(child.pid)
        exited = False
        try:
            with selectors.DefaultSelector() as events:
                for index, stream in enumerate(streams):
                    events.register(stream, selectors.EVENT_READ, index)
                events.register(0, selectors.EVENT_READ, 2)
                events.register(pidfd, selectors.EVENT_READ, 3)
                while len(events.get_map()) > 1:
                    ready = events.select(deadline.remaining())
                    require(bool(ready), "process_deadline")
                    for key, _ in ready:
                        require(key.data != 2, "controller_closed_or_early_command")
                        if key.data == 3:
                            exited = True
                            events.unregister(pidfd)
                            continue
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            events.unregister(key.fileobj)
                            continue
                        buffers[key.data].extend(chunk)
                        require(sum(map(len, buffers)) <= limit, "process_output_bound")
            require(exited, "process_exit_unobserved")
            status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
            code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
            return Result(code, bytes(buffers[0]), bytes(buffers[1]))
        finally:
            # The exact session we created, including descendants, is ours.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            child.wait(timeout=5)
            os.close(pidfd)


def checked(argv: tuple[str, ...], deadline: Deadline) -> bytes:
    result = run(argv, deadline)
    if result.code != 0:
        raise InstallError("native_tool_exit:" + os.path.basename(argv[0]) + ":" + str(result.code))
    return result.stdout
