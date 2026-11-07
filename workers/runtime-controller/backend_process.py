"""Fixed guest tools with bounded pipes and real process exit acknowledgements."""
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Final


class BackendError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise BackendError(code)


ENV: Final = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
              "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
USER_ENV: Final = {**ENV, "HOME": "/home/wakeio-m1", "XDG_RUNTIME_DIR": "/run/user/10001",
                  "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/10001/bus",
                  "DOCKER_CONFIG": "/home/wakeio-m1/.docker"}


@dataclass(frozen=True, slots=True)
class Command:
    argv: tuple[str, ...]
    seconds: float = 30
    user: bool = False


@dataclass(frozen=True, slots=True)
class Result:
    code: int
    stdout: bytes


def run(command: Command, body: bytes = b"") -> Result:
    require(0 < command.seconds <= 120 and command.argv[0].startswith("/"), "command_bound")
    require(len(body) <= 1024 * 1024, "input_bound")
    end = time.monotonic() + command.seconds
    with subprocess.Popen(command.argv, env=USER_ENV if command.user else ENV, start_new_session=True,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          user=10001 if command.user else None,
                          group=10001 if command.user else None, extra_groups=()) as child:
        require(child.stdin is not None and child.stdout is not None and child.stderr is not None,
                "process_pipes")
        with selectors.DefaultSelector() as events:
            events.register(child.stdout, selectors.EVENT_READ, "out")
            events.register(child.stderr, selectors.EVENT_READ, "err")
            events.register(child.stdin, selectors.EVENT_WRITE, "in")
            pidfd = os.pidfd_open(child.pid)
            events.register(pidfd, selectors.EVENT_READ, "exit")
            output = bytearray()
            used = offset = 0
            try:
                while events.get_map():
                    remaining = end - time.monotonic()
                    require(remaining > 0, "command_deadline")
                    ready = events.select(remaining)
                    require(bool(ready), "command_deadline")
                    for key, _ in ready:
                        if key.data == "exit":
                            events.unregister(pidfd)
                            continue
                        if key.data == "in":
                            offset += os.write(key.fd, body[offset:offset + 4096]) if offset < len(body) else 0
                            if offset == len(body):
                                events.unregister(key.fileobj)
                                child.stdin.close()
                            continue
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            events.unregister(key.fileobj)
                            continue
                        used += len(chunk)
                        require(used <= 1024 * 1024, "command_output_bound")
                        if key.data == "out":
                            output.extend(chunk)
                status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
                code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                return Result(code, bytes(output))
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                child.wait(timeout=5)
                os.close(pidfd)


def checked(command: Command, body: bytes = b"") -> bytes:
    result = run(command, body)
    require(result.code == 0, "native_command_failed:" + os.path.basename(command.argv[0]))
    return result.stdout
