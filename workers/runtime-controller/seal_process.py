"""Guest service descendants: kernel exit events, never timer-as-drain."""
import ctypes
import os
import selectors
import signal
from contextlib import ExitStack

from install_process import Deadline
from seal_types import require


def group(pid: int) -> str:
    with open(f"/proc/{pid}/cgroup", "r", encoding="ascii") as stream:
        lines = stream.read(4096).splitlines()
    require(len(lines) == 1 and lines[0].startswith("0::/system.slice/wakeio-install-"), "owned_service")
    path = lines[0][3:]
    require(path.endswith(".service") and ".." not in path, "owned_service_path")
    return path


def members(path: str) -> set[int]:
    with open("/sys/fs/cgroup" + path + "/cgroup.procs", "r", encoding="ascii") as stream:
        raw = stream.read(4097)
    require(len(raw) <= 4096, "service_process_bound")
    result = {int(value) for value in raw.split()}
    require(len(result) <= 256 and os.getpid() in result, "service_membership")
    return result - {os.getpid()}


def own_service() -> str:
    path = group(os.getpid())
    require(not members(path), "inherited_service_process")
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, "service_subreaper")
    return path


def drain_service(path: str, deadline: Deadline) -> None:
    require(group(os.getpid()) == path, "service_replaced")
    with ExitStack() as lifetime, selectors.DefaultSelector() as events:
        for pid in members(path):
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            lifetime.callback(os.close, fd)
            require(group(pid) == path, "cleanup_foreign_process")
            events.register(fd, selectors.EVENT_READ, pid)
        # Subscribe to every original PID before any signal. PID reuse cannot
        # redirect these requests, and an empty second inventory is mandatory.
        for key in list(events.get_map().values()):
            signal.pidfd_send_signal(key.fd, signal.SIGKILL)
        while events.get_map():
            ready = events.select(deadline.remaining())
            require(bool(ready), "guest_drain_unconfirmed")
            for key, _ in ready:
                events.unregister(key.fd)
                try:
                    os.waitpid(key.data, 0)
                except ChildProcessError:
                    # The pidfd event independently proves exit even if this
                    # process was reaped by its still-running original parent.
                    continue
        require(not members(path), "guest_descendants_retained")
