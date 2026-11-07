"""Forked installer with an inherited, credential-checked single-use hook channel."""
import os
import selectors
import signal
import socket

from install_config import apt
from install_prepare import Prepared
from install_process import Deadline
from install_sandbox import peer, sandbox
from seal_files import Files
from seal_operation import Operation
from seal_types import ENV, InstallError, require


def installer(files: Files, channel: socket.socket, prepared: Prepared) -> None:
    os.setsid()
    sandbox(files)
    channel.sendall(b"READY")
    channel.settimeout(15)
    require(channel.recv(8) == b"GO", "installer_gate")
    os.set_inheritable(channel.fileno(), True)
    argv = apt(("--no-download", "install", *(p.name + "=" + p.new.version for p in prepared.packages)))
    env = {**ENV, "WAKEIO_INSTALL_FD": str(channel.fileno())}
    # No apt/tool chatter on the private controller protocol.
    with open("/dev/null", "r+b") as sink:
        os.dup2(sink.fileno(), 0)
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    os.execve(argv[0], argv, env)


def transaction(owner: Operation, files: Files, channels: tuple[socket.socket, socket.socket]) -> str:
    prepared = owner.consume()  # Irreversible before the first child allocation.
    deadline = Deadline(300)
    parent, child = channels
    parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            installer(files, child, prepared)
        except (InstallError, OSError, UnicodeError):
            os._exit(125)
        os._exit(125)
    child.close()
    fd = os.pidfd_open(pid)
    digest = ""
    try:
        with selectors.DefaultSelector() as events:
            events.register(parent, selectors.EVENT_READ, "channel")
            events.register(fd, selectors.EVENT_READ, "exit")
            events.register(0, selectors.EVENT_READ, "abort")
            ready = False
            while True:
                selected = events.select(deadline.remaining())
                require(bool(selected), "installer_deadline")
                for key, _ in selected:
                    match key.data:
                        case "abort":
                            raise InstallError("controller_closed_or_replayed")
                        case "exit":
                            result = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOWAIT)
                            require(result.si_code == os.CLD_EXITED and result.si_status == 0, "installer_exit")
                            require(bool(digest), "missing_actual_hook")
                            return digest
                        case "channel":
                            if not ready:
                                require(parent.recv(16) == b"READY", "installer_ready")
                                files.check()
                                parent.sendall(b"GO")
                                ready = True
                            else:
                                require(not digest, "hook_replay")
                                payload = peer(parent, pid)
                                digest = owner.hook(payload)
                                parent.sendall(b"ACCEPT")
                        case unexpected:
                            raise InstallError("unknown_installer_event:" + str(unexpected))
    finally:
        # WNOWAIT retains the child's PID until all its process-group members
        # have been signalled. Reaping before killpg would introduce PID reuse.
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(fd)
