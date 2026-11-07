"""Linux-only immutable consumption view inside the owned transient service."""
import ctypes
import fcntl
import os
import socket
import stat
from contextlib import ExitStack

from seal_files import Files
from seal_types import BASE, require


def syscall(result: int, code: str) -> None:
    require(result == 0, code + ":" + str(ctypes.get_errno()))


def mount(source: bytes | None, target: str, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    syscall(libc.mount(source, os.fsencode(target), None, ctypes.c_ulong(flags), None), "mount")


def sandbox(files: Files) -> None:
    require(os.uname().sysname == "Linux" and os.geteuid() == 0, "linux_root_required")
    files.check()
    libc = ctypes.CDLL(None, use_errno=True)
    network = os.stat("/proc/self/ns/net").st_ino
    syscall(libc.unshare(0x40000000 | 0x00020000), "unshare")
    require(os.stat("/proc/self/ns/net").st_ino != network, "private_network")
    mount(None, "/", 1 << 18 | 16384)  # MS_PRIVATE | MS_REC, before any bind.
    with ExitStack() as retained:
        for anchor in files.anchors:
            if anchor.path == "/var/lib/dpkg/status" or anchor.path.endswith("/lock"):
                continue
            body = anchor.read()
            fd = os.memfd_create("wakeio-install", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            retained.callback(os.close, fd)
            offset = 0
            while offset < len(body):
                offset += os.write(fd, body[offset:])
            os.fchmod(fd, stat.S_IMODE(anchor.metadata[2]))
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == seals, "memfd_seals")
            mount(os.fsencode("/proc/self/fd/" + str(fd)), anchor.path, 4096)
            mount(None, anchor.path, 4096 | 32 | 1 | 2 | 4)
        # Empty config dirs cannot acquire inherited hooks/sources after the check.
        for name in ("empty", "lists", "archives"):
            path = BASE + "/" + name
            mount(os.fsencode(path), path, 4096)
            mount(None, path, 4096 | 32 | 1 | 2 | 4)
        # Native APT must still acquire its own archive/list locks. Bind only those
        # already-owned zero-byte files writable; package/index mounts stay sealed.
        for anchor in files.anchors:
            if anchor.path in (BASE + "/archives/lock", BASE + "/lists/lock"):
                mount(os.fsencode("/proc/self/fd/" + str(anchor.fd)), anchor.path, 4096)
        for path in ("/run/systemd", "/run/dbus"):
            if os.path.isdir(path):
                syscall(libc.mount(b"tmpfs", os.fsencode(path), b"tmpfs", 2 | 4 | 8,
                                   b"size=64k,mode=000"), "hide_service_bus")
        mount(b"/sys/fs/cgroup", "/sys/fs/cgroup", 4096)
        mount(None, "/sys/fs/cgroup", 4096 | 32 | 1 | 2 | 4 | 8)
        # No remount, namespace/cgroup escape or privileged network operation after exec.
        for capability in (12, 13, 16, 17, 19, 21, 22, 23, 25, 26, 27, 32, 33, 38, 39, 40):
            syscall(libc.prctl(24, capability, 0, 0, 0), "capability_drop")
        syscall(libc.prctl(38, 1, 0, 0, 0), "no_new_privileges")


def peer(channel: socket.socket, apt_pid: int) -> bytes:
    """SCM_CREDENTIALS identifies the actual sender, not socketpair's creator."""
    import struct
    body, ancillary, flags, _ = channel.recvmsg(65537, socket.CMSG_SPACE(struct.calcsize("3i")))
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "hook_message_truncated")
    credentials = [data for level, kind, data in ancillary
                   if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
    require(len(credentials) == 1, "hook_credentials")
    pid, uid, gid = struct.unpack("3i", credentials[0])
    require(uid == gid == 0 and pid != apt_pid, "hook_sender")
    with open(f"/proc/{pid}/cmdline", "rb") as stream:
        command = stream.read(8193)
    require(len(command) <= 8192 and b"/install_hook.py\x00" in command, "hook_executable")
    current = pid
    for _ in range(8):
        with open(f"/proc/{current}/stat", "rb") as stream:
            fields = stream.read(8192).rsplit(b") ", 1)[1].split()
        parent = int(fields[1])
        if parent == apt_pid:
            return body
        require(parent > 1 and parent != current, "hook_ancestry")
        current = parent
    require(False, "hook_ancestry_depth")
    return b""
