#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fixed source-free guest bootstrap, embedded by the pinned controller configuration."""
import os
import pwd
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/wakeio-controller")
from backend_process import Command, checked, require


def write_new(path: str, body: str) -> None:
    with open(path, "x", encoding="ascii") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def subordinate_ids(path: str) -> None:
    rows = Path(path).read_text(encoding="ascii").splitlines()
    existing = []
    for row in rows:
        name, start, count = row.split(":")
        if name == "wakeio-m1":
            existing.append(row)
        else:
            require(int(start) + int(count) <= 231072 or int(start) >= 296608, "subid_overlap")
    require(not existing or existing == ["wakeio-m1:231072:65536"], "subid_identity")
    if not existing:
        with open(path, "a", encoding="ascii") as stream:
            stream.write("wakeio-m1:231072:65536\n")


def bootstrap() -> None:
    require(os.getuid() == 0 and os.uname().machine == "aarch64", "guest_identity")
    require(Path("/usr/lib/os-release").read_text().find('VERSION_ID="24.04"') >= 0, "guest_release")
    require(Path("/sys/fs/cgroup/cgroup.controllers").exists(), "cgroup_v2_required")
    require(pwd.getpwnam("wakeio-admin").pw_uid == 10000, "admin_uid")
    try:
        target = pwd.getpwnam("wakeio-m1")
    except KeyError:
        checked(Command(("/usr/sbin/useradd", "--uid", "10001", "--create-home", "--shell", "/bin/bash",
                         "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", "wakeio-m1")))
        target = pwd.getpwnam("wakeio-m1")
    require(target.pw_uid == 10001 and target.pw_gid == 10001, "engine_uid")
    listing = checked(Command(("/usr/bin/sudo", "-n", "-l", "-U", "wakeio-m1"))).decode("ascii")
    require(re.fullmatch(r"User wakeio-m1 is not allowed to run sudo on [a-zA-Z0-9.-]+\.\n", listing)
            is not None, "engine_sudo")
    for path in ("/etc/subuid", "/etc/subgid"):
        subordinate_ids(path)
    directory = "/etc/systemd/system/user@10001.service.d"
    os.mkdir(directory, 0o700)
    write_new(directory + "/wakeio.conf",
              "[Service]\nDelegate=cpu cpuset io memory pids\nCPUQuota=600%\nMemoryMax=6G\nTasksMax=1024\n")
    checked(Command(("/usr/bin/systemctl", "daemon-reload")))
    checked(Command(("/usr/bin/loginctl", "enable-linger", "wakeio-m1")))
    checked(Command(("/usr/bin/systemctl", "start", "user@10001.service")))
    controllers = Path("/sys/fs/cgroup/user.slice/user-10001.slice/user@10001.service/cgroup.controllers")
    require({"cpu", "memory", "pids"}.issubset(controllers.read_text().split()), "delegation_missing")
    state = Path("/run/wakeio-m1")
    state.mkdir(mode=0o750)
    os.chown(state, 0, 10000)
    require(stat.S_IMODE(state.stat().st_mode) == 0o750, "state_mode")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[a-f0-9-]{36}", boot) is not None, "boot_id")
    write_new(str(state / "boot"), boot + "\n")


if __name__ == "__main__":
    bootstrap()
