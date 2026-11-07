"""Actual guest baseline, autostart suppression and post-state audit."""
import os

from install_prepare import Prepared
from install_process import Deadline, checked
from install_records import installed
from seal_files import Files, identity, write_new
from seal_types import require

UNITS = ("docker.service", "docker.socket", "containerd.service")


def inactive(deadline: Deadline) -> None:
    for name in UNITS:
        raw = checked(("/usr/bin/systemctl", "show", name, "--property=ActiveState"), deadline)
        values = dict(line.split("=", 1) for line in raw.decode("ascii").splitlines())
        require(values.get("ActiveState") == "inactive", "rootful_unit")
    for path in ("/run/docker.sock", "/run/containerd/containerd.sock"):
        require(not os.path.lexists(path), "rootful_socket")
    for entry in os.scandir("/proc"):
        if entry.name.isdecimal():
            try:
                with open(entry.path + "/comm", "rb") as stream:
                    name = stream.read(128).strip()
                require(name not in (b"dockerd", b"containerd"), "rootful_process")
            except FileNotFoundError:
                continue  # Process disappearance is normal during this bounded enumeration.


def service_limits() -> None:
    with open("/proc/self/cgroup", "r", encoding="ascii") as stream:
        rows = stream.read(4096).splitlines()
    require(len(rows) == 1 and rows[0].startswith("0::/system.slice/wakeio-install-"), "install_unit")
    relative = rows[0][3:]
    require(relative.endswith(".service") and ".." not in relative, "install_cgroup")
    directory = "/sys/fs/cgroup" + relative
    with open(directory + "/cpu.max", "r", encoding="ascii") as stream:
        quota, period = stream.read(128).split()
    require(quota.isdecimal() and int(quota) == 2 * int(period), "install_cpu")
    for name, expected in (("memory.max", "4294967296"), ("pids.max", "256")):
        with open(directory + "/" + name, "r", encoding="ascii") as stream:
            require(stream.read(128).strip() == expected, "install_" + name)


class Autostart:
    """Only explicitly created policy/masks are owned; unknown state is retained."""
    def __init__(self) -> None:
        self.masks: list[tuple[str, tuple[int, ...]]] = []
        self.policy: tuple[int, ...] | None = None

    def install(self, files: Files, deadline: Deadline) -> None:
        inactive(deadline)
        path = "/usr/sbin/policy-rc.d"
        write_new(path, b"#!/bin/sh\nexit 101\n")
        os.chmod(path, 0o755)
        self.policy = identity(os.lstat(path))
        files.capture(path, 64)
        for name in UNITS:
            path = "/etc/systemd/system/" + name
            require(not os.path.lexists(path), "inherited_unit_mask")
            os.symlink("/dev/null", path)
            self.masks.append((path, identity(os.lstat(path))))
        checked(("/usr/bin/systemctl", "daemon-reload"), deadline)
        self.check()
        inactive(deadline)

    def check(self) -> None:
        require(self.policy is not None and identity(os.lstat("/usr/sbin/policy-rc.d")) == self.policy,
                "policy_replaced")
        for path, metadata in self.masks:
            require(identity(os.lstat(path)) == metadata and os.readlink(path) == "/dev/null", "mask_replaced")

    def cleanup_policy(self) -> None:
        if self.policy is not None:
            self.check()
            os.unlink("/usr/sbin/policy-rc.d")
        # Rootful masks intentionally survive until the controller destroys this VM.


def post_state(prepared: Prepared, files: Files, deadline: Deadline) -> str:
    files.check(mutable_status=True)
    require(checked(("/usr/bin/dpkg", "--audit"), deadline) == b"", "post_dpkg_audit")
    with Files() as observation:
        status = observation.capture("/var/lib/dpkg/status", 32 * 1024 * 1024)
        actual = installed(status.read())
        expected = dict(prepared.baseline)
        expected.update((p.name, p.new) for p in prepared.packages)
        require(actual == expected, "post_package_closure")
        require(checked(("/usr/bin/dpkg", "--verify", *(p.name for p in prepared.packages)), deadline) == b"",
                "post_installed_bytes")
        inactive(deadline)
        return status.sha256
