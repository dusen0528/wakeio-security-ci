"""One UID10001 systemd-user engine, never a system Docker service."""
import json
import os
import re
import stat
from pathlib import Path
from dataclasses import dataclass
from typing import Final

from backend_process import Command, checked, require, run

SOCKET: Final = "/run/user/10001/docker.sock"
DOCKER: Final = ("/usr/bin/docker", "--host=unix://" + SOCKET)
USERCTL: Final = ("/usr/bin/systemctl", "--user")
UNIT: Final = """[Unit]
Description=Owned Wakeio rootless engine
[Service]
Type=notify
NotifyAccess=all
ExecStart=/usr/bin/dockerd-rootless.sh --host=unix:///run/user/10001/docker.sock --exec-opt=native.cgroupdriver=systemd
Environment=HOME=/home/wakeio-m1 XDG_RUNTIME_DIR=/run/user/10001 DOCKER_CONFIG=/home/wakeio-m1/.docker
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=slirp4netns
Delegate=yes
KillMode=mixed
TimeoutStartSec=60
TimeoutStopSec=30
Restart=no
LimitNOFILE=65536
"""

@dataclass(frozen=True, slots=True)
class EngineInfo:
    identifier: str
    version: str
    cgroup_version: str
    driver: str
    security: tuple[str, ...]


def user_file(path: Path, content: bytes) -> None:
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        os.fchown(stream.fileno(), 10001, 10001)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


class Daemon:
    """Mutable identities are bound once and checked on each privileged operation."""
    def __init__(self) -> None:
        self.identity = ""
        self.socket_identity: tuple[int, int] | None = None
        self.invocation = ""
        self.started = False

    def start(self) -> str:
        require(not self.started, "daemon_replay")
        for name in ("docker.service", "docker.socket", "containerd.service"):
            state = run(Command(("/usr/bin/systemctl", "is-active", name)))
            require(state.code != 0, "rootful_active")
        root = Path("/home/wakeio-m1")
        for name in (".config", ".config/systemd", ".config/systemd/user", ".docker"):
            path = root / name
            if path.exists():
                require(path.is_dir() and not path.is_symlink() and path.stat().st_uid == 10001, "user_directory")
            else:
                path.mkdir(mode=0o700)
                os.chown(path, 10001, 10001)
        user_file(root / ".config/systemd/user/docker.service", UNIT.encode("ascii"))
        checked(Command((*USERCTL, "daemon-reload"), user=True))
        # systemctl subscribes to JobRemoved before dispatch and waits for Type=notify's ready event.
        checked(Command((*USERCTL, "start", "docker.service"), seconds=65, user=True))
        self.started = True
        s = os.lstat(SOCKET)
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 10001, "daemon_socket")
        os.chmod(SOCKET, 0o600)
        self.socket_identity = (s.st_dev, s.st_ino)
        unit = self.unit()
        require(unit["ActiveState"] == "active" and unit["SubState"] == "running", "daemon_unit_state")
        self.invocation = unit["InvocationID"]
        info = self.info()
        require(info.cgroup_version == "2" and info.driver == "systemd", "daemon_cgroup")
        require("name=rootless" in info.security, "daemon_rootless")
        self.identity = info.identifier + ":" + self.invocation
        self.check()
        return self.identity

    def unit(self) -> dict[str, str]:
        body = checked(Command((*USERCTL, "show", "docker.service", "--property=ActiveState,SubState,"
                                "InvocationID,MainPID,ControlGroup"), user=True)).decode("ascii")
        result = dict(line.split("=", 1) for line in body.splitlines())
        require(set(result) == {"ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup"},
                "daemon_unit_fields")
        return result

    def info(self) -> EngineInfo:
        value = json.loads(checked(Command((*DOCKER, "info", "--format", "{{json .}}"), user=True)))
        require(isinstance(value, dict), "daemon_info")
        fields = [value.get(name) for name in ("ID", "ServerVersion", "CgroupVersion", "CgroupDriver")]
        require(all(isinstance(item, str) and 0 < len(item) <= 256 for item in fields), "daemon_info_fields")
        security = value.get("SecurityOptions")
        require(isinstance(security, list) and len(security) <= 16
                and all(isinstance(item, str) for item in security), "daemon_security_fields")
        require(tuple(option for option in security if option.startswith("name=seccomp"))
                == ("name=seccomp,profile=builtin",), "daemon_seccomp_profile")
        return EngineInfo(*fields, tuple(security))

    def check(self) -> None:
        require(self.started, "daemon_closed")
        s = os.lstat(SOCKET)
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 10001 and stat.S_IMODE(s.st_mode) == 0o600
                and (s.st_dev, s.st_ino) == self.socket_identity, "daemon_socket_changed")
        unit = self.unit()
        require(unit["InvocationID"] == self.invocation and unit["ActiveState"] == "active", "daemon_restarted")
        pid = unit["MainPID"]
        require(re.fullmatch(r"[1-9][0-9]*", pid) is not None, "daemon_pid")
        status = Path("/proc/" + pid + "/status").read_text()
        require("\nUid:\t10001\t10001\t10001\t10001\n" in status, "daemon_uid")
        cgroup = Path("/proc/" + pid + "/cgroup").read_text().strip()
        require(cgroup == "0::" + unit["ControlGroup"]
                and "/user-10001.slice/user@10001.service/" in cgroup, "daemon_delegation")
        info = self.info()
        require(info.identifier + ":" + self.invocation == self.identity, "daemon_identity_changed")

    def stop(self) -> None:
        self.check()
        checked(Command((*USERCTL, "stop", "docker.service"), seconds=35, user=True))
        unit = self.unit()
        require(unit["MainPID"] == "0" and unit["ActiveState"] == "inactive", "daemon_stop_unconfirmed")
        require(not os.path.lexists(SOCKET), "daemon_socket_retained")
        self.started = False
