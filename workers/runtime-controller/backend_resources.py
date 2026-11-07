"""Exact-ID source-free resources; all control remains outside workload inputs."""
import io
import json
import re
import tarfile
from dataclasses import dataclass
from typing import Final, Literal

from backend_process import Command, checked, require, run
from daemon import DOCKER, Daemon

NODE: Final = "docker.io/library/node@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d"
Role = Literal["security", "memory", "network", "proxy"]
SCRIPTS: Final = {"security": "collector.mjs", "memory": "collector-memory.mjs",
                 "network": "collector-network.mjs", "proxy": "proxy.mjs"}


@dataclass(frozen=True, slots=True)
class Inspection:
    identifier: str
    state: str
    oom: bool
    exit_code: int
    image: str
    pid: int
    runtime: str
    host_mounts: int
    cap_drop_all: bool
    seccomp_profile: str


class Resources:
    """A mutable ledger records only IDs returned by this owner's creation calls."""
    def __init__(self, daemon: Daemon, run_id: str, scope: Literal["qualification", "infrastructure"]):
        require(re.fullmatch(r"[a-f0-9]{32}", run_id) is not None, "run_identity")
        self.daemon = daemon
        self.run_id = run_id
        self.scope = scope
        self.containers: dict[str, Role] = {}
        self.networks: set[str] = set()
        self.borrowed_networks: set[str] = set()
        self.image = ""

    def acquire(self) -> None:
        self.daemon.check()
        checked(Command((*DOCKER, "pull", "--platform=linux/arm64", NODE), seconds=120, user=True))
        data = json.loads(checked(Command((*DOCKER, "image", "inspect", NODE), user=True)))
        require(isinstance(data, list) and len(data) == 1, "probe_image_inspection")
        image = data[0]
        require(image.get("Os") == "linux" and image.get("Architecture") == "arm64", "probe_image_platform")
        digests = image.get("RepoDigests")
        require(isinstance(digests, list) and any(
            item.endswith("@sha256:" + NODE.split("@sha256:")[1]) for item in digests), "probe_image_digest")
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image.get("Id", "")) is not None, "probe_image_config")
        self.image = image["Id"]

    def network(self, internal: bool) -> str:
        self.daemon.check()
        argv = (*DOCKER, "network", "create", "--driver=bridge", "--label=wakeio.owner=t6p",
                "--label=wakeio.run=" + self.run_id, "--label=wakeio.scope=" + self.scope)
        name = "wk-" + self.run_id + "-" + self.scope + "-" + str(len(self.networks))
        body = checked(Command((*argv, *(("--internal",) if internal else ()), name), user=True))
        identifier = body.decode("ascii").strip()
        require(re.fullmatch(r"[a-f0-9]{64}", identifier) is not None, "network_id")
        self.networks.add(identifier)
        data = json.loads(checked(Command((*DOCKER, "network", "inspect", identifier), user=True)))
        require(len(data) == 1 and data[0]["Id"] == identifier
                and data[0]["Labels"]["wakeio.run"] == self.run_id
                and data[0]["Internal"] is internal, "network_binding")
        return identifier

    def create(self, role: Role, network: str) -> str:
        self.daemon.check()
        require(network in self.networks | self.borrowed_networks and bool(self.image), "resource_binding")
        cpu, memory, pids = (0.5, 268435456, 64) if role == "proxy" else (2, 2147483648, 256)
        argv = (*DOCKER, "create", "--label=wakeio.owner=t6p", "--label=wakeio.run=" + self.run_id,
                "--label=wakeio.scope=" + self.scope,
                "--label=wakeio.role=" + role, "--network=" + network, "--user=65532:65532",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--cpus=" + str(cpu), "--memory=" + str(memory),
                "--memory-swap=" + str(memory), "--pids-limit=" + str(pids),
                "--entrypoint=/usr/local/bin/node", self.image, "/controller/" + SCRIPTS[role])
        identifier = checked(Command(argv, user=True)).decode("ascii").strip()
        require(re.fullmatch(r"[a-f0-9]{64}", identifier) is not None, "container_id")
        self.containers[identifier] = role
        self.inspect(identifier)
        return identifier

    def seed(self, identifier: str, files: tuple[tuple[str, bytes], ...]) -> None:
        require(self.inspect(identifier).state == "created", "seed_state")
        with io.BytesIO() as buffer:
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                directories = {"controller"}
                for name, _ in files:
                    parts = ("controller/" + name).split("/")
                    directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
                for name in sorted(directories, key=lambda path: (path.count("/"), path)):
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.DIRTYPE
                    info.uid = info.gid = 65532
                    info.mode = 0o500
                    archive.addfile(info)
                for name, body in files:
                    require(re.fullmatch(r"[a-zA-Z0-9_./-]+", name) is not None
                            and all(part not in ("", ".", "..") for part in name.split("/")), "helper_path")
                    info = tarfile.TarInfo("controller/" + name)
                    info.uid = info.gid = 65532
                    info.mode = 0o400
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
            checked(Command((*DOCKER, "cp", "-", identifier + ":/"), user=True), buffer.getvalue())

    def inspect(self, identifier: str) -> Inspection:
        self.daemon.check()
        require(identifier in self.containers, "foreign_container")
        data = json.loads(checked(Command((*DOCKER, "inspect", identifier), user=True)))
        require(isinstance(data, list) and len(data) == 1, "container_inspection")
        value = data[0]
        config, host, state = value["Config"], value["HostConfig"], value["State"]
        cpu, memory, pids = (500000000, 268435456, 64) if self.containers[identifier] == "proxy" else (
            2000000000, 2147483648, 256)
        labels = config["Labels"]
        require(value["Id"] == identifier and value["Image"] == self.image
                and labels["wakeio.run"] == self.run_id and labels["wakeio.owner"] == "t6p"
                and labels["wakeio.scope"] == self.scope
                and labels["wakeio.role"] == self.containers[identifier], "container_identity")
        require(config["Entrypoint"] == ["/usr/local/bin/node"]
                and config["Cmd"] == ["/controller/" + SCRIPTS[self.containers[identifier]]]
                and config.get("Healthcheck") is None, "container_command")
        environment = config["Env"]
        require(isinstance(environment, list) and len(environment) <= 5
                and all(isinstance(item, str) and "=" in item for item in environment), "container_environment")
        names = [item.split("=", 1)[0] for item in environment]
        require(len(set(names)) == len(names)
                and set(names).issubset({"PATH", "HOSTNAME", "HOME", "NODE_VERSION", "YARN_VERSION"}),
                "container_environment")
        require(config["User"] == "65532:65532" and host["ReadonlyRootfs"] is True
                and host["Privileged"] is False and host["CapDrop"] == ["ALL"]
                and host["Binds"] in (None, []) and value["Mounts"] == []
                and host["VolumesFrom"] in (None, []) and host["DeviceRequests"] in (None, [])
                and host["Devices"] in (None, []) and host["ExtraHosts"] in (None, [])
                and host["Dns"] in (None, []) and host["DnsSearch"] in (None, [])
                and host["PidMode"] == "" and host["IpcMode"] == "private"
                and host["NetworkMode"] in self.networks | self.borrowed_networks and not host["PortBindings"],
                "container_boundary")
        require(host["NanoCpus"] == cpu and host["Memory"] == memory and host["MemorySwap"] == memory
                and host["PidsLimit"] == pids and not host["CapAdd"] and not host["Devices"]
                and host["Runtime"] == "runc" and host["SecurityOpt"] == ["no-new-privileges"],
                "container_resources")
        require(type(state["OOMKilled"]) is bool and type(state["ExitCode"]) is int
                and type(state["Pid"]) is int, "container_state_types")
        return Inspection(identifier, state["Status"], state["OOMKilled"], state["ExitCode"],
                          value["Image"], state["Pid"], host["Runtime"], len(value["Mounts"]),
                          host["CapDrop"] == ["ALL"], "default")

    def borrow_network(self, identifier: str) -> None:
        value = json.loads(checked(Command((*DOCKER, "network", "inspect", identifier), user=True)))
        require(len(value) == 1 and value[0]["Id"] == identifier and value[0]["Internal"] is True
                and value[0]["Labels"]["wakeio.run"] == self.run_id
                and value[0]["Labels"]["wakeio.scope"] == "infrastructure", "network_borrow_identity")
        self.borrowed_networks.add(identifier)

    def execute(self, identifier: str) -> tuple[int, bytes]:
        require(self.inspect(identifier).state == "created", "container_state")
        # Docker start --attach attaches before start and waits on the exact container's exit.
        result = run(Command((*DOCKER, "start", "--attach", identifier), seconds=120, user=True))
        observed = self.inspect(identifier)
        require(observed.state == "exited" and observed.pid == 0, "container_exit_unconfirmed")
        return result.code, result.stdout

    def cleanup(self) -> None:
        for identifier in tuple(self.containers):
            observed = self.inspect(identifier)
            if observed.state == "running":
                checked(Command((*DOCKER, "stop", "--time=10", identifier), user=True))
                require(self.inspect(identifier).state == "exited", "container_stop_unconfirmed")
            checked(Command((*DOCKER, "rm", identifier), user=True))
            del self.containers[identifier]
        owned = checked(Command((*DOCKER, "ps", "--all", "--quiet", "--no-trunc",
                                 "--filter=label=wakeio.run=" + self.run_id,
                                 "--filter=label=wakeio.scope=" + self.scope), user=True))
        require(owned == b"", "container_remainder")
        for identifier in tuple(self.networks):
            checked(Command((*DOCKER, "network", "rm", identifier), user=True))
            self.networks.remove(identifier)
        owned = checked(Command((*DOCKER, "network", "ls", "--quiet", "--no-trunc",
                                 "--filter=label=wakeio.run=" + self.run_id,
                                 "--filter=label=wakeio.scope=" + self.scope), user=True))
        require(owned == b"", "network_remainder")
