"""Actual source-free collector. Probe removal is separate from the live daemon lifetime."""
import hashlib
import ipaddress
import json
import socket
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, Literal

from backend_process import Command, checked, require
from backend_resources import Resources
from daemon import Daemon, USERCTL
from proxy_owner import Mirror


@dataclass(frozen=True, slots=True)
class Qualification:
    artifact_sha256: str
    daemon_version: str
    runtime_version: str
    security_options: tuple[str, ...]
    cgroup_version: int
    cgroup_driver: str
    delegated_unit: str
    controllers: tuple[str, ...]
    cpu_quota: int
    cpu_period: int
    memory_max: int
    pids_max: int
    target_uid: int
    effective_caps: str
    seccomp_mode: int
    no_new_privileges: bool
    read_only_rootfs: bool
    secret_environment_empty: bool
    runtime: str
    host_mounts: int
    cap_drop_all: bool
    seccomp_profile: str
    cpu_enforced: bool
    memory_enforced: bool
    pids_enforced: bool
    build_repository: bool
    build_denied: bool
    runtime_denied: bool
    probe_cleanup_confirmed: bool


ControllerName = Literal["cpu", "memory", "pids"]
OwnerKind = Literal["baseline", "daemon", "container", "structural"]
P: Final = Path("/sys/fs/cgroup/user.slice/user-10001.slice")
U: Final = P / "user@10001.service"


@dataclass(frozen=True, slots=True)
class DelegationRefusal:
    missing: tuple[ControllerName, ...]
    kind: Literal["refused"] = "refused"
    phase: Literal["qualification"] = "qualification"
    code: Literal["delegation_missing"] = "delegation_missing"


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    cgroup: str
    dev: str
    ino: str


@dataclass(frozen=True, slots=True)
class UnitIdentity(NodeIdentity):
    invocationId: str
    mainPid: int
    startTicks: str


@dataclass(frozen=True, slots=True)
class GroupIdentity:
    relative: str
    dev: str
    ino: str
    ownerKind: OwnerKind
    ownerId: str


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    startTicks: str
    relativeCgroup: str
    ownerId: str


@dataclass(frozen=True, slots=True)
class Ownership:
    version: int
    run: str
    boot: str
    daemon: str
    helper: str
    parent: NodeIdentity
    unit: UnitIdentity
    groups: tuple[GroupIdentity, ...]
    processRoots: tuple[ProcessIdentity, ...]


def node_identity(path: Path) -> NodeIdentity:
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and not path.is_symlink(), "inventory_directory")
    return NodeIdentity(str(path).removeprefix("/sys/fs/cgroup"), str(value.st_dev), str(value.st_ino))


def process_identity(pid: int, owner: str) -> ProcessIdentity:
    require(type(pid) is int and 0 < pid <= 4194304, "inventory_pid")
    root = Path("/proc") / str(pid)
    value = (root / "stat").read_text().rsplit(") ", 1)[1].split()
    require(len(value) >= 20 and value[19].isdigit(), "inventory_start_time")
    group = (root / "cgroup").read_text().strip()
    prefix = "0::" + str(U).removeprefix("/sys/fs/cgroup")
    require(group == prefix or group.startswith(prefix + "/"), "inventory_process_group")
    return ProcessIdentity(pid, value[19], group[len(prefix):].lstrip("/") or ".", owner)


def user_unit() -> UnitIdentity:
    command = ("/usr/bin/systemctl", "show", "user@10001.service",
               "--property=InvocationID,MainPID,ControlGroup,ActiveState")
    data = dict(line.split("=", 1) for line in checked(Command(command)).decode("ascii").splitlines())
    node = node_identity(U)
    require(data["ActiveState"] == "active" and data["ControlGroup"] == node.cgroup
            and len(data["InvocationID"]) == 32 and data["MainPID"].isdigit(), "inventory_unit")
    pid = int(data["MainPID"])
    require("\nUid:\t10001\t10001\t10001\t10001\n" in
            Path(f"/proc/{pid}/status").read_text(), "inventory_manager_uid")
    process = process_identity(pid, data["InvocationID"])
    return UnitIdentity(node.cgroup, node.dev, node.ino, data["InvocationID"], pid, process.startTicks)


def hierarchy() -> tuple[NodeIdentity, ...]:
    nodes = []
    require([path.name for path in P.iterdir() if path.is_dir()] == ["user@10001.service"], "inventory_parent")
    for path, directories, _ in os.walk(U, followlinks=False):
        require(all(not (Path(path) / child).is_symlink() for child in directories), "inventory_symlink")
        nodes.append(node_identity(Path(path)))
        require(len(nodes) <= 64, "inventory_group_bound")
    return tuple(sorted(nodes, key=lambda node: node.cgroup))


def baseline_inventory(run_id: str, helper_hash: str) -> Ownership:
    checked(Command((*USERCTL, "show", "--property=Version"), user=True))
    unit = user_unit()
    groups = tuple(GroupIdentity(node.cgroup[len(unit.cgroup):].lstrip("/") or ".",
                                 node.dev, node.ino, "baseline", unit.invocationId) for node in hierarchy())
    processes = tuple(process_identity(int(pid), group.ownerId) for group in groups
                      for pid in (U / group.relative / "cgroup.procs").read_text().split())
    require(len(processes) <= 256, "inventory_pid_bound")
    return Ownership(1, run_id, Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                     "", helper_hash, node_identity(P), unit, groups, processes)


def owned_inventory(base: Ownership, daemon: Daemon, resources: Resources) -> Ownership:
    daemon.check()
    require(user_unit() == base.unit and node_identity(P) == base.parent, "inventory_identity_changed")
    baseline = {group.relative: group for group in base.groups}
    roots: dict[str, tuple[OwnerKind, str]] = {
        process_identity(int(daemon.unit()["MainPID"]), daemon.identity).relativeCgroup: ("daemon", daemon.identity)}
    for identifier, role in resources.containers.items():
        require(role == "proxy", "inventory_workload")
        observed = resources.inspect(identifier)
        require(observed.state == "running", "inventory_container_state")
        group = checked(Command((*USERCTL, "show", "docker-" + identifier + ".scope",
                                 "--property=ControlGroup", "--value"), user=True)).decode("ascii").strip()
        require(group.startswith(base.unit.cgroup + "/") and group.endswith("/docker-" + identifier + ".scope"),
                "inventory_container_group")
        roots[group[len(base.unit.cgroup) + 1:]] = ("container", identifier)
    groups = []
    for node in hierarchy():
        relative = node.cgroup[len(base.unit.cgroup):].lstrip("/") or "."
        if relative in baseline:
            previous = baseline[relative]
            require((previous.dev, previous.ino) == (node.dev, node.ino), "inventory_baseline_changed")
            kind, owner = previous.ownerKind, previous.ownerId
        else:
            matches = [(path, identity) for path, identity in roots.items()
                       if relative == path or relative.startswith(path + "/")]
            if matches:
                kind, owner = max(matches, key=lambda item: len(item[0]))[1]
            else:
                require(any(path.startswith(relative + "/") for path in roots), "inventory_foreign_group")
                kind, owner = "structural", base.run
        groups.append(GroupIdentity(relative, node.dev, node.ino, kind, owner))
    require(set(baseline).issubset(group.relative for group in groups), "inventory_baseline_missing")
    processes = tuple(process_identity(int(pid), group.ownerId) for group in groups
                      for pid in (U / group.relative / "cgroup.procs").read_text().split())
    require(len(processes) <= 256 and set(base.processRoots).issubset(processes), "inventory_process_changed")
    for process in processes:
        if process.relativeCgroup in baseline:
            require(process in base.processRoots, "inventory_foreign_process")
    return replace(base, daemon=daemon.identity, groups=tuple(groups), processRoots=processes)


def helper(name: str) -> bytes:
    path = Path("/usr/local/lib/wakeio-controller") / name
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0, "collector_helper_identity")
    body = path.read_bytes()
    require(0 < len(body) <= 131072, "collector_helper_bound")
    return body


def endpoints(mirror: Mirror) -> tuple[tuple[str, int], ...]:
    routes = json.loads(checked(Command(("/usr/sbin/ip", "-j", "route", "show", "default"))))
    require(isinstance(routes, list) and len(routes) == 1, "guest_gateway")
    gateway = routes[0]["gateway"]
    require(ipaddress.ip_address(gateway).is_private, "guest_gateway")
    addresses = json.loads(checked(Command(("/usr/sbin/ip", "-j", "address", "show", "scope", "global"))))
    guest = [entry["local"] for interface in addresses for entry in interface["addr_info"]
             if entry["family"] == "inet" and entry["local"].startswith("192.168.5.")]
    require(len(guest) == 1, "guest_management_address")
    return ((gateway, 22), ("169.254.169.254", 80), (mirror.network.ipv6, 443), (guest[0], 22))


def network_probe(resources: Resources, mirror: Mirror, phase: str) -> bool:
    network = mirror.build if phase == "BUILD" else resources.network(True)
    # A qualification container may join the live owner's exact internal BUILD network.
    if network == mirror.build:
        resources.borrow_network(network)
    identifier = resources.create("network", network)
    denied = [{"host": ip, "port": port} for ip, port in endpoints(mirror)]
    denied.append({"host": mirror.network.maven[0], "port": 443})
    config = json.dumps({"phase": phase, "denied": denied}).encode("ascii")
    resources.seed(identifier, (("collector-network.mjs", helper("collector-network.mjs")),
                                ("endpoints.json", config), ("mirror.crt", mirror.certificate)))
    code, body = resources.execute(identifier)
    value = json.loads(body)
    require(code == 0 and value["phase"] == phase and len(value["blocked"]) == len(denied), "network_probe")
    require(all(item is True for item in value["blocked"]), "network_escape_or_unconfirmed")
    require(phase != "BUILD" or value["repository"] is True, "repository_unavailable")
    return True


def collect(daemon: Daemon, mirror: Mirror, run_id: str) -> Qualification | DelegationRefusal:
    required: tuple[ControllerName, ...] = ("cpu", "memory", "pids")
    controllers = tuple((U / "cgroup.controllers").read_text().split())
    missing = tuple(controller for controller in required if controller not in controllers)
    if missing:
        return DelegationRefusal(missing)
    resources = Resources(daemon, run_id, "qualification")
    resources.image = mirror.resources.image
    network = resources.network(True)
    security = resources.create("security", network)
    source = helper("collector.mjs")
    resources.seed(security, (("collector.mjs", source),))
    try:
        code, body = resources.execute(security)
        inspection = resources.inspect(security)
        value = json.loads(body)
        require(code == 0 and value["artifactSha256"] == hashlib.sha256(source).hexdigest(), "collector_binding")
        require(value["targetUid"] == 65532 and value["effectiveCaps"] == "0000000000000000"
                and all(value[field] == "0000000000000000"
                        for field in ("permittedCaps", "ambientCaps", "inheritedCaps"))
                and value["seccompMode"] == 2 and value["noNewPrivileges"] is True
                and value["readOnlyRootfs"] is True and value["secretEnvironmentEmpty"] is True,
                "collector_security")
        require(value["cpuQuota"] == 2 * value["cpuPeriod"] and value["memoryMax"] == 2147483648
                and value["pidsMax"] == 256 and value["cpuEnforced"] is True
                and value["pidsEnforced"] is True, "collector_resources")
        memory = resources.create("memory", network)
        resources.seed(memory, (("collector-memory.mjs", helper("collector-memory.mjs")),))
        code, body = resources.execute(memory)
        require(code == 137 and resources.inspect(memory).oom
                and json.loads(body)["memoryMax"] == 2147483648, "memory_enforcement_unconfirmed")
        build = network_probe(resources, mirror, "BUILD")
        runtime = network_probe(resources, mirror, "RUNTIME")
        info = daemon.info()
        runtime_version = checked(Command(("/usr/bin/runc", "--version"))).decode("ascii").splitlines()[0]
        delegated = "user.slice/user-10001.slice/user@10001.service"
    finally:
        resources.cleanup()
    return Qualification(hashlib.sha256(source).hexdigest(), info.version, runtime_version, info.security,
                         int(info.cgroup_version), info.driver, "user@10001.service", controllers,
                         value["cpuQuota"], value["cpuPeriod"], value["memoryMax"], value["pidsMax"],
                         value["targetUid"], value["effectiveCaps"], value["seccompMode"],
                         value["noNewPrivileges"], value["readOnlyRootfs"], value["secretEnvironmentEmpty"],
                         inspection.runtime, inspection.host_mounts, inspection.cap_drop_all,
                         inspection.seccomp_profile,
                         value["cpuEnforced"], True, value["pidsEnforced"], build, build, runtime, True)
