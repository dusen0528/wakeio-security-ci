#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fixed owned CPU-withdrawal transaction; stdin program, one bounded snapshot argument."""
import base64
import json
import os
import re
import select
import stat
import sys
import time
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import TypeAlias, TypedDict, Union, assert_never

sys.path.insert(0, "/usr/local/lib/wakeio-controller")
from backend_process import BackendError, require
from collector import (P, U, GroupIdentity, NodeIdentity, Ownership, OwnerKind,
                       ProcessIdentity, UnitIdentity, process_identity, user_unit)

Json: TypeAlias = Union[None, bool, int, float, str, list["Json"], tuple[tuple[str, "Json"], ...]]

class KernelObservation(TypedDict):
    controllers: list[str]
    parent: list[str]
    groups: dict[str, list[str]]
    memory: str
    pids: str


class FixtureResult(TypedDict):
    run: str
    boot: str
    unitInvocation: str
    before: KernelObservation
    after: KernelObservation
    writes: list[tuple[str, str]]
    thawObserved: bool


def child_groups(fd: int) -> set[str]:
    entries = {name: os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode for name in os.listdir(fd)}
    require(not any(stat.S_ISLNK(mode) for mode in entries.values()), "inventory_symlink")
    return {name for name, mode in entries.items() if stat.S_ISDIR(mode)}


def fields(raw: Json, names: str) -> Mapping[str, Json]:
    if not isinstance(raw, tuple) or len(raw) != len(names.split()) or set(dict(raw)) != set(names.split()):
        raise BackendError("inventory_fields")
    return dict(raw)


def text(raw: Json, pattern: str) -> str:
    if not isinstance(raw, str) or re.fullmatch(pattern, raw) is None:
        raise BackendError("inventory_text")
    return raw


def pid(raw: Json) -> int:
    if type(raw) is not int or not 0 < raw <= 4194304:
        raise BackendError("inventory_pid")
    return raw


def relative(raw: Json) -> str:
    value = text(raw, r"[A-Za-z0-9_./@:-]{1,240}")
    require(value == "." or all(part not in ("", ".", "..") for part in value.split("/")), "inventory_path")
    return value


def rows(raw: Json, limit: int) -> list[Json]:
    if not isinstance(raw, list) or not 0 < len(raw) <= limit:
        raise BackendError("inventory_bound")
    return raw


def owner_kind(raw: Json) -> OwnerKind:
    match raw:
        case "baseline" | "daemon" | "container" | "structural":
            return raw
        case _:
            raise BackendError("inventory_owner_kind")


def parse_snapshot(encoded: str) -> Ownership:
    require(len(encoded) <= 43692, "inventory_bound")
    body = base64.b64decode(encoded, validate=True)
    require(len(body) <= 32768, "inventory_bound")
    data = fields(json.loads(body, object_pairs_hook=tuple),
                  "version run boot daemon helper parent unit groups processRoots")
    require(type(data["version"]) is int and data["version"] == 1, "inventory_version")
    parent = fields(data["parent"], "cgroup dev ino")
    unit = fields(data["unit"], "cgroup dev ino invocationId mainPid startTicks")
    number = r"[0-9]{1,20}"
    parent_record = NodeIdentity(text(parent["cgroup"], re.escape(str(P).removeprefix("/sys/fs/cgroup"))),
                                 text(parent["dev"], number), text(parent["ino"], number))
    unit_record = UnitIdentity(text(unit["cgroup"], re.escape(str(U).removeprefix("/sys/fs/cgroup"))),
                               text(unit["dev"], number), text(unit["ino"], number),
                               text(unit["invocationId"], r"[a-f0-9]{32}"), pid(unit["mainPid"]),
                               text(unit["startTicks"], number))
    groups = []
    for raw in rows(data["groups"], 64):
        row = fields(raw, "relative dev ino ownerKind ownerId")
        groups.append(GroupIdentity(relative(row["relative"]), text(row["dev"], number),
                                    text(row["ino"], number), owner_kind(row["ownerKind"]),
                                    text(row["ownerId"], r"[A-Za-z0-9_:-]{1,256}")))
    processes = []
    for raw in rows(data["processRoots"], 256):
        row = fields(raw, "pid startTicks relativeCgroup ownerId")
        processes.append(ProcessIdentity(pid(row["pid"]), text(row["startTicks"], number),
                                         relative(row["relativeCgroup"]),
                                         text(row["ownerId"], r"[A-Za-z0-9_:-]{1,256}")))
    require(len({group.relative for group in groups}) == len(groups)
            and len({(group.dev, group.ino) for group in groups}) == len(groups)
            and len({process.pid for process in processes}) == len(processes), "inventory_duplicate")
    require(any(group.relative == "." for group in groups), "inventory_unit_missing")
    owners = {group.relative: group.ownerId for group in groups}
    require(all(owners.get(process.relativeCgroup) == process.ownerId for process in processes),
            "inventory_process_owner")
    return Ownership(1, text(data["run"], r"[a-f0-9]{32}"),
                     text(data["boot"], r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"),
                     text(data["daemon"], r"[A-Za-z0-9_:-]{1,256}"),
                     text(data["helper"], r"[a-f0-9]{64}"), parent_record, unit_record,
                     tuple(groups), tuple(processes))


def read_control(fd: int, name: str) -> str:
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    with os.fdopen(opened, "r", encoding="ascii") as stream:
        value = stream.read(32769)
        require(len(value) <= 32768, "kernel_observation_bound")
        return value.strip()


class Hierarchy:
    """FDs are transaction-local; VM/process/asset lifetime belongs to the original controller."""
    def __init__(self, expected: Ownership, stack: ExitStack):
        self.expected = expected
        self.deadline = time.monotonic() + 25
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root = os.open("/sys/fs/cgroup", flags)
        stack.callback(os.close, root)
        for component in ("user.slice", "user-10001.slice"):
            root = os.open(component, flags, dir_fd=root)
            stack.callback(os.close, root)
        self.parent = root
        self.unit = os.open("user@10001.service", flags, dir_fd=root)
        stack.callback(os.close, self.unit)
        self.nodes = {".": self.unit}
        for group in sorted(expected.groups, key=lambda item: (item.relative.count("/"), item.relative)):
            if group.relative != ".":
                parent, _, name = group.relative.rpartition("/")
                require((parent or ".") in self.nodes, "inventory_parent_missing")
                fd = os.open(name, flags, dir_fd=self.nodes[parent or "."])
                stack.callback(os.close, fd)
                self.nodes[group.relative] = fd
        self.events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.unit)
        stack.callback(os.close, self.events)
        self.poller = select.poll()
        self.poller.register(self.events, select.POLLPRI | select.POLLERR)
        self.check()

    def check(self) -> None:
        require(time.monotonic() < self.deadline + 5, "fixture_deadline")
        expected = self.expected
        require(user_unit() == expected.unit, "inventory_unit_changed")
        parent = os.fstat(self.parent)
        require((str(parent.st_dev), str(parent.st_ino)) == (expected.parent.dev, expected.parent.ino),
                "inventory_parent_changed")
        require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == expected.boot,
                "inventory_boot_changed")
        require(child_groups(self.parent) == {"user@10001.service"}, "inventory_parent_membership")
        for group in expected.groups:
            fd = self.nodes[group.relative]
            value = os.fstat(fd)
            require((str(value.st_dev), str(value.st_ino)) == (group.dev, group.ino), "inventory_group_changed")
            parent_name, _, child = group.relative.rpartition("/")
            parent_fd = self.parent if group.relative == "." else self.nodes[parent_name or "."]
            name = "user@10001.service" if group.relative == "." else child
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            require((named.st_dev, named.st_ino) == (value.st_dev, value.st_ino), "inventory_named_group_changed")
            require(read_control(fd, "cgroup.type") == "domain", "inventory_group_type")
            children = child_groups(fd)
            prefix = "" if group.relative == "." else group.relative + "/"
            wanted = {item.relative[len(prefix):] for item in expected.groups
                      if item.relative.startswith(prefix) and item.relative != group.relative
                      and "/" not in item.relative[len(prefix):]}
            require(children == wanted, "inventory_membership_changed")
            actual = {int(value) for value in read_control(fd, "cgroup.procs").split()}
            processes = [process for process in expected.processRoots if process.relativeCgroup == group.relative]
            require(actual == {process.pid for process in processes}, "inventory_pid_changed")
            require(all(process_identity(process.pid, process.ownerId) == process for process in processes),
                    "inventory_start_changed")

    def observation(self) -> KernelObservation:
        self.check()
        return {"controllers": sorted(read_control(self.unit, "cgroup.controllers").split()),
                "parent": sorted(read_control(self.parent, "cgroup.subtree_control").split()),
                "groups": {name: sorted(read_control(fd, "cgroup.subtree_control").split())
                           for name, fd in self.nodes.items()},
                "memory": read_control(self.unit, "memory.max"), "pids": read_control(self.unit, "pids.max")}

    def write(self, fd: int, name: str, value: bytes) -> None:
        opened = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            require(os.write(opened, value) == len(value), "kernel_write_incomplete")
        finally:
            os.close(opened)

    def freeze(self, value: int) -> None:
        end = min(self.deadline + (5 if value == 0 else 0), time.monotonic() + 5)
        self.write(self.unit, "cgroup.freeze", str(value).encode("ascii") + b"\n")
        while True:
            os.lseek(self.events, 0, os.SEEK_SET)
            state = dict(line.split() for line in os.read(self.events, 4096).decode("ascii").splitlines())
            if state.get("frozen") == str(value):
                return
            remaining = end - time.monotonic()
            require(remaining > 0 and bool(self.poller.poll(max(1, int(remaining * 1000)))), "freeze_unconfirmed")

    def withdraw(self) -> FixtureResult:
        before = self.observation()
        require({"cpu", "memory", "pids"}.issubset(read_control(self.unit, "cgroup.controllers").split())
                and "cpu" in read_control(self.parent, "cgroup.subtree_control").split(), "fixture_prerequisite")
        require(before["memory"] == "6442450944" and before["pids"] == "1024", "fixture_limits")
        require("frozen 0" in read_control(self.unit, "cgroup.events").splitlines(), "fixture_already_frozen")
        writes = []
        try:
            self.freeze(1)
            self.check()
            ordered = sorted(self.nodes, key=lambda name: (name.count("/"), name != "."), reverse=True)
            for name in ordered:
                self.check()
                if "cpu" in read_control(self.nodes[name], "cgroup.subtree_control").split():
                    self.write(self.nodes[name], "cgroup.subtree_control", b"-cpu\n")
                    writes.append((str(U / name / "cgroup.subtree_control"), "-cpu\n"))
            self.check()
            self.write(self.parent, "cgroup.subtree_control", b"-cpu\n")
            writes.append((str(P / "cgroup.subtree_control"), "-cpu\n"))
            after = self.observation()
            require(after["controllers"] == [item for item in before["controllers"] if item != "cpu"]
                    and after["parent"] == [item for item in before["parent"] if item != "cpu"]
                    and after["memory"] == before["memory"] and after["pids"] == before["pids"],
                    "withdrawal_unconfirmed")
            for name, fd in self.nodes.items():
                require(sorted(read_control(fd, "cgroup.subtree_control").split()) ==
                        [item for item in before["groups"][name] if item != "cpu"], "withdrawal_token_changed")
        finally:
            self.freeze(0)
        require(self.observation() == after, "controllers_reappeared")
        return {"run": self.expected.run, "boot": self.expected.boot,
                "unitInvocation": self.expected.unit.invocationId, "before": before, "after": after,
                "writes": writes, "thawObserved": True}


def main() -> None:
    require(sys.platform == "linux" and os.geteuid() == 0 and len(sys.argv) == 2, "fixture_ingress")
    expected = parse_snapshot(sys.argv[1])
    with open("/proc/self/mountinfo", encoding="ascii") as stream:
        mounts = [line.split() for line in stream]
    root = [row for row in mounts if row[4] == "/sys/fs/cgroup"]
    require(len(root) == 1 and root[0][3] == "/" and "cgroup2" == root[0][root[0].index("-") + 1]
            and all(row[4] not in (str(P), str(P.parent)) and not row[4].startswith(str(P) + "/")
                    for row in mounts), "fixture_mount")
    with open("/proc/self/cgroup", encoding="ascii") as stream:
        require(stream.read().strip() == "0::/system.slice/wakeio-delegation-" + expected.run + ".service",
                "fixture_unit_owner")
    with ExitStack() as stack:
        result = Hierarchy(expected, stack).withdraw()
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (BackendError, OSError) as error:
        match error:
            case BackendError(code=code):
                detail = {"code": code, "errno": None}
            case OSError(errno=number):
                detail = {"code": "fixture_native", "errno": number}
            case unreachable:
                assert_never(unreachable)
        sys.stderr.write(json.dumps(detail) + "\n")
        sys.exit(125)
