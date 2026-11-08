# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original started-tool envelope custody; no cold/known-unused object is enrolled here."""
from __future__ import annotations

import os
import re
import select
import stat
import sys
from typing import TYPE_CHECKING, Final, Literal

from backend_process import BackendError, require
from cold_envelope_data import ColdDataError, Events, parse_events, parse_unit
from collector import user_unit
from input_resources import checked
from preparation_config_data import ConfigFrame, Operation, unit_bytes
from preparation_config_volumes import ConfigurationPaths

if TYPE_CHECKING:
    from preparation_config_tool import ConfigurationTool

UNIT_DIRECTORY: Final = "/home/wakeio-m1/.config/systemd/user"
GROUP_DIRECTORY: Final = "/sys/fs/cgroup/user.slice/user-10001.slice/user@10001.service"
ATTRIBUTES: Final = ("cgroup.events", "cpu.max", "memory.max", "memory.swap.max", "pids.max")
EnvelopeAction = Literal["envelope-present", "envelope-files", "envelope-inspect", "envelope-reload",
                         "envelope-start", "envelope-stop"]


class UnitAllocation:
    """Typed local allocation is retained before open; it is never a fake session Pending."""

    def __init__(self, owner: ConfigurationEnvelope) -> None:
        self.owner = owner
        self.descriptor: int | None = None
        self.identity: tuple[int, int] | None = None
        self.written = False
        self.attempted = False


class ConfigurationEnvelope:
    """Mutable unit/group originals outlive revocation until their real tool has closed."""

    def __init__(self, tool: ConfigurationTool) -> None:
        self.tool, self.configuration = tool, tool.configuration
        self.session, self.backend = self.configuration.session, self.configuration.backend
        self.frame = tool.frame("envelope-inspect")
        self.name, self.unit = self.frame.slice_name(), unit_bytes(self.frame)
        self.paths = ConfigurationPaths(self)
        self.file = UnitAllocation(self)
        self.descriptors: dict[str, int] = {}
        self.identities: dict[str, tuple[int, int]] = {}
        self.events = select.poll()
        self.invocation = ""
        self.observation: tuple[tuple[int, int], bytes] | None = None
        self.armed = False
        self.started = False
        self.ready = False
        self.stopped = False
        self.file_removed = False
        self.reloaded = False
        self.close_unknown = False
        self.identity_unknown = False
        self.drained = False

    def original(self) -> None:
        self.configuration.original()
        require(type(self) is ConfigurationEnvelope and self.tool.envelope is self
                and self.configuration.tool(self.tool.role) is self.tool
                and self.tool.role in ("producer", "verifier") and self.file.owner is self,
                "config_envelope_original")

    def call(self, action: EnvelopeAction) -> bytes:
        self.original()
        pending = self.configuration.call(self.tool.frame(action))
        body = checked(pending)
        require(pending.process is not None and not pending.process.errors, "config_envelope_control")
        if pending.mutation:
            require(body == b"", "config_envelope_mutation_response")
            self.session._settle(pending)
        return body

    def file_binding(self) -> None:
        self.paths.check()
        descriptor = self.file.descriptor
        require(descriptor is not None and self.descriptors.get("unit") == descriptor
                and self.file.written, "config_unit_allocation")
        if descriptor is None:
            raise BackendError("config_unit_descriptor")
        value = os.fstat(descriptor)
        linked = os.stat(self.name, dir_fd=self.paths.descriptors[UNIT_DIRECTORY], follow_symlinks=False)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 10001
                and value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o600
                and (value.st_dev, value.st_ino) == (linked.st_dev, linked.st_ino) == self.file.identity,
                "config_unit_replaced")
        require(os.pread(descriptor, len(self.unit) + 1, 0) == self.unit, "config_unit_changed")

    def unit_binding(self) -> None:
        self.file_binding()
        value = parse_unit(self.call("envelope-inspect"))
        require(value.name == value.names == self.name and value.load == "loaded"
                and value.active == value.sub == "active" and value.dropins == ""
                and value.fragment == UNIT_DIRECTORY + "/" + self.name and value.transient == "no"
                and value.group == GROUP_DIRECTORY.removeprefix("/sys/fs/cgroup") + "/" + self.name,
                "config_unit_identity")
        require(re.fullmatch(r"[a-f0-9]{32}", value.invocation) is not None
                and (not self.invocation or self.invocation == value.invocation), "config_unit_invocation")
        require((value.quota, value.memory, value.swap, value.tasks) == ("2s", "2147483648", "0", "256"),
                "config_unit_limits")
        if not self.invocation:
            self.invocation = value.invocation

    def read(self, name: str) -> bytes:
        self.original()
        self.paths.check()
        require(name in ATTRIBUTES, "config_attribute")
        group = os.fstat(self.descriptors["group"])
        linked = os.stat(self.name, dir_fd=self.paths.descriptors[GROUP_DIRECTORY], follow_symlinks=False)
        require(stat.S_ISDIR(group.st_mode)
                and (group.st_dev, group.st_ino) == (linked.st_dev, linked.st_ino) == self.identities["group"],
                "config_group_replaced")
        descriptor = self.descriptors[name]
        value = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=self.descriptors["group"], follow_symlinks=False)
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                and (value.st_dev, value.st_ino) == (linked.st_dev, linked.st_ino) == self.identities[name],
                "config_attribute_replaced")
        os.lseek(descriptor, 0, os.SEEK_SET)
        body = os.read(descriptor, 129)
        require(len(body) <= 128, "config_attribute_bound")
        return body

    def observe(self) -> Events:
        self.observation = None
        try:
            self.original()
            require(self.ready and self.armed and not self.stopped, "config_envelope_observer")
            self.unit_binding()
            batch = self.events.poll(0)
            require(all(fd == self.descriptors["cgroup.events"] and flags != 0
                        and not flags & ~(select.POLLPRI | select.POLLERR) for fd, flags in batch),
                    "config_group_event")
            raw = self.read("cgroup.events")
            value = parse_events(raw)
            require(not value.frozen, "config_group_frozen")
            self.observation = (self.identities["cgroup.events"], raw)
            return value
        except (BackendError, ColdDataError, OSError, ValueError, KeyError, TypeError) as error:
            self.identity_unknown = True
            raise BackendError("config_envelope_observation:" + str(error)) from error

    def absent(self, parent: int) -> None:
        self.paths.check()
        try:
            os.stat(self.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise BackendError("config_envelope_preexisting")

    def prepare(self) -> None:
        self.original()
        self.configuration.admit()
        require(sys.platform == "linux" and not self.started, "config_envelope_platform_or_replay")
        self.started = True
        directory = self.paths.directory(UNIT_DIRECTORY)
        parent = self.paths.directory(GROUP_DIRECTORY)
        baseline = self.backend.baseline
        require(tuple(map(str, self.paths.identities[GROUP_DIRECTORY])) == (baseline.unit.dev, baseline.unit.ino)
                and tuple(map(str, self.paths.identities[GROUP_DIRECTORY.rsplit("/", 1)[0]]))
                == (baseline.parent.dev, baseline.parent.ino) and user_unit() == baseline.unit,
                "config_envelope_manager")
        self.absent(directory)
        self.absent(parent)
        require(self.call("envelope-present") == b"" and self.call("envelope-files") == b"",
                "config_unit_preexisting")
        self.file.attempted = True
        self.file.descriptor = os.open(self.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                       | os.O_CLOEXEC, 0o600, dir_fd=directory)
        self.descriptors["unit"] = self.file.descriptor
        value = os.fstat(self.file.descriptor)
        self.file.identity = (value.st_dev, value.st_ino)
        os.fchmod(self.file.descriptor, 0o600)
        os.fchown(self.file.descriptor, 10001, 10001)
        require(os.write(self.file.descriptor, self.unit) == len(self.unit), "config_unit_write")
        os.fsync(self.file.descriptor)
        self.file.written = True
        self.file_binding()
        self.call("envelope-reload")
        self.call("envelope-start")
        self.unit_binding()
        self.descriptors["group"] = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                            | os.O_CLOEXEC, dir_fd=parent)
        value = os.fstat(self.descriptors["group"])
        self.identities["group"] = (value.st_dev, value.st_ino)
        for name in ATTRIBUTES:
            self.descriptors[name] = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                              dir_fd=self.descriptors["group"])
            value = os.fstat(self.descriptors[name])
            self.identities[name] = (value.st_dev, value.st_ino)
        self.events.register(self.descriptors["cgroup.events"], select.POLLPRI | select.POLLERR)
        self.armed = True
        quota = self.read("cpu.max")
        require(re.fullmatch(rb"[1-9][0-9]{0,17} [1-9][0-9]{0,17}\n", quota) is not None,
                "config_cpu_limit_format")
        amount, period = map(int, quota.split())
        require(amount == 2 * period and self.read("memory.max") == b"2147483648\n"
                and self.read("memory.swap.max") == b"0\n" and self.read("pids.max") == b"256\n",
                "config_kernel_limits")
        self.ready = True
        self.observe()

    def close(self, name: str) -> None:
        descriptor = self.descriptors.pop(name)
        if name == "unit":
            self.file.descriptor = None
        try:
            os.close(descriptor)
        except OSError:
            self.close_unknown = True
            raise

    def remove(self) -> None:
        self.original()
        require(self.session._cleaning and not self.close_unknown and not self.identity_unknown
                and (self.tool.container_removed or self.tool.never_created)
                and (not self.tool.released or self.tool.closed),
                "config_envelope_tool_retained")
        require(not self.file.attempted or "unit" in self.descriptors or self.file_removed,
                "config_unit_allocation_unconfirmed")
        if "unit" in self.descriptors:
            require(self.ready, "config_unit_preparation_unconfirmed")
            if not self.stopped:
                require(not self.observe().populated, "config_group_populated")
                self.call("envelope-stop")
                self.stopped = True
            self.absent(self.paths.descriptors[GROUP_DIRECTORY])
            if self.armed:
                self.events.unregister(self.descriptors["cgroup.events"])
                self.armed = False
            for name in (*ATTRIBUTES, "group"):
                if name in self.descriptors:
                    self.close(name)
            if not self.file_removed:
                self.file_binding()
                os.unlink(self.name, dir_fd=self.paths.descriptors[UNIT_DIRECTORY])
                self.file_removed = True
            if not self.reloaded:
                self.call("envelope-reload")
                self.reloaded = True
        for name in tuple(self.descriptors):
            self.close(name)
        self.paths.dispose()
        self.drained = not self.descriptors and not self.close_unknown and (not self.file.attempted or self.reloaded)
