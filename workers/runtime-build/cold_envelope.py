# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original never-enrolled slice custody. Empty DATA is not workload CLOSE."""
from __future__ import annotations

import os
import re
import select
import stat
import sys
from typing import TYPE_CHECKING, Final, Literal

from backend_process import BackendError, require
from cold_envelope_data import UNIT, ColdDataError, Events, Phase, parse_events, parse_unit, slice_name
from collector import user_unit
from input_resources import checked
from launch import Role, Selection

if TYPE_CHECKING:
    from build import BuildSession

UNIT_DIRECTORY: Final = "/home/wakeio-m1/.config/systemd/user"
GROUP_DIRECTORY: Final = "/sys/fs/cgroup/user.slice/user-10001.slice/user@10001.service"
Attribute = Literal["cgroup.events", "cpu.max", "memory.max", "memory.swap.max", "pids.max"]
ATTRIBUTES: Final[tuple[Attribute, ...]] = ("cgroup.events", "cpu.max", "memory.max", "memory.swap.max", "pids.max")


class ColdEnvelope:
    """Mutable original allocation and descriptors survive partial preparation and revocation."""

    def __init__(self, session: BuildSession, phase: Phase) -> None:
        from build import BuildSession
        require(type(session) is BuildSession, "cold_session_type")
        self.session = session
        self.backend = session.backend
        self.daemon = session.daemon
        self.generation = session._generation
        self.input = session._copy
        self.phase = phase
        self.name = slice_name(self.backend.run_id, self.generation, phase)
        self.descriptors: dict[str, int] = {}
        self.identities: dict[str, tuple[int, int]] = {}
        self.events = select.poll()
        self.armed = False
        self.invocation = ""
        self.started = False
        self.ready = False
        self.stopped = False
        self.file_removed = False
        self.reloaded = False
        self.close_unknown = False
        self.drained = False
        self.observation: tuple[bytes] | None = None

    def _original(self) -> None:
        self.session._original()
        require(type(self) is ColdEnvelope and self.session._cold.get(self.phase) is self
                and self.session.backend is self.backend and self.backend.daemon is self.daemon
                and self.generation == self.session._generation and self.input is self.session._copy
                and self.input is not None and not self.drained, "cold_original_owner")
        if self.session._cleaning:
            self.backend.check()
        else:
            self.session._check()
        require(user_unit() == self.backend.baseline.unit, "cold_manager_changed")

    def accept(self, selection: Selection) -> None:
        self._original()
        require(selection.role in ("slice-present", "slice-files", "slice-reload", "slice-start",
                                   "slice-inspect", "slice-stop"), "cold_role")
        require(selection.operand == (None if selection.role == "slice-reload" else self.name), "cold_operand")
        require(not self.session._cleaning or selection.role != "slice-start", "cold_cleanup_start")

    def _call(self, role: Role) -> bytes:
        self._original()
        pending = self.session._run(self, Selection(role, None if role == "slice-reload" else self.name))
        body = checked(pending)
        if pending.process is None:
            raise BackendError("cold_process_missing")
        require(not pending.process.errors, "cold_control_diagnostic")
        if pending.mutation:
            require(body == b"", "cold_mutation_response")
            self.session._settle(pending)
        return body

    def _directory(self, path: str) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        if "/" not in self.descriptors:
            self.descriptors["/"] = os.open("/", flags)
            value = os.fstat(self.descriptors["/"])
            self.identities["/"] = (value.st_dev, value.st_ino)
        parent = "/"
        for part in path.split("/")[1:]:
            self._original()
            current = parent.rstrip("/") + "/" + part
            if current not in self.descriptors:
                self.descriptors[current] = os.open(part, flags, dir_fd=self.descriptors[parent])
                value = os.fstat(self.descriptors[current])
                self.identities[current] = (value.st_dev, value.st_ino)
            parent = current
        self._anchors()
        return self.descriptors[path]

    def _anchors(self) -> None:
        self._original()
        for path, descriptor in self.descriptors.items():
            if not path.startswith("/"):
                continue
            value = os.fstat(descriptor)
            require(stat.S_ISDIR(value.st_mode) and value.st_uid in (0, 10001)
                    and value.st_mode & 0o022 == 0
                    and (value.st_dev, value.st_ino) == self.identities[path], "cold_directory_changed")
            if path != "/":
                parent, name = path.rsplit("/", 1)
                linked = os.stat(name, dir_fd=self.descriptors[parent or "/"], follow_symlinks=False)
                require((linked.st_dev, linked.st_ino) == self.identities[path], "cold_anchor_replaced")

    def _absent(self, name: str, parent: int) -> None:
        self._anchors()
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise BackendError("cold_namespace_preexisting")

    def _file(self) -> None:
        self._anchors()
        value = os.fstat(self.descriptors["unit"])
        linked = os.stat(self.name, dir_fd=self.descriptors[UNIT_DIRECTORY], follow_symlinks=False)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 10001
                and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1
                and (value.st_dev, value.st_ino) == (linked.st_dev, linked.st_ino) == self.identities["unit"],
                "cold_file_changed")
        require(os.pread(self.descriptors["unit"], len(UNIT) + 1, 0) == UNIT, "cold_file_content")

    def _unit(self) -> None:
        self._file()
        value = parse_unit(self._call("slice-inspect"))
        require(value.name == value.names == self.name and value.load == "loaded"
                and value.active == value.sub == "active" and value.fragment == UNIT_DIRECTORY + "/" + self.name
                and value.dropins == "" and value.group == GROUP_DIRECTORY.removeprefix("/sys/fs/cgroup")
                + "/" + self.name and value.transient == "no", "cold_unit_changed")
        require(re.fullmatch(r"[a-f0-9]{32}", value.invocation) is not None
                and (not self.invocation or self.invocation == value.invocation), "cold_invocation_changed")
        require((value.quota, value.memory, value.swap, value.tasks) == ("2s", "2147483648", "0", "256"),
                "cold_unit_limits")
        if not self.invocation:
            self.invocation = value.invocation

    def _read(self, name: Attribute) -> bytes:
        self._anchors()
        group = os.fstat(self.descriptors["group"])
        linked = os.stat(self.name, dir_fd=self.descriptors[GROUP_DIRECTORY], follow_symlinks=False)
        require(stat.S_ISDIR(group.st_mode)
                and (group.st_dev, group.st_ino) == (linked.st_dev, linked.st_ino) == self.identities["group"],
                "cold_group_replaced")
        value = os.fstat(self.descriptors[name])
        linked = os.stat(name, dir_fd=self.descriptors["group"], follow_symlinks=False)
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                and (value.st_dev, value.st_ino) == (linked.st_dev, linked.st_ino) == self.identities[name],
                "cold_attribute_replaced")
        os.lseek(self.descriptors[name], 0, os.SEEK_SET)
        body = os.read(self.descriptors[name], 129)
        if name == "cgroup.events":
            self.observation = (body,)
        require(len(body) <= 128, "cold_attribute_bound")
        return body

    def observe(self) -> Events:
        """Read the same armed original descriptor; return raw DATA, never readiness or CLOSE."""
        try:
            self._original()
            require(self.ready and self.armed and not self.stopped, "cold_observer_unavailable")
            self._unit()
            for descriptor, flags in self.events.poll(0):
                require(descriptor == self.descriptors["cgroup.events"]
                        and bool(flags & (select.POLLPRI | select.POLLERR))
                        and not flags & ~(select.POLLPRI | select.POLLERR), "cold_notification_invalid")
            value = parse_events(self._read("cgroup.events"))
            require(not value.frozen, "cold_group_frozen")
            return value
        except (BackendError, ColdDataError, OSError, ValueError, KeyError, TypeError) as error:
            self.session._fail("cold_observation_failed:" + str(error))
            raise BackendError("cold_observation_failed:" + str(error)) from error

    def prepare(self) -> None:
        self._original()
        require(sys.platform == "linux" and not self.started, "cold_platform_or_replay")
        self.started = True
        unit_directory = self._directory(UNIT_DIRECTORY)
        group_directory = self._directory(GROUP_DIRECTORY)
        baseline = self.backend.baseline
        require(tuple(map(str, self.identities[GROUP_DIRECTORY])) == (baseline.unit.dev, baseline.unit.ino)
                and tuple(map(str, self.identities[GROUP_DIRECTORY.rsplit("/", 1)[0]]))
                == (baseline.parent.dev, baseline.parent.ino), "cold_parent_binding")
        self._absent(self.name, unit_directory)
        self._absent(self.name, group_directory)
        require(self._call("slice-present") == b"" and self._call("slice-files") == b"", "cold_unit_preexisting")
        self._anchors()
        self.descriptors["unit"] = os.open(self.name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                          | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=unit_directory)
        value = os.fstat(self.descriptors["unit"])
        self.identities["unit"] = (value.st_dev, value.st_ino)
        self._original()
        os.fchmod(self.descriptors["unit"], 0o600)
        os.fchown(self.descriptors["unit"], 10001, 10001)
        require(os.write(self.descriptors["unit"], UNIT) == len(UNIT), "cold_file_write")
        os.fsync(self.descriptors["unit"])
        self._file()
        self._call("slice-reload")
        self._file()
        self._call("slice-start")
        self._unit()
        self._anchors()
        self.descriptors["group"] = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                           | os.O_CLOEXEC, dir_fd=group_directory)
        value = os.fstat(self.descriptors["group"])
        self.identities["group"] = (value.st_dev, value.st_ino)
        for attribute in ATTRIBUTES:
            self._original()
            self.descriptors[attribute] = os.open(attribute, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                  dir_fd=self.descriptors["group"])
            value = os.fstat(self.descriptors[attribute])
            self.identities[attribute] = (value.st_dev, value.st_ino)
        self.events.register(self.descriptors["cgroup.events"], select.POLLPRI | select.POLLERR)
        self.armed = True
        quota = self._read("cpu.max")
        require(re.fullmatch(rb"[1-9][0-9]{0,17} [1-9][0-9]{0,17}\n", quota) is not None,
                "cold_cpu_limit_format")
        amount, period = map(int, quota.split())
        require(amount == 2 * period and self._read("memory.max") == b"2147483648\n"
                and self._read("memory.swap.max") == b"0\n" and self._read("pids.max") == b"256\n",
                "cold_kernel_limits")
        self.ready = True
        self.observe()

    def _close(self, name: str) -> None:
        descriptor = self.descriptors.pop(name)
        try:
            os.close(descriptor)
        except OSError:
            self.close_unknown = True
            raise

    def remove(self) -> None:
        """Known-unused disposal only; no enrolment or workload terminal predicate exists here."""
        self._original()
        require(self.session._cleaning and not self.close_unknown, "cold_cleanup_unavailable")
        if "unit" in self.descriptors:
            require(self.ready, "cold_preparation_unconfirmed")
            if not self.stopped:
                require(not self.observe().populated, "cold_group_populated")
                self._call("slice-stop")
                self.stopped = True
            self._absent(self.name, self.descriptors[GROUP_DIRECTORY])
            if self.armed:
                self.events.unregister(self.descriptors["cgroup.events"])
                self.armed = False
            for name in (*ATTRIBUTES, "group"):
                if name in self.descriptors:
                    self._close(name)
            if not self.file_removed:
                self._file()
                os.unlink(self.name, dir_fd=self.descriptors[UNIT_DIRECTORY])
                self.file_removed = True
            if not self.reloaded:
                self._call("slice-reload")
                self.reloaded = True
        for name in reversed(tuple(self.descriptors)):
            self._close(name)
        self.drained = not self.descriptors and not self.close_unknown and (not self.file_removed or self.reloaded)
