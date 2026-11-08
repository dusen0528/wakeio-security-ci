# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original one-shot daemon wait socket; HTTP DATA never owns or completes a tool."""
from __future__ import annotations

import errno
import os
import select
import socket
import stat
import struct
from pathlib import Path
from typing import TYPE_CHECKING

from backend_process import BackendError, require
from daemon import SOCKET
from preparation_config_data import ConfigError
from preparation_config_volumes import ConfigurationPaths
from preparation_config_wait_data import WaitParser, WaitTerminal, wait_request

if TYPE_CHECKING:
    from preparation_config_tool import ConfigurationTool


class SocketAllocation:
    """Retained local socket allocation, not a Pending without an actual Process."""

    def __init__(self, owner: ConfigurationWait) -> None:
        self.owner = owner
        self.channel: socket.socket | None = None
        self.identity: tuple[int, int] | None = None
        self.attempted = False


class ConfigurationWait:
    """Mutable original connection, parser and closure history cannot reconnect or reset."""

    def __init__(self, tool: ConfigurationTool) -> None:
        self.tool, self.configuration = tool, tool.configuration
        self.daemon = self.configuration.daemon
        self.daemon_identity, self.invocation = self.daemon.identity, self.daemon.invocation
        self.socket_identity = self.daemon.socket_identity
        self.paths = ConfigurationPaths(self)
        self.allocation = SocketAllocation(self)
        self.request = wait_request(tool.container)
        self.parser = WaitParser()
        self.peer: tuple[int, int, int] | None = None
        self.offset = 0
        self.connected = False
        self.headers_acknowledged = False
        self.complete = False
        self.close_unknown = False
        self.identity_unknown = False
        self.drained = False
        self.terminal: WaitTerminal | None = None

    def original(self) -> None:
        self.configuration.original()
        require(type(self) is ConfigurationWait and self.tool.wait is self
                and self.configuration.tool(self.tool.role) is self.tool
                and self.tool.role in ("producer", "verifier") and self.allocation.owner is self,
                "config_wait_original")

    @property
    def descriptor(self) -> int:
        channel = self.allocation.channel
        if channel is None:
            raise BackendError("config_wait_socket_missing")
        return channel.fileno()

    @property
    def flags(self) -> int:
        return (select.POLLOUT if not self.connected or self.offset < len(self.request) else select.POLLIN)

    def binding(self) -> socket.socket:
        self.original()
        require(not self.close_unknown and not self.identity_unknown and not self.drained,
                "config_wait_uncertain")
        self.paths.check()
        self.configuration.backend.check()
        value = os.stat("docker.sock", dir_fd=self.paths.descriptors["/run/user/10001"],
                        follow_symlinks=False)
        require(stat.S_ISSOCK(value.st_mode) and value.st_uid == 10001
                and stat.S_IMODE(value.st_mode) == 0o600
                and (value.st_dev, value.st_ino) == self.socket_identity == self.daemon.socket_identity
                and self.daemon.identity == self.daemon_identity and self.daemon.invocation == self.invocation,
                "config_wait_daemon_changed")
        channel = self.allocation.channel
        if channel is None:
            raise BackendError("config_wait_socket_missing")
        held = os.fstat(channel.fileno())
        require(stat.S_ISSOCK(held.st_mode) and (held.st_dev, held.st_ino) == self.allocation.identity,
                "config_wait_descriptor_changed")
        if self.connected:
            peer = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer[0] > 0 and peer[1] == peer[2] == 10001
                    and (self.peer is None or self.peer == peer), "config_wait_peer_changed")
            unit = self.daemon.unit()
            require(unit["InvocationID"] == self.invocation and unit["ActiveState"] == "active",
                    "config_wait_daemon_invocation")
            with Path("/proc/" + str(peer[0]) + "/cgroup").open("rb") as source:
                group = source.read(4097)
            require(group == ("0::" + unit["ControlGroup"] + "\n").encode("ascii"),
                    "config_wait_peer_group")
            self.peer = peer
        return channel

    def prepare(self) -> None:
        self.original()
        self.configuration.admit()
        require(not self.allocation.attempted, "config_wait_replay")
        self.paths.directory("/run/user/10001")
        self.allocation.attempted = True
        self.allocation.channel = socket.socket(socket.AF_UNIX,
                                                socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        value = os.fstat(self.allocation.channel.fileno())
        self.allocation.identity = (value.st_dev, value.st_ino)
        channel = self.binding()
        status = channel.connect_ex(SOCKET)
        require(status in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK), "config_wait_connect")
        if status == 0:
            self.connected = True
            self.binding()
            self.send()

    def send(self) -> None:
        channel = self.binding()
        require(self.connected and self.offset < len(self.request), "config_wait_request_state")
        try:
            sent = channel.send(self.request[self.offset:])
        except BlockingIOError:
            return
        require(sent > 0, "config_wait_request_closed")
        self.offset += sent
        self.binding()

    def ready(self, flags: int) -> None:
        try:
            require(flags != 0 and not flags & ~(select.POLLIN | select.POLLOUT | select.POLLERR | select.POLLHUP),
                    "config_wait_event")
            channel = self.binding()
            if not self.connected:
                require(bool(flags & select.POLLOUT) and channel.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
                        "config_wait_connect_result")
                self.connected = True
                self.binding()
            if self.offset < len(self.request):
                self.send()
                return
            if flags & (select.POLLIN | select.POLLHUP | select.POLLERR):
                try:
                    body = channel.recv(65536)
                except BlockingIOError:
                    return
                if body:
                    self.parser.feed(body)
                    if self.parser.headers_ready:
                        self.binding()
                        self.headers_acknowledged = True
                    require(self.parser.terminal is None or self.tool.released, "config_wait_early_terminal")
                else:
                    self.binding()
                    self.terminal = self.parser.eof()
                    require(self.tool.released, "config_wait_early_eof")
                    self.complete = True
                    self.binding()
        except (BackendError, ConfigError, OSError, ValueError, KeyError, TypeError) as error:
            self.identity_unknown = True
            raise BackendError("config_wait_observation:" + str(error)) from error

    def dispose(self) -> None:
        self.original()
        require(self.tool.container_removed and (not self.tool.released or self.complete)
                and not self.close_unknown and not self.identity_unknown, "config_wait_tool_retained")
        channel = self.allocation.channel
        if channel is not None:
            self.binding()
            self.allocation.channel = None
            try:
                channel.close()
            except OSError:
                self.close_unknown = True
                raise
        self.paths.dispose()
        self.drained = self.allocation.channel is None and not self.close_unknown
