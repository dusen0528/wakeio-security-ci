# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: only by relay.serve on the original Backend.
"""One original authenticated conversation; its accepted socket outlives failed work."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import struct
from typing import TYPE_CHECKING

from backend_process import BackendError, require
from backend_startup_data import RELAY_READY
from backend_startup_io import Identity, descriptor_identity

if TYPE_CHECKING:
    from backend_startup import OriginalStartup
    from relay import Backend


class OriginalConnection:
    """Mutable actual accept and dispatch history; no supplied socket or readiness record."""

    def __init__(self, source: OriginalStartup) -> None:
        source.original()
        require(source.connection is None, "backend_connection_replay")
        self.source = source
        self.socket: socket.socket | None = None
        self.identity: Identity | None = None
        self.peer: tuple[int, int, int] | None = None
        self.generation = 0
        self.active = 0
        self.sequence = 0
        self.closed = False
        self.close_unknown = False
        source.connection = self

    def original(self) -> Backend:
        backend = self.source.original()
        require(type(self) is OriginalConnection and self.source.connection is self,
                "backend_connection_original")
        return backend

    def descriptor(self) -> int:
        self.original()
        channel = self.socket
        if channel is None:
            raise BackendError("backend_connection_missing")
        return channel.fileno()

    def check(self) -> None:
        self.original()
        channel = self.socket
        if channel is None:
            raise BackendError("backend_connection_missing")
        require(not self.closed and not self.close_unknown and self.generation == 1
                and channel.family == socket.AF_UNIX and channel.type == socket.SOCK_STREAM
                and descriptor_identity(channel.fileno()) == self.identity
                and struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                == self.peer, "backend_connection_changed")

    def observe(self) -> None:
        self.check()
        channel = self.socket
        if channel is None:
            raise BackendError("backend_connection_missing")
        timeout = channel.gettimeout()
        channel.setblocking(False)
        try:
            body = channel.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except BlockingIOError:
            return
        finally:
            channel.settimeout(timeout)
        self.check()
        self.source.revoke("backend_unexpected_traffic" if body else "backend_disconnected")

    def work(self) -> None:
        self.check()
        require(self.active > 0 and self.active == self.sequence, "backend_operation_inactive")
        self.observe()
        self.source.raise_if_failed()

    def _accept(self, listener: socket.socket) -> None:
        require(self.generation == 0 and self.socket is None, "backend_connection_replay")
        self.generation = 1
        self.socket, _ = listener.accept()
        self.identity = descriptor_identity(self.socket.fileno())
        self.peer = struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(self.peer[1] == 10000, "rpc_peer")
        self.socket.settimeout(900)

    def _request(self, nonce: str) -> None:
        from relay import operation, receive, unique_pairs
        backend = self.original()
        channel = self.socket
        if channel is None:
            raise BackendError("backend_connection_missing")
        request = json.loads(receive(channel, backend), object_pairs_hook=unique_pairs)
        self.sequence += 1
        require(set(request) == {"version", "sequence", "challenge", "run", "operation", "mac"}
                and request["version"] == 1 and request["sequence"] == self.sequence and self.sequence <= 1024
                and request["run"] == backend.run_id
                and re.fullmatch(r"[a-f0-9]{64}", request["challenge"]) is not None, "rpc_binding")
        payload = {key: request[key] for key in ("version", "sequence", "run", "challenge", "operation")}
        canonical = json.dumps(payload, separators=(",", ":"))
        expected = hmac.new(bytes.fromhex(nonce), ("request:" + canonical).encode(), hashlib.sha256).hexdigest()
        require(hmac.compare_digest(expected, request["mac"]), "rpc_request_mac")
        self.active = self.sequence
        try:
            result = backend.dispatch(operation(request["operation"]))
            require(not backend._interrupted, "backend_interrupted")
            response = {"version": 1, "sequence": self.sequence, "run": backend.run_id,
                        "challenge": request["challenge"], "result": result}
            canonical = json.dumps(response, separators=(",", ":"))
            mac = hmac.new(bytes.fromhex(nonce), ("response:" + canonical).encode(),
                           hashlib.sha256).hexdigest()
            body = json.dumps({**response, "mac": mac}, separators=(",", ":")).encode()
            require(len(body) <= 1024 * 1024, "rpc_response_bound")
            channel.sendall(struct.pack("!I", len(body)) + body)
        finally:
            self.active = 0

    def serve(self, nonce: str) -> None:
        backend = self.original()
        path = "/run/wakeio-m1/relay.sock"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                os.chown(path, 0, 10000)
                os.chmod(path, 0o660)
                listener.listen(1)
                listener.settimeout(900)
                require(os.write(1, RELAY_READY) == len(RELAY_READY), "relay_marker_short")
                backend.wait_readable(listener)
                self._accept(listener)
                while not backend.closed:
                    self._request(nonce)
            os.unlink(path)
        finally:
            if not backend.closed:
                self.source.revoke("backend_conversation_left")

    def close(self) -> None:
        backend = self.original()
        if self.closed:
            return
        require(backend.closed and backend.build._drained and self.source.observers_retired,
                "backend_connection_retained")
        if self.socket is not None:
            try:
                self.check()
                self.socket.close()
            except (BackendError, OSError) as error:
                self.close_unknown = True
                raise BackendError("backend_connection_close_unconfirmed:" + str(error)) from error
        self.closed = True


def serve(backend: Backend, nonce: str) -> None:
    OriginalConnection(backend._startup).serve(nonce)
