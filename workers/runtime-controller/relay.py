#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fixed controller-only Unix RPC. No Docker HTTP, argv, SQL or shell is accepted."""
import hashlib
import hmac
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
from dataclasses import asdict
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from types import FrameType
from typing import Literal, assert_never

sys.path.insert(0, "/usr/local/lib/wakeio-controller")
sys.path.insert(0, "/usr/local/lib/wakeio-controller/build")
if __name__ == "__main__":
    sys.modules["relay"] = sys.modules[__name__]
from backend_process import BackendError, require
from backend_resources import Resources
import build
from collector import collect, baseline_inventory, owned_inventory, DelegationRefusal, Qualification
from daemon import Daemon
from network import Network
from proxy_owner import Mirror

Operation = Literal["identity", "qualify", "network-build", "network-runtime", "shutdown"]


def operation(raw: str) -> Operation:
    match raw:
        case "identity" | "qualify" | "network-build" | "network-runtime" | "shutdown":
            return raw
        case _:
            raise BackendError("rpc_operation")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "rpc_duplicate_key")
        result[key] = value
    return result


def receive(connection: socket.socket, backend: "Backend") -> bytes:
    header = bytearray()
    while len(header) < 4:
        backend.wait_readable(connection)
        chunk = connection.recv(4 - len(header))
        require(bool(chunk), "rpc_closed")
        header.extend(chunk)
    length = struct.unpack("!I", header)[0]
    require(0 < length <= 65536, "rpc_bound")
    body = bytearray()
    while len(body) < length:
        backend.wait_readable(connection)
        chunk = connection.recv(length - len(body))
        require(bool(chunk), "rpc_closed")
        body.extend(chunk)
    return bytes(body)


class Backend(build.phase_factory.ConfigurationObservationBoundary):
    """Only this source-free producer can answer qualification; JSON never restores it."""
    def __init__(self, run_id: str):
        self.run_id = run_id
        self._mutation_lock = RLock()
        self._mutation_unknown = False
        self.qualified = False
        self.refused = False
        self._interrupted = False
        self.closed = False
        self._wake_read, self._wake_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.root = Path("/usr/local/lib/wakeio-controller")
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        manifest = (self.root / "manifest.json").read_bytes()
        self.helper_hash = hashlib.sha256(manifest).hexdigest()
        self.files = []
        for entry in json.loads(manifest):
            path = Path("/usr/local/lib/wakeio-" + entry["installation"]) / entry["name"]
            self.files.append((path, path.stat().st_ino, entry["sha256"]))
        self.network = Network()
        self.network.apply()
        self.baseline = baseline_inventory(run_id, self.helper_hash)
        self.daemon = Daemon()
        self.daemon.start()
        self.resources = Resources(self.daemon, run_id, "infrastructure")
        self.mirror = Mirror(self.resources, self.network)
        self.build = build.BuildSession(self)

    def acquire(self) -> None:
        with self.mutation():
            require(not self.refused and not self.resources.image, "backend_acquisition_replay")
            self.resources.acquire()

    @contextmanager
    def mutation(self, cleanup: bool = False) -> Iterator[None]:
        """Legacy mutation uncertainty survives leaving the shared serialization scope."""
        with self._mutation_lock:
            require(not self._mutation_unknown and (cleanup or not self.refused), "backend_mutation_unknown")
            acknowledged = False
            try:
                yield
                acknowledged = True
            finally:
                if not acknowledged:
                    self._mutation_unknown = True
                    self.build._fail("backend_mutation_unknown")
                    self.build.drain()

    def interrupt(self) -> None:
        self._interrupted = True
        self.build._fail("backend_interrupted")
        try:
            os.write(self._wake_write, b"!")
        except OSError as error:
            self.build._fail("backend_wake_failed:" + str(error))

    def wait_readable(self, channel: socket.socket) -> None:
        events = select.poll()
        events.register(channel.fileno(), select.POLLIN)
        events.register(self._wake_read, select.POLLIN)
        require(bool(events.poll(900000)) and not self._interrupted, "backend_rpc_stopped")

    def check(self) -> None:
        require(not self.closed and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == self.boot,
                "backend_revoked")
        for path, inode, digest in self.files:
            value = os.lstat(path)
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_ino == inode
                    and value.st_nlink == 1 and value.st_mode & 0o022 == 0
                    and hashlib.sha256(path.read_bytes()).hexdigest() == digest, "helper_changed")
        self.daemon.check()

    def dispatch(self, selected: Operation):
        require(not self.refused or selected == "shutdown", "backend_refused")
        self.check()
        if selected in ("network-build", "qualify", "network-runtime"):
            with self.mutation():
                return self._dispatch(selected)
        return self._dispatch(selected)

    def _dispatch(self, selected: Operation):
        match selected:
            case "identity":
                return {"run": self.run_id, "boot": self.boot, "daemon": self.daemon.identity,
                        "helper": self.helper_hash}
            case "network-build":
                require(not self.qualified, "backend_phase")
                self.network.transition("BUILD")
                files = tuple((name, (self.root / name).read_bytes()) for name in (
                    "proxy.mjs", "runtime/builders/build-policy.js", "json-snapshot.js", "package.json"))
                self.mirror.start(files)
                ownership = owned_inventory(self.baseline, self.daemon, self.resources)
                require(len(json.dumps(asdict(ownership), separators=(",", ":")).encode()) <= 32768,
                        "inventory_bound")
                return {"phase": "BUILD", "certificateSha256": self.mirror.certificate_sha256(),
                        "network": self.mirror.build, "endpoint": "https://wakeio-maven:8443",
                        "ownership": asdict(ownership)}
            case "qualify":
                require(not self.qualified and self.network.phase == "BUILD", "backend_phase")
                observed = collect(self.daemon, self.mirror, self.run_id)
                match observed:
                    case DelegationRefusal():
                        self.refused = True
                    case Qualification():
                        self.qualified = True
                    case unreachable:
                        assert_never(unreachable)
                return asdict(observed)
            case "network-runtime":
                require(self.qualified, "backend_unqualified")
                return asdict(self.network.transition("RUNTIME"))
            case "shutdown":
                self.close()
                return {"closed": True}
            case unreachable:
                assert_never(unreachable)

    def close(self) -> None:
        if self.closed:
            return
        self.build.drain()
        with self.mutation(True):
            if self.mirror.container or self.mirror.build:
                self.mirror.close()
            else:
                self.resources.cleanup()
            self.daemon.stop()
            self.network.cleanup()
        os.close(self._wake_read)
        os.close(self._wake_write)
        self.closed = True


def serve(backend: Backend, nonce: str) -> None:
    path = "/run/wakeio-m1/relay.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        os.chown(path, 0, 10000)
        os.chmod(path, 0o660)
        listener.listen(1)
        listener.settimeout(900)
        sys.stdout.write("RELAY_READY\n")
        sys.stdout.flush()
        backend.wait_readable(listener)
        connection, _ = listener.accept()
        with connection:
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer[1] == 10000, "rpc_peer")
            connection.settimeout(900)
            sequence = 0
            while not backend.closed:
                request = json.loads(receive(connection, backend), object_pairs_hook=unique_pairs)
                sequence += 1
                require(set(request) == {"version", "sequence", "challenge", "run", "operation", "mac"}
                        and request["version"] == 1 and request["sequence"] == sequence and sequence <= 1024
                        and request["run"] == backend.run_id
                        and re.fullmatch(r"[a-f0-9]{64}", request["challenge"]) is not None, "rpc_binding")
                payload = {key: request[key] for key in ("version", "sequence", "run", "challenge", "operation")}
                canonical = json.dumps(payload, separators=(",", ":"))
                expected = hmac.new(bytes.fromhex(nonce), ("request:" + canonical).encode(),
                                    hashlib.sha256).hexdigest()
                require(hmac.compare_digest(expected, request["mac"]), "rpc_request_mac")
                result = backend.dispatch(operation(request["operation"]))
                require(not backend._interrupted, "backend_interrupted")
                response = {"version": 1, "sequence": sequence, "run": backend.run_id,
                            "challenge": request["challenge"], "result": result}
                canonical = json.dumps(response, separators=(",", ":"))
                mac = hmac.new(bytes.fromhex(nonce), ("response:" + canonical).encode(),
                               hashlib.sha256).hexdigest()
                body = json.dumps({**response, "mac": mac}, separators=(",", ":")).encode()
                require(len(body) <= 1024 * 1024, "rpc_response_bound")
                connection.sendall(struct.pack("!I", len(body)) + body)
    os.unlink(path)


def main() -> None:
    require(os.geteuid() == 0 and len(sys.argv) == 2
            and re.fullmatch(r"[a-f0-9]{32}", sys.argv[1]) is not None, "backend_ingress")
    nonce = Path("/usr/local/lib/wakeio-controller/session").read_text(encoding="ascii")
    require(re.fullmatch(r"[a-f0-9]{64}", nonce) is not None, "backend_session")
    backend: Backend | None = None
    early_interrupt = False
    def interrupted(signum: int, frame: FrameType | None) -> None:
        nonlocal early_interrupt
        early_interrupt = True
        if backend is not None:
            backend.interrupt()
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    backend = Backend(sys.argv[1])
    try:
        if early_interrupt:
            backend.interrupt()
        backend.acquire()
        serve(backend, nonce)
    finally:
        backend.close()


if __name__ == "__main__":
    try:
        main()
    except (BackendError, OSError, ValueError, KeyError):
        sys.stderr.write("BACKEND_FAILED\n")
        sys.exit(125)
