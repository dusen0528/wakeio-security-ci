"""Own the single dual-network Maven mirror and its real readiness/exit stream."""
import hashlib
import json
import os
import selectors
import subprocess
from pathlib import Path

from backend_process import Command, USER_ENV, checked, require
from backend_resources import Resources
from daemon import DOCKER
from network import Network


class Mirror:
    """The attach child remains owned until Docker stop and actual child wait complete."""
    def __init__(self, resources: Resources, network: Network):
        self.resources = resources
        self.network = network
        self.container = ""
        self.build = ""
        self.certificate = b""
        self.child: subprocess.Popen | None = None

    def start(self, helpers: tuple[tuple[str, bytes], ...]) -> None:
        self.build = self.resources.network(True)
        egress = self.resources.network(False)
        self.container = self.resources.create("proxy", egress)
        checked(Command((*DOCKER, "network", "connect", "--alias=wakeio-maven",
                         self.build, self.container), user=True))
        directory = Path("/run/wakeio-m1/mirror")
        directory.mkdir(mode=0o700)
        checked(Command(("/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                         "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=wakeio-maven",
                         "-addext", "subjectAltName=DNS:wakeio-maven",
                         "-keyout", str(directory / "mirror.key"), "-out", str(directory / "mirror.crt"))))
        self.certificate = (directory / "mirror.crt").read_bytes()
        files = (*helpers, ("mirror.crt", self.certificate),
                 ("mirror.key", (directory / "mirror.key").read_bytes()),
                 ("upstream.json", json.dumps(self.network.maven).encode("ascii")))
        self.resources.seed(self.container, files)
        self.child = subprocess.Popen((*DOCKER, "start", "--attach", self.container), env=USER_ENV,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      user=10001, group=10001, extra_groups=(), start_new_session=True)
        require(self.child.stdout is not None and self.child.stderr is not None, "mirror_pipes")
        with selectors.DefaultSelector() as events:
            events.register(self.child.stdout, selectors.EVENT_READ)
            events.register(self.child.stderr, selectors.EVENT_READ)
            ready = events.select(30)
            require(bool(ready), "mirror_ready_deadline")
            for key, _ in ready:
                body = os.read(key.fd, 1025)
                require(key.fileobj is self.child.stdout and body == b"MIRROR_READY\n", "mirror_ready_protocol")
        require(self.resources.inspect(self.container).state == "running", "mirror_not_running")

    def certificate_sha256(self) -> str:
        return hashlib.sha256(self.certificate).hexdigest()

    def close(self) -> None:
        self.resources.cleanup()
        if self.child is not None:
            require(self.child.wait(timeout=30) == 0, "mirror_close_unconfirmed")
            self.child.stdout.close()
            self.child.stderr.close()
        directory = Path("/run/wakeio-m1/mirror")
        for name in ("mirror.key", "mirror.crt"):
            (directory / name).unlink()
        directory.rmdir()
