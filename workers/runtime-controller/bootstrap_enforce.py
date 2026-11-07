#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Verify the live PREPARE envelope, then exec the unchanged sealed installer."""
import errno
import json
import os
import socket
import sys

sys.path.insert(0, "/usr/local/lib/wakeio-controller")
from backend_process import BackendError, require


def probe_endpoint(endpoint: tuple[str, int], allowed: bool) -> None:
    address, port = endpoint
    require(address in ("127.0.0.2", "::1", "127.0.0.1", "2001:db8::1")
            and 1024 <= port <= 65535, "prepare_witness_endpoint")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe, probe.makefile("rb") as incoming:
        probe.settimeout(2)
        blocked = False
        try:
            probe.connect((address, port))
        except TimeoutError:
            blocked = True
        except OSError as error:
            blocked = error.errno in (errno.EACCES, errno.EPERM, errno.ENETUNREACH)
        if allowed:
            require(not blocked, "prepare_allow_unconfirmed")
            probe.sendall(b"ALLOW\n")
            require(incoming.readline(7) == b"OWNED\n", "prepare_allow_unconfirmed")
        else:
            require(blocked, "prepare_egress_escape")


def verify_prepare_envelope() -> None:
    require(os.geteuid() == 0, "prepare_envelope_ingress")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control, control.makefile("rb") as incoming:
        control.settimeout(30)
        control.connect("/run/wakeio-m1/prepare.sock")
        control.sendall(b"PROBE\n")
        body = incoming.readline(1025)
        require(body.endswith(b"\n") and len(body) <= 1024, "prepare_witness_bound")
        raw = json.loads(body)
        require(isinstance(raw, list) and len(raw) == 4, "prepare_witness_protocol")
        endpoints: list[tuple[str, int]] = []
        for item in raw:
            if (not isinstance(item, list) or len(item) != 2
                    or not isinstance(item[0], str) or type(item[1]) is not int):
                raise BackendError("prepare_witness_endpoint")
            endpoints.append((item[0], item[1]))
        require(tuple(item[0] for item in endpoints) ==
                ("127.0.0.2", "::1", "127.0.0.1", "2001:db8::1"), "prepare_witness_order")
        for index, endpoint in enumerate(endpoints):
            probe_endpoint(endpoint, index < 2)
        control.sendall(b"DONE\n")
        require(incoming.readline(8) == b"NARROW\n", "prepare_enforcement_unconfirmed")
        for endpoint in endpoints[:2]:
            probe_endpoint(endpoint, False)
        control.sendall(b"DONE\n")
        require(incoming.readline(8) == b"DENIED\n", "prepare_enforcement_unconfirmed")


def main() -> None:
    require(os.geteuid() == 0 and len(sys.argv) == 1, "prepare_envelope_ingress")
    verify_prepare_envelope()
    os.execv("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B",
                                "/usr/local/lib/wakeio-install/install_supervisor.py"))


if __name__ == "__main__":
    main()
