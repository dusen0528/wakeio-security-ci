#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Source-free PREPARE witness for the service envelope before nft is installed."""
import ipaddress
import json
import os
import re
import socket
import struct
import sys
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/wakeio-controller")
from backend_process import Command, checked, require

SOCKET = "/run/wakeio-m1/prepare.sock"


def calibrate(listener: socket.socket) -> None:
    with socket.socket(listener.family, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(listener.getsockname())
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b"owned")
            require(client.recv(5) == b"owned", "prepare_witness_calibration")


def addresses() -> tuple[str, ...]:
    selected = []
    with open("/etc/hosts", "a", encoding="ascii") as hosts:
        for host in ("download.docker.com", "ports.ubuntu.com"):
            resolved = sorted({row[4][0] for row in socket.getaddrinfo(host, 443, socket.AF_INET,
                                                                     socket.SOCK_STREAM)})
            require(0 < len(resolved) <= 32
                    and all(ipaddress.ip_address(ip).is_global for ip in resolved), "prepare_publisher")
            for ip in resolved:
                hosts.write(ip + " " + host + "\n")
            selected.extend(resolved)
    return tuple(sorted(set(selected)))


def main() -> None:
    require(os.geteuid() == 0 and len(sys.argv) == 2
            and re.fullmatch(r"wakeio-install-[a-f0-9]{32}\.service", sys.argv[1]) is not None,
            "prepare_witness_owner")
    resolved = addresses()
    # The IPv6 deny address exists only inside this newly owned VM. No host
    # interface or firewall is changed. Failure to allocate it refuses PREPARE.
    checked(Command(("/usr/sbin/ip", "-6", "address", "add", "2001:db8::1/128", "dev", "lo")))
    with ExitStack() as stack:
        stack.callback(checked, Command(("/usr/sbin/ip", "-6", "address", "del",
                                        "2001:db8::1/128", "dev", "lo")))
        witnesses = []
        for family, address in ((socket.AF_INET, "127.0.0.2"), (socket.AF_INET6, "::1"),
                                (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "2001:db8::1")):
            witness = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
            witness.settimeout(3)
            if family == socket.AF_INET6:
                witness.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            witness.bind((address, 0))
            witness.listen(1)
            calibrate(witness)
            witnesses.append(witness)
        listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        listener.bind(SOCKET)
        os.chmod(SOCKET, 0o600)
        listener.listen(1)
        listener.settimeout(300)
        sys.stdout.write(json.dumps({"addresses": resolved}, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        connection, _ = listener.accept()
        with connection, connection.makefile("rb") as incoming:
            connection.settimeout(30)
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == 0, "prepare_witness_peer")
            group = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").strip()
            require(group == "0::/system.slice/" + sys.argv[1], "prepare_witness_service")
            require(incoming.readline(7) == b"PROBE\n", "prepare_witness_protocol")
            connection.sendall(json.dumps([list(item.getsockname()[:2]) for item in witnesses],
                                          separators=(",", ":")).encode("ascii") + b"\n")
            for item in witnesses[:2]:
                arrived, _ = item.accept()
                with arrived, arrived.makefile("rb") as acknowledgement:
                    arrived.settimeout(3)
                    require(acknowledgement.readline(7) == b"ALLOW\n", "prepare_allow_witness")
                    arrived.sendall(b"OWNED\n")
            require(incoming.readline(6) == b"DONE\n", "prepare_witness_protocol")
            confirm_denied(witnesses[2:])
            # Remove the two temporary allow witnesses before ANY package
            # preparation. Reset (do not append) the service's full allow set.
            checked(Command(("/usr/bin/systemctl", "set-property", "--runtime", sys.argv[1],
                             "IPAddressAllow=" + " ".join(resolved))))
            connection.sendall(b"NARROW\n")
            require(incoming.readline(6) == b"DONE\n", "prepare_witness_protocol")
            confirm_denied(witnesses[:2])
            connection.sendall(b"DENIED\n")
    os.unlink(SOCKET)


def confirm_denied(witnesses: list[socket.socket]) -> None:
    for witness in witnesses:
        witness.setblocking(False)
        try:
            arrived, _ = witness.accept()
        except BlockingIOError:
            arrived = None
        if arrived is not None:
            arrived.close()
        require(arrived is None, "prepare_egress_escape")
        witness.settimeout(3)
        calibrate(witness)


if __name__ == "__main__":
    main()
