#!/usr/bin/python3 -IB
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fixed APT InfoFD entry. Run only by the owned apt-get transaction."""
import os
import socket
import sys

# Installed as verified root-owned helper bytes; never imported from source/cwd.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from seal_types import InstallError, require


def main() -> None:
    require(os.geteuid() == 0 and os.environ.get("APT_HOOK_INFO_FD") == "0", "hook_infofd")
    raw_fd = os.environ.get("WAKEIO_INSTALL_FD", "")
    require(raw_fd.isascii() and raw_fd.isdecimal(), "hook_channel")
    fd = int(raw_fd)
    require(fd > 2, "hook_channel_fd")
    payload = sys.stdin.buffer.read(65537)
    require(0 < len(payload) <= 65536, "hook_payload")
    with socket.socket(fileno=fd) as channel:
        channel.settimeout(15)
        channel.sendall(payload)
        require(channel.recv(16) == b"ACCEPT", "hook_rejected")


if __name__ == "__main__":
    try:
        main()
    except (InstallError, OSError, UnicodeError):
        sys.exit(125)
