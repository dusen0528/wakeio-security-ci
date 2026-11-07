#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Authenticate the guest host key using the per-boot secret delivered in owned cidata."""
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 2 or re.fullmatch(r"[a-f0-9]{64}", sys.argv[1]) is None:
        raise ValueError("bootstrap_identity_ingress")
    path = "/etc/ssh/ssh_host_ed25519_key.pub"
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_size > 4096:
        raise ValueError("bootstrap_host_key")
    key = Path(path).read_text(encoding="ascii").strip().split()
    if len(key) not in (2, 3) or key[0] != "ssh-ed25519" or re.fullmatch(r"[A-Za-z0-9+/=]+", key[1]) is None:
        raise ValueError("bootstrap_host_key")
    root = Path("/usr/local/lib/wakeio-controller")
    secret = bytes.fromhex((root / "session").read_text(encoding="ascii"))
    payload = {"boot": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
               "challenge": sys.argv[1], "helper": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
               "key": key[0] + " " + key[1]}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(secret, canonical.encode("ascii"), hashlib.sha256).hexdigest()
    sys.stdout.write(json.dumps({"payload": payload, "mac": mac}, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
