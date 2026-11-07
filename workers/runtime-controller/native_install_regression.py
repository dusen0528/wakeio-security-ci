#!/usr/bin/python3 -IB
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fixed pre-install exec after original SSH-bound installed bytes and service checks."""
import hashlib
import hmac
import json
import os
import re
import selectors
import stat
import sys
from pathlib import Path
from typing import Final

sys.path.insert(0, "/usr/local/lib/wakeio-controller")
from backend_process import require

ROOT: Final = Path("/usr/local/lib/wakeio-controller")
INSTALL: Final = Path("/usr/local/lib/wakeio-install")
CASES: Final = ("mount-original", "mount-corrected", "apt-original", "apt-corrected")
TESTS: Final = {
    "mount": ("runtime_provision_install_mount_test.py",
              "a217ce99104dba417614e5851414ef376a695f2ff598a7591888ec1757bd296e"),
    "apt": ("runtime_provision_install_apt_test.py",
            "43366a9059c93956ee5bf767465421eb9996e3713b3fe9645b6b24e80393f6d0"),
}


def directory(path: Path) -> None:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
            "native_directory_identity")


def regular(path: Path, mode: int, limit: int) -> bytes:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= limit, "native_file_identity")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        body = stream.read(limit + 1)
        after = path.lstat()
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and len(body) == info.st_size, "native_file_changed")
    return body


def installed(expected: str, case_id: str) -> bytes:
    for path in (Path("/"), Path("/usr"), Path("/usr/local"), Path("/usr/local/lib"), ROOT, INSTALL):
        directory(path)
    manifest = regular(ROOT / "manifest.json", 0o600, 32768)
    require(hashlib.sha256(manifest).hexdigest() == expected, "native_manifest_binding")
    rows = json.loads(manifest)
    require(isinstance(rows, list) and len(rows) == 44, "native_manifest_count")
    expected_files = {ROOT / "manifest.json", ROOT / "session"}
    install_count = 0
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"name", "installation", "sha256"},
                "native_manifest_fields")
        name, location, digest = row["name"], row["installation"], row["sha256"]
        require(isinstance(name, str) and re.fullmatch(r"(?:[a-z][a-z0-9_-]*/)*[a-z][a-z0-9_-]*\.(?:py|mjs|js|json)",
                                                     name) is not None
                and location in ("controller", "install") and isinstance(digest, str)
                and re.fullmatch(r"[a-f0-9]{64}", digest) is not None, "native_manifest_entry")
        root = ROOT if location == "controller" else INSTALL
        path = root / name
        require(path not in expected_files, "native_manifest_duplicate")
        expected_files.add(path)
        install_count += location == "install"
        for parent in path.parents:
            directory(parent)
        body = regular(path, 0o755 if name == "install_hook.py" else 0o644, 128 * 1024)
        require(hashlib.sha256(body).hexdigest() == digest, "native_helper_digest")
    require(install_count == 14, "native_installer_count")
    expected_dirs = {ROOT, INSTALL, *(p for f in expected_files for p in f.parents if p in (ROOT, INSTALL)
                                    or ROOT in p.parents or INSTALL in p.parents)}
    actual_files = set()
    for root in (ROOT, INSTALL):
        for parent, directories, files in os.walk(root, followlinks=False):
            directory(Path(parent))
            for child in directories:
                require(Path(parent) / child in expected_dirs, "native_package_directory")
                directory(Path(parent) / child)
            actual_files.update(Path(parent) / name for name in files)
            require(len(actual_files) <= len(expected_files), "native_package_bound")
    require(actual_files == expected_files, "native_package_membership")
    for name, digest in TESTS.values():
        require(hashlib.sha256(regular(ROOT / "native" / name, 0o644, 16384)).hexdigest() == digest,
                "native_test_binding")
    originals = {"mount-original": ("install_sandbox.py",
                  "d415ec310c495e773688b1b07f2964c2c797e86e73233ee758c99fb70d789882"),
                 "apt-original": ("install_config.py",
                  "93ad70b2d6c2797e86bf4bdc1a6a7d688c808699cdcbecddb048014a2e5267b4")}
    if case_id in originals:
        name, digest = originals[case_id]
        require(hashlib.sha256(regular(INSTALL / name, 0o644, 65536)).hexdigest() == digest,
                "native_original_binding")
    secret = regular(ROOT / "session", 0o600, 64)
    require(re.fullmatch(rb"[a-f0-9]{64}", secret) is not None and secret != b"0" * 64, "native_session")
    return bytes.fromhex(secret.decode("ascii"))


def service(expected_boot: str, unit: str) -> str:
    sys.path.insert(0, str(INSTALL))
    from install_supervisor import prerequisite
    from seal_files import Files
    from seal_process import own_service
    from install_process import Deadline, checked
    from install_audit import inactive
    with Files() as files:
        require(prerequisite(files).decode("ascii").strip() == expected_boot, "native_boot_binding")
        group = own_service()
        require(group == "/system.slice/" + unit, "native_service_binding")
        with selectors.DefaultSelector() as events:
            events.register(0, selectors.EVENT_READ)
            require(stat.S_ISFIFO(os.fstat(0).st_mode) and not events.select(0), "native_controller_pipe")
        inactive(Deadline(30))
        output = checked(("/usr/bin/systemctl", "show", unit,
                          "--property=Id,InvocationID,MainPID,ControlGroup"), Deadline(30))
        state = dict(line.split("=", 1) for line in output.decode("ascii").splitlines())
        invocation = state.get("InvocationID", "")
        require(state.get("Id") == unit and state.get("MainPID") == str(os.getpid())
                and state.get("ControlGroup") == group and re.fullmatch(r"[a-f0-9]{32}", invocation) is not None
                and os.environ.get("INVOCATION_ID") == invocation, "native_service_identity")
        files.check()
    return invocation


def main() -> None:
    require(os.geteuid() == os.getegid() == 0 and sys.platform == "linux" and sys.version_info >= (3, 11)
            and len(sys.argv) == 6, "native_ingress")
    case_id, helper, boot, unit, challenge = sys.argv[1:]
    require(case_id in CASES and re.fullmatch(r"[a-f0-9]{64}", helper) is not None
            and re.fullmatch(r"[a-f0-9]{64}", challenge) is not None
            and re.fullmatch(r"wakeio-install-[a-f0-9]{32}\.service", unit) is not None, "native_ingress")
    secret = installed(helper, case_id)
    invocation = service(boot, unit)
    if case_id.startswith("apt-"):
        from bootstrap_enforce import verify_prepare_envelope
        verify_prepare_envelope()
    name, digest = TESTS["mount" if case_id.startswith("mount-") else "apt"]
    payload = {"boot": boot, "caseId": case_id, "cgroup": "/system.slice/" + unit, "challenge": challenge,
               "helper": helper, "invocation": invocation, "mainPid": os.getpid(), "test": name,
               "testSha256": digest, "unit": unit}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(secret, canonical.encode("ascii"), hashlib.sha256).hexdigest()
    print(json.dumps({"payload": payload, "mac": mac}, separators=(",", ":")), flush=True)
    # No prior prepare/BASE/masks: the unchanged test alone owns its setUp and signed closure.
    os.execv("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B", str(ROOT / "native" / name)))


if __name__ == "__main__":
    main()
