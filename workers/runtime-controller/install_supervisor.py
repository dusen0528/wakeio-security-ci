#!/usr/bin/python3 -IB
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run via the fixed transient service command exported by provision-install.ts."""
import os
import selectors
import shutil
import signal
import socket
import sys
from contextlib import ExitStack

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from install_audit import Autostart, post_state, service_limits
from install_prepare import prepare
from install_process import Deadline
from install_transaction import transaction
from seal_files import Files, identity
from seal_operation import Operation
from seal_process import own_service, drain_service, members
from seal_types import BASE, WORKERS, InstallError, require

HELPERS = ("seal_types.py", "seal_files.py", "seal_hook.py", "seal_operation.py",
           "install_process.py", "install_records.py", "install_config.py", "install_prepare.py",
           "install_audit.py", "install_sandbox.py", "install_transaction.py",
           "install_supervisor.py", "install_hook.py", "seal_process.py")


def interrupted(signum: int, frame) -> None:
    raise InstallError("operation_interrupted:" + str(signum))


def boot() -> bytes:
    with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
        body = stream.read(38)
    require(len(body) == 37 and body.endswith(b"\n"), "boot_identity")
    return body


def prerequisite(files: Files) -> bytes:
    require(os.geteuid() == 0 and os.uname().sysname == "Linux", "guest_linux_root")
    require(os.uname().machine == "aarch64", "guest_architecture")
    require(os.path.realpath(os.path.dirname(__file__)) == WORKERS, "helper_location")
    service_limits()
    os_release = files.capture("/usr/lib/os-release", 8192).read()
    require(b"ID=ubuntu\n" in os_release and b'VERSION_ID="24.04"\n' in os_release, "guest_os")
    for name in HELPERS:
        files.capture(WORKERS + "/" + name, 65536)
    require(os.access(WORKERS + "/install_hook.py", os.X_OK), "hook_executable_mode")
    for tool in ("/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/dpkg-deb", "/usr/bin/gpgv",
                 "/usr/bin/systemctl", "/usr/bin/python3", "/usr/lib/apt/apt-helper",
                 "/usr/lib/apt/methods/http", "/usr/lib/apt/methods/gpgv",
                 "/usr/lib/apt/methods/store"):
        files.capture(os.path.realpath(tool), 32 * 1024 * 1024)
    require(os.path.realpath("/usr/lib/apt/methods/https") == "/usr/lib/apt/methods/http", "https_method")
    require(not os.path.lexists(BASE), "preparation_already_exists")
    return boot()


def consume_command(deadline: Deadline) -> None:
    with selectors.DefaultSelector() as events:
        events.register(0, selectors.EVENT_READ)
        body = bytearray()
        while b"\n" not in body:
            require(bool(events.select(deadline.remaining())), "controller_deadline")
            chunk = os.read(0, 9 - len(body))
            require(bool(chunk), "controller_closed")
            body.extend(chunk)
            require(len(body) <= 8, "controller_command_bound")
        require(body == b"INSTALL\n", "controller_command")


def main() -> None:
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    signal.setitimer(signal.ITIMER_REAL, 300)
    deadline = Deadline(900)
    with ExitStack() as lifetime:
        files = lifetime.enter_context(Files())
        original_boot = prerequisite(files)
        service = own_service()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        lifetime.enter_context(parent)
        lifetime.enter_context(child)
        owner = Operation(files, deadline)
        policy = Autostart()
        root_identity = None
        try:
            os.mkdir(BASE, 0o700)
            root_identity = identity(os.lstat(BASE))[:5]
            policy.install(files, Deadline(30))
            prepared = prepare(files, Deadline(300), child.fileno())
            require(boot() == original_boot, "boot_replaced")
            owner.prepared(prepared)
            sys.stdout.write("PREPARED " + prepared.digest + "\n")
            sys.stdout.flush()
            consume_command(deadline)
            signal.setitimer(signal.ITIMER_REAL, 300)
            require(boot() == original_boot, "boot_replaced")
            policy.check()
            hook_digest = transaction(owner, files, (parent, child))
            require(boot() == original_boot, "boot_replaced")
            policy.check()
            status = post_state(prepared, files, Deadline(30))
            require(not members(service), "post_install_descendants")
            owner.complete()
            result = "INSTALLED " + prepared.digest + " " + hook_digest + " " + status
        finally:
            owner.close()
            signal.setitimer(signal.ITIMER_REAL, 120)
            # If drain is unknown, throw before removing policy or preparation
            # files. The controller must retain its assets and destroy this VM.
            drain_service(service, Deadline(120))
            policy.cleanup_policy()
            if root_identity is not None:
                require(identity(os.lstat(BASE))[:5] == root_identity, "cleanup_root_replaced")
                shutil.rmtree(BASE)
        signal.setitimer(signal.ITIMER_REAL, 0)
        sys.stdout.write(result + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except (InstallError, OSError, UnicodeError, KeyError, ValueError):
        # Fixed bounded failure; do not export native tool chatter, paths or secrets.
        sys.stdout.write("FAILED\n")
        sys.stdout.flush()
        sys.exit(125)
