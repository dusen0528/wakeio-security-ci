"""Native signed APT resolves the complete transaction, including Pre-Depends.

This adapts M1's selection/download flow without requiring python3-apt to
bootstrap itself. apt-get, gpgv and dpkg must already belong to the verified OS.
"""
import hashlib
import os
import re
from dataclasses import dataclass

from install_config import apt, capture_indexes, configure, targets
from install_process import Deadline, checked, run
from install_records import Download, downloads, installed, paragraphs, version
from seal_files import Files
from seal_types import BASE, PINS, Package, Version, require


@dataclass(frozen=True, slots=True)
class Prepared:
    packages: tuple[Package, ...]
    baseline: dict[str, Version]
    configuration: dict[str, str]
    digest: str


def prepare(files: Files, deadline: Deadline, hook_fd: int) -> Prepared:
    status = files.capture("/var/lib/dpkg/status", 32 * 1024 * 1024)
    baseline = installed(status.read())
    require(not any(name in baseline for name, _, _, _ in PINS), "engine_present")
    require(checked(("/usr/bin/dpkg", "--audit"), deadline) == b"", "baseline_audit")
    files.capture("/usr/share/keyrings/ubuntu-archive-keyring.gpg", 1024 * 1024)
    configuration = configure(files, hook_fd)
    # APT_CONFIG is supplied by the supervisor before any native APT invocation;
    # Parts/main are already redirected before apt's initialization reads them.
    checked(apt(("update", "--error-on=any")), deadline)
    capture_indexes(files, deadline)
    files.check()
    selection = downloads(checked(apt(("--print-uris", "--download-only", "install", *targets())), deadline))
    checked(apt(("--download-only", "install", *targets())), deadline)
    packages = tuple(package(record, files, (baseline, deadline)) for record in selection)
    require(len({p.name for p in packages}) == len(packages), "package_duplicate")
    for name, expected, size, sha in PINS:
        matches = [p for p in packages if p.name == name]
        require(len(matches) == 1, "required_pin")
        value = matches[0]
        require((value.new.version, value.size, value.sha256, value.origin, value.new.arch)
                == (expected, size, sha, "docker", "arm64"), "package_pin")
    require(set(os.listdir(BASE + "/archives")) == {p.file for p in packages} | {"partial", "lock"},
            "archive_entries")
    require(os.listdir(BASE + "/archives/partial") == [], "partial_download")
    files.capture(BASE + "/archives/lock", 0)
    files.directory(BASE + "/archives/partial")
    files.directory(BASE + "/archives")
    files.directory(BASE)
    files.check()
    digest = hashlib.sha256((files.digest() + repr(packages)).encode("ascii")).hexdigest()
    return Prepared(packages, baseline, configuration, digest)


def package(record: Download, files: Files, context: tuple[dict[str, Version], Deadline]) -> Package:
    baseline, deadline = context
    path = BASE + "/archives/" + record.file
    anchor = files.capture(path, 128 * 1024 * 1024)
    require(anchor.size == record.size and anchor.sha256 == record.sha256, "deb_identity")
    fields = paragraphs(checked(("/usr/bin/dpkg-deb", "--field", path), deadline))
    require(len(fields) == 1, "deb_fields")
    metadata = fields[0]
    name = metadata["Package"]
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,63}", name) is not None, "package_name")
    new = version(metadata)
    old = baseline.get(name, Version("-", "-", "none"))
    if old.version != "-":
        comparison = run(("/usr/bin/dpkg", "--compare-versions", new.version, "gt", old.version), deadline)
        require(comparison.code == 0, "non_upgrade")
    require(record.origin == "ubuntu" or name in {p[0] for p in PINS}, "unapproved_docker_package")
    anchor.read()
    return Package(name, old, new, "<", record.file, record.size, record.sha256, record.origin)
