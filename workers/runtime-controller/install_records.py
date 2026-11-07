"""M1 signed-record path restrictions and native APT output parsers, not a solver."""
import re
import urllib.parse
from dataclasses import dataclass

from seal_types import Version, require


@dataclass(frozen=True, slots=True)
class Download:
    uri: str
    file: str
    size: int
    sha256: str
    origin: str


def package_uri(uri: str) -> str:
    parts = urllib.parse.urlsplit(uri)
    roots = {"download.docker.com": ("docker", "/linux/ubuntu/"),
             "ports.ubuntu.com": ("ubuntu", "/ubuntu-ports/")}
    require(parts.scheme == "https" and parts.netloc in roots, "uri_host")
    require(not parts.query and not parts.fragment and "\\" not in uri, "uri_components")
    origin, root = roots[parts.netloc]
    require(parts.path.startswith(root), "uri_root")
    tail = parts.path[len(root):]
    require(re.fullmatch(r"(?:[A-Za-z0-9.+~_:/-]|%2b|%7e)+", tail) is not None, "uri_encoding")
    raw = urllib.parse.unquote_to_bytes(tail).decode("ascii")
    require(tail in (raw, raw.replace("+", "%2b").replace("~", "%7e")), "uri_canonical")
    require(".." not in raw and all(p not in ("", ".") for p in raw.split("/")), "uri_path")
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*_[A-Za-z0-9.+:~_-]+_(arm64|all)\.deb",
                         raw.rsplit("/", 1)[-1]) is not None, "uri_deb")
    if origin == "docker":
        require(raw.startswith("dists/noble/pool/stable/arm64/") and len(raw.split("/")) == 6,
                "docker_path")
    else:
        match = re.fullmatch(r"pool/(main|universe)/([a-z0-9]|lib[a-z0-9])/([a-z0-9][a-z0-9+.-]*)/[^/]+", raw)
        require(match is not None, "ubuntu_path")
        if match is not None:
            source = match.group(3)
            require(match.group(2) == (source[:4] if source.startswith("lib") else source[:1]), "source_path")
    return origin


def downloads(raw: bytes) -> tuple[Download, ...]:
    require(len(raw) <= 1024 * 1024, "uri_output_bound")
    records = []
    for line in raw.decode("ascii").splitlines():
        if not line.startswith("'"):
            continue
        match = re.fullmatch(r"'([^']+)' ([A-Za-z0-9+~_.:%-]+\.deb) ([0-9]+) SHA256:([a-f0-9]{64})", line)
        require(match is not None, "download_record")
        if match is not None:
            uri, filename, size, sha = match.groups()
            require(".." not in filename and 0 < int(size) <= 128 * 1024 * 1024, "download_bound")
            records.append(Download(uri, filename, int(size), sha, package_uri(uri)))
    require(4 <= len(records) <= 48, "closure_count")
    require(len({r.file for r in records}) == len(records), "closure_duplicate")
    require(sum(r.size for r in records) <= 512 * 1024 * 1024, "closure_bytes")
    return tuple(records)


def paragraphs(raw: bytes) -> tuple[dict[str, str], ...]:
    require(len(raw) <= 32 * 1024 * 1024 and b"\x00" not in raw, "deb822_bound")
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines() + [""]:
        if not line:
            if current:
                records.append(current)
                current = {}
        elif not line.startswith((" ", "\t")):
            key, separator, value = line.partition(": ")
            require(separator == ": " and key not in current, "deb822_field")
            current[key] = value
    return tuple(records)


def version(record: dict[str, str]) -> Version:
    multi = record.get("Multi-Arch", "no")
    value = Version(record["Version"], record["Architecture"], "none" if multi == "no" else multi)
    require(re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,127}", value.version) is not None, "version")
    require(value.arch in ("arm64", "all"), "architecture")
    require(value.multi in ("none", "same", "foreign", "allowed"), "multiarch")
    return value


def installed(raw: bytes) -> dict[str, Version]:
    result = {}
    for record in paragraphs(raw):
        status = record.get("Status")
        require(status in ("install ok installed", "deinstall ok config-files"), "unclean_dpkg_state")
        if status == "deinstall ok config-files":
            continue
        require(not record.get("Triggers-Pending") and not record.get("Triggers-Awaited"), "pending_triggers")
        name = record["Package"]
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,63}", name) is not None, "package_name")
        require(name not in result, "duplicate_package")
        result[name] = version(record)
    require(bool(result), "empty_baseline")
    return result
