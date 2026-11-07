"""One owned APT configuration, created before index acquisition and never rewritten."""
import base64
import hashlib
import os
import urllib.request

from install_process import Deadline, checked
from seal_files import Files, write_new
from seal_types import BASE, HOOK, KEY_FINGERPRINT, KEY_SHA, PINS, InstallError, require


def options(hook_fd: int) -> dict[str, str]:
    return {
        "Dir": "/", "Dir::Etc": BASE, "Dir::State": BASE + "/scratch", "Dir::Cache": BASE,
        "Dir::Etc::Parts": BASE + "/empty", "Dir::Etc::main": BASE + "/absent",
        "Dir::Etc::sourcelist": BASE + "/sources.list", "Dir::Etc::sourceparts": BASE + "/empty",
        "Dir::Etc::preferences": BASE + "/absent", "Dir::Etc::preferencesparts": BASE + "/empty",
        "Dir::Etc::trusted": BASE + "/absent", "Dir::Etc::trustedparts": BASE + "/empty",
        "Dir::Etc::netrc": BASE + "/absent", "Dir::Etc::netrcparts": BASE + "/empty",
        "Dir::State::lists": BASE + "/lists", "Dir::State::status": "/var/lib/dpkg/status",
        "Dir::Cache::archives": BASE + "/archives", "Dir::Cache::pkgcache": "",
        "Dir::Cache::srcpkgcache": "", "Dir::State::extended_states": BASE + "/scratch/extended",
        "Dir::Log": BASE + "/scratch", "APT::Architecture": "arm64",
        "Dir::Log::Terminal": "term.log", "Dir::Log::History": "history.log",
        "Dir::Log::Planner": "eipp.log.xz",
        "Dir::Bin::dpkg": "/usr/bin/dpkg", "Dir::Bin::methods": "/usr/lib/apt/methods",
        "Dir::Bin::apt-key": "/usr/bin/apt-key", "Dir::Bin::solvers::": "/usr/lib/apt/solvers",
        "Dir::Bin::planners::": "/usr/lib/apt/planners", "APT::Keep-Downloaded-Packages": "true",
        "APT::Get::force-yes": "false",
        "APT::Install-Recommends": "false", "APT::Install-Suggests": "false",
        "Acquire::Languages": "none", "Acquire::Retries": "0", "Acquire::ForceHash": "sha256",
        "Acquire::https::Timeout": "8", "Acquire::http::Proxy": "DIRECT",
        "Acquire::https::Proxy": "DIRECT", "Acquire::https::AllowRedirect": "false",
        "Acquire::https::Verify-Peer": "true", "Acquire::https::Verify-Host": "true",
        "APT::Get::AllowUnauthenticated": "false", "Acquire::AllowInsecureRepositories": "false",
        "Acquire::AllowDowngradeToInsecureRepositories": "false", "Acquire::Check-Valid-Until": "true",
        "Acquire::AllowWeakRepositories": "false", "APT::Sandbox::User": "root",
        "APT::Get::Remove": "false", "APT::Get::allow-downgrades": "false",
        "APT::Get::allow-change-held-packages": "false", "APT::Get::allow-remove-essential": "false",
        "DPkg::ConfigurePending": "false", "DPkg::TriggersPending": "false", "DPkg::NoTriggers": "false",
        "DPkg::Use-Pty": "false",
        "DPkg::Tools::Options::" + HOOK + "::Version": "3",
        "DPkg::Tools::Options::" + HOOK + "::InfoFD": "0",
        "APT::Keep-Fds::": str(hook_fd),
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InstallError("key_redirect")


def configure(files: Files, hook_fd: int) -> dict[str, str]:
    for name in ("empty", "lists", "lists/partial", "archives", "archives/partial", "scratch"):
        os.mkdir(BASE + "/" + name, 0o700)
    # Canonical M1 fixed key acquisition; exact pinned bytes are trust input, not a signature claim.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open("https://download.docker.com/linux/ubuntu/gpg", timeout=8) as response:
        require(response.status == 200, "key_http")
        body = response.read(3818)
    require(len(body) == 3817 and hashlib.sha256(body).hexdigest() == KEY_SHA, "key_pin")
    write_new(BASE + "/docker.asc", body)
    files.capture(BASE + "/docker.asc", 3817)
    payload = body.split(b"\n\n", 1)[1].split(b"-----END", 1)[0]
    keyring = base64.b64decode(b"".join(line for line in payload.splitlines() if not line.startswith(b"=")),
                              validate=True)
    write_new(BASE + "/docker.gpg", keyring)
    files.capture(BASE + "/docker.gpg", 4096)
    sources = f"deb [arch=arm64 signed-by={BASE}/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n"
    for suite in ("noble", "noble-updates", "noble-security"):
        sources += ("deb [arch=arm64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                    f"https://ports.ubuntu.com/ubuntu-ports {suite} main universe\n")
    write_new(BASE + "/sources.list", sources.encode("ascii"))
    files.capture(BASE + "/sources.list", 8192)
    config = options(hook_fd)
    cleared = ("DPkg", "APT::Update", "APT::Get", "Dir::Ignore-Files-Silently", "Dir::Media",
               "Dir::State::cdroms", "Dir::Bin::solvers", "Dir::Bin::planners",
               "Acquire::cdrom", "Acquire::Changelogs", "Acquire::Snapshots")
    text = "".join(f"#clear {key};\n" for key in cleared)
    text += "".join(f'{key} "{value}";\n' for key, value in config.items())
    text += f'DPkg::Pre-Install-Pkgs {{ "{HOOK}"; }};\n'
    write_new(BASE + "/apt.conf", text.encode("ascii"))
    files.capture(BASE + "/apt.conf", 16384)
    files.directory(BASE + "/empty")
    return config


def apt(arguments: tuple[str, ...]) -> tuple[str, ...]:
    return ("/usr/bin/apt-get", "-c", BASE + "/apt.conf", "-o", "Dir::Etc::Parts=" + BASE + "/empty",
            "-o", "Dir::Etc::main=" + BASE + "/absent", "--yes", "--no-remove", *arguments)


def targets() -> tuple[str, ...]:
    return tuple(name + "=" + version for name, version, _, _ in PINS) + (
        "uidmap", "slirp4netns", "dbus-user-session", "iptables", "nftables")


def capture_indexes(files: Files, deadline: Deadline) -> None:
    names = sorted(os.listdir(BASE + "/lists"))
    records = [n for n in names if n not in ("lock", "partial", "auxfiles")]
    require(4 <= len(records) <= 32, "index_count")
    docker_signed = ubuntu_signed = False
    for name in records:
        require(name.endswith("InRelease") or "_Packages" in name, "index_kind")
        require("/" not in name and ".." not in name, "index_path")
        anchor = files.capture(BASE + "/lists/" + name, 256 * 1024 * 1024)
        require(anchor.size > 0, "empty_index")
        if name.endswith("InRelease"):
            docker = name.startswith("download.docker.com_")
            require(docker or name.startswith("ports.ubuntu.com_"), "index_origin")
            key = BASE + "/docker.gpg" if docker else "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
            status = checked(("/usr/bin/gpgv", "--status-fd", "1", "--keyring", key, anchor.path), deadline)
            valid = [line.split() for line in status.decode("ascii").splitlines()
                     if line.startswith("[GNUPG:] VALIDSIG ")]
            require(bool(valid), "signature_unverified")
            if docker:
                require(any(KEY_FINGERPRINT in line[2:] for line in valid), "docker_signer")
                docker_signed = True
            else:
                ubuntu_signed = True
    require(docker_signed and ubuntu_signed, "signed_repositories")
    for directory in ("lists/partial", "lists/auxfiles"):
        path = BASE + "/" + directory
        if os.path.exists(path):
            require(not os.listdir(path), "index_partial")
            files.directory(path)
    files.capture(BASE + "/lists/lock", 0)
    files.directory(BASE + "/lists")
