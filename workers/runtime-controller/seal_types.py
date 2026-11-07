"""Private install values. No serialized value grants operation authority."""
from dataclasses import dataclass
from typing import Final


class InstallError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str = "install_invariant") -> None:
    if not condition:
        raise InstallError(code)


@dataclass(frozen=True, slots=True)
class Version:
    version: str
    arch: str
    multi: str


@dataclass(frozen=True, slots=True)
class Package:
    name: str
    old: Version
    new: Version
    direction: str
    file: str
    size: int
    sha256: str
    origin: str


DOCKER_VERSION: Final = "5:29.9.2-1~ubuntu.24.04~noble"
# M1 359dfa7f: independent expectations, not observed signatures.
PINS: Final = (
    ("docker-ce", DOCKER_VERSION, 21023748,
     "c34d0bd4a58891b1fd9bab57702d7ce84c0f0c77db5fbabcf192288fe52d2535"),
    ("docker-ce-cli", DOCKER_VERSION, 15847216,
     "de18f48f32758568af16d73aa758678af472c2e780dc2aaa9fd9279b8260f7a9"),
    ("docker-ce-rootless-extras", DOCKER_VERSION, 9128964,
     "12584930245f79a0fb82c835edc6004c82b9ce790eae1fe99c833625c76d0536"),
    ("containerd.io", "2.4.2-3~ubuntu.24.04~noble", 19561964,
     "7837470e586f0b5d228a5eefdd9674b6bd0f127c47841ae808b086ae7fe3f41a"),
)
KEY_SHA: Final = "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
KEY_FINGERPRINT: Final = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
BASE: Final = "/run/wakeio-install"
WORKERS: Final = "/usr/local/lib/wakeio-install"
HOOK: Final = WORKERS + "/install_hook.py"
ENV: Final = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/root",
             "DEBIAN_FRONTEND": "noninteractive", "PYTHONDONTWRITEBYTECODE": "1",
             "APT_CONFIG": BASE + "/apt.conf"}
