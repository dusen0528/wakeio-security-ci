# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Fixed original helper IO and parent/image bindings; no owner can be issued from these observations."""
from __future__ import annotations

import base64
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from backend_process import BackendError, require
from input_resources import checked, inspection
from preparation_config_archive import HelperInputs
from preparation_config_data import ConfigError
from preparation_config_inspect import ContainerObservation, Verification, container_observation
from preparation_config_inspect import image_observation, semantic_observation

if TYPE_CHECKING:
    from preparation_config import PreparationConfiguration
    from preparation_config_tool import ConfigurationTool


@dataclass(frozen=True, slots=True)
class Helper:
    path: Path
    inode: int
    digest: str
    body: bytes


class HelperRead:
    """Retained local read FD fact, never a separately issuable helper or successful owner."""

    def __init__(self, path: Path, inode: int, digest: str) -> None:
        self.path, self.inode, self.digest = path, inode, digest
        self.descriptor: int | None = None
        self.close_unknown = False


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def load_helpers(configuration: PreparationConfiguration) -> None:
    configuration.admit()
    require(configuration.helpers is None and not configuration.started
            and not configuration.helper_reads, "config_helpers_replay")
    helpers: list[Helper] = []
    for name in ("PrepConfigProduce.java", "PrepConfigVerify.java"):
        path = configuration.backend.root / "build" / name
        matches = tuple((inode, digest) for candidate, inode, digest in configuration.files if candidate == path)
        require(len(matches) == 1, "config_helper_unavailable")
        inode, digest = matches[0]
        configuration.admit()
        record = HelperRead(path, inode, digest)
        configuration.helper_reads.append(record)
        record.descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(record.descriptor)
            body = os.read(record.descriptor, 32769)
            after = os.fstat(record.descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                    and before.st_mode & 0o022 == 0 and before.st_ino == inode
                    and _identity(before) == _identity(after) and 0 < len(body) <= 32768
                    and len(body) == before.st_size and hashlib.sha256(body).hexdigest() == digest,
                    "config_helper_changed")
            helpers.append(Helper(path, inode, digest, body))
        finally:
            descriptor, record.descriptor = record.descriptor, None
            try:
                os.close(descriptor)
            except OSError:
                record.close_unknown = True
                configuration.close_unknown = True
                raise
    configuration.helpers = (helpers[0], helpers[1])
    configuration.helper_inputs = HelperInputs(helpers[0].body, helpers[1].body, configuration.certificate)
    configuration.backend.check()


def inspect_parent(configuration: PreparationConfiguration) -> None:
    configuration.admit()
    configuration.backend.check()
    require(configuration.input._volume() == configuration.materials.input_volume, "config_input_volume_changed")
    raw = checked(configuration.input._call("image-inspect"))
    require(inspection(raw) == configuration.input.image, "config_original_image_changed")
    observed = image_observation(raw)
    original = configuration.image
    require(original is not None, "config_parent_image_missing")
    if original is None:
        raise BackendError("config_parent_image_missing")
    require((observed.reference, observed.config, observed.command, observed.environment)
            == (original.reference, original.config, original.command, original.environment), "config_image_changed")
    configuration.tool_image = observed
    for kind, previous in configuration.parent_volumes:
        require(configuration.materials._volume(kind) == previous, "config_parent_volume_changed")
    require(configuration.resources.inspect(configuration.mirror.container).state == "running", "config_mirror_stopped")
    configuration.bindings()


def verify_original_result(configuration: PreparationConfiguration) -> None:
    tool = configuration.verifier
    if tool is None or tool.attach is None or tool.attach.process is None or tool.pre_read.accepted is None:
        raise BackendError("config_verification_original_missing")
    process = tool.attach.process
    require(tool.exit_code == 0 and not process.errors and not process.output_overflow
            and configuration.session._failure is None, "config_verifier_failed")
    lines = configuration.certificate.splitlines()
    require(len(lines) >= 3 and lines[0] == b"-----BEGIN CERTIFICATE-----"
            and lines[-1] == b"-----END CERTIFICATE-----", "config_original_certificate")
    payload = b"".join(lines[1:-1])
    der = base64.b64decode(payload, validate=True)
    require(base64.b64encode(der) == payload, "config_certificate_encoding")
    store = tool.pre_read.accepted.entries[-1].body
    if store is None:
        raise BackendError("config_store_missing")
    expected = Verification(hashlib.sha256(der).hexdigest(), hashlib.sha256(store).hexdigest())
    configuration.verification = semantic_observation(bytes(process.output), expected)
    configuration.config_observation = tool.read("read-config")



def inspect_tool(tool: ConfigurationTool) -> ContainerObservation:
    image = tool.configuration.tool_image
    if image is None:
        raise BackendError("config_tool_image_missing")
    pending = tool.configuration.call(tool.frame("container-inspect"))
    try:
        value = container_observation(pending.selection.configuration(), image, checked(pending))
        require(tool.creation is None or (value.identifier, value.created)
                == (tool.creation.identifier, tool.creation.created), "config_container_replaced")
        return value
    except (BackendError, ConfigError, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        tool.identity_unknown = True
        raise BackendError("config_container_identity_lost:" + str(error)) from error
