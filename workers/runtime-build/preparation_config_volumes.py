# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Original configuration-owned volume allocations and descriptor/ACK histories."""
from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING, Literal, assert_never

from backend_process import BackendError, require
from input_resources import checked
from preparation_config_data import ConfigFrame, Operation
from preparation_config_inspect import VolumeObservation, volume_observation

if TYPE_CHECKING:
    from build import BuildSession, Pending
    from preparation_config import PreparationConfiguration
    from preparation_config_envelope import ConfigurationEnvelope
    from preparation_config_wait import ConfigurationWait
    type AllocationOwner = ConfigurationVolume | ConfigurationEnvelope | ConfigurationWait


class ConfigurationVolume:
    """One of the original child's two fixed allocations, not a separately issuable resource."""

    def __init__(self, configuration: PreparationConfiguration, auxiliary: bool) -> None:
        self.configuration = configuration
        self.auxiliary = auxiliary
        suffix = "-input" if auxiliary else ""
        self.name = f"wk-{configuration.run}-b{configuration.generation}-prepare-config{suffix}"
        self.creation: Pending | None = None
        self.removal: Pending | None = None
        self.observation: VolumeObservation | None = None
        self.paths = ConfigurationPaths(self)
        self.descriptors, self.identities = self.paths.descriptors, self.paths.identities
        self.returned = self.removed = self.close_unknown = self.identity_unknown = False

    def original(self) -> None:
        owner = self.configuration
        owner.original()
        require(type(self) is ConfigurationVolume and (
            owner.inputs is self if self.auxiliary else owner.result is self), "config_volume_owner")

    def frame(self, action: Literal["inspect", "create", "remove"]) -> ConfigFrame:
        self.original()
        prefix = "input-volume-" if self.auxiliary else "volume-"
        return ConfigFrame(self.configuration.run, self.configuration.generation,
                           Operation(prefix + action), None, None)

    def anchors(self) -> None:
        self.original()
        require(not self.close_unknown and not self.identity_unknown, "config_volume_uncertain")
        try:
            self.paths.check()
        except (BackendError, OSError):
            self.identity_unknown = True
            raise

    def directory(self, path: str) -> None:
        self.anchors()
        self.paths.directory(path)

    def inspect(self) -> VolumeObservation:
        self.anchors()
        frame = self.frame("inspect")
        pending = self.configuration.call(frame)
        try:
            observed = volume_observation(frame, checked(pending))
            require(self.observation is None or observed == self.observation, "config_volume_replaced")
            self.directory(observed.mountpoint)
            return observed
        except (BackendError, OSError, ValueError, TypeError, RecursionError) as error:
            self.identity_unknown = True
            raise BackendError("config_volume_observation_lost:" + str(error)) from error

    def allocate(self) -> None:
        self.original()
        require(self.creation is None and self.observation is None, "config_volume_replay")
        absent = self.configuration.call(self.frame("inspect"))
        process = absent.process
        if process is None or process.child is None:
            raise BackendError("config_volume_absence_process")
        expected = ("Error response from daemon: get " + self.name + ": no such volume\n").encode("ascii")
        require(process.drained and not process.output_overflow and process.child.returncode == 1
                and bytes(process.errors) == expected and bytes(process.output) in (b"", b"[]\n"),
                "config_volume_preexisting_or_unknown")
        creation = self.configuration.call(self.frame("create"))
        require(self.creation is creation and checked(creation) == (self.name + "\n").encode("ascii"),
                "config_volume_create_response")
        self.returned = True
        self.observation = self.inspect()
        self.configuration.session._settle(creation)

    def close(self, path: str) -> None:
        descriptor = self.descriptors.pop(path)
        try:
            os.close(descriptor)
        except OSError:
            self.close_unknown = True
            raise

    def remove(self) -> None:
        self.original()
        require(self.configuration.session._cleaning and not self.close_unknown
                and not self.identity_unknown, "config_volume_cleanup_unavailable")
        if self.removed:
            require(not self.descriptors, "config_removed_descriptors")
            return
        self.configuration.volume_unborrowed(self)
        creation = self.creation
        absent = creation is None or (creation.process is not None and creation.process.drained
                                     and not creation.process.released and not self.returned)
        if not absent:
            require(self.creation is not None and self.creation.settled
                    and self.returned and self.observation is not None,
                    "config_volume_creation_unconfirmed")
            observed = self.inspect()
            removal = self.configuration.call(self.frame("remove"))
            require(self.removal is removal and checked(removal) == (observed.name + "\n").encode("ascii"),
                    "config_volume_remove_response")
            self.configuration.session._settle(removal)
            self.removed = True
        for path in reversed(tuple(self.descriptors)):
            self.close(path)


class ConfigurationPaths:
    """Mutable no-follow directory FD history, usable only by six original fixed allocations."""

    def __init__(self, owner: AllocationOwner) -> None:
        self.owner = owner
        self.descriptors: dict[str, int] = {}
        self.identities: dict[str, tuple[int, int]] = {}
        self.close_unknown = False
        self.identity_unknown = False

    def scope(self) -> tuple[str, ...]:
        from preparation_config_envelope import ConfigurationEnvelope, GROUP_DIRECTORY, UNIT_DIRECTORY
        from preparation_config_wait import ConfigurationWait
        owner = self.owner
        owner.original()
        require(owner.paths is self, "config_path_original_owner")
        match owner:
            case ConfigurationVolume():
                require(type(owner) is ConfigurationVolume, "config_path_volume_type")
                return ("/home/wakeio-m1/.local/share/docker/volumes/" + owner.name + "/_data",)
            case ConfigurationEnvelope():
                require(type(owner) is ConfigurationEnvelope, "config_path_envelope_type")
                return (UNIT_DIRECTORY, GROUP_DIRECTORY)
            case ConfigurationWait():
                require(type(owner) is ConfigurationWait, "config_path_wait_type")
                return ("/run/user/10001",)
            case unreachable:
                assert_never(unreachable)

    def check(self) -> None:
        self.scope()
        require(not self.close_unknown and not self.identity_unknown, "config_path_uncertain")
        try:
            for path, descriptor in self.descriptors.items():
                value = os.fstat(descriptor)
                require(stat.S_ISDIR(value.st_mode) and value.st_nlink > 0
                        and (value.st_dev, value.st_ino) == self.identities[path], "config_path_descriptor")
                if not path.endswith("/_data"):
                    require(value.st_uid in (0, 10001) and value.st_mode & 0o022 == 0,
                            "config_path_permissions")
                if path != "/":
                    parent, name = path.rsplit("/", 1)
                    linked = os.stat(name, dir_fd=self.descriptors[parent or "/"], follow_symlinks=False)
                    require(stat.S_ISDIR(linked.st_mode)
                            and (linked.st_dev, linked.st_ino) == self.identities[path], "config_path_replaced")
        except (BackendError, OSError) as error:
            self.identity_unknown = True
            raise BackendError("config_path_identity_lost:" + str(error)) from error

    def directory(self, path: str) -> int:
        require(path in self.scope(), "config_directory_not_fixed")
        self.check()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = "/"
        for current in ("/", *("/" + "/".join(path.split("/")[1:index])
                               for index in range(2, len(path.split("/")) + 1))):
            if current not in self.descriptors:
                self.descriptors[current] = (os.open("/", flags) if current == "/" else
                    os.open(current.rsplit("/", 1)[1], flags, dir_fd=self.descriptors[parent]))
                value = os.fstat(self.descriptors[current])
                self.identities[current] = (value.st_dev, value.st_ino)
            parent = current
        self.check()
        return self.descriptors[path]

    def close(self, path: str) -> None:
        descriptor = self.descriptors.pop(path)
        try:
            os.close(descriptor)
        except OSError:
            self.close_unknown = True
            raise

    def dispose(self) -> None:
        self.check()
        for path in reversed(tuple(self.descriptors)):
            self.close(path)




class ConfigurationBorrow:
    """Fixed original future-consumer history; construction alone establishes no retained membership."""

    def __init__(self, configuration: PreparationConfiguration, creator: BuildSession, offline: bool) -> None:
        self._configuration, self._creator = configuration, creator
        self._volume, self._offline = configuration.result, offline
        self.drained = False

    @property
    def configuration(self) -> PreparationConfiguration:
        return self._configuration

    @property
    def creator(self) -> BuildSession:
        return self._creator

    @property
    def volume(self) -> ConfigurationVolume:
        return self._volume

    @property
    def offline(self) -> bool:
        return self._offline

    @staticmethod
    def _require_creator(configuration: PreparationConfiguration, creator: BuildSession) -> None:
        from build import BuildSession
        from preparation_config import PreparationConfiguration
        require(type(configuration) is PreparationConfiguration, "config_borrow_configuration_type")
        configuration.original()
        configuration.bindings()
        require(type(creator) is BuildSession and creator is configuration.session
                and configuration.held and configuration.state == "CONFIGURATION_HELD"
                and configuration.verification is not None and configuration.config_observation is not None
                and not configuration.drained and not configuration.uncertain()
                and creator._failure is None and not creator._closing, "config_borrow_creator")

    @staticmethod
    def require_preparation(configuration: PreparationConfiguration, creator: BuildSession) -> None:
        ConfigurationBorrow._require_creator(configuration, creator)
        require(not configuration.preparation_burned and configuration.preparation_borrow is None,
                "config_borrow_replay")
        creator._require_preparation_configuration_creator()
        configuration.admit()
        configuration.result.inspect()

    @staticmethod
    def require_offline(configuration: PreparationConfiguration, creator: BuildSession) -> None:
        ConfigurationBorrow._require_creator(configuration, creator)
        preparation = configuration.preparation_borrow
        require(not configuration.offline_burned and configuration.offline_borrow is None
                and preparation is not None and preparation.drained, "config_offline_prerequisites")
        if preparation is None:
            raise BackendError("config_preparation_borrow_missing")
        preparation.original()
        creator._require_offline_configuration_creator()
        configuration.admit()
        configuration.result.inspect()

    def original(self) -> None:
        from preparation_config import PreparationConfiguration
        owner = self.configuration
        require(type(owner) is PreparationConfiguration, "config_borrow_configuration_type")
        owner.original()
        slot = owner.offline_borrow if self.offline else owner.preparation_borrow
        burned = owner.offline_burned if self.offline else owner.preparation_burned
        require(type(self) is ConfigurationBorrow and slot is self and burned
                and self.creator is owner.session and self.volume is owner.result, "config_borrow_original")

    def drain(self) -> None:
        with self.configuration.backend._mutation_lock:
            self.original()
            if not self.drained:
                if self.offline:
                    self.creator._require_offline_configuration_closed()
                else:
                    self.creator._require_preparation_configuration_closed()
                self.drained = True
