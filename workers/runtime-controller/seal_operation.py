"""One-way original-operation lifetime. A digest is only an observation."""
import os
from enum import Enum, auto

from install_prepare import Prepared
from install_process import Deadline
from seal_files import Files
from seal_hook import validate_install_hook
from seal_types import InstallError, require


class Phase(Enum):
    PREPARING = auto()
    PREPARED = auto()
    INSTALLING = auto()
    ACCEPTED = auto()
    CONSUMED = auto()
    CLOSED = auto()


class Operation:
    """Only the process that created the owner may advance its state."""
    def __init__(self, files: Files, deadline: Deadline):
        self._pid = os.getpid()
        self._files = files
        self._deadline = deadline
        self._phase = Phase.PREPARING
        self._prepared: Prepared | None = None

    def _check(self, expected: Phase) -> None:
        try:
            require(os.getpid() == self._pid, "operation_owner")
            self._deadline.remaining()
            require(self._phase is expected, "operation_phase")
            self._files.check()
        except (InstallError, OSError):
            self.close()
            raise

    def prepared(self, result: Prepared) -> None:
        self._check(Phase.PREPARING)
        self._prepared = result
        self._phase = Phase.PREPARED

    def consume(self) -> Prepared:
        self._check(Phase.PREPARED)
        require(self._prepared is not None, "operation_plan")
        self._phase = Phase.INSTALLING
        return self._prepared

    def hook(self, payload: bytes) -> str:
        try:
            self._check(Phase.INSTALLING)
            require(self._prepared is not None, "operation_plan")
            if self._prepared is None:
                raise InstallError("operation_plan")
            digest = validate_install_hook(payload, self._prepared.packages, self._prepared.configuration)
            self._phase = Phase.ACCEPTED
            return digest
        except (InstallError, OSError, UnicodeError):
            self.close()
            raise

    def complete(self) -> None:
        require(os.getpid() == self._pid, "operation_owner")
        self._deadline.remaining()
        require(self._phase is Phase.ACCEPTED, "hook_not_observed")
        self._phase = Phase.CONSUMED
        self._prepared = None

    def close(self) -> None:
        self._phase = Phase.CLOSED
        self._prepared = None
