# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Effect-free cold slice DATA; parsed observations confer no ownership or CLOSE."""
import re
from dataclasses import dataclass
from typing import Final, Literal

Phase = Literal["prepare", "offline"]
_NAME: Final = re.compile(r"wk[a-f0-9]{32}b[1-9][0-9]{0,15}(?:prepare|offline)\.slice")
UNIT: Final[bytes] = (
    b"[Unit]\n"
    b"Description=Wakeio cold build phase\n"
    b"[Slice]\n"
    b"CPUQuota=200%\n"
    b"MemoryMax=2147483648\n"
    b"MemorySwapMax=0\n"
    b"TasksMax=256\n"
)
UNIT_PROPERTIES: Final[str] = (
    "Id,Names,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,ControlGroup,InvocationID,"
    "CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Transient"
)


@dataclass(frozen=True, slots=True)
class ColdDataError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def validated_name(raw: str) -> str:
    if type(raw) is not str or _NAME.fullmatch(raw) is None:
        raise ColdDataError("cold_slice_name")
    return raw


def slice_name(run: str, generation: int, phase: Phase) -> str:
    if type(run) is not str or re.fullmatch(r"[a-f0-9]{32}", run) is None:
        raise ColdDataError("cold_run")
    if type(generation) is not int or not 1 <= generation <= 9999999999999999:
        raise ColdDataError("cold_generation")
    if type(phase) is not str or phase not in ("prepare", "offline"):
        raise ColdDataError("cold_phase")
    return validated_name(f"wk{run}b{generation}{phase}.slice")


@dataclass(frozen=True, slots=True)
class UnitState:
    name: str
    names: str
    load: str
    active: str
    sub: str
    fragment: str
    dropins: str
    group: str
    invocation: str
    quota: str
    memory: str
    swap: str
    tasks: str
    transient: str


@dataclass(frozen=True, slots=True)
class Events:
    populated: bool
    frozen: bool


def _lines(raw: bytes, bound: int) -> list[str]:
    """Require a bounded printable ASCII record with one final LF."""
    if type(raw) is not bytes or not 0 < len(raw) <= bound:
        raise ColdDataError("cold_record_bound")
    if not raw.endswith(b"\n") or any(byte != 10 and not 32 <= byte <= 126 for byte in raw):
        raise ColdDataError("cold_record_framing")
    lines = raw[:-1].decode("ascii").split("\n")
    if any(not line for line in lines):
        raise ColdDataError("cold_record_framing")
    return lines


def parse_unit(raw: bytes) -> UnitState:
    """Parse property DATA only; the original owner must bind all field values."""
    fields: dict[str, str] = {}
    expected = UNIT_PROPERTIES.split(",")
    for line in _lines(raw, 65536):
        key, separator, value = line.partition("=")
        if separator != "=" or key not in expected or key in fields:
            raise ColdDataError("cold_unit_fields")
        fields[key] = value
    if len(fields) != len(expected):
        raise ColdDataError("cold_unit_fields")
    return UnitState(
        name=fields["Id"], names=fields["Names"], load=fields["LoadState"],
        active=fields["ActiveState"], sub=fields["SubState"], fragment=fields["FragmentPath"],
        dropins=fields["DropInPaths"], group=fields["ControlGroup"], invocation=fields["InvocationID"],
        quota=fields["CPUQuotaPerSecUSec"], memory=fields["MemoryMax"], swap=fields["MemorySwapMax"],
        tasks=fields["TasksMax"], transient=fields["Transient"],
    )


def parse_events(raw: bytes) -> Events:
    """Parse raw kernel fields, including initial empty observations, never CLOSE."""
    fields: dict[str, bool] = {}
    for line in _lines(raw, 64):
        key, separator, value = line.partition(" ")
        if separator != " " or key not in ("populated", "frozen") or key in fields or value not in ("0", "1"):
            raise ColdDataError("cold_events_fields")
        fields[key] = value == "1"
    if len(fields) != 2:
        raise ColdDataError("cold_events_fields")
    return Events(populated=fields["populated"], frozen=fields["frozen"])
