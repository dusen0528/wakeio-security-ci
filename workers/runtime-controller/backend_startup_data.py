# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: imported by the original controller; this module performs no I/O.
"""Closed startup protocol and integer arithmetic; parsed DATA never qualifies a clock."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final, Never, assert_never

STARTUP_READY: Final = b"WAKEIO_STARTUP_1\n"
RELAY_READY: Final = b"RELAY_READY\n"
INITIAL_BOUND: Final = 128


class StartupDataError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class StartupBudget:
    remaining_ms: int

    def __post_init__(self) -> None:
        if type(self.remaining_ms) is not int or not 0 < self.remaining_ms <= 900000:
            raise StartupDataError("startup_budget_bound")


@dataclass(frozen=True, slots=True)
class ClockProfile:
    """Arithmetic DATA only; construction is not runtime support or execution authority."""
    numerator: int
    denominator: int
    margin_ns: int

    def __post_init__(self) -> None:
        if any(type(value) is not int for value in (self.numerator, self.denominator, self.margin_ns)):
            raise StartupDataError("startup_clock_number")
        if self.numerator <= 0 or self.denominator <= 0 or self.margin_ns < 0:
            raise StartupDataError("startup_clock_bound")


@dataclass(frozen=True, slots=True)
class JsonPairs:
    items: tuple[tuple[str, Json], ...]


type Json = None | bool | int | float | str | list[Json] | JsonPairs


def _pairs(items: list[tuple[str, Json]]) -> JsonPairs:
    return JsonPairs(tuple(items))


def _constant(value: str) -> Never:
    raise StartupDataError("startup_json_constant:" + value)


def parse_initialization(packet: bytes) -> StartupBudget:
    """Parse one bounded original-service record, including its sole final LF."""
    if not 0 < len(packet) <= INITIAL_BOUND or not packet.endswith(b"\n") or packet.count(b"\n") != 1:
        raise StartupDataError("startup_record_framing")
    try:
        raw: Json = json.loads(packet[:-1].decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StartupDataError("startup_record_json") from error
    match raw:
        case JsonPairs(items=items):
            if len(items) != 2 or {key for key, _ in items} != {"v", "remainingMs"}:
                raise StartupDataError("startup_record_keys")
            values = dict(items)
            version, remaining = values["v"], values["remainingMs"]
            if type(version) is not int or version != 1 or type(remaining) is not int:
                raise StartupDataError("startup_record_types")
            return StartupBudget(remaining)
        case None | bool() | int() | float() | str() | list():
            raise StartupDataError("startup_record_object")
        case unreachable:
            assert_never(unreachable)


def cutoff_ns(anchor_ns: int, budget: StartupBudget, profile: ClockProfile) -> int:
    """Round the same original allowance earlier; never sample or reset an anchor."""
    if type(anchor_ns) is not int or anchor_ns < 0:
        raise StartupDataError("startup_anchor")
    allowance = profile.numerator * budget.remaining_ms * 1000000 // profile.denominator
    return anchor_ns + allowance - profile.margin_ns
