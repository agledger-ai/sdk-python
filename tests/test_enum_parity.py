"""SDK <-> API Enum-Member Parity (Python).

The Python mirror of the TS ``enum-parity.test.ts``, sharing its snapshot.

``routes.json`` pins the route surface and ``schema-fields.json``'s ``schemas``
block pins per-model FIELD NAMES. Neither has ever looked inside a ``Literal``,
so every enumerated value in this SDK was unguarded, and ``DisputeStatus``
drifted: it named ``OPENED`` and ``TIER_1_REVIEW``, which exist nowhere in the
API, while all three dispute-status query params declare a strict enum. Either
value was a guaranteed 400 from a typed, documented parameter.

Mocks cannot catch this class, because they assert what the SDK sends. The
parity snapshots could not either, because they are built from the SDK's own
idea of the shape. It took a live drive against a deployed Server to find, and
this is the cheap version of that drive.

Values are read from the runtime types rather than parsed out of the source:
``typing.get_args`` already knows what a ``Literal`` holds, so there is nothing
to re-derive and no comment-stripping to get wrong. The equivalent TS guard does
parse source, and its first parser truncated a union at a semicolon inside a
comment, checked a fifth of it, and passed.

The ``enums`` block is regenerated from the production OpenAPI alongside the
``schemas`` block above it, in the TS repo, and vendored here.
"""

from __future__ import annotations

import json
import typing
from pathlib import Path

import pytest

import agledger.types as types_module

SNAPSHOT_PATH = Path(__file__).parent / "parity" / "schema-fields.json"

pytestmark = pytest.mark.skipif(
    not SNAPSHOT_PATH.exists(),
    reason="schema-fields.json is not vendored in this install",
)


def _literal_values(annotation: object) -> set[str]:
    """String members of a ``Literal``, including one inside a union.

    Response models widen to ``Literal[...] | str`` so a value added by a newer
    Server parses instead of raising. That union still names the members, and
    those are what this compares.
    """
    if typing.get_origin(annotation) is typing.Literal:
        return {a for a in typing.get_args(annotation) if isinstance(a, str)}
    members: set[str] = set()
    for arg in typing.get_args(annotation):
        if typing.get_origin(arg) is typing.Literal:
            members |= {a for a in typing.get_args(arg) if isinstance(a, str)}
    return members


def _sdk_literals() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for name in dir(types_module):
        values = _literal_values(getattr(types_module, name))
        if values:
            out[name] = values
    return out


SNAPSHOT = json.loads(SNAPSHOT_PATH.read_text())
PINNED: dict[str, dict[str, object]] = SNAPSHOT["enums"]
SDK_LITERALS = _sdk_literals()
COVERED = sorted(set(SDK_LITERALS) & set(PINNED))

# Named Literals with no pinned API enum to check against. Each is deliberate:
#   AcceptanceStatus    the spec declares it ``type: ["null", "string"]``
#   ApiKeyRole          key roles are an SDK concept, not a served enum
#   RecordType          customer-registered, so the API cannot enumerate it
#   RiskClassification  EU AI Act tiers plus ``unclassified``, an SDK addition
UNCOVERED = ["AcceptanceStatus", "ApiKeyRole", "RecordType", "RiskClassification"]


def test_every_literal_is_pinned_or_explicitly_uncovered() -> None:
    """A Literal that is neither checked nor listed is silently unguarded."""
    assert sorted(SDK_LITERALS) == sorted(COVERED + UNCOVERED)


def test_the_snapshot_actually_covers_something() -> None:
    """Guards against an empty or malformed snapshot passing vacuously."""
    assert len(COVERED) >= 10
    assert "DisputeStatus" in COVERED


@pytest.mark.parametrize("name", COVERED)
def test_literal_matches_the_api_enum(name: str) -> None:
    expected = set(PINNED[name]["values"])  # type: ignore[arg-type]
    actual = SDK_LITERALS[name]
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    sites = " + ".join(PINNED[name]["specSites"])  # type: ignore[arg-type]
    assert not extra and not missing, (
        f"{name} drifted from {sites}\n"
        f"  SDK names values the API does not have (these 400 when sent): {extra or 'none'}\n"
        f"  API serves values the SDK does not name: {missing or 'none'}"
    )
