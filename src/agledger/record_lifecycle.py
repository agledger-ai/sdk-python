"""
Record lifecycle state machine — customer-facing display statuses.

The API maps internal states to these display statuses; this table reflects
what SDK consumers actually observe. Unknown statuses return empty arrays
for forward compatibility.
"""

from __future__ import annotations

from typing import Final

RECORD_TRANSITIONS: Final[dict[str, tuple[str, ...]]] = {
    "CREATED": ("ACTIVE", "PROPOSED", "CANCELLED"),
    "PROPOSED": ("CREATED", "REJECTED", "CANCELLED"),
    "ACTIVE": ("PROCESSING", "EXPIRED", "CANCELLED"),
    "PROCESSING": ("FULFILLED", "FAILED", "REVISION_REQUESTED", "DISPUTED"),
    "REVISION_REQUESTED": ("PROCESSING", "EXPIRED", "CANCELLED"),
    "DISPUTED": ("FULFILLED", "FAILED", "PENDING_ARBITRATION"),
    "FULFILLED": (),
    "FAILED": ("REMEDIATED", "REVISION_REQUESTED"),
    "REMEDIATED": (),
    "EXPIRED": (),
    "PENDING_ARBITRATION": (),
    "CANCELLED": (),
    "REJECTED": (),
    "RECORDED": (),
}

TERMINAL_STATUSES: Final[tuple[str, ...]] = tuple(
    status for status, targets in RECORD_TRANSITIONS.items() if not targets
)


def can_transition_to(current: str, target: str) -> bool:
    """Whether a transition from ``current`` to ``target`` is valid. Unknown statuses return False."""
    targets = RECORD_TRANSITIONS.get(current)
    if targets is None:
        return False
    return target in targets


def get_valid_transitions(status: str) -> tuple[str, ...]:
    """Valid next statuses for a given status. Unknown statuses return ``()``."""
    return RECORD_TRANSITIONS.get(status, ())


def is_terminal_status(status: str) -> bool:
    """Whether a status is terminal (no outbound transitions). Unknown statuses return False."""
    targets = RECORD_TRANSITIONS.get(status)
    if targets is None:
        return False
    return len(targets) == 0
