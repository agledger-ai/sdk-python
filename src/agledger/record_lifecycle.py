"""
Record lifecycle state machine: customer-facing display statuses.

``RECORD_TRANSITIONS`` is the graph the Server's ``GET /lifecycle`` serves: the
display statuses each status can reach on some Record, the union over every
Type whatever its ``flipRecordStatusOnDispute``. A given Record can reach fewer
(a spent revision or dispute budget, a passed deadline, a Type that keeps the
Record's status while disputed); its own ``valid_transitions`` is the answer for
that Record. Unknown statuses return empty tuples for forward compatibility.
"""

from __future__ import annotations

from typing import Final

RECORD_TRANSITIONS: Final[dict[str, tuple[str, ...]]] = {
    "CREATED": ("ACTIVE", "CANCELLED", "EXPIRED", "PROPOSED"),
    "PROPOSED": ("CANCELLED", "CREATED", "EXPIRED", "REJECTED"),
    "ACTIVE": ("CANCELLED", "EXPIRED", "PROCESSING"),
    "PROCESSING": ("ACTIVE", "CANCELLED", "EXPIRED", "FAILED", "FULFILLED"),
    "REVISION_REQUESTED": ("ACTIVE", "CANCELLED", "EXPIRED", "PROCESSING"),
    "DISPUTED": ("FAILED", "FULFILLED", "REMEDIATED"),
    "FULFILLED": ("DISPUTED",),
    "FAILED": ("DISPUTED", "FULFILLED", "REVISION_REQUESTED"),
    "REMEDIATED": ("DISPUTED",),
    "EXPIRED": (),
    "CANCELLED": (),
    "REJECTED": (),
    "RECORDED": (),
}

TERMINAL_STATUSES: Final[tuple[str, ...]] = (
    "FULFILLED",
    "REMEDIATED",
    "EXPIRED",
    "CANCELLED",
    "REJECTED",
    "RECORDED",
)
"""Terminal outcomes, as ``GET /lifecycle`` marks them. FULFILLED and REMEDIATED
are terminal although a dispute can still reopen them, so a terminal status is
not the same as one with no transitions."""


def can_transition_to(current: str, target: str) -> bool:
    """Whether some Record at ``current`` can reach ``target``. Unknown statuses return False."""
    targets = RECORD_TRANSITIONS.get(current)
    if targets is None:
        return False
    return target in targets


def get_valid_transitions(status: str) -> tuple[str, ...]:
    """The statuses some Record at ``status`` can reach next. Unknown statuses return ``()``."""
    return RECORD_TRANSITIONS.get(status, ())


def is_terminal_status(status: str) -> bool:
    """Whether a status is a terminal outcome (see ``TERMINAL_STATUSES``). Unknown statuses return False."""
    return status in TERMINAL_STATUSES
