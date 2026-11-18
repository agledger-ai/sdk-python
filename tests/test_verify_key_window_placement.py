"""The window rule for signed artifacts other than chain entries (vault
checkpoints, read-log leaves and tree heads), and the condition under which a
``distrusted_keys`` entry accounts for one. The Server applies one rule to all
of them, the one CHAIN_KEY_NOT_YET_ACTIVE and CHAIN_KEY_EXPIRED mirror. A port
of verify-core's ``key-window-placement.test.ts``."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from agledger.verify import (
    DistrustSpan,
    KeyWindowPlacement,
    distrust_accounts,
    place_in_key_window,
)
from agledger.verify.verify_export import RegisteredKey

from .key_statement_helpers import make_key

_K = make_key()


def _key(**over: Any) -> RegisteredKey:
    base = RegisteredKey(
        spki_base64=_K.public_key,
        source="embedded",
        activated_at="2026-09-02T00:01:00.000000Z",
        retired_at="2026-09-02T00:05:00.000000Z",
        trust="anchored",
    )
    return replace(base, **over)


def _place(key: RegisteredKey, at: object, what: str) -> KeyWindowPlacement:
    return place_in_key_window(_K.kid, key, at, what)


class TestPlaceInKeyWindow:
    def test_places_a_write_time_between_the_edges_inside_both_edges_included(self) -> None:
        for at in ("2026-09-02T00:01:00.000Z", "2026-09-02T00:03:00.000Z", "2026-09-02T00:05:00.000Z"):
            assert _place(_key(), at, "Checkpoint") == KeyWindowPlacement("inside")

    def test_reports_a_write_before_activation_and_one_after_retirement_naming_the_artifact(self) -> None:
        before = _place(_key(), "2026-09-02T00:00:59.999Z", "Checkpoint")
        assert before.placement == "not-yet-active"
        assert re.match(r"^Checkpoint written 2026-09-02T00:00:59\.999Z predates key", before.detail or "")
        after = _place(_key(), "2026-09-02T00:05:00.001Z", "Leaf")
        assert after.placement == "expired"
        assert re.match(r"^Leaf written .* postdates key .* retirement", after.detail or "")

    def test_checks_only_the_edges_the_key_carries(self) -> None:
        assert _place(_key(activated_at=None, retired_at=None), "not a time", "Leaf") == KeyWindowPlacement("inside")
        assert _place(_key(retired_at=None), "2030-01-01T00:00:00.000Z", "Leaf") == KeyWindowPlacement("inside")
        assert _place(_key(activated_at=None), "2020-01-01T00:00:00.000Z", "Leaf") == KeyWindowPlacement("inside")

    def test_fails_closed_on_a_write_time_or_an_edge_it_cannot_read(self) -> None:
        assert _place(_key(), "2026-09-02 00:03:00", "Checkpoint").placement == "unplaceable"
        assert _place(_key(), None, "Checkpoint").placement == "unplaceable"
        unreadable_edge = _place(_key(retired_at="2026-02-30T00:00:00Z"), "2026-09-02T00:03:00.000Z", "Checkpoint")
        assert unreadable_edge.placement == "unplaceable"
        assert "so the checkpoint cannot be placed inside its window" in (unreadable_edge.detail or "")

    def test_accounts_for_a_write_from_the_distrust_instant_up_to_the_trusted_retirement_and_no_further(self) -> None:
        distrusted = _key(
            retired_at="2026-09-02T00:05:00.000000Z",
            distrust_cutoff="2026-09-02T00:02:00.000000Z",
            distrust_span=DistrustSpan(cutoff="2026-09-02T00:02:00.000000Z", retired_at="2026-09-02T00:05:00.000000Z"),
        )
        assert _place(distrusted, "2026-09-02T00:01:30.000Z", "Checkpoint").placement == "inside"
        assert _place(distrusted, "2026-09-02T00:03:00.000Z", "Checkpoint").placement == "accounted"
        assert _place(distrusted, "2026-09-02T00:05:00.000Z", "Checkpoint").placement == "expired"
        assert _place(distrusted, "2026-09-02T00:06:00.000Z", "Checkpoint").placement == "expired"


class TestDistrustAccounts:
    span = DistrustSpan(cutoff=None, retired_at="2026-09-02T00:05:00.000000Z")

    def test_accounts_for_what_an_unanchored_distrusted_key_signed_before_a_trusted_key_retired_it(self) -> None:
        unanchored = _key(trust="unanchored", distrust_span=self.span)
        assert distrust_accounts(unanchored, "2026-09-02T00:04:59.999Z") is True
        assert distrust_accounts(unanchored, "2026-09-02T00:05:00.000Z") is False
        assert distrust_accounts(unanchored, "not a time") is False

    def test_accounts_for_nothing_under_an_unanchored_key_no_trusted_key_retired_or_one_nothing_distrusts(self) -> None:
        never_retired = _key(trust="unanchored", distrust_span=DistrustSpan(cutoff=None, retired_at=None))
        assert distrust_accounts(never_retired, "2026-09-02T00:03:00.000Z") is False
        assert distrust_accounts(_key(trust="unanchored"), "2026-09-02T00:03:00.000Z") is False

    def test_accounts_for_what_an_anchored_key_signed_past_its_distrust_instant_and_not_inside_its_window(self) -> None:
        anchored = _key(
            distrust_cutoff="2026-09-02T00:02:00.000000Z",
            distrust_span=DistrustSpan(cutoff="2026-09-02T00:02:00.000000Z", retired_at="2026-09-02T00:05:00.000000Z"),
        )
        assert distrust_accounts(anchored, "2026-09-02T00:03:00.000Z") is True
        assert distrust_accounts(anchored, "2026-09-02T00:01:30.000Z") is False
        assert distrust_accounts(_key(), "2026-09-02T00:06:00.000Z") is False

    def test_accounts_for_nothing_under_a_key_whose_registry_row_misstates_its_algorithm_or_one_the_host_cannot_decide(
        self,
    ) -> None:
        lying = _key(trust="unanchored", distrust_span=self.span, algorithm="ES256")
        assert distrust_accounts(lying, "2026-09-02T00:03:00.000Z") is False
        undecided = _key(trust="undecided", distrust_span=self.span)
        assert distrust_accounts(undecided, "2026-09-02T00:03:00.000Z") is False
