"""The export chain is held to the entry counts it states.

A chain cut from the end still links and verifies entry by entry. Its length is
the only thing that shows the cut, so the verifier holds it to the two counts
the export states. Mirrors verify-core ``entry-count.test.ts``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import EntryCount, verify_dump, verify_export
from agledger.verify.cli import (
    _entry_count_summary,  # pyright: ignore[reportPrivateUsage]
)
from tests.dump_fixtures import build_happy_dump

LIVE = Path(__file__).parent / "fixtures" / "live-2.0.0"


def _load() -> dict[str, Any]:
    return json.loads((LIVE / "export-lifecycle.json").read_text())


def test_passes_whole_and_reports_the_counts() -> None:
    result = verify_export(_load())
    assert result.valid is True
    assert result.entry_count == EntryCount(expected_entries=None, stated_entries=9)


@pytest.mark.parametrize("cut", [1, 3, 6])
def test_fails_a_tail_cut_that_leaves_total_entries_standing(cut: int) -> None:
    exp = _load()
    exp["entries"] = exp["entries"][:-cut]
    result = verify_export(exp)
    assert result.valid is False
    assert result.verdict == "failed"
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (9 - cut + 1, "CHAIN_POSITION_GAP")


def test_fails_a_chain_shorter_than_its_checkpoint_position() -> None:
    exp = _load()
    exp["exportMetadata"]["expectedEntries"] = 7
    exp["entries"] = exp["entries"][:4]
    exp["exportMetadata"]["totalEntries"] = 4
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (7, "CHECKPOINT_ROW_MISSING")
    assert result.entry_count == EntryCount(expected_entries=7, stated_entries=4)


@pytest.mark.parametrize("expected", [9, 7, 0])
def test_passes_a_chain_at_or_past_its_checkpoint_position(expected: int) -> None:
    exp = _load()
    exp["exportMetadata"]["expectedEntries"] = expected
    assert verify_export(exp).valid is True


@pytest.mark.parametrize("name", ["expectedEntries", "totalEntries"])
@pytest.mark.parametrize("bad", ["7", 7.5, -1, True, {}])
def test_refuses_a_count_that_is_not_a_non_negative_integer(name: str, bad: object) -> None:
    exp = _load()
    exp["exportMetadata"][name] = bad
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (0, "UNSUPPORTED_FORMAT")


def test_an_export_that_states_neither_count_is_held_to_nothing() -> None:
    exp = _load()
    del exp["exportMetadata"]["totalEntries"]
    del exp["exportMetadata"]["expectedEntries"]
    exp["entries"] = exp["entries"][:-2]
    result = verify_export(exp)
    assert result.valid is True
    assert result.entry_count == EntryCount()


def test_the_report_says_what_the_count_was_held_to() -> None:
    assert _entry_count_summary(EntryCount(7, 9), 9) == "held to the checkpoint at position 7; 2 newer than it"
    assert _entry_count_summary(EntryCount(None, 9), 9) == (
        "held to the 9 the export states; it names no checkpoint for this record yet"
    )
    assert _entry_count_summary(EntryCount(), 9).startswith("the file's own")
    assert _entry_count_summary(EntryCount(7, 7), 4) == "4 where the checkpoint at position 7 anchors 7"
    assert _entry_count_summary(EntryCount(None, 9), 6).startswith("6 where the export states 9")


def test_a_dump_counts_the_chains_a_checkpoint_holds() -> None:
    dump, _key = build_happy_dump()
    report = verify_dump(dump)
    assert report.vault.record_count == 2
    assert report.vault.checkpointed_chain_count == 1
    assert report.vault.to_json()["checkpointedChainCount"] == 1
