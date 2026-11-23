"""An export's metadata is unsigned, so whoever edits it must not be able to
change what the verdict is about or switch a check off. Mirrors verify-core's
export-metadata-binding.test.ts."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import verify_export

LIVE = Path(__file__).parent / "fixtures" / "live-2.0.0" / "export-lifecycle.json"
OTHER = "11111111-2222-4333-8444-555555555555"


def _live() -> dict[str, Any]:
    return json.loads(LIVE.read_text())


class TestTheRecordIdAResultReportsIsTheOneTheEntriesSign:
    def test_reports_the_signed_id_of_an_untouched_export(self) -> None:
        exp = _live()
        r = verify_export(exp)
        assert r.valid
        assert r.record_id == exp["exportMetadata"]["recordId"]

    def test_fails_when_the_metadata_names_another_record_and_reports_the_signed_id(self) -> None:
        exp = _live()
        signed = exp["exportMetadata"]["recordId"]
        exp["exportMetadata"]["recordId"] = OTHER
        r = verify_export(exp)
        assert not r.valid
        assert r.verdict == "failed"
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_PAYLOAD_BINDING_MISMATCH"
        assert "the unsigned metadata was edited" in (r.broken_at.detail or "")
        assert r.record_id == signed

    def test_holds_the_signed_predicate_to_the_id_when_the_entries_carry_no_column_or_payload(self) -> None:
        exp = _live()
        exp["exportMetadata"]["recordId"] = OTHER
        for e in exp["entries"]:
            for field in ("recordId", "payload", "entryType"):
                e.pop(field, None)
        r = verify_export(exp)
        assert not r.valid
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_PAYLOAD_BINDING_MISMATCH"

    def test_fails_when_the_metadata_names_no_record_at_all(self) -> None:
        exp = _live()
        del exp["exportMetadata"]["recordId"]
        r = verify_export(exp)
        assert not r.valid
        assert r.record_id != ""

    def test_fails_when_two_entries_name_different_records(self) -> None:
        exp = _live()
        for e in exp["entries"]:
            del e["payload"]
            del e["entryType"]
        exp["entries"][4]["recordId"] = OTHER
        r = verify_export(exp)
        assert not r.valid
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_PAYLOAD_BINDING_MISMATCH"
        assert "name different records" in (r.broken_at.detail or "")


class TestTheEntryCountCheckIsReportedAndCanBeSuppliedOutOfBand:
    @staticmethod
    def _stripped() -> dict[str, Any]:
        exp = _live()
        exp["exportMetadata"].pop("expectedEntries", None)
        exp["exportMetadata"].pop("totalEntries", None)
        return exp

    def test_is_applied_while_the_export_states_a_count_and_skipped_once_the_counts_are_deleted(self) -> None:
        assert verify_export(_live()).optional_checks["entry_count"] == "applied"
        r = verify_export(self._stripped())
        assert r.optional_checks["entry_count"] == "skipped_no_input"
        assert (r.entry_count.expected_entries, r.entry_count.stated_entries) == (None, None)

    def test_a_truncated_export_with_its_counts_deleted_passes_only_as_an_unchecked_count(self) -> None:
        exp = self._stripped()
        del exp["entries"][-3:]
        r = verify_export(exp)
        assert r.optional_checks["entry_count"] == "skipped_no_input"

    def test_fails_a_truncation_against_expected_entry_count_however_the_metadata_was_edited(self) -> None:
        exp = self._stripped()
        del exp["entries"][-3:]
        r = verify_export(exp, expected_entry_count=9)
        assert not r.valid
        assert r.optional_checks["entry_count"] == "applied"
        assert r.broken_at is not None
        assert (r.broken_at.position, r.broken_at.code) == (7, "CHAIN_POSITION_GAP")

    def test_fails_an_export_with_more_entries_than_expected_and_passes_an_exact_match(self) -> None:
        assert verify_export(_live(), expected_entry_count=9).valid
        r = verify_export(_live(), expected_entry_count=8)
        assert not r.valid
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_POSITION_GAP"
        assert "added past the end" in (r.broken_at.detail or "")

    @pytest.mark.parametrize("bad", [-1, 1.5, "9", float("nan"), True])
    def test_raises_on_a_count_that_is_not_a_non_negative_integer(self, bad: Any) -> None:
        with pytest.raises(TypeError, match="expected_entry_count"):
            verify_export(_live(), expected_entry_count=bad)

    def test_an_export_with_no_entries_still_reports_the_check(self) -> None:
        exp = _live()
        exp["entries"] = []
        r = verify_export(exp, expected_entry_count=0)
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_EMPTY"
        assert r.optional_checks["entry_count"] == "applied"


class TestPayloadAndEntryTypeCannotBeDeletedToSkipTheirChecks:
    @pytest.mark.parametrize("field", ["payload", "entryType"])
    def test_fails_an_entry_that_lost_one_while_others_carry_theirs(self, field: str) -> None:
        exp = _live()
        del exp["entries"][3][field]
        r = verify_export(exp)
        assert not r.valid
        assert r.broken_at is not None
        assert (r.broken_at.position, r.broken_at.code) == (4, "CHAIN_PAYLOAD_BINDING_MISMATCH")
        assert r.optional_checks["payload_binding"] == "not_checked"

    def test_an_export_with_no_payloads_at_all_passes_unchecked_and_fails_once_federation_keys_are_supplied(
        self,
    ) -> None:
        exp = _live()
        for e in exp["entries"]:
            del e["payload"]
            del e["entryType"]
        plain = verify_export(exp)
        assert plain.valid
        assert plain.optional_checks["payload_binding"] == "skipped_no_input"
        keyed = verify_export(exp, federation_keys={"hub-a": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="})
        assert not keyed.valid
        assert keyed.optional_checks["federation_wire"] == "not_checked"

    def test_fails_inlined_evidence_on_an_entry_with_no_payload(self) -> None:
        exp = _live()
        del exp["entries"][2]["payload"]
        exp["entries"][2]["evidence"] = {"any": "body"}
        assert not verify_export(exp).valid


class TestTheFormatGateRefusesAnExportThatDoesNotStateItsFormat:
    @pytest.mark.parametrize("field", ["exportFormatVersion", "canonicalization"])
    def test_fails_when_the_field_is_absent(self, field: str) -> None:
        exp = _live()
        del exp["exportMetadata"][field]
        r = verify_export(exp)
        assert not r.valid
        assert r.broken_at is not None and r.broken_at.code == "UNSUPPORTED_FORMAT"
        assert f"no {field}" in (r.broken_at.detail or "")
        assert r.optional_checks["entry_count"] == "skipped_no_input"

    def test_still_reads_the_corpus_export_as_the_format_it_states(self) -> None:
        assert _live()["exportMetadata"]["exportFormatVersion"] == "2.0"


class TestSuppliedKeysAreRefusedBeforeTheFormatGate:
    def test_a_bad_federation_key_raises_whatever_the_export_states(self) -> None:
        exp = _live()
        del exp["exportMetadata"]["exportFormatVersion"]
        with pytest.raises(TypeError, match="not an Ed25519 public key"):
            verify_export(exp, federation_keys={"hub-a": "nope"})

    def test_a_bad_agent_key_raises_whatever_the_export_states(self) -> None:
        exp = copy.deepcopy(_live())
        del exp["exportMetadata"]["canonicalization"]
        with pytest.raises(TypeError):
            verify_export(exp, agent_keys=[{"kty": "RSA"}])
