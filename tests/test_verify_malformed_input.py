"""Row data no engine writes (a nulled, dropped or retyped column) is a failure
code on the entry it sits in, or a statement finding, never a raise out of the
walk and never a pass read off a check that was skipped; and key_trust.status
says whether a pass is trusted. The same cases, codes and detail strings as
@agledger/verify-core's malformed-input and key-trust-status tests, each a
mutation of a real corpus vector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import (
    compute_key_trust,
    key_statement_from_dump_row,
    load_dump,
    settle_key_trust,
    spki_sha256,
    trust_key_from_dump_row,
    verify_dump,
    verify_export,
)
from agledger.verify.key_statements import no_anchor_report
from agledger.verify.types import Dump, VerifyReport

CONFORMANCE = Path(__file__).resolve().parent.parent / "testdata" / "conformance"
STRANGER = "sha256:" + "a" * 64


def _load(rel: str) -> Any:
    return json.loads((CONFORMANCE / rel).read_text())


def _rows(rel: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (CONFORMANCE / rel).read_text().splitlines() if line.strip()]


ANCHOR: str = _load("export/valid.json")["exportMetadata"]["anchoredFrom"]
KEY_ID = ANCHOR[len("sha256:") : len("sha256:") + 16]


def _mid_cutoff() -> str:
    return f"{ANCHOR}@{_load('export/valid.json')['entries'][1]['createdAt']}"


def _dump_codes(report: VerifyReport) -> list[str]:
    return sorted(
        {f.code for f in report.key_trust.findings}
        | {f.code for f in report.vault.failures}
        | {f.code for f in report.org_admin_reads.failures}
    )


# --- an entry with no readable createdAt fails closed -------------------------


@pytest.mark.parametrize(
    "blank",
    [
        "drop",
        None,
        "garbage",
        7,
        "2026-09-01T00:00:00",
        "2026-09-01 00:00:00Z",
        "1",
        "2026-02-30T00:00:00.000000Z",
    ],
)
def test_a_distrusted_key_cannot_be_slipped_past_its_cutoff_by_nulling_entry_times(blank: object) -> None:
    plain = verify_export(_load("export/valid.json"), trust_anchors=[ANCHOR], distrusted_keys=[_mid_cutoff()])
    assert "CHAIN_KEY_EXPIRED" in {e.code for e in plain.entries}

    exp = _load("export/valid.json")
    for e in exp["entries"]:
        if blank == "drop":
            del e["createdAt"]
        else:
            e["createdAt"] = blank
    r = verify_export(exp, trust_anchors=[ANCHOR], distrusted_keys=[_mid_cutoff()])
    assert r.valid is False
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_MALFORMED_ENTRY")
    assert r.broken_at.detail == f"Entry has no parseable createdAt, so it cannot be placed inside key {KEY_ID}'s window."
    assert r.optional_checks["key_temporal"] == "applied"


def test_a_key_with_no_window_needs_no_entry_time() -> None:
    exp = _load("export/valid.json")
    del exp["exportMetadata"]["signingKeyWindows"]
    for e in exp["entries"]:
        del e["createdAt"]
    assert verify_export(exp).valid is True


def test_a_single_unsigned_entry_with_its_time_nulled_is_not_early_history_under_a_pin() -> None:
    exp = _load("export/unsigned-history-then-signed.json")
    exp["entries"] = exp["entries"][:1]
    exp["entries"][0]["createdAt"] = None
    r = verify_export(exp, trust_anchors=[ANCHOR])
    assert r.valid is False
    assert r.broken_at is not None and r.broken_at.code == "CHAIN_MALFORMED_ENTRY"
    assert r.signature_coverage.skipped == 0


def test_nulling_every_vault_write_time_does_not_pass_a_distrusted_key() -> None:
    d = load_dump(CONFORMANCE / "dump" / "valid")
    pin = f"sha256:{spki_sha256(d.signing_keys[0]['public_key'])}"
    mid = d.vault_entries[len(d.vault_entries) // 2]["created_at"]
    assert "CHAIN_KEY_EXPIRED" in _dump_codes(verify_dump(d, trust_anchors=[pin], distrusted_keys=[f"{pin}@{mid}"]))
    for e in d.vault_entries:
        e["created_at"] = None
    report = verify_dump(d, trust_anchors=[pin], distrusted_keys=[f"{pin}@{mid}"])
    assert report.verdict == "failed"
    assert "CHAIN_MALFORMED_ENTRY" in _dump_codes(report)


# --- malformed rows are failure codes, not raises -----------------------------


@pytest.mark.parametrize("payload", [None, "x", 7, []])
def test_a_null_or_retyped_export_payload_is_a_binding_mismatch(payload: object) -> None:
    exp = _load("export/valid.json")
    exp["entries"][0]["payload"] = payload
    r = verify_export(exp)
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_PAYLOAD_BINDING_MISMATCH")


@pytest.mark.parametrize("mutation", ["integrity-null", "integrity-drop", "cose-int", "hash-int"])
def test_a_malformed_integrity_block_is_chain_malformed_entry(mutation: str) -> None:
    exp = _load("export/valid.json")
    e = exp["entries"][0]
    if mutation == "integrity-null":
        e["integrity"] = None
    elif mutation == "integrity-drop":
        del e["integrity"]
    elif mutation == "cose-int":
        e["integrity"]["coseSign1"] = 7
    else:
        e["integrity"]["payloadHash"] = 7
    r = verify_export(exp)
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_MALFORMED_ENTRY")
    assert r.broken_at.detail == "Entry is missing coseSign1 or payloadHash, or carries one that is not a string."


def test_an_entry_that_is_not_an_object_fails_its_position() -> None:
    exp = _load("export/valid.json")
    exp["entries"][0] = None
    r = verify_export(exp)
    assert r.broken_at is not None and r.broken_at.code == "CHAIN_POSITION_GAP"


@pytest.mark.parametrize("spki", [None, 7, ""])
def test_an_embedded_key_with_no_key_material_is_no_key(spki: object) -> None:
    for anchors in (None, [ANCHOR]):
        exp = _load("export/valid.json")
        exp["exportMetadata"]["signingPublicKeys"][KEY_ID] = spki
        r = verify_export(exp, trust_anchors=anchors)
        assert r.broken_at is not None
        assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_SIGNATURE_MISSING_KEY")


def test_a_null_window_or_a_retyped_anchored_from_is_ignored() -> None:
    exp = _load("export/valid.json")
    exp["exportMetadata"]["signingKeyWindows"][KEY_ID] = None
    exp["exportMetadata"]["anchoredFrom"] = 7
    r = verify_export(exp, trust_anchors=[ANCHOR])
    assert r.valid is True
    assert r.key_trust.anchored_from is None


@pytest.mark.parametrize(
    "doc",
    [None, "x", {"exportMetadata": None, "entries": []}, {"exportMetadata": {"recordId": "r"}, "entries": "x"}],
)
def test_a_document_that_is_not_an_export_raises_type_error(doc: Any) -> None:
    with pytest.raises(TypeError) as err:
        verify_export(doc)
    assert str(err.value) == "Expected an /audit-export document: { exportMetadata: { recordId, ... }, entries: [...] }."


def _dump(mutate: str) -> Dump:
    d = load_dump(CONFORMANCE / "dump" / "valid")
    if mutate == "payload-null":
        d.vault_entries[0]["payload"] = None
    elif mutate == "payload-drop":
        del d.vault_entries[0]["payload"]
    elif mutate == "public-key-null":
        for k in d.signing_keys:
            k["public_key"] = None
    elif mutate == "chain-key-int":
        for e in d.vault_entries:
            e["chain_key"] = 7
    elif mutate == "checkpoint-record-null":
        for c in d.vault_checkpoints:
            c["record_id"] = None
    elif mutate == "read-record-null":
        d.org_admin_reads[0]["record_id"] = None
    elif mutate == "head-root-null":
        d.org_admin_reads_checkpoints[0]["root_hash"] = None
    elif mutate == "head-size-null":
        d.org_admin_reads_checkpoints[0]["tree_size"] = None
    elif mutate == "position-null":
        d.vault_entries[1]["chain_position"] = None
    elif mutate == "leaf-index-null":
        d.org_admin_reads[0]["leaf_index"] = None
    return d


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        ("payload-null", "CHAIN_PAYLOAD_BINDING_MISMATCH"),
        ("payload-drop", "CHAIN_PAYLOAD_BINDING_MISMATCH"),
        ("public-key-null", "CHAIN_SIGNATURE_MISSING_KEY"),
        ("chain-key-int", "CHECKPOINT_ROW_MISSING"),
        ("checkpoint-record-null", "CHECKPOINT_CLAIM_MISMATCH"),
        ("read-record-null", "TENANT_READ_CLAIM_MISMATCH"),
        ("head-root-null", "TENANT_CHECKPOINT_ROOT_MISMATCH"),
        ("head-size-null", "TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH"),
        ("position-null", "CHAIN_POSITION_GAP"),
        ("leaf-index-null", "TENANT_READ_LEAF_INDEX_GAP"),
    ],
)
def test_a_malformed_dump_row_fails_rather_than_raising(mutate: str, code: str) -> None:
    pin = f"sha256:{spki_sha256(load_dump(CONFORMANCE / 'dump' / 'valid').signing_keys[0]['public_key'])}"
    for anchors in (None, [pin]):
        report = verify_dump(_dump(mutate), trust_anchors=anchors)
        assert report.verdict == "failed"
        assert code in _dump_codes(report)


@pytest.mark.parametrize("blank", ["drop", None, 7, "garbage"])
def test_a_statement_row_with_no_created_at_is_key_statement_invalid(blank: object) -> None:
    rows = _rows("dump/valid/vault_key_statements.ndjson")
    row = rows[-1]
    if blank == "drop":
        del row["created_at"]
    else:
        row["created_at"] = blank
    trust = compute_key_trust(
        keys=[trust_key_from_dump_row(k) for k in _rows("dump/valid/vault_signing_keys.ndjson")],
        statements=[key_statement_from_dump_row(r) for r in rows],
        trust_anchors=[ANCHOR],
    )
    assert trust.order == "written"
    assert any(
        f.code == "KEY_STATEMENT_INVALID"
        and f.statement_id == row["id"]
        and f.detail == "the row has no parseable created_at to order it by"
        for f in trust.findings
    )


@pytest.mark.parametrize("blank", ["drop", None, 7])
def test_a_statement_row_with_no_subject_key_id_binds_to_nothing(blank: object) -> None:
    rows = _rows("dump/valid/vault_key_statements.ndjson")
    if blank == "drop":
        del rows[0]["subject_key_id"]
    else:
        rows[0]["subject_key_id"] = blank
    trust = compute_key_trust(
        keys=[trust_key_from_dump_row(k) for k in _rows("dump/valid/vault_signing_keys.ndjson")],
        statements=[key_statement_from_dump_row(r) for r in rows],
        trust_anchors=[ANCHOR],
    )
    assert "KEY_STATEMENT_INVALID" in {f.code for f in trust.findings}


def test_a_key_row_with_no_public_key_or_a_retyped_algorithm_is_not_raised_on() -> None:
    keys = [{**k, "public_key": None, "algorithm": 7} for k in _rows("dump/valid/vault_signing_keys.ndjson")]
    assert trust_key_from_dump_row(keys[0]).algorithm is None
    compute_key_trust(
        keys=[trust_key_from_dump_row(k) for k in keys],
        statements=[key_statement_from_dump_row(r) for r in _rows("dump/valid/vault_key_statements.ndjson")],
        trust_anchors=[ANCHOR],
    )


def test_distrusted_keys_without_trust_anchors_are_refused() -> None:
    for anchors in (None, []):
        with pytest.raises(TypeError) as err:
            verify_export(_load("export/valid.json"), trust_anchors=anchors, distrusted_keys=[ANCHOR])
        assert str(err.value) == (
            "distrusted_keys act only inside the key-statement walk, which runs from trust_anchors; "
            "pass trust_anchors as well."
        )
    assert verify_export(_load("export/valid.json"), distrusted_keys=[]).valid is True


# --- key_trust.status ---------------------------------------------------------


def test_no_anchor_says_a_pass_is_not_a_trusted_verdict() -> None:
    r = verify_export(_load("export/valid.json"))
    assert r.valid is True
    assert r.key_trust.status == "no_anchor"
    assert r.key_trust.detail == (
        "No trustAnchors were given, so no key was anchored and this is not a trusted verdict: every key "
        "was taken on the word of whoever embedded or supplied it, and a key written into the Server's "
        "database alone would verify. Pin the SPKI digest of a vault key you hold or took out of band "
        "(sha256:<hex>) as trustAnchors."
    )
    assert r.optional_checks["key_anchoring"] == "skipped_no_input"


@pytest.mark.parametrize("anchor", [STRANGER, ANCHOR])
def test_an_unsigned_only_chain_under_any_pin_is_no_anchored_signature(anchor: str) -> None:
    r = verify_export(_load("export/unsigned.json"), trust_anchors=[anchor])
    assert r.valid is True
    assert r.signature_coverage.signed == 0
    assert r.key_trust.status == "no_anchored_signature"
    assert r.key_trust.detail == (
        f"The key statements were walked from {anchor}, but no signature here verified under a key they "
        "anchor, so this is not a trusted verdict: an entry written before the install began signing "
        "carries no signature, and proves nothing about who wrote it."
    )
    assert r.optional_checks["key_anchoring"] == "not_checked"


def test_unsigned_history_then_entries_signed_under_the_anchored_key_is_walked() -> None:
    r = verify_export(_load("export/unsigned-history-then-signed.json"), trust_anchors=[ANCHOR])
    assert r.valid is True
    assert (r.signature_coverage.signed, r.signature_coverage.skipped) == (1, 2)
    assert r.key_trust.status == "walked"
    assert r.optional_checks["key_anchoring"] == "applied"


def test_a_chain_broken_before_the_anchoring_check_reports_not_checked() -> None:
    exp = _load("export/valid.json")
    exp["entries"] = exp["entries"][1:]
    r = verify_export(exp, trust_anchors=[ANCHOR])
    assert all(e.code == "CHAIN_POSITION_GAP" for e in r.entries)
    assert r.valid is False
    assert r.key_trust.status == "no_anchored_signature"
    assert r.optional_checks["key_anchoring"] == "not_checked"


def test_a_pinned_dump_of_unsigned_history_passes_unanchored() -> None:
    d = load_dump(CONFORMANCE / "dump" / "valid-unsigned-history-then-signed")
    pin = f"sha256:{spki_sha256(d.signing_keys[0]['public_key'])}"
    assert verify_dump(d, trust_anchors=[pin]).verdict == "trusted"
    d.vault_entries = [e for e in d.vault_entries if e["signing_key_id"] is None]
    d.vault_checkpoints = [c for c in d.vault_checkpoints if c["signing_key_id"] is None]
    d.org_admin_reads = []
    d.org_admin_reads_checkpoints = []
    d.key_statements = []
    report = verify_dump(d, trust_anchors=[STRANGER])
    assert report.ok is True
    assert report.verdict == "unanchored"
    assert report.key_trust.status == "no_anchored_signature"
    assert report.vault.signed_entries == 0
    assert report.vault.optional_checks["key_anchoring"] == "not_checked"


def test_settle_key_trust_leaves_a_report_it_has_nothing_to_say_about() -> None:
    no_anchor = no_anchor_report()
    assert settle_key_trust(no_anchor, 0) is no_anchor
    from dataclasses import replace

    walked = replace(no_anchor, status="walked", anchors=[ANCHOR])
    assert settle_key_trust(walked, 1) is walked
    assert settle_key_trust(walked, 0).status == "no_anchored_signature"


def test_the_cli_headline_says_a_pin_that_anchored_no_signature_is_not_trusted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agledger.verify.cli import run_cli

    assert run_cli([str(CONFORMANCE / "export" / "unsigned.json"), "--trust-anchor", STRANGER]) == 0
    out = capsys.readouterr().out
    assert out.startswith(
        "[VERIFIED, NOT ANCHORED] AGLedger offline verification (audit-export)\n"
        "  Nothing failed, but this is NOT a trusted verdict: the --trust-anchor was walked, but no\n"
        "  signature here verified under a key it anchors. An entry written before the install\n"
        "  began signing carries no signature, and proves nothing about who wrote it.\n"
    )
