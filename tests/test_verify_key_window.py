"""Vault checkpoints, read-log leaves and read-log tree heads against the
signed window of the key that signed them, and the ones a ``distrusted_keys``
entry accounts for. The Server's scan reports the same findings as
checkpoint_key_not_yet_active, checkpoint_key_expired,
leaf_key_not_yet_active, leaf_key_expired, accounted_checkpoint_only and
checkpoint_accounted_run_exceeded, and lists the rows set aside in
distrustedCheckpoints and orgAdminReads.distrustedEntries. A port of
``@agledger/verify``'s ``test/key-window.test.ts``."""

from __future__ import annotations

import base64
import re
from typing import Any

import pytest

from agledger.verify import (
    ACCOUNTED_CHECKPOINT_RUN_CAP,
    Dump,
    FailureCode,
    VerifyReport,
    verify_dump,
)
from agledger.verify.cli import _format_dump_text  # pyright: ignore[reportPrivateUsage]

from .dump_fixtures import (
    KeyMaterial,
    build_happy_dump,
    build_key_statement,
    build_org_admin_reads_checkpoint,
    build_vault_checkpoint,
    generate_key,
    pin_of,
    signing_key_dump,
    stable_uuid_from_string,
)

ACTIVATED = "2026-01-01T00:00:00.000000Z"
RETIRED = "2026-06-01T00:00:00.000000Z"
#: The instant a dated distrust entry gives for the first key.
DISTRUSTED_FROM = "2026-03-01T00:00:00Z"


def _codes(report: VerifyReport) -> list[FailureCode]:
    return [
        *(f.code for f in report.vault.failures),
        *(f.code for f in report.org_admin_reads.failures),
        *(f.code for f in report.key_trust.findings),
    ]


def _rotated() -> tuple[Dump, KeyMaterial, KeyMaterial]:
    """The happy dump, every row signed by ``k1`` (entries and the vault
    checkpoint in February, the read log in April), after a rotation: ``k1``
    was active from January and ``k2`` succeeded it in June, each edge signed."""
    dump, k1 = build_happy_dump()
    k2 = generate_key()
    dump.signing_keys = [
        signing_key_dump(k1, activated_at="2026-01-01T00:00:00.000Z", retired_at="2026-06-01T00:00:00.000Z", status="retired"),
        signing_key_dump(k2, activated_at="2026-06-01T00:00:00.000Z"),
    ]
    dump.key_statements = [
        build_key_statement("genesis", k1, signers=[k1], activated_at=ACTIVATED, created_at=ACTIVATED),
        build_key_statement("succession", k2, endorser=k1, signers=[k1, k2], activated_at=RETIRED, created_at=RETIRED),
        build_key_statement(
            "closure",
            k1,
            endorser=k2,
            signers=[k2],
            activated_at=ACTIVATED,
            retired_at=RETIRED,
            created_at="2026-06-01T00:00:01.000000Z",
        ),
    ]
    return dump, k1, k2


def _wipe_signature(cose_sign1: str) -> str:
    """Flip a bit of the signature, the last bytes of the envelope."""
    raw = bytearray(base64.b64decode(cose_sign1))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def _pinned(k2: KeyMaterial) -> dict[str, Any]:
    return {"trust_anchors": [pin_of(k2)]}


def _distrusting(k1: KeyMaterial, k2: KeyMaterial) -> dict[str, Any]:
    return {"trust_anchors": [pin_of(k2)], "distrusted_keys": [f"{pin_of(k1)}@{DISTRUSTED_FROM}"]}


class TestARowWrittenOutsideItsSigningKeysWindow:
    def test_passes_the_rotated_dump_every_row_inside_the_window_of_the_key_that_signed_it(self) -> None:
        dump, _k1, k2 = _rotated()
        report = verify_dump(dump, **_pinned(k2))
        assert _codes(report) == []
        assert report.verdict == "trusted"

    @pytest.mark.parametrize(
        ("at", "suffix"),
        [
            ("2026-06-01T00:00:00.001Z", "KEY_EXPIRED"),
            ("2025-12-31T23:59:59.999Z", "KEY_NOT_YET_ACTIVE"),
        ],
        ids=["after the retirement", "before the activation"],
    )
    def test_fails_a_vault_checkpoint_a_leaf_and_a_tree_head_written_outside(self, at: str, suffix: str) -> None:
        dump, _k1, k2 = _rotated()
        dump.vault_checkpoints[0]["created_at"] = at
        checkpoint = verify_dump(dump, **_pinned(k2))
        assert _codes(checkpoint) == [f"CHECKPOINT_{suffix}"]
        failure = checkpoint.vault.failures[0]
        assert (failure.position, failure.signing_key_id) == (3, dump.vault_checkpoints[0]["signing_key_id"])
        assert "Checkpoint written " in failure.message

        leaf_dump, _k1, leaf_k2 = _rotated()
        leaf_dump.org_admin_reads[1]["read_at"] = at
        assert _codes(verify_dump(leaf_dump, **_pinned(leaf_k2))) == [f"TENANT_READ_{suffix}"]

        head_dump, _k1, head_k2 = _rotated()
        head_dump.org_admin_reads_checkpoints[0]["checkpoint_at"] = at
        assert _codes(verify_dump(head_dump, **_pinned(head_k2))) == [f"TENANT_CHECKPOINT_{suffix}"]

    def test_passes_a_row_written_exactly_at_the_retirement(self) -> None:
        dump, _k1, k2 = _rotated()
        dump.vault_checkpoints[0]["created_at"] = "2026-06-01T00:00:00.000Z"
        dump.org_admin_reads[1]["read_at"] = "2026-06-01T00:00:00.000Z"
        dump.org_admin_reads_checkpoints[0]["checkpoint_at"] = "2026-06-01T00:00:00.000Z"
        assert _codes(verify_dump(dump, **_pinned(k2))) == []

    def test_reports_a_signature_that_does_not_verify_ahead_of_the_window(self) -> None:
        dump, _k1, k2 = _rotated()
        cp = dump.vault_checkpoints[0]
        cp["created_at"] = "2026-07-01T00:00:00.000Z"
        cp["cose_sign1"] = _wipe_signature(cp["cose_sign1"])
        head = dump.org_admin_reads_checkpoints[0]
        head["checkpoint_at"] = "2026-07-01T00:00:00.000Z"
        head["cose_sign1"] = _wipe_signature(head["cose_sign1"])
        assert _codes(verify_dump(dump, **_pinned(k2))) == [
            "CHECKPOINT_SIGNATURE_INVALID",
            "TENANT_CHECKPOINT_SIGNATURE_INVALID",
        ]

    def test_fails_closed_on_a_row_whose_write_time_cannot_be_read(self) -> None:
        dump, _k1, k2 = _rotated()
        dump.vault_checkpoints[0]["created_at"] = "2026-02-01 06:00:00"
        report = verify_dump(dump, **_pinned(k2))
        assert report.ok is False
        assert report.vault.failures[-1].code == "CHAIN_MALFORMED_ENTRY"
        assert "no parseable write time" in report.vault.failures[-1].message

    def test_with_no_pin_holds_a_row_to_the_window_the_registry_row_lists_as_it_holds_an_entry(self) -> None:
        dump, _key = build_happy_dump()
        dump.vault_checkpoints[0]["created_at"] = "2031-01-01T00:00:00.000Z"
        assert verify_dump(dump).verdict == "unanchored"
        dump.signing_keys[0]["retired_at"] = "2030-01-01T00:00:00.000Z"
        assert _codes(verify_dump(dump)) == ["CHECKPOINT_KEY_EXPIRED"]


class TestRowsADistrustedKeysEntryAccountsFor:
    def test_sets_aside_what_the_key_signed_from_the_distrust_instant_to_its_retirement_and_verifies_what_it_signed_before(
        self,
    ) -> None:
        dump, k1, k2 = _rotated()
        report = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(report) == []
        assert report.ok is True
        # February: entries and the vault checkpoint, before the instant.
        assert report.vault.accounted == []
        assert report.vault.accounted_checkpoints == []
        # April: the read log, four leaves and a tree head.
        accounted = report.org_admin_reads.accounted
        assert [f"{a.org_id} {a.kind} {a.at}" for a in accounted] == [
            "enterprise-1 leaf 0",
            "enterprise-1 leaf 1",
            "enterprise-1 leaf 2",
            "enterprise-1 checkpoint 3",
            "enterprise-2 leaf 0",
        ]
        assert (accounted[0].code, accounted[0].key_id) == ("CHAIN_SIGNED_BY_DISTRUSTED_KEY", k1.key_id)
        out = report.to_json()["orgAdminReads"]
        assert (out["accountedCount"], len(out["accounted"])) == (5, 5)
        assert out["accounted"][3] == {
            "code": "CHAIN_SIGNED_BY_DISTRUSTED_KEY",
            "orgId": "enterprise-1",
            "kind": "checkpoint",
            "at": 3,
            "keyId": k1.key_id,
            "detail": accounted[3].detail,
        }
        assert accounted[3].detail.startswith(
            f"Tree head written 2026-04-25T18:00:00.000Z is signed by key {k1.key_id}, which distrustedKeys names, "
            f"before {RETIRED}, when a key the walk trusts retired it"
        )
        text = _format_dump_text(report)
        assert re.search(r"accounted for {4}: 5 \(signed by a distrusted key", text)
        assert "Org enterprise-1 tree head at size 3" in text
        assert "Org enterprise-1 leaf 0 key" in text

    def test_lists_a_vault_checkpoint_written_inside_the_span_and_compares_no_chain_with_it(self) -> None:
        dump, k1, k2 = _rotated()
        cp = dump.vault_checkpoints[0]
        cp["created_at"] = "2026-04-01T00:00:00.000Z"
        # A holder of the leaked key anchors a position the chain never reached.
        planted = {**build_vault_checkpoint("record-bbbb", 999, "ab" * 32, k1), "created_at": "2026-04-02T00:00:00.000Z"}
        dump.vault_checkpoints.append(planted)
        report = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(report) == []
        assert [a.position for a in report.vault.accounted_checkpoints] == [3, 999]
        first = report.vault.accounted_checkpoints[0]
        assert (first.chain, first.key_id, first.code) == ("record", k1.key_id, "CHAIN_SIGNED_BY_DISTRUSTED_KEY")
        out = report.to_json()["vault"]
        assert (out["accountedCheckpointCount"], len(out["accountedCheckpoints"])) == (2, 2)
        # A checkpoint set aside holds no chain's length; one the walk trusts does.
        assert report.vault.checkpointed_chain_count == 0
        first_entry = next(
            e for e in dump.vault_entries if e["record_id"] == cp["record_id"] and e["chain_position"] == 1
        )
        dump.vault_checkpoints.append(
            {
                **build_vault_checkpoint("record-bbbb", 1, first_entry["payload_hash"], k2),
                "created_at": "2026-07-01T00:00:00.000Z",
            }
        )
        held = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(held) == []
        assert len(held.vault.accounted_checkpoints) == 2
        assert held.vault.checkpointed_chain_count == 1
        text = _format_dump_text(report)
        assert re.search(r"checkpoints set aside: 2 ", text)
        assert f"Record {first.record_id} checkpoint pos 3 key {k1.key_id}" in text

    def test_compares_no_root_and_finds_no_fork_among_tree_heads_set_aside(self) -> None:
        dump, k1, k2 = _rotated()
        leaves = [leaf for leaf in dump.org_admin_reads if leaf["org_id"] == "enterprise-1"]
        forged = build_org_admin_reads_checkpoint("enterprise-1", list(reversed(leaves)), k1, 3)
        dump.org_admin_reads_checkpoints.append({**forged, "id": "forged"})
        report = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(report) == []
        assert len([a for a in report.org_admin_reads.accounted if a.kind == "checkpoint"]) == 2

    def test_still_holds_a_leaf_set_aside_to_its_index_hash_and_claim(self) -> None:
        dump, k1, k2 = _rotated()
        dump.org_admin_reads[1]["leaf_hash"] = "cd" * 32
        assert _codes(verify_dump(dump, **_distrusting(k1, k2))) == ["TENANT_READ_LEAF_HASH_MISMATCH"]

    def test_sets_nothing_aside_whose_signature_does_not_verify_under_the_key(self) -> None:
        dump, k1, k2 = _rotated()
        head = dump.org_admin_reads_checkpoints[0]
        head["cose_sign1"] = _wipe_signature(head["cose_sign1"])
        report = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(report) == ["TENANT_CHECKPOINT_SIGNATURE_INVALID"]
        assert not any(a.kind == "checkpoint" for a in report.org_admin_reads.accounted)

    def test_fails_what_the_key_signed_after_a_trusted_key_retired_it(self) -> None:
        dump, k1, k2 = _rotated()
        dump.vault_checkpoints[0]["created_at"] = "2026-06-02T00:00:00.000Z"
        dump.org_admin_reads_checkpoints[0]["checkpoint_at"] = "2026-06-02T00:00:00.000Z"
        assert _codes(verify_dump(dump, **_distrusting(k1, k2))) == [
            "CHECKPOINT_KEY_EXPIRED",
            "TENANT_CHECKPOINT_KEY_EXPIRED",
        ]

    def test_sets_aside_every_row_of_an_unanchored_distrusted_key_a_trusted_key_retired_where_it_failed_each_as_unanchored(
        self,
    ) -> None:
        # k1 has no statement linking it to the pin; k2, pinned, runs under its
        # own genesis and retired k1 with force.
        dump, k1, k2 = _rotated()
        dump.key_statements = [
            build_key_statement("genesis", k1, signers=[k1], activated_at=ACTIVATED, created_at=ACTIVATED),
            build_key_statement("genesis", k2, signers=[k2], activated_at=RETIRED, created_at=RETIRED),
            build_key_statement(
                "closure",
                k1,
                endorser=k2,
                signers=[k2],
                activated_at=ACTIVATED,
                retired_at=RETIRED,
                forced=True,
                created_at="2026-06-01T00:00:01.000000Z",
            ),
        ]
        without = _codes(verify_dump(dump, **_pinned(k2)))
        # One finding per org log, so the leaf is reported and the walk stops before the tree head.
        for code in ("CHAIN_SIGNING_KEY_UNANCHORED", "CHECKPOINT_KEY_UNANCHORED", "TENANT_READ_KEY_UNANCHORED"):
            assert code in without

        report = verify_dump(dump, trust_anchors=[pin_of(k2)], distrusted_keys=[pin_of(k1)])
        assert report.vault.failures == []
        assert report.org_admin_reads.failures == []
        assert len(report.vault.accounted) == 6
        assert len(report.vault.accounted_checkpoints) == 1
        assert len(report.org_admin_reads.accounted) == 5


class TestAChainLeftWithOnlyCheckpointsSetAside:
    uuid = stable_uuid_from_string("record-bbbb")

    def test_fails_a_chain_with_no_entry_whose_only_checkpoints_are_set_aside(self) -> None:
        dump, k1, k2 = _rotated()
        dump.vault_entries = [e for e in dump.vault_entries if e["record_id"] != self.uuid]
        dump.vault_checkpoints[0]["created_at"] = "2026-04-01T00:00:00.000Z"
        report = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(report) == ["CHECKPOINT_ACCOUNTED_ONLY"]
        failure = report.vault.failures[0]
        assert (failure.scope_id, failure.position) == (self.uuid, 0)

    def test_reports_the_missing_rows_instead_when_one_checkpoint_of_the_chain_is_not_set_aside(self) -> None:
        dump, k1, k2 = _rotated()
        dump.vault_entries = [e for e in dump.vault_entries if e["record_id"] != self.uuid]
        dump.vault_checkpoints.append(
            {**build_vault_checkpoint("record-bbbb", 2, "ab" * 32, k1), "created_at": "2026-04-01T00:00:00.000Z"}
        )
        assert _codes(verify_dump(dump, **_distrusting(k1, k2))) == ["CHECKPOINT_ROW_MISSING"]

    def test_a_schema_chain_left_with_only_checkpoints_set_aside_is_not_reported(self) -> None:
        dump, k1, k2 = _rotated()
        dump.vault_entries = [e for e in dump.vault_entries if e["record_id"] != self.uuid]
        cp = dump.vault_checkpoints[0]
        cp["created_at"] = "2026-04-01T00:00:00.000Z"
        cp["chain_key"] = "schema:enterprise-1"
        report = verify_dump(dump, **_distrusting(k1, k2))
        assert _codes(report) == []
        assert len(report.vault.accounted_checkpoints) == 1

    def test_fails_a_run_of_set_aside_checkpoints_longer_than_the_walk_reads_above_the_newest_that_is_not(self) -> None:
        dump, k1, k2 = _rotated()
        # One checkpoint signed per position, then the run is cut to length.
        planted = [
            {**build_vault_checkpoint("record-bbbb", 4 + i, "ab" * 32, k1), "created_at": "2026-04-01T00:00:00.000Z"}
            for i in range(ACCOUNTED_CHECKPOINT_RUN_CAP + 1)
        ]

        def run(length: int) -> VerifyReport:
            dump.vault_checkpoints = [dump.vault_checkpoints[0], *planted[:length]]
            return verify_dump(dump, **_distrusting(k1, k2))

        assert _codes(run(ACCOUNTED_CHECKPOINT_RUN_CAP)) == []
        over = run(ACCOUNTED_CHECKPOINT_RUN_CAP + 1)
        assert _codes(over) == ["CHECKPOINT_ACCOUNTED_RUN_EXCEEDED"]
        failure = over.vault.failures[0]
        assert (failure.scope_id, failure.position) == (self.uuid, 4)
        assert len(over.vault.accounted_checkpoints) == ACCOUNTED_CHECKPOINT_RUN_CAP + 1
        out = over.to_json()["vault"]
        assert (out["accountedCheckpointCount"], len(out["accountedCheckpoints"])) == (
            ACCOUNTED_CHECKPOINT_RUN_CAP + 1,
            ACCOUNTED_CHECKPOINT_RUN_CAP,
        )
