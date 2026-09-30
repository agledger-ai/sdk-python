"""The claim checks: each vault checkpoint, read-log leaf and read-log tree head
carries a signed claim, and the row beside it must say the same thing, as the
engine's scan holds them (``checkpoint_claim_mismatch``,
``leaf_claim_mismatch``). Every case tampers a real corpus dump (``dump/valid``)
while leaving the hash and root cross-checks intact, which is the gap the claim
checks close. Mirrors ``@agledger/verify``'s ``claims.test.ts``."""

from __future__ import annotations

import base64
from pathlib import Path

from agledger.verify import (
    Dump,
    Failure,
    VerifyReport,
    load_dump,
    org_read_merkle_root,
    verify_dump,
)

_VALID = Path(__file__).resolve().parents[1] / "testdata" / "conformance" / "dump" / "valid"


def _only(report: VerifyReport) -> Failure:
    failures = report.vault.failures + report.org_admin_reads.failures
    assert len(failures) == 1, [f.to_json() for f in failures]
    return failures[0]


def _valid() -> Dump:
    dump = load_dump(str(_VALID))
    assert len(dump.vault_checkpoints) >= 2
    assert len(dump.org_admin_reads) == 2
    assert len(dump.org_admin_reads_checkpoints) == 1
    return dump


# --- vault checkpoints: CHECKPOINT_CLAIM_MISMATCH ---


def test_the_unmodified_dump_carries_no_claim_finding() -> None:
    assert verify_dump(_valid()).ok is True


def test_an_envelope_moved_onto_another_chains_checkpoint_row_its_columns_intact() -> None:
    dump = _valid()
    a, b = dump.vault_checkpoints[0], dump.vault_checkpoints[1]
    a["cose_sign1"] = b["cose_sign1"]
    failure = _only(verify_dump(dump))
    assert (failure.code, failure.scope_id, failure.position) == (
        "CHECKPOINT_CLAIM_MISMATCH",
        a["chain_key"],
        a["chain_position"],
    )
    assert "checkpoint claim does not match its row" in failure.message


def test_a_record_id_column_rewritten_under_an_intact_envelope() -> None:
    dump = _valid()
    dump.vault_checkpoints[0]["record_id"] = "019a0000-0000-7000-8000-000000000001"
    failure = _only(verify_dump(dump))
    assert failure.code == "CHECKPOINT_CLAIM_MISMATCH"
    assert "subject digest" in failure.message


def test_a_key_id_column_nulled_beside_a_signed_envelope_is_a_claim_mismatch_not_an_unsigned_checkpoint() -> None:
    dump = _valid()
    dump.vault_checkpoints[0]["signing_key_id"] = None
    failure = _only(verify_dump(dump))
    assert failure.code == "CHECKPOINT_CLAIM_MISMATCH"
    assert "kid" in failure.message


def test_an_empty_key_id_column_is_a_claim_mismatch_never_unsigned() -> None:
    dump = _valid()
    dump.vault_checkpoints[0]["signing_key_id"] = ""
    assert [f.code for f in verify_dump(dump).vault.failures] == ["CHECKPOINT_CLAIM_MISMATCH"]


def test_checkpoint_bytes_that_are_not_an_envelope() -> None:
    dump = _valid()
    dump.vault_checkpoints[0]["cose_sign1"] = base64.b64encode(b"not an envelope").decode()
    assert "does not decode as a signed AGLedger claim" in _only(verify_dump(dump)).message


def test_the_row_and_hash_cross_checks_still_come_first() -> None:
    dump = _valid()
    a, b = dump.vault_checkpoints[0], dump.vault_checkpoints[1]
    a["cose_sign1"] = b["cose_sign1"]
    a["payload_hash"] = "e" * 64
    assert _only(verify_dump(dump)).code == "CHECKPOINT_HASH_MISMATCH"


# --- read-log leaves: TENANT_READ_CLAIM_MISMATCH ---


def test_a_record_id_column_rewritten_under_an_intact_leaf() -> None:
    dump = _valid()
    dump.org_admin_reads[1]["record_id"] = "019a0000-0000-7000-8000-000000000002"
    failure = _only(verify_dump(dump))
    assert (failure.code, failure.leaf_index) == ("TENANT_READ_CLAIM_MISMATCH", 1)
    assert "record_id" in failure.message


def test_two_leaves_swapped_and_renumbered_so_every_index_and_hash_still_holds() -> None:
    dump = _valid()
    first, second = dump.org_admin_reads[0], dump.org_admin_reads[1]
    first["leaf_index"], second["leaf_index"] = 1, 0
    cp = dump.org_admin_reads_checkpoints[0]
    cp["root_hash"] = org_read_merkle_root([second["leaf_hash"], first["leaf_hash"]])
    failure = _only(verify_dump(dump))
    assert (failure.code, failure.leaf_index) == ("TENANT_READ_CLAIM_MISMATCH", 0)
    assert "position" in failure.message


def test_the_index_and_hash_checks_still_come_first() -> None:
    dump = _valid()
    dump.org_admin_reads[1]["record_id"] = "019a0000-0000-7000-8000-000000000002"
    dump.org_admin_reads[1]["leaf_hash"] = "a" * 64
    assert _only(verify_dump(dump)).code == "TENANT_READ_LEAF_HASH_MISMATCH"


# --- read-log tree heads: TENANT_CHECKPOINT_CLAIM_MISMATCH ---


def test_a_tree_head_cut_to_a_smaller_tree_size_with_its_root_recomputed_to_match() -> None:
    dump = _valid()
    cp = dump.org_admin_reads_checkpoints[0]
    cp["tree_size"] = 1
    cp["root_hash"] = org_read_merkle_root([dump.org_admin_reads[0]["leaf_hash"]])
    failure = _only(verify_dump(dump))
    assert (failure.code, failure.scope_id, failure.tree_size) == ("TENANT_CHECKPOINT_CLAIM_MISMATCH", cp["org_id"], 1)
    assert "position" in failure.message


def test_a_key_id_column_nulled_beside_a_signed_tree_head() -> None:
    dump = _valid()
    dump.org_admin_reads_checkpoints[0]["signing_key_id"] = None
    failure = _only(verify_dump(dump))
    assert failure.code == "TENANT_CHECKPOINT_CLAIM_MISMATCH"
    assert "kid" in failure.message


def test_the_root_check_still_comes_first() -> None:
    dump = _valid()
    cp = dump.org_admin_reads_checkpoints[0]
    cp["signing_key_id"] = None
    cp["root_hash"] = "c" * 64
    assert _only(verify_dump(dump)).code == "TENANT_CHECKPOINT_ROOT_MISMATCH"
