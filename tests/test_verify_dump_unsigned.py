"""The engine's rule for unsigned rows, applied to a dump, and the read-log
leaf signature check.

An unsigned chain entry, vault checkpoint, read-log leaf or read-log tree head
is a break when it was written at or after the earliest ``activated_at`` in the
key registry (retired keys included), and an unsigned entry or leaf is also a
break after a signed one in its chain or log. Anything else is reduced
coverage. A read-log leaf that names a real kid must carry a signature that
verifies under it, or the leaf rule could be skipped by naming any kid.

Ported case for case from ``@agledger/verify``'s ``unsigned-rule.test.ts``.
Every case is a mutation of the real corpus dump ``dump/valid``: three record
chains, three signed vault checkpoints, two signed read-log leaves under a
signed tree head, one key activated before all of it.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
import pytest

from agledger.verify import load_dump, verify_dump
from agledger.verify.cli import run_cli
from agledger.verify.types import Dump, Failure, VerifyReport
from agledger.verify.verify_dump import (
    UNSIGNED_KID_SENTINEL,
    verify_org_admin_reads_chains,
)
from agledger.verify.verify_export import org_read_leaf_hash, org_read_merkle_root

VALID = Path(__file__).resolve().parent.parent / "testdata" / "conformance" / "dump" / "valid"


def _dump() -> Dump:
    return load_dump(VALID)


def _all(report: VerifyReport) -> list[Failure]:
    return report.vault.failures + report.org_admin_reads.failures


def _codes(report: VerifyReport) -> list[str]:
    return [f.code for f in _all(report)]


def _only(report: VerifyReport) -> Failure:
    failures = _all(report)
    assert len(failures) == 1, [f.to_json() for f in failures]
    return failures[0]


def _shift_ms(iso: str, ms: int) -> str:
    moved = datetime.fromisoformat(iso) + timedelta(milliseconds=ms)
    return moved.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _activation(d: Dump) -> str:
    at = d.signing_keys[0].get("activated_at")
    assert isinstance(at, str)
    return at


def _long_chain(d: Dump) -> list[dict[str, Any]]:
    """The record chain with more than one entry, in position order."""
    by_chain: dict[str, list[dict[str, Any]]] = {}
    for e in d.vault_entries:
        by_chain.setdefault(str(e["chain_key"]), []).append(e)
    chain = next(c for c in by_chain.values() if len(c) > 1)
    return sorted(chain, key=lambda r: r["chain_position"])


def _as_unsigned_envelope(
    cose_b64: str,
    kid_hex: str = UNSIGNED_KID_SENTINEL,
    zero_signature: bool = True,
    previous_hash: str | None = None,
) -> str:
    """Re-encode a real envelope as the engine writes an unsigned one: the kid
    is the eight-zero-byte sentinel and the signature slot is zeroed. The
    protected header is otherwise unchanged, so every chain claim still holds;
    ``previous_hash`` restamps the chain claim when the leaf before was
    rewritten too."""
    tagged = cbor2.loads(base64.b64decode(cose_b64))
    protected, _unprotected, payload, signature = tagged.value
    header = dict(cbor2.loads(protected))
    header[4] = bytes.fromhex(kid_hex)
    if previous_hash is not None:
        header[-65537] = {**header[-65537], 2: bytes.fromhex(previous_hash)}
    new_protected = cbor2.dumps(header, canonical=True)
    new_signature = bytes(len(signature)) if zero_signature else signature
    envelope = cbor2.dumps(cbor2.CBORTag(18, [new_protected, {}, payload, new_signature]), canonical=True)
    return base64.b64encode(envelope).decode()


def _replace_leaf(d: Dump, index: int, cose_b64: str) -> dict[str, Any]:
    """Replace a leaf's envelope and restamp leaf_hash, the way a writer
    holding no key would append it, then re-root every tree head over the new
    leaves so the Merkle cross-check still holds. The tree heads keep their
    (now stale) signatures, so tests that reach them make them unsigned too."""
    leaf = d.org_admin_reads[index]
    leaf["cose_sign1"] = cose_b64
    leaf["leaf_hash"] = org_read_leaf_hash(base64.b64decode(cose_b64))
    for cp in d.org_admin_reads_checkpoints:
        hashes = [str(r["leaf_hash"]) for r in d.org_admin_reads if r["org_id"] == cp["org_id"]]
        cp["root_hash"] = org_read_merkle_root(hashes[: cp["tree_size"]])
    return leaf


def _unsign(cp: dict[str, Any]) -> None:
    """Make a checkpoint row unsigned the way the engine writes one: no key id,
    and an envelope carrying the unsigned kid and a zeroed signature. Nulling
    the column alone leaves the signed kid disagreeing with it, which is a
    claim mismatch rather than an unsigned checkpoint."""
    cp["signing_key_id"] = None
    cp["cose_sign1"] = _as_unsigned_envelope(cp["cose_sign1"])


def _unsign_tree_heads(d: Dump, before: str) -> None:
    """Make every read-log tree head unsigned and written before ``before``,
    its signed root restamped to the row's (which ``_replace_leaf`` may have
    re-rooted), as an engine writing that tree head unsigned would have signed it."""
    for cp in d.org_admin_reads_checkpoints:
        _unsign(cp)
        tagged = cbor2.loads(base64.b64decode(cp["cose_sign1"]))
        protected, _unprotected, payload, signature = tagged.value
        stmt = cbor2.loads(payload)
        stmt["subject"][0]["digest"]["sha256"] = bytes.fromhex(cp["root_hash"])
        stmt["predicate"]["chain_tip_hash"] = f"sha256:{cp['root_hash']}"
        new_payload = cbor2.dumps(stmt, canonical=True)
        envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, new_payload, signature]), canonical=True)
        cp["cose_sign1"] = base64.b64encode(envelope).decode()
        cp["checkpoint_at"] = _shift_ms(before, -1)


# --- baseline ----------------------------------------------------------------


def test_dump_valid_verifies_clean_and_every_read_log_leaf_signature_is_checked() -> None:
    report = verify_dump(_dump())
    assert report.ok, _codes(report)
    assert report.org_admin_reads.leaf_count == 2


# --- audit_vault chain entries: CHAIN_ENTRY_UNSIGNED -------------------------


def test_an_unsigned_entry_after_a_signed_one_fails_with_no_activation_time_anywhere() -> None:
    d = _dump()
    # Only the signed-before half of the rule can fire.
    for k in d.signing_keys:
        del k["activated_at"]
    chain = _long_chain(d)
    chain[1]["signing_key_id"] = None
    failure = _only(verify_dump(d))
    assert (failure.code, failure.position, failure.scope_id) == ("CHAIN_ENTRY_UNSIGNED", 2, chain[1]["chain_key"])
    assert "follows a signed entry" in failure.message


def test_an_unsigned_tip_after_signed_entries_fails() -> None:
    d = _dump()
    for k in d.signing_keys:
        del k["activated_at"]
    chain = _long_chain(d)
    chain[-1]["signing_key_id"] = None
    failure = _only(verify_dump(d))
    assert (failure.code, failure.position) == ("CHAIN_ENTRY_UNSIGNED", len(chain))


def test_every_unsigned_entry_written_after_the_earliest_activation_fails() -> None:
    d = _dump()
    chain = _long_chain(d)
    for e in chain:
        e["signing_key_id"] = None
    failures = verify_dump(d).vault.failures
    # Each entry is graded on its own write time, so every one of them fails.
    assert [(f.code, f.position) for f in failures] == [
        ("CHAIN_ENTRY_UNSIGNED", e["chain_position"]) for e in chain
    ]
    assert _activation(d) in failures[0].message


def test_a_retired_key_still_marks_when_the_install_began_signing() -> None:
    d = _dump()
    key = d.signing_keys[0]
    key["status"] = "retired"
    key["retired_at"] = _shift_ms(_activation(d), 1)
    # Keep only the chain under test, all of it unsigned, so the retired key
    # signs nothing that could fail CHAIN_KEY_EXPIRED.
    chain = _long_chain(d)
    for e in chain:
        e["signing_key_id"] = None
    d.vault_entries, d.vault_checkpoints, d.org_admin_reads, d.org_admin_reads_checkpoints = chain, [], [], []
    report = verify_dump(d)
    assert [f.code for f in report.vault.failures] == ["CHAIN_ENTRY_UNSIGNED"] * len(chain)
    assert report.vault.failures[0].position == 1


def test_an_all_unsigned_chain_from_before_the_first_key_is_reduced_coverage_and_inclusive_at_it() -> None:
    d = _dump()
    chain = _long_chain(d)
    for e in chain:
        e["signing_key_id"] = None
    d.vault_entries, d.vault_checkpoints, d.org_admin_reads, d.org_admin_reads_checkpoints = chain, [], [], []
    last = chain[-1]["created_at"]
    d.signing_keys[0]["activated_at"] = _shift_ms(last, 1)
    report = verify_dump(d)
    assert report.ok, _codes(report)

    # At the activation instant itself it is a break: the window is inclusive.
    d.signing_keys[0]["activated_at"] = last
    failure = _only(verify_dump(d))
    assert (failure.code, failure.position) == ("CHAIN_ENTRY_UNSIGNED", len(chain))


def test_an_install_with_no_key_at_all_still_verifies_an_all_unsigned_vault() -> None:
    d = _dump()
    for e in d.vault_entries:
        e["signing_key_id"] = None
    d.signing_keys, d.vault_checkpoints, d.org_admin_reads, d.org_admin_reads_checkpoints = [], [], [], []
    report = verify_dump(d)
    assert report.ok, _codes(report)


def test_a_tampered_hash_on_an_unsigned_entry_keeps_its_own_code() -> None:
    d = _dump()
    chain = _long_chain(d)
    chain[1]["signing_key_id"] = None
    chain[1]["payload_hash"] = "f" * 64
    assert _codes(verify_dump(d))[0] == "CHAIN_HASH_MISMATCH"


# --- vault_checkpoints: CHECKPOINT_UNSIGNED -----------------------------------


def test_an_unsigned_checkpoint_written_after_the_earliest_activation_fails() -> None:
    d = _dump()
    cp = d.vault_checkpoints[0]
    _unsign(cp)
    failure = _only(verify_dump(d))
    assert (failure.code, failure.position, failure.scope_id) == (
        "CHECKPOINT_UNSIGNED", cp["chain_position"], cp["chain_key"],
    )
    assert _activation(d) in failure.message


def test_an_unsigned_checkpoint_before_the_earliest_activation_passes_and_at_it_fails() -> None:
    d = _dump()
    cp = d.vault_checkpoints[0]
    _unsign(cp)
    cp["created_at"] = _shift_ms(_activation(d), -1)
    report = verify_dump(d)
    assert report.ok, _codes(report)

    cp["created_at"] = _activation(d)
    assert _only(verify_dump(d)).code == "CHECKPOINT_UNSIGNED"


def test_an_unsigned_checkpoint_with_no_write_time_cannot_be_placed() -> None:
    d = _dump()
    cp = d.vault_checkpoints[0]
    _unsign(cp)
    del cp["created_at"]
    assert verify_dump(d).ok


def test_a_diverged_or_orphaned_unsigned_checkpoint_keeps_its_own_code() -> None:
    d = _dump()
    diverged, orphaned = d.vault_checkpoints[0], d.vault_checkpoints[1]
    _unsign(diverged)
    diverged["payload_hash"] = "e" * 64
    _unsign(orphaned)
    d.vault_entries = [e for e in d.vault_entries if e["chain_key"] != orphaned["chain_key"]]
    assert sorted(_codes(verify_dump(d))) == ["CHECKPOINT_HASH_MISMATCH", "CHECKPOINT_ROW_MISSING"]


# --- org_admin_reads leaves: TENANT_READ_LEAF_UNSIGNED ------------------------


def test_an_unsigned_leaf_after_a_signed_leaf_fails_with_no_activation_time_anywhere() -> None:
    d = _dump()
    for k in d.signing_keys:
        del k["activated_at"]
    leaf = _replace_leaf(d, 1, _as_unsigned_envelope(d.org_admin_reads[1]["cose_sign1"]))
    failure = _only(verify_dump(d))
    assert (failure.code, failure.leaf_index, failure.scope_id) == ("TENANT_READ_LEAF_UNSIGNED", 1, leaf["org_id"])
    assert failure.message.endswith(
        f"leaf is unsigned (kid {UNSIGNED_KID_SENTINEL}) but follows a signed leaf in the same org log"
    )


def test_an_unsigned_first_leaf_read_after_the_earliest_activation_fails() -> None:
    d = _dump()
    _replace_leaf(d, 0, _as_unsigned_envelope(d.org_admin_reads[0]["cose_sign1"]))
    failure = _only(verify_dump(d))
    assert (failure.code, failure.leaf_index) == ("TENANT_READ_LEAF_UNSIGNED", 0)
    assert _activation(d) in failure.message


def test_a_retired_key_counts_when_placing_a_leaf() -> None:
    d = _dump()
    d.signing_keys[0]["status"] = "retired"
    d.signing_keys[0]["retired_at"] = _shift_ms(_activation(d), 1)
    _replace_leaf(d, 0, _as_unsigned_envelope(d.org_admin_reads[0]["cose_sign1"]))
    report = verify_org_admin_reads_chains(d.org_admin_reads, d.org_admin_reads_checkpoints, d.signing_keys)
    assert [f.code for f in report.failures] == ["TENANT_READ_LEAF_UNSIGNED"]


def test_an_all_unsigned_log_before_the_first_key_passes_and_a_leaf_at_it_fails() -> None:
    d = _dump()
    at = _shift_ms(d.org_admin_reads[1]["read_at"], 1)
    d.signing_keys[0]["activated_at"] = at
    first = _replace_leaf(d, 0, _as_unsigned_envelope(d.org_admin_reads[0]["cose_sign1"]))
    _replace_leaf(
        d, 1, _as_unsigned_envelope(d.org_admin_reads[1]["cose_sign1"], previous_hash=first["leaf_hash"])
    )
    _unsign_tree_heads(d, at)

    def verify() -> list[Failure]:
        return verify_org_admin_reads_chains(
            d.org_admin_reads, d.org_admin_reads_checkpoints, d.signing_keys
        ).failures

    assert verify() == []

    d.signing_keys[0]["activated_at"] = d.org_admin_reads[1]["read_at"]
    _unsign_tree_heads(d, d.org_admin_reads[1]["read_at"])
    assert [(f.code, f.leaf_index) for f in verify()] == [("TENANT_READ_LEAF_UNSIGNED", 1)]


def test_an_unsigned_leaf_with_a_rewritten_hash_reports_the_hash_and_a_gap_comes_first() -> None:
    d = _dump()
    _replace_leaf(d, 0, _as_unsigned_envelope(d.org_admin_reads[0]["cose_sign1"]))
    d.org_admin_reads[0]["leaf_hash"] = "d" * 64
    assert _codes(verify_dump(d)) == ["TENANT_READ_LEAF_HASH_MISMATCH"]

    gapped = _dump()
    _replace_leaf(gapped, 1, _as_unsigned_envelope(gapped.org_admin_reads[1]["cose_sign1"]))
    gapped.org_admin_reads[1]["leaf_index"] = 2
    assert _codes(verify_dump(gapped)) == ["TENANT_READ_LEAF_INDEX_GAP"]


# --- org_admin_reads leaves: the signature a real kid claims ------------------


def test_a_zeroed_signature_under_a_real_kid_is_signature_invalid_never_unsigned() -> None:
    d = _dump()
    kid = d.signing_keys[0]["key_id"]
    _replace_leaf(d, 1, _as_unsigned_envelope(d.org_admin_reads[1]["cose_sign1"], kid))
    failure = _only(verify_dump(d))
    assert (failure.code, failure.leaf_index) == ("TENANT_READ_SIGNATURE_INVALID", 1)


def test_a_kid_the_registry_does_not_hold_is_chain_signature_missing_key() -> None:
    d = _dump()
    _replace_leaf(d, 1, _as_unsigned_envelope(d.org_admin_reads[1]["cose_sign1"], "ab" * 8, zero_signature=False))
    failure = _only(verify_dump(d))
    assert (failure.code, failure.leaf_index, failure.signing_key_id) == (
        "CHAIN_SIGNATURE_MISSING_KEY", 1, "ab" * 8,
    )


def test_a_leaf_restamped_over_altered_envelope_bytes_fails_its_signature() -> None:
    d = _dump()
    raw = bytearray(base64.b64decode(d.org_admin_reads[0]["cose_sign1"]))
    raw[-1] = (raw[-1] + 1) % 256
    _replace_leaf(d, 0, base64.b64encode(bytes(raw)).decode())
    failure = _only(verify_dump(d))
    assert (failure.code, failure.leaf_index) == ("TENANT_READ_SIGNATURE_INVALID", 0)


def test_a_leaf_that_is_not_a_cose_sign1_envelope_is_a_claim_mismatch_as_the_engine_grades_it() -> None:
    d = _dump()
    _replace_leaf(d, 0, base64.b64encode(b"not an envelope").decode())
    failure = _only(verify_dump(d))
    assert (failure.code, failure.leaf_index) == ("TENANT_READ_CLAIM_MISMATCH", 0)
    assert "does not decode" in failure.message


# --- org_admin_reads_checkpoints: TENANT_CHECKPOINT_UNSIGNED ------------------


def test_an_unsigned_tree_head_written_after_the_earliest_activation_fails() -> None:
    d = _dump()
    cp = d.org_admin_reads_checkpoints[0]
    _unsign(cp)
    failure = _only(verify_dump(d))
    assert (failure.code, failure.scope_id, failure.tree_size) == (
        "TENANT_CHECKPOINT_UNSIGNED", cp["org_id"], cp["tree_size"],
    )
    assert _activation(d) in failure.message


def test_an_unsigned_tree_head_before_the_earliest_activation_passes_and_at_it_fails() -> None:
    d = _dump()
    cp = d.org_admin_reads_checkpoints[0]
    _unsign(cp)
    cp["checkpoint_at"] = _shift_ms(_activation(d), -1)
    assert verify_dump(d).ok

    cp["checkpoint_at"] = _activation(d)
    assert _only(verify_dump(d)).code == "TENANT_CHECKPOINT_UNSIGNED"


def test_an_unsigned_tree_head_over_the_wrong_root_reports_the_root() -> None:
    d = _dump()
    cp = d.org_admin_reads_checkpoints[0]
    _unsign(cp)
    cp["root_hash"] = "c" * 64
    assert _codes(verify_dump(d)) == ["TENANT_CHECKPOINT_ROOT_MISMATCH"]


# --- When the install began signing --------------------------------------------

_VALID_PIN = "sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e"


def _stripped_dump(move: str) -> Dump:
    """A single-entry chain unsigned: its entry has no signed entry before it,
    so only the install's signing-start time can make it a break."""
    d = _dump()
    counts: dict[str, int] = {}
    for e in d.vault_entries:
        counts[str(e["chain_key"])] = counts.get(str(e["chain_key"]), 0) + 1
    lone = next(e for e in d.vault_entries if counts[str(e["chain_key"])] == 1)
    lone["signing_key_id"] = None
    d.vault_checkpoints = [c for c in d.vault_checkpoints if c["chain_key"] != lone["chain_key"]]
    for k in d.signing_keys:
        if move == "strip":
            k.pop("activated_at", None)
        else:
            k["activated_at"] = "2099-01-01T00:00:00.000Z"
    return d


@pytest.mark.parametrize("move", ["strip", "later"])
def test_pinned_an_unsigned_entry_still_fails_when_the_registry_activated_at_column_is_moved(move: str) -> None:
    report = verify_dump(_stripped_dump(move), trust_anchors=[_VALID_PIN])
    assert "CHAIN_ENTRY_UNSIGNED" in _codes(report)


def test_unpinned_the_same_edit_hides_the_unsigned_entry_which_is_what_the_pin_is_for() -> None:
    report = verify_dump(_stripped_dump("strip"))
    assert "CHAIN_ENTRY_UNSIGNED" not in _codes(report)


# --- CLI -----------------------------------------------------------------------


def test_the_cli_exits_1_and_names_each_unsigned_finding(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    d = _dump()
    _long_chain(d)[1]["signing_key_id"] = None
    _unsign(d.vault_checkpoints[0])
    _unsign(d.org_admin_reads_checkpoints[0])
    for name, rows in (
        ("audit_vault.ndjson", d.vault_entries),
        ("vault_checkpoints.ndjson", d.vault_checkpoints),
        ("vault_signing_keys.ndjson", d.signing_keys),
        ("org_admin_reads.ndjson", d.org_admin_reads),
        ("org_admin_reads_checkpoints.ndjson", d.org_admin_reads_checkpoints),
        ("vault_key_statements.ndjson", d.key_statements),
    ):
        (tmp_path / name).write_text("".join(json.dumps(r) + "\n" for r in rows))
    code = run_cli([str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 1
    for failure_code in ("CHAIN_ENTRY_UNSIGNED", "CHECKPOINT_UNSIGNED", "TENANT_CHECKPOINT_UNSIGNED"):
        assert failure_code in out
