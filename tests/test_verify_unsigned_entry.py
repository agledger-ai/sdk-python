"""When a row with no signing key is a break, and when it is reduced coverage.

The engine grades an entry whose ``signingKeyId`` is null as ``signature_missing``
when either:

  1. an earlier entry in the same chain names a signing key, whatever that
     entry's own verdict; or
  2. its ``createdAt`` is at or after the earliest ``activatedAt`` across the
     whole signing key set, retired keys included.

Anything else stays a ``skipped`` signature. The same instant turns an unsigned
vault checkpoint into ``checkpoint_unsigned``, and on the cross-party read log
an unsigned leaf (sentinel kid ``0000000000000000``) or tree head into
``leaf_signature_missing`` / ``checkpoint_unsigned``. The verifier codes are
CHAIN_ENTRY_UNSIGNED, CHECKPOINT_UNSIGNED, TENANT_READ_LEAF_UNSIGNED and
TENANT_CHECKPOINT_UNSIGNED.

The export cases are ported one for one from verify-core's
``unsigned-entry.test.ts`` so the two suites pin the same behaviour. Every
fixture is a mutation of a real corpus vector: ``valid.json`` (signed with a
key activated before its entries were written), ``unsigned.json`` (written
before any key was registered) and the ``dump/valid`` directory.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import cbor2
import pytest

from agledger.verify import load_dump, verify_export
from agledger.verify.types import Dump, Failure
from agledger.verify.verify_dump import (
    UNSIGNED_KID_SENTINEL,
    verify_dump,
    verify_org_admin_reads_chains,
    verify_vault_chains,
)
from agledger.verify.verify_export import (
    KeyCache,
    RegisteredKey,
    earliest_key_activation,
    written_while_signing,
)

CONFORMANCE = Path(__file__).resolve().parent.parent / "testdata" / "conformance"


def _load(rel: str) -> Any:
    return json.loads((CONFORMANCE / rel).read_text())


def _oob_keys() -> dict[str, str]:
    return cast("dict[str, str]", _load("export/keys-oob.json"))


def _real_window() -> tuple[str, dict[str, Any]]:
    """The single real key window valid.json carries, and its key id."""
    windows: dict[str, dict[str, Any]] = _load("export/valid.json")["exportMetadata"]["signingKeyWindows"]
    key_id, window = next(iter(windows.items()))
    return key_id, window


def _valid_all_nulled() -> dict[str, Any]:
    """valid.json with every entry's signingKeyId nulled: a chain written after
    activation with no key."""
    exp = _load("export/valid.json")
    for e in exp["entries"]:
        e["integrity"]["signingKeyId"] = None
    return exp


def _shift_ms(iso: str, ms: int) -> str:
    moved = datetime.fromisoformat(iso) + timedelta(milliseconds=ms)
    return moved.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --- rule 1: an unsigned entry after a signed one ---------------------------


def test_rule1_fails_at_the_unsigned_position_with_no_key_window_anywhere() -> None:
    exp = _load("export/valid.json")
    # Strip every activation time so only the signed-before half can fire.
    del exp["exportMetadata"]["signingKeyWindows"]
    exp["entries"][1]["integrity"]["signingKeyId"] = None
    result = verify_export(exp, public_keys=_oob_keys())
    assert result.valid is False
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (2, "CHAIN_ENTRY_UNSIGNED")
    assert result.broken_at.detail == (
        "Entry has no signingKeyId but follows a signed entry in the same chain."
    )
    first, second = result.entries[0], result.entries[1]
    assert (first.position, first.valid, first.signature) == (1, True, "ok")
    assert (second.position, second.valid, second.signature) == (2, False, "not-checked")
    assert result.optional_checks["key_temporal"] == "skipped_no_input"


def test_rule1_fires_on_the_tip_entry_the_shape_a_keyless_writer_leaves() -> None:
    exp = _load("export/valid.json")
    del exp["exportMetadata"]["signingKeyWindows"]
    exp["entries"][-1]["integrity"]["signingKeyId"] = None
    result = verify_export(exp)
    n = len(exp["entries"])
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (n, "CHAIN_ENTRY_UNSIGNED")
    assert result.verified_entries == n - 1


def test_rule1_counts_an_earlier_entry_that_names_a_key_even_when_it_failed() -> None:
    # Entry 1 names a key it cannot resolve (CHAIN_SIGNATURE_MISSING_KEY); it
    # still says the chain was being signed, so entry 2 unsigned is a break.
    exp = _load("export/valid.json")
    del exp["exportMetadata"]["signingKeyWindows"]
    exp["exportMetadata"]["signingPublicKeys"] = {}
    exp["entries"][1]["integrity"]["signingKeyId"] = None
    result = verify_export(exp)
    assert [(e.position, e.code) for e in result.entries[:2]] == [
        (1, "CHAIN_SIGNATURE_MISSING_KEY"),
        (2, "CHAIN_ENTRY_UNSIGNED"),
    ]


# --- rule 2: an unsigned entry written once the install signs ---------------


def test_rule2_an_all_unsigned_chain_with_no_keys_is_reduced_coverage() -> None:
    exp = _load("export/unsigned.json")
    assert exp["exportMetadata"]["signingKeyWindows"] == {}
    result = verify_export(exp)
    assert result.valid is True
    cov = result.signature_coverage
    assert (cov.signed, cov.unsigned, cov.skipped) == (0, 0, 3)


def test_rule2_caller_keys_without_activated_at_inherit_the_export_window() -> None:
    result = verify_export(_valid_all_nulled(), public_keys=_oob_keys())
    # valid.json's own export window still applies: the caller keys inherit it.
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_ENTRY_UNSIGNED"

    no_windows = _valid_all_nulled()
    del no_windows["exportMetadata"]["signingKeyWindows"]
    bare = verify_export(no_windows, public_keys=_oob_keys())
    assert bare.valid is True
    assert bare.signature_coverage.skipped == len(no_windows["entries"])


def test_rule2_an_entry_written_before_the_earliest_activation_is_not_a_break() -> None:
    exp = _load("export/unsigned.json")
    key_id, window = _real_window()
    # The generator writes this chain before registering the key valid.json
    # was signed with, so the real window postdates every entry here.
    for e in exp["entries"]:
        assert e["createdAt"] < window["activatedAt"]
    exp["exportMetadata"]["signingKeyWindows"] = {key_id: window}
    result = verify_export(exp)
    assert result.valid is True
    assert result.signature_coverage.skipped == 3


def test_rule2_counts_a_key_that_is_already_retired() -> None:
    exp = _valid_all_nulled()
    key_id, window = _real_window()
    # The only key in the set was retired before the first entry was written.
    retired_at = _shift_ms(window["activatedAt"], 1)
    assert exp["entries"][0]["createdAt"] > retired_at
    exp["exportMetadata"]["signingKeyWindows"] = {
        key_id: {"activatedAt": window["activatedAt"], "retiredAt": retired_at}
    }
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")
    assert result.broken_at.detail == (
        f"Entry has no signingKeyId but was written {exp['entries'][0]['createdAt']}, "
        f"at or after the earliest signing key activation {window['activatedAt']}."
    )


def test_rule2_counts_a_window_for_a_key_the_export_carries_no_public_key_for() -> None:
    exp = _valid_all_nulled()
    key_id, window = _real_window()
    exp["exportMetadata"]["signingPublicKeys"] = {}
    exp["exportMetadata"]["signingKeyWindows"] = {
        key_id: {"activatedAt": window["activatedAt"], "retiredAt": _shift_ms(window["activatedAt"], 1)}
    }
    result = verify_export(exp)
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")


def test_rule2_takes_the_earliest_activation_across_several_keys() -> None:
    exp = _valid_all_nulled()
    created = exp["entries"][0]["createdAt"]
    exp["exportMetadata"]["signingKeyWindows"] = {
        "later": {"activatedAt": _shift_ms(created, 60_000), "retiredAt": None},
        "earlier": {"activatedAt": _shift_ms(created, -60_000), "retiredAt": _shift_ms(created, -30_000)},
    }
    result = verify_export(exp)
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")


def test_rule2_is_inclusive_at_the_activation_instant_and_silent_one_ms_before() -> None:
    created = _valid_all_nulled()["entries"][0]["createdAt"]

    at = _valid_all_nulled()
    at["entries"] = at["entries"][:1]
    at["exportMetadata"]["signingKeyWindows"] = {"k": {"activatedAt": created, "retiredAt": None}}
    at_result = verify_export(at)
    assert at_result.broken_at is not None
    assert (at_result.broken_at.position, at_result.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")

    before = _valid_all_nulled()
    before["entries"] = before["entries"][:1]
    before["exportMetadata"]["signingKeyWindows"] = {
        "k": {"activatedAt": _shift_ms(created, 1), "retiredAt": None}
    }
    assert verify_export(before).valid is True


def test_rule2_compares_at_millisecond_resolution_as_the_ts_verifier_does() -> None:
    # Date.parse truncates to the millisecond, so an activation 0.4 ms after
    # the write reads as the same instant there, and must here too.
    exp = _valid_all_nulled()
    exp["entries"] = exp["entries"][:1]
    created = exp["entries"][0]["createdAt"]
    assert created.endswith("Z") and len(created.split(".")[1]) == 4
    exp["entries"][0]["createdAt"] = created[:-1] + "1Z"
    exp["exportMetadata"]["signingKeyWindows"] = {"k": {"activatedAt": created[:-1] + "5Z", "retiredAt": None}}
    result = verify_export(exp)
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_ENTRY_UNSIGNED"


def test_rule2_reads_caller_supplied_activated_at_when_the_export_carries_no_windows() -> None:
    exp = _valid_all_nulled()
    del exp["exportMetadata"]["signingKeyWindows"]
    key_id, window = _real_window()
    spki = _oob_keys()[key_id]
    result = verify_export(
        exp,
        public_keys=[
            {
                "keyId": key_id,
                "publicKey": spki,
                "activatedAt": window["activatedAt"],
                "retiredAt": _shift_ms(window["activatedAt"], 1),
            }
        ],
    )
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")


def test_rule2_reads_the_window_off_a_verification_key_model() -> None:
    # The natural caller shape: the .data list of client.verification_keys.list().
    from agledger.types import VerificationKey

    exp = _valid_all_nulled()
    del exp["exportMetadata"]["signingKeyWindows"]
    key_id, window = _real_window()
    model = VerificationKey.model_validate(
        {
            "keyId": key_id,
            "algorithm": "Ed25519",
            "publicKey": _oob_keys()[key_id],
            "status": "active",
            "activatedAt": window["activatedAt"],
            "retiredAt": None,
        }
    )
    result = verify_export(exp, public_keys=[model])
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_ENTRY_UNSIGNED"


def test_rule2_prefers_the_callers_window_for_a_key_over_the_exports() -> None:
    exp = _valid_all_nulled()
    key_id, _ = _real_window()
    last_created = exp["entries"][-1]["createdAt"]
    spki = _oob_keys()[key_id]
    result = verify_export(
        exp,
        public_keys=[
            {"keyId": key_id, "publicKey": spki, "activatedAt": _shift_ms(last_created, 1), "retiredAt": None}
        ],
    )
    assert result.valid is True


def test_rule2_does_not_apply_to_an_entry_that_carries_no_created_at() -> None:
    exp = _valid_all_nulled()
    for e in exp["entries"]:
        del e["createdAt"]
    assert verify_export(exp).valid is True


def test_rule2_ignores_a_key_with_an_unparseable_activation() -> None:
    exp = _valid_all_nulled()
    exp["exportMetadata"]["signingKeyWindows"] = {"k": {"activatedAt": "not a time", "retiredAt": None}}
    assert verify_export(exp).valid is True


# --- ordering against the key policy ----------------------------------------


def test_the_unsigned_break_is_reported_ahead_of_the_key_policy() -> None:
    exp = _valid_all_nulled()
    key_id, _ = _real_window()
    result = verify_export(exp, require_key_id=key_id)
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")

    oob = verify_export(_valid_all_nulled(), public_keys=_oob_keys(), require_out_of_band_keys=True)
    assert oob.broken_at is not None
    assert oob.broken_at.code == "CHAIN_ENTRY_UNSIGNED"


# --- a tamper finding on an unsigned entry keeps its own code ---------------

_STRUCTURAL = {
    "CHAIN_POSITION_GAP",
    "CHAIN_GENESIS_INVALID",
    "CHAIN_LINK_BROKEN",
    "CHAIN_HASH_MISMATCH",
    "CHAIN_MALFORMED_ENTRY",
    "CHAIN_COSE_DECODE_FAILED",
    "CHAIN_COSE_HEADER_MISMATCH",
    "CHAIN_PAYLOAD_BINDING_MISMATCH",
    "CHAIN_ACTOR_ATTRIBUTION_MISMATCH",
    "CHAIN_OIDC_ACTOR_MISMATCH",
}
_STRUCTURAL_VECTORS = [
    v
    for v in _load("manifest-export.json")["vectors"]
    if v["expect"] == "fail" and v.get("failureCode") in _STRUCTURAL
]


def test_the_structural_vectors_are_covered() -> None:
    assert len(_STRUCTURAL_VECTORS) >= 8


@pytest.mark.parametrize(
    "vector", _STRUCTURAL_VECTORS, ids=[f"{v['file']}:{v['failureCode']}" for v in _STRUCTURAL_VECTORS]
)
def test_a_structural_finding_keeps_its_code_with_the_key_id_nulled(vector: dict[str, Any]) -> None:
    exp = _load(vector["file"])
    at = vector.get("brokenAt", 1)
    # Signed entries precede it, so both halves of the rule would fire here if
    # the grading ran ahead of the structural checks.
    nulled = 0
    for e in exp["entries"]:
        if e.get("chainPosition", e.get("position")) == at and e.get("integrity"):
            e["integrity"]["signingKeyId"] = None
            nulled += 1
    assert nulled > 0
    result = verify_export(exp)
    assert result.broken_at is not None
    assert result.broken_at.code == vector["failureCode"]
    if "brokenAt" in vector:
        assert result.broken_at.position == vector["brokenAt"]


# --- a zeroed signature under a named key -----------------------------------


def _zero_signature_export() -> dict[str, Any]:
    """valid.json's first entry alone, its signature slot zeroed and its hash
    recomputed: an entry that names a key but carries no signature."""
    exp = _load("export/valid.json")
    entry = exp["entries"][0]
    tagged = cbor2.loads(base64.b64decode(entry["integrity"]["coseSign1"]))
    protected, unprotected, payload, signature = tagged.value
    envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, bytes(len(signature))]))
    entry["integrity"]["coseSign1"] = base64.b64encode(envelope).decode()
    entry["integrity"]["payloadHash"] = hashlib.sha256(envelope).hexdigest()
    exp["entries"] = [entry]
    return exp


@pytest.mark.parametrize("policy", ["none", "require_key_id", "require_out_of_band_keys"])
def test_a_zeroed_signature_under_a_named_key_fails_signature_invalid(policy: str) -> None:
    exp = _zero_signature_export()
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    kwargs: dict[str, Any] = {"public_keys": _oob_keys()}
    if policy == "require_key_id":
        kwargs["require_key_id"] = key_id
    elif policy == "require_out_of_band_keys":
        kwargs["require_out_of_band_keys"] = True
    result = verify_export(exp, **kwargs)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_SIGNATURE_INVALID"
    assert result.broken_at.detail == (
        f"Entry claims signingKeyId={key_id} but carries an all-zero signature."
    )
    assert result.entries[0].signature == "invalid"
    cov = result.signature_coverage
    assert (cov.signed, cov.unsigned, cov.skipped) == (0, 0, 0)


# --- the dump: the instant comes from the dumped key registry ---------------


@pytest.fixture
def dump() -> Dump:
    return load_dump(CONFORMANCE / "dump" / "valid")


def _chain_rows(d: Dump) -> tuple[str, list[dict[str, Any]]]:
    """The longest record chain in the dump, by chain key."""
    by_chain: dict[str, list[dict[str, Any]]] = {}
    for row in d.vault_entries:
        by_chain.setdefault(str(row.get("chain_key") or row.get("record_id")), []).append(row)
    key = max(by_chain, key=lambda k: len(by_chain[k]))
    return key, sorted(by_chain[key], key=lambda r: r["chain_position"])


def _codes(failures: list[Failure]) -> list[str]:
    return [f.code for f in failures]


def test_dump_valid_verifies_clean(dump: Dump) -> None:
    report = verify_dump(dump)
    assert report.ok, [f.to_json() for f in report.vault.failures + report.org_admin_reads.failures]


def test_dump_an_unsigned_entry_after_a_signed_one_breaks_its_chain(dump: Dump) -> None:
    chain_key, rows = _chain_rows(dump)
    assert len(rows) >= 2
    rows[1]["signing_key_id"] = None
    report = verify_vault_chains(dump.vault_entries, dump.vault_checkpoints, dump.signing_keys)
    hits = [f for f in report.failures if f.code == "CHAIN_ENTRY_UNSIGNED"]
    assert [(f.scope_id, f.position) for f in hits] == [(chain_key, 2)]


def test_dump_an_unsigned_first_entry_written_after_activation_breaks(dump: Dump) -> None:
    chain_key, rows = _chain_rows(dump)
    rows[0]["signing_key_id"] = None
    report = verify_vault_chains(dump.vault_entries, dump.vault_checkpoints, dump.signing_keys)
    hits = [f for f in report.failures if f.code == "CHAIN_ENTRY_UNSIGNED"]
    assert [(f.scope_id, f.position) for f in hits] == [(chain_key, 1)]
    assert "at or after the earliest signing key activation" in hits[0].message


def test_dump_an_all_unsigned_chain_from_before_the_first_key_is_not_a_break(dump: Dump) -> None:
    _, rows = _chain_rows(dump)
    for row in rows:
        row["signing_key_id"] = None
    keys = [dict(k, activated_at=_shift_ms(rows[-1]["created_at"], 1)) for k in dump.signing_keys]
    report = verify_vault_chains(rows, [], keys)
    assert report.failures == []


def test_dump_signing_since_none_switches_off_only_the_time_half(dump: Dump) -> None:
    _, rows = _chain_rows(dump)
    for row in rows:
        row["signing_key_id"] = None
    registry = KeyCache(
        {k["key_id"]: RegisteredKey(spki_base64=k["public_key"], source="embedded") for k in dump.signing_keys},
        signing_since=None,
    )
    assert verify_vault_chains(rows, [], dump.signing_keys, registry).failures == []

    rows[0]["signing_key_id"] = dump.signing_keys[0]["key_id"]
    report = verify_vault_chains(rows, [], dump.signing_keys, registry)
    # Row 1 now names a key, so row 2 fails on the signed-before half.
    assert (2, "CHAIN_ENTRY_UNSIGNED") in [(f.position, f.code) for f in report.failures]


def test_an_unparseable_signing_since_is_refused_rather_than_switching_the_check_off() -> None:
    with pytest.raises(TypeError):
        KeyCache({}, signing_since="soon")


def test_dump_an_unsigned_vault_checkpoint_after_activation_is_checkpoint_unsigned(dump: Dump) -> None:
    cp = dump.vault_checkpoints[0]
    cp["signing_key_id"] = None
    report = verify_vault_chains(dump.vault_entries, dump.vault_checkpoints, dump.signing_keys)
    assert _codes(report.failures) == ["CHECKPOINT_UNSIGNED"]
    assert report.failures[0].position == cp["chain_position"]


def test_dump_an_unsigned_vault_checkpoint_is_inclusive_at_the_activation_instant(dump: Dump) -> None:
    cp = dump.vault_checkpoints[0]
    cp["signing_key_id"] = None

    at = [dict(k, activated_at=cp["created_at"]) for k in dump.signing_keys]
    report = verify_vault_chains(dump.vault_entries, dump.vault_checkpoints, at)
    assert "CHECKPOINT_UNSIGNED" in _codes(report.failures)

    after = [dict(k, activated_at=_shift_ms(cp["created_at"], 1)) for k in dump.signing_keys]
    report = verify_vault_chains(dump.vault_entries, dump.vault_checkpoints, after)
    assert "CHECKPOINT_UNSIGNED" not in _codes(report.failures)


# --- the dump: the cross-party read log -------------------------------------


def _unsign_leaf(leaf: dict[str, Any]) -> None:
    """Rewrite a read-log leaf as the engine writes one with no key: the
    sentinel kid in the protected header and an all-zero signature, its
    leaf_hash recomputed so only the signature state differs."""
    tagged = cbor2.loads(base64.b64decode(leaf["cose_sign1"]))
    protected, unprotected, payload, signature = tagged.value
    header = cbor2.loads(protected)
    header[4] = bytes.fromhex(UNSIGNED_KID_SENTINEL)
    envelope = cbor2.dumps(
        cbor2.CBORTag(18, [cbor2.dumps(header, canonical=True), unprotected, payload, bytes(len(signature))])
    )
    leaf["cose_sign1"] = base64.b64encode(envelope).decode()
    leaf["leaf_hash"] = hashlib.sha256(envelope).hexdigest()


def _later_keys(d: Dump, after: str) -> list[dict[str, Any]]:
    return [dict(k, activated_at=_shift_ms(after, 1)) for k in d.signing_keys]


def test_read_log_an_unsigned_leaf_after_a_signed_one_breaks_before_activation(dump: Dump) -> None:
    leaves = sorted(dump.org_admin_reads, key=lambda r: r["leaf_index"])
    assert len(leaves) >= 2
    _unsign_leaf(leaves[1])
    # Every read predates the key here, so only the signed-before half can fire.
    keys = _later_keys(dump, max(r["read_at"] for r in leaves))
    report = verify_org_admin_reads_chains(leaves, [], keys)
    assert [(f.code, f.leaf_index) for f in report.failures] == [("TENANT_READ_LEAF_UNSIGNED", 1)]
    assert "follows a signed leaf" in report.failures[0].message


def test_read_log_an_unsigned_first_leaf_read_after_activation_breaks(dump: Dump) -> None:
    leaves = sorted(dump.org_admin_reads, key=lambda r: r["leaf_index"])
    _unsign_leaf(leaves[0])
    report = verify_org_admin_reads_chains(leaves, [], dump.signing_keys)
    assert [(f.code, f.leaf_index) for f in report.failures] == [("TENANT_READ_LEAF_UNSIGNED", 0)]


def test_read_log_unsigned_leaves_from_before_the_first_key_are_not_a_break(dump: Dump) -> None:
    leaves = sorted(dump.org_admin_reads, key=lambda r: r["leaf_index"])
    for leaf in leaves:
        _unsign_leaf(leaf)
    keys = _later_keys(dump, max(r["read_at"] for r in leaves))
    assert verify_org_admin_reads_chains(leaves, [], keys).failures == []

    # At the activation instant it is a break.
    at = [dict(k, activated_at=leaves[0]["read_at"]) for k in dump.signing_keys]
    report = verify_org_admin_reads_chains(leaves, [], at)
    assert [(f.code, f.leaf_index) for f in report.failures] == [("TENANT_READ_LEAF_UNSIGNED", 0)]


def test_read_log_an_unsigned_tree_head_after_activation_is_tenant_checkpoint_unsigned(dump: Dump) -> None:
    cp = dump.org_admin_reads_checkpoints[0]
    cp["signing_key_id"] = None
    report = verify_org_admin_reads_chains(
        dump.org_admin_reads, dump.org_admin_reads_checkpoints, dump.signing_keys
    )
    assert [(f.code, f.tree_size) for f in report.failures] == [
        ("TENANT_CHECKPOINT_UNSIGNED", cp["tree_size"])
    ]


def test_read_log_an_unsigned_tree_head_from_before_the_first_key_is_not_a_break(dump: Dump) -> None:
    cp = dump.org_admin_reads_checkpoints[0]
    cp["signing_key_id"] = None
    keys = _later_keys(dump, cp["checkpoint_at"])
    report = verify_org_admin_reads_chains(dump.org_admin_reads, dump.org_admin_reads_checkpoints, keys)
    assert report.failures == []


def test_verify_dump_reports_every_unsigned_code_it_finds(dump: Dump) -> None:
    d = copy.deepcopy(dump)
    _, rows = _chain_rows(d)
    rows[1]["signing_key_id"] = None
    d.org_admin_reads_checkpoints[0]["signing_key_id"] = None
    report = verify_dump(d)
    assert not report.ok
    codes = set(_codes(report.vault.failures + report.org_admin_reads.failures))
    assert {"CHAIN_ENTRY_UNSIGNED", "TENANT_CHECKPOINT_UNSIGNED"} <= codes


# --- the shared helpers ------------------------------------------------------


def test_earliest_key_activation_takes_the_minimum_and_ignores_unusable_keys() -> None:
    _, window = _real_window()
    assert earliest_key_activation([]) is None
    assert earliest_key_activation([{}, {"activatedAt": None}, {"activatedAt": "not a time"}]) is None
    retired = _shift_ms(window["activatedAt"], -5_000)
    assert (
        earliest_key_activation([{"activatedAt": window["activatedAt"]}, {"activatedAt": retired}, {}])
        == retired
    )
    # The dump spelling reads the same.
    assert earliest_key_activation([{"activated_at": retired}]) == retired


def test_written_while_signing_is_inclusive_and_needs_both_times() -> None:
    _, window = _real_window()
    since = window["activatedAt"]
    assert written_while_signing(since, since) is True
    assert written_while_signing(_shift_ms(since, 1), since) is True
    assert written_while_signing(_shift_ms(since, -1), since) is False
    assert written_while_signing(since, None) is False
    assert written_while_signing(None, since) is False
    assert written_while_signing("garbage", since) is False
