"""Unit tests for the offline full-vault dump verifier + the agledger-verify CLI.

The cross-language behavioural contract is asserted by the dump conformance
corpus in ``test_conformance.py``; these tests cover the pieces that live only in
the dump package: the loader's fail-closed IO, fork detection, and the CLI's auto-detect + exit-code wiring.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agledger.verify import load_dump, verify_dump
from agledger.verify.cli import run_cli
from agledger.verify.loader import DumpLoadError
from agledger.verify.types import VerifyReport
from agledger.verify.verify_dump import report_codes

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFORMANCE_DIR = _REPO_ROOT / "testdata" / "conformance"
_VALID_DUMP = _CONFORMANCE_DIR / "dump" / "valid"
_EMPTY_DUMP = _CONFORMANCE_DIR / "dump" / "chain-empty"

_HAS_CORPUS = _VALID_DUMP.is_dir()


# --- loader: fail-closed IO -------------------------------------------------


def test_loader_missing_file_raises(tmp_path: Path) -> None:
    # An empty directory is missing all six required files.
    with pytest.raises(DumpLoadError, match="Required dump file not found"):
        load_dump(str(tmp_path))


def test_loader_malformed_json_raises(tmp_path: Path) -> None:
    # Create five valid empty files and one with a broken line.
    for name in (
        "vault_checkpoints.ndjson",
        "vault_signing_keys.ndjson",
        "vault_key_statements.ndjson",
        "org_admin_reads.ndjson",
        "org_admin_reads_checkpoints.ndjson",
    ):
        (tmp_path / name).write_text("")
    (tmp_path / "audit_vault.ndjson").write_text('{"id": 1}\n{not valid json}\n')
    with pytest.raises(DumpLoadError, match="Invalid JSON on line 2"):
        load_dump(str(tmp_path))


def test_loader_blank_lines_ignored(tmp_path: Path) -> None:
    for name in (
        "vault_checkpoints.ndjson",
        "vault_signing_keys.ndjson",
        "vault_key_statements.ndjson",
        "org_admin_reads.ndjson",
        "org_admin_reads_checkpoints.ndjson",
    ):
        (tmp_path / name).write_text("\n\n")
    (tmp_path / "audit_vault.ndjson").write_text('{"id": "a"}\n\n{"id": "b"}\n')
    dump = load_dump(str(tmp_path))
    assert len(dump.vault_entries) == 2
    assert dump.vault_checkpoints == []


# --- fork detection (no corpus needed) --------------------------------------


def test_fork_detection_flags_divergent_roots() -> None:
    from agledger.verify.types import Dump

    dump = Dump(
        vault_entries=[
            {
                "id": "e1",
                "record_id": "r1",
                "entry_type": "X",
                "payload": {},
                "payload_hash": "h",
                "previous_hash": None,
                "chain_position": 1,
                "cose_sign1": "AA==",
                "signing_key_id": None,
            }
        ],
        org_admin_reads_checkpoints=[
            {"id": "cp1", "org_id": "o1", "tree_size": 2, "root_hash": "ROOT_A"},
            {"id": "cp2", "org_id": "o1", "tree_size": 2, "root_hash": "ROOT_B"},
        ],
    )
    report = verify_dump(dump)
    codes = [f.code for f in report.org_admin_reads.failures]
    assert "TENANT_CHECKPOINT_FORK" in codes


# --- CLI auto-detect + exit codes -------------------------------------------


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_cli_dump_pass_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_cli([str(_VALID_DUMP)])
    out = capsys.readouterr().out
    assert code == 0
    # No pin: the dump passes, flagged as not a trusted verdict.
    assert out.startswith("[VERIFIED, NOT ANCHORED]")
    assert "this is NOT a trusted verdict" in out


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_cli_dump_pinned_on_its_key_is_trusted(capsys: pytest.CaptureFixture[str]) -> None:
    from agledger.verify.key_statements import spki_sha256

    key = json.loads((_VALID_DUMP / "vault_signing_keys.ndjson").read_text().splitlines()[0])
    code = run_cli([str(_VALID_DUMP), "--trust-anchor", f"sha256:{spki_sha256(key['public_key'])}"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("[PASS]")
    assert "anchored 1, unanchored 0" in out


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_cli_dump_fail_exits_one_and_names_code(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_cli([str(_EMPTY_DUMP)])
    out = capsys.readouterr().out
    assert code == 1
    assert "CHAIN_EMPTY" in out


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_cli_dump_json_format(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_cli([str(_VALID_DUMP), "--report-format", "json"])
    out = capsys.readouterr().out
    assert code == 0
    parsed = json.loads(out)
    assert parsed["ok"] is True
    # camelCase keys, matching the TS report JSON.
    assert "orgAdminReads" in parsed
    assert "recordCount" in parsed["vault"]


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_cli_quiet_suppresses_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_cli([str(_VALID_DUMP), "--quiet"])
    out = capsys.readouterr().out
    assert code == 0
    assert out == ""


def test_cli_export_file_detected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A minimal export with an unsupported version forces a deterministic FAIL
    # through the export path: the point is that the file branch fired.
    doc = {
        "exportMetadata": {
            "recordId": "rec-1",
            "exportFormatVersion": "1.0",
            "canonicalization": "RFC8949-CDE",
        },
        "entries": [],
    }
    f = tmp_path / "audit-export.json"
    f.write_text(json.dumps(doc))
    code = run_cli([str(f), "--report-format", "json"])
    out = capsys.readouterr().out
    assert code == 1
    parsed = json.loads(out)
    assert parsed["recordId"] == "rec-1"
    assert parsed["brokenAt"]["code"] == "UNSUPPORTED_FORMAT"


def test_cli_rejects_non_export_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "random.json"
    f.write_text(json.dumps({"hello": "world"}))
    code = run_cli([str(f)])
    err = capsys.readouterr().err
    assert code == 2  # usage/IO, not a verification failure
    assert "neither a dump directory nor an /audit-export" in err


def test_cli_missing_target_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    f = "/nonexistent/path/to/nothing.json"
    code = run_cli([f])
    assert code == 2


# --- checkpoint join on chain_key -------------------------------
#
# A schema chain's checkpoint carries a derived UUIDv8 in record_id that matches
# no audit_vault row. Joining on that column stranded the checkpoint and failed
# a healthy vault with CHECKPOINT_ROW_MISSING.

_DERIVED_V8 = "019a0000-0000-8000-8000-0000000000ff"


def _as_schema_chain(dump: object, chain_key: str) -> object:
    """Relabel the chain a checkpoint anchors as a schema chain: rows gain
    chain_key, and the checkpoint gets the derived v8 the engine writes."""
    cp = dump.vault_checkpoints[0]  # type: ignore[attr-defined]
    covered = str(cp.get("record_id"))
    for e in dump.vault_entries:  # type: ignore[attr-defined]
        if str(e.get("record_id")) == covered:
            e["chain_key"] = chain_key
    cp["chain_key"] = chain_key
    cp["record_id"] = _DERIVED_V8
    _resign_checkpoint_subject(dump, cp)
    return dump


def _resign_checkpoint_subject(dump: object, cp: dict[str, object]) -> None:
    """The engine signs the derived v8 as the checkpoint's subject, so the
    envelope is re-signed over that subject, under a fresh key the dump's
    registry lists beside the vault key."""
    import base64
    import hashlib

    import cbor2
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = hashlib.sha256(spki).hexdigest()[:16]
    registry = dump.signing_keys  # type: ignore[attr-defined]
    registry.append({**registry[0], "key_id": kid, "public_key": base64.b64encode(spki).decode()})
    protected, _u, payload, _sig = cbor2.loads(base64.b64decode(str(cp["cose_sign1"]))).value
    header = dict(cbor2.loads(protected))
    header[4] = bytes.fromhex(kid)
    protected = cbor2.dumps(header, canonical=True)
    stmt = cbor2.loads(payload)
    stmt["subject"][0]["digest"]["sha256"] = hashlib.sha256(bytes.fromhex(_DERIVED_V8.replace("-", ""))).digest()
    payload = cbor2.dumps(stmt, canonical=True)
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", payload], canonical=True))
    cp["cose_sign1"] = base64.b64encode(cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]), canonical=True)).decode()
    cp["signing_key_id"] = kid


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not vendored")
def test_checkpoint_joins_on_chain_key_healthy_schema_chain() -> None:
    dump = _as_schema_chain(load_dump(str(_VALID_DUMP)), "schema:org-1")
    report = verify_dump(dump)
    missing = [f for f in report.vault.failures if f.code == "CHECKPOINT_ROW_MISSING"]
    assert missing == [], f"healthy schema chain reported: {[f.message for f in missing]}"
    assert report.ok


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not vendored")
def test_truncated_schema_chain_still_fails_and_is_named_by_chain_key() -> None:
    dump = _as_schema_chain(load_dump(str(_VALID_DUMP)), "schema:org-1")
    anchored = [e for e in dump.vault_entries if e.get("chain_key") == "schema:org-1"]
    dump.vault_entries = [e for e in dump.vault_entries if e is not anchored[-1]]
    report = verify_dump(dump)
    missing = [f for f in report.vault.failures if f.code == "CHECKPOINT_ROW_MISSING"]
    assert missing, "truncated schema chain must still fail"
    assert missing[0].scope_id == "schema:org-1"
    assert "Chain schema:org-1" in missing[0].message
    assert "RecordRow" not in missing[0].message


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not vendored")
def test_entry_level_failure_is_named_by_the_chain_it_is_on() -> None:
    dump = _as_schema_chain(load_dump(str(_VALID_DUMP)), "schema:org-1")
    on_schema = [e for e in dump.vault_entries if e.get("chain_key") == "schema:org-1"]
    on_schema[-1]["payload_hash"] = "0" * 64
    report = verify_dump(dump)
    entry_failure = next(
        (
            f
            for f in report.vault.failures
            if f.scope_id == "schema:org-1" and f.position is not None
        ),
        None,
    )
    assert entry_failure is not None
    assert re.match(r"^Chain schema:org-1 pos \d+: ", entry_failure.message)

    plain = load_dump(str(_VALID_DUMP))
    plain.vault_entries[-1]["payload_hash"] = "0" * 64
    record_report = verify_dump(plain)
    record_failure = next(f for f in record_report.vault.failures if f.position is not None)
    assert re.match(
        rf"^Record {re.escape(str(record_failure.scope_id))} pos \d+: ", record_failure.message
    )


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not vendored")
def test_dump_without_chain_key_falls_back_to_record_id() -> None:
    dump = load_dump(str(_VALID_DUMP))
    for e in dump.vault_entries:
        e.pop("chain_key", None)
    for cp in dump.vault_checkpoints:
        cp.pop("chain_key", None)
    assert verify_dump(dump).ok


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_a_rewritten_key_id_is_drift_before_any_question_about_the_key_it_names() -> None:
    """The signed-kid check runs ahead of the registry's algorithm check, the
    order the engine applies: a row pointed at an alias whose declared
    algorithm contradicts its material reports the rewrite, not the alias."""
    dump = load_dump(str(_CONFORMANCE_DIR / "dump" / "chain-alg-registry-lie"))
    lying = dump.signing_keys[0]
    dump.signing_keys.append({**lying, "key_id": "ab" * 8})
    entry = min(dump.vault_entries, key=lambda e: (str(e.get("chain_key")), e["chain_position"]))
    entry["signing_key_id"] = "ab" * 8
    failures = [
        f for f in verify_dump(dump).vault.failures if f.scope_id == entry.get("chain_key") and f.position == entry["chain_position"]
    ]
    assert [f.code for f in failures] == ["CHAIN_SIGNING_KEY_DRIFT"]


# --- producer order and missing envelopes, as @agledger/verify streams them ---

_STRANGER = "sha256:" + "ab" * 32


def _codes(report: VerifyReport) -> set[str]:
    return set(report_codes(report))


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_a_chain_that_reappears_after_it_closed_is_refused_as_out_of_producer_order() -> None:
    dump = load_dump(str(_VALID_DUMP))
    first = dump.vault_entries[0]
    assert any(e["chain_key"] != first["chain_key"] for e in dump.vault_entries)
    dump.vault_entries = [*dump.vault_entries[1:], first]
    report = verify_dump(dump)
    assert not report.ok
    assert any(
        f.code == "UNSUPPORTED_FORMAT" and "not in producer order" in f.message for f in report.vault.failures
    )


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
def test_a_row_without_cose_sign1_stops_the_walk_and_keeps_what_the_chains_closed_before_it_found() -> None:
    # Under a pin nothing links to, every chain closed before the refused row
    # has already failed on its keys; the refusal does not erase that.
    dump = load_dump(str(_VALID_DUMP))
    dump.vault_entries[-1]["cose_sign1"] = None
    codes = _codes(verify_dump(dump, trust_anchors=[_STRANGER]))
    assert {"UNSUPPORTED_FORMAT", "CHAIN_SIGNING_KEY_UNANCHORED"} <= codes


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
@pytest.mark.parametrize(
    ("table", "code"),
    [
        ("vault_checkpoints", "CHECKPOINT_CLAIM_MISMATCH"),
        ("org_admin_reads", "TENANT_READ_LEAF_HASH_MISMATCH"),
        ("org_admin_reads_checkpoints", "TENANT_CHECKPOINT_CLAIM_MISMATCH"),
    ],
)
def test_a_null_envelope_on_a_checkpoint_leaf_or_tree_head_is_a_finding_not_a_crash(table: str, code: str) -> None:
    dump = load_dump(str(_VALID_DUMP))
    rows = getattr(dump, table)
    rows[0]["cose_sign1"] = None
    if table != "org_admin_reads":
        rows[0]["signing_key_id"] = None
    report = verify_dump(dump)
    assert not report.ok
    assert code in _codes(report)


@pytest.mark.skipif(not _HAS_CORPUS, reason="conformance corpus not present")
@pytest.mark.parametrize("value", [[], [{"kind": "genesis", "cose": []}], "statements"])
def test_signing_key_statements_not_keyed_by_key_id_are_refused_as_verify_core_refuses_them(value: object) -> None:
    from agledger.verify import verify_export

    doc = json.loads((_CONFORMANCE_DIR / "export" / "valid-es256.json").read_text())
    doc["exportMetadata"]["signingKeyStatements"] = value
    with pytest.raises(TypeError, match=r"^signingKeyStatements must be an object keyed by key id\.$"):
        verify_export(doc, trust_anchors=[doc["exportMetadata"]["anchoredFrom"]])
