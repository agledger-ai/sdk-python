"""Unit tests for the offline full-vault dump verifier + the agledger-verify CLI.

The cross-language behavioural contract is asserted by the dump conformance
corpus in ``test_conformance.py``; these tests cover the pieces that live only in
the dump package — the loader's fail-closed IO, the Merkle primitive, fork
detection, and the CLI's auto-detect + exit-code wiring.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agledger.verify import load_dump, verify_dump
from agledger.verify.cli import run_cli
from agledger.verify.loader import DumpLoadError
from agledger.verify.verify_export import _hash_pair, merkle_root

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFORMANCE_DIR = _REPO_ROOT / "testdata" / "conformance"
_VALID_DUMP = _CONFORMANCE_DIR / "dump" / "valid"
_EMPTY_DUMP = _CONFORMANCE_DIR / "dump" / "chain-empty"

_HAS_CORPUS = _VALID_DUMP.is_dir()


# --- loader: fail-closed IO -------------------------------------------------


def test_loader_missing_file_raises(tmp_path: Path) -> None:
    # An empty directory is missing all five required files.
    with pytest.raises(DumpLoadError, match="Required dump file not found"):
        load_dump(str(tmp_path))


def test_loader_malformed_json_raises(tmp_path: Path) -> None:
    # Create four valid empty files and one with a broken line.
    for name in (
        "vault_checkpoints.ndjson",
        "vault_signing_keys.ndjson",
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
        "org_admin_reads.ndjson",
        "org_admin_reads_checkpoints.ndjson",
    ):
        (tmp_path / name).write_text("\n\n")
    (tmp_path / "audit_vault.ndjson").write_text('{"id": "a"}\n\n{"id": "b"}\n')
    dump = load_dump(str(tmp_path))
    assert len(dump.vault_entries) == 2
    assert dump.vault_checkpoints == []


# --- Merkle primitive -------------------------------------------------------


def test_merkle_root_empty_is_sha256_of_empty() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_merkle_root_single_leaf_is_the_leaf() -> None:
    assert merkle_root(["abc"]) == "abc"


def test_merkle_root_two_leaves_is_hash_pair() -> None:
    assert merkle_root(["aa", "bb"]) == _hash_pair("aa", "bb")


def test_merkle_root_odd_duplicates_last_leaf() -> None:
    # Three leaves: level1 = [H(a,b), H(c,c)]; root = H(level1[0], level1[1]).
    a, b, c = "11", "22", "33"
    level1 = [_hash_pair(a, b), _hash_pair(c, c)]
    assert merkle_root([a, b, c]) == _hash_pair(level1[0], level1[1])


def test_hash_pair_is_hex_string_concat_not_byte_concat() -> None:
    # Guards the F-682-class trap: the digest is over the concatenated hex TEXT,
    # not over the decoded bytes.
    assert _hash_pair("ab", "cd") == hashlib.sha256(b"abcd").hexdigest()


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
    assert out.startswith("[PASS]")


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
    # through the export path — the point is that the file branch fired.
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


# --- checkpoint join on chain_key (agents#103) -------------------------------
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
    return dump


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
def test_dump_without_chain_key_falls_back_to_record_id() -> None:
    dump = load_dump(str(_VALID_DUMP))
    for e in dump.vault_entries:
        e.pop("chain_key", None)
    for cp in dump.vault_checkpoints:
        cp.pop("chain_key", None)
    assert verify_dump(dump).ok
