"""Shared conformance-corpus runner for the Python offline verifiers.

Loads the cross-language anti-drift corpus (see ``testdata/conformance/SPEC.md``)
and runs both manifests:
  - ``manifest-export.json`` through ``agledger.verify.verify_export`` (per-record)
  - ``manifest-dump.json``   through ``agledger.verify.verify_dump`` (full vault)

Each vector pairs a real-shaped document with an expected verdict and a canonical
``FailureCode``; the TS verify-core, the TS ``@agledger/verify`` dump verifier,
and these Python verifiers all run the SAME corpus, so a wire-format change that
breaks one language's verifier is caught here in lockstep.

This MUST fail loudly on any mismatch — a ``pass`` vector returning invalid, or a
``fail`` vector returning the wrong code, is the exact drift the corpus exists to
catch. On the EXPORT runner, dump-only codes (inputs the ``/audit-export`` wire
cannot carry) are skipped with an explicit reason; the dump runner covers them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import load_dump, verify_dump, verify_export

# tests/ -> repo root (standalone source-of-truth layout; corpus vendored at
# repo-root testdata/conformance/).
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFORMANCE_DIR = _REPO_ROOT / "testdata" / "conformance"
_MANIFEST = _CONFORMANCE_DIR / "manifest-export.json"
_DUMP_MANIFEST = _CONFORMANCE_DIR / "manifest-dump.json"

# Codes the EXPORT path can never emit (they need dump-only inputs the
# /audit-export wire does not carry). On the export runner a vector carrying one
# of these is skipped with a clear reason; the dump runner below covers them.
# CHAIN_PAYLOAD_BINDING_MISMATCH is NOT here: the export now carries the row
# payload (engine ≥ v0.26.x), so the binding check runs on the export path too
# and Python must catch it (F-731).
_DUMP_ONLY_CODES = frozenset(
    {
        "CHAIN_OIDC_ACTOR_MISMATCH",
        "CHAIN_KEY_EXPIRED",
        "CHECKPOINT_ROW_MISSING",
        "CHECKPOINT_HASH_MISMATCH",
        "CHECKPOINT_SIGNATURE_INVALID",
        "TENANT_READ_LEAF_HASH_MISMATCH",
        "TENANT_READ_LEAF_INDEX_GAP",
        "TENANT_READ_SIGNATURE_INVALID",
        "TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH",
        "TENANT_CHECKPOINT_ROOT_MISMATCH",
        "TENANT_CHECKPOINT_SIGNATURE_INVALID",
        "TENANT_CHECKPOINT_FORK",
    }
)


def _load_manifest() -> dict[str, Any]:
    return json.loads(_MANIFEST.read_text())


def _export_vectors() -> list[dict[str, Any]]:
    if not _MANIFEST.exists():
        return []
    return [v for v in _load_manifest().get("vectors", []) if v.get("kind") == "export"]


def _vector_id(vector: dict[str, Any]) -> str:
    label = vector["file"].split("/")[-1].removesuffix(".json")
    suffix = vector.get("failureCode") or vector["expect"]
    opts = vector.get("options") or {}
    if opts.get("requireKeyId"):
        suffix += "+requireKeyId"
    if opts.get("requireOutOfBandKeys"):
        suffix += "+requireOOB"
    return f"{label}:{suffix}"


_VECTORS = _export_vectors()


@pytest.mark.skipif(not _MANIFEST.exists(), reason=f"conformance manifest not found at {_MANIFEST}")
def test_manifest_present_and_nonempty() -> None:
    """Guard: the corpus must exist and carry export vectors. A silently empty
    corpus would let real drift slip through parametrize."""
    manifest = _load_manifest()
    assert manifest.get("formatVersion") == "2.0"
    assert len(_VECTORS) > 0, "manifest-export.json has no export-kind vectors"


@pytest.mark.skipif(not _VECTORS, reason="no export vectors in conformance manifest")
@pytest.mark.parametrize("vector", _VECTORS, ids=[_vector_id(v) for v in _VECTORS])
def test_conformance_vector(vector: dict[str, Any]) -> None:
    code = vector.get("failureCode")
    if code in _DUMP_ONLY_CODES:
        pytest.skip(f"{code} is a dump-only check; the Python verifier is per-record/export only")

    options = vector.get("options") or {}
    kwargs: dict[str, Any] = {}
    keys_file = options.get("keysFile")
    if keys_file:
        kwargs["public_keys"] = json.loads((_CONFORMANCE_DIR / keys_file).read_text())
    if options.get("requireKeyId"):
        kwargs["require_key_id"] = options["requireKeyId"]
    if options.get("requireOutOfBandKeys"):
        kwargs["require_out_of_band_keys"] = True

    export_data = json.loads((_CONFORMANCE_DIR / vector["file"]).read_text())
    result = verify_export(export_data, **kwargs)

    expect_pass = vector["expect"] == "pass"
    assert result.valid is expect_pass, (
        f"{vector['file']}: expected valid={expect_pass}, got {result.valid} "
        f"(broken_at={result.broken_at})"
    )

    if not expect_pass:
        assert result.broken_at is not None, f"{vector['file']}: fail vector has no broken_at"
        assert result.broken_at.code == code, (
            f"{vector['file']}: expected code {code}, got {result.broken_at.code}"
        )
        if "brokenAt" in vector:
            assert result.broken_at.position == vector["brokenAt"], (
                f"{vector['file']}: expected position {vector['brokenAt']}, "
                f"got {result.broken_at.position}"
            )

    expected_cov = vector.get("expectSignatureCoverage")
    if expected_cov is not None:
        cov = result.signature_coverage
        assert cov.signed == expected_cov["signed"], f"{vector['file']}: signed coverage mismatch"
        assert cov.unsigned == expected_cov["unsigned"], f"{vector['file']}: unsigned coverage mismatch"
        assert cov.skipped == expected_cov["skipped"], f"{vector['file']}: skipped coverage mismatch"


# --- DUMP-kind conformance vectors (manifest-dump.json) ---
# The full-vault dump verifier (agledger.verify.verify_dump) replays the SAME
# corpus as the TS @agledger/verify dump verifier. Assertion style mirrors
# packages/verify/test/corpus.test.ts: a pass vector must verify clean; a fail
# vector must NOT verify clean AND its canonical failureCode must appear in the
# flattened failure list (vault + org_admin_reads).


def _dump_vectors() -> list[dict[str, Any]]:
    if not _DUMP_MANIFEST.exists():
        return []
    manifest = json.loads(_DUMP_MANIFEST.read_text())
    return [v for v in manifest.get("vectors", []) if v.get("kind") == "dump"]


def _dump_vector_id(vector: dict[str, Any]) -> str:
    label = vector["file"].split("/")[-1]
    return f"{label}:{vector.get('failureCode') or vector['expect']}"


_DUMP_VECTORS = _dump_vectors()


@pytest.mark.skipif(
    not _DUMP_MANIFEST.exists(), reason=f"dump conformance manifest not found at {_DUMP_MANIFEST}"
)
def test_dump_manifest_present_and_nonempty() -> None:
    """Guard: the dump corpus must exist and carry the full required code set, so
    a silently empty corpus can't let drift slip through parametrize."""
    manifest = json.loads(_DUMP_MANIFEST.read_text())
    assert manifest.get("formatVersion") == "2.0"
    assert len(_DUMP_VECTORS) > 0, "manifest-dump.json has no dump-kind vectors"
    codes = {v.get("failureCode") for v in _DUMP_VECTORS if v.get("failureCode")}
    for required in (
        "CHAIN_EMPTY",
        "CHECKPOINT_ROW_MISSING",
        "CHECKPOINT_HASH_MISMATCH",
        "CHAIN_PAYLOAD_BINDING_MISMATCH",
        "CHAIN_OIDC_ACTOR_MISMATCH",
        "CHAIN_KEY_EXPIRED",
        "TENANT_CHECKPOINT_ROOT_MISMATCH",
        "TENANT_CHECKPOINT_FORK",
    ):
        assert required in codes, f"missing required dump vector for {required}"
    assert any(v["expect"] == "pass" for v in _DUMP_VECTORS)


@pytest.mark.skipif(not _DUMP_VECTORS, reason="no dump vectors in conformance manifest")
@pytest.mark.parametrize("vector", _DUMP_VECTORS, ids=[_dump_vector_id(v) for v in _DUMP_VECTORS])
def test_dump_conformance_vector(vector: dict[str, Any]) -> None:
    report = verify_dump(load_dump(str(_CONFORMANCE_DIR / vector["file"])))
    all_failures = report.vault.failures + report.org_admin_reads.failures
    codes = [f.code for f in all_failures]

    if vector["expect"] == "pass":
        assert report.ok, f"{vector['file']}: expected pass but got failures {codes}"
        return

    assert not report.ok, f"{vector['file']}: expected fail but verified clean"
    assert vector["failureCode"] in codes, (
        f"{vector['file']}: expected {vector['failureCode']} in {codes}"
    )
