"""verify_export against @agledger/verify-core's verifyAuditExport, field for
field, on every corpus export vector unpinned and pinned on the export's own
anchoredFrom: validity, every entry's position, code, detail and signature
state, the broken-at entry, signature coverage, key provenance, the optional
checks, the agent-signature counts and the whole key-trust report.

The verify-core results in ``fixtures/verify-core-exports.json`` were recorded
by ``scripts/record-verify-core-exports.mjs`` from the verify-core build the
fixture names; re-record them when verify-core's export walk changes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import VerifyExportResult, verify_export

CONFORMANCE = Path(__file__).resolve().parent.parent / "testdata" / "conformance"
_RECORDED: dict[str, Any] = json.loads((Path(__file__).parent / "fixtures" / "verify-core-exports.json").read_text())


def _json(rel: str) -> Any:
    return json.loads((CONFORMANCE / rel).read_text())


def _project(r: VerifyExportResult) -> dict[str, Any]:
    """The result in verify-core's shape, the fields the fixture records."""
    trust = r.key_trust.to_json()
    return {
        "valid": r.valid,
        "totalEntries": r.total_entries,
        "verifiedEntries": r.verified_entries,
        "brokenAt": (
            {"position": r.broken_at.position, "code": r.broken_at.code, "detail": r.broken_at.detail}
            if r.broken_at is not None
            else None
        ),
        "entries": [
            {"position": e.position, "valid": e.valid, "code": e.code, "detail": e.detail, "signature": e.signature}
            for e in r.entries
        ],
        "signatureCoverage": {
            "signed": r.signature_coverage.signed,
            "unsigned": r.signature_coverage.unsigned,
            "skipped": r.signature_coverage.skipped,
            "total": r.signature_coverage.total,
        },
        "keyProvenance": {"supplied": r.key_provenance.supplied, "embedded": r.key_provenance.embedded},
        "optionalChecks": dict(r.optional_checks),
        "agentSignatures": {"present": r.agent_signatures.present, "verified": r.agent_signatures.verified},
        "keyTrust": trust,
    }


def test_the_fixture_covers_every_corpus_export_vector_both_ways() -> None:
    files = {v["file"] for v in _json("manifest-export.json")["vectors"]}
    assert {run["file"] for run in _RECORDED["runs"].values()} == files
    assert sum(1 for run in _RECORDED["runs"].values() if run["trustAnchors"]) >= 20


@pytest.mark.parametrize("run_id", sorted(_RECORDED["runs"]))
def test_verify_export_gives_verify_core_s_result_field_for_field(run_id: str) -> None:
    run = _RECORDED["runs"][run_id]
    options = run["options"]
    kwargs: dict[str, Any] = {}
    if "keysFile" in options:
        keys = _json(options["keysFile"])
        kwargs["public_keys"] = keys["data"] if isinstance(keys, dict) and isinstance(keys.get("data"), list) else keys
    if "agentKeysFile" in options:
        kwargs["agent_keys"] = _json(options["agentKeysFile"])
    if "requireKeyId" in options:
        kwargs["require_key_id"] = options["requireKeyId"]
    if options.get("requireOutOfBandKeys"):
        kwargs["require_supplied_keys"] = True
    result = verify_export(_json(run["file"]), trust_anchors=run["trustAnchors"], **kwargs)
    assert _project(result) == run["result"]
