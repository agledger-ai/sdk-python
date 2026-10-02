"""What a caller reads off a verification, held to what ``@agledger/verify`` and
``@agledger/verify-core`` give: the one-word verdict, the key list as the
Server serves it, a pin that is also distrusted refused, the closure finding
the engine's scan reports, and the ``-f json`` fields the npm verifier prints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agledger.types import VerificationKeysResponse
from agledger.verify import load_dump, spki_sha256, verify_dump, verify_export
from agledger.verify.cli import run_cli

_CORPUS = Path(__file__).resolve().parents[1] / "testdata" / "conformance"


def _export(name: str) -> dict[str, Any]:
    return json.loads((_CORPUS / "export" / name).read_text())


def _pin(name: str) -> str:
    return _export(name)["exportMetadata"]["anchoredFrom"]


def test_verdict_is_unanchored_without_a_pin_trusted_pinned_and_failed_on_a_broken_chain() -> None:
    assert verify_export(_export("valid.json")).verdict == "unanchored"
    assert verify_export(_export("valid.json"), trust_anchors=[_pin("valid.json")]).verdict == "trusted"
    assert verify_export(_export("hash-mismatch.json")).verdict == "failed"
    unsigned = verify_export(_export("unsigned.json"), trust_anchors=[f"sha256:{'ab' * 32}"])
    assert (unsigned.valid, unsigned.verdict) == (True, "unanchored")


def test_the_1x_option_name_is_refused_rather_than_ignored() -> None:
    with pytest.raises(TypeError, match="require_out_of_band_keys"):
        verify_export(_export("valid.json"), require_out_of_band_keys=True)  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]


def test_public_keys_takes_the_verification_keys_body_as_served_and_as_the_typed_response() -> None:
    exp = _export("valid.json")
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    data = [{"keyId": key_id, "publicKey": exp["exportMetadata"]["signingPublicKeys"][key_id]}]
    plain = verify_export(_export("valid.json"), public_keys=data, require_supplied_keys=True)
    assert plain.key_provenance.supplied > 0
    for wrapped in (
        {"data": data, "anchoredFrom": None},
        VerificationKeysResponse.model_construct(data=data),
    ):
        r = verify_export(_export("valid.json"), public_keys=wrapped, require_supplied_keys=True)
        assert (r.verdict, r.key_provenance.supplied) == (plain.verdict, plain.key_provenance.supplied)


def test_a_key_both_pinned_and_distrusted_is_refused_on_both_paths() -> None:
    pin = _pin("valid.json")
    with pytest.raises(TypeError, match="both a trust anchor and a distrusted key"):
        verify_export(_export("valid.json"), trust_anchors=[pin], distrusted_keys=[pin])
    dump = load_dump(_CORPUS / "dump" / "valid")
    dpin = f"sha256:{spki_sha256(dump.signing_keys[0]['public_key'])}"
    with pytest.raises(TypeError, match="both a trust anchor and a distrusted key"):
        verify_dump(dump, trust_anchors=[dpin], distrusted_keys=[f"{dpin}@2026-09-01T00:00:00Z"])


def test_pinned_on_the_genesis_key_the_closure_its_unanchored_successor_signed_is_key_closure_invalid() -> None:
    # As the engine's scan grades it: the successor is reached but not anchored
    # from the genesis pin, and no key surface publishes it.
    d = load_dump(_CORPUS / "dump" / "valid-key-succession")
    previous = next(k for k in d.signing_keys if k["status"] == "retired")
    current = next(k for k in d.signing_keys if k["status"] == "active")
    report = verify_dump(d, trust_anchors=[f"sha256:{spki_sha256(previous['public_key'])}"])
    assert report.verdict == "failed"
    assert current["key_id"] in report.key_trust.unanchored_key_ids
    closure = next(st for st in d.key_statements if st["kind"] == "closure")
    assert [(f.code, f.key_id, f.statement_id) for f in report.key_trust.findings] == [
        ("KEY_CLOSURE_INVALID", previous["key_id"], closure["id"])
    ]
    assert f"{current['key_id']}, which is reached but not anchored" in report.key_trust.findings[0].detail


def test_json_on_an_export_lists_entries_as_the_npm_verifier_does(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli([str(_CORPUS / "export" / "hash-mismatch.json"), "-f", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "failed"
    assert out["entries"][0] == {"position": 1, "valid": True, "signature": "ok"}
    assert out["entries"][1]["code"] == "CHAIN_HASH_MISMATCH"
    assert out["entries"][1]["signature"] == "not-checked"


def test_json_on_a_dump_carries_failure_counts(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli([str(_CORPUS / "dump" / "valid"), "-f", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["vault"]["failureCount"] == 0
    assert out["orgAdminReads"]["failureCount"] == 0
    assert run_cli([str(_CORPUS / "dump" / "checkpoint-hash-mismatch"), "-f", "json"]) == 1
    failed = json.loads(capsys.readouterr().out)
    assert failed["vault"]["failureCount"] == len(failed["vault"]["failures"]) > 0
