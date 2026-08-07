"""Tests for the offline audit export verifier (format 2.0, COSE_Sign1).

Codes asserted here are the canonical SCREAMING_SNAKE ``FailureCode`` strings
shared with the TS verification core (``@agledger/verify-core``). The
cross-language byte-for-byte agreement is exercised separately by
``test_conformance.py`` over the shared corpus.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import cbor2
import pytest

from agledger.verify import verify_export


def _make_keypair() -> tuple[str, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    private = Ed25519PrivateKey.generate()
    der = private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode(), private


def _build_protected_header(position: int, previous_hash: str | None) -> bytes:
    """CBOR-encode a minimal protected header: the alg (label 1, EdDSA) plus
    the chain claim. The alg is load-bearing since the verifier floor: the
    engine always writes it, and a missing or foreign alg is a tamper-class
    failure (dispatch binds to the trusted key; the header is asserted equal).
    """
    chain_map: dict[int, Any] = {1: position, 2: None if previous_hash is None else bytes.fromhex(previous_hash)}
    header: dict[int, Any] = {1: -8, -65537: chain_map}
    return cbor2.dumps(header, canonical=True)


def _build_cose_sign1(
    private_key: Any,
    position: int,
    previous_hash: str | None,
    payload: dict[str, Any],
) -> bytes:
    """Build a tagged COSE_Sign1 envelope mirroring the engine encoder."""
    protected_bstr = _build_protected_header(position, previous_hash)
    payload_bstr = cbor2.dumps(payload, canonical=True)
    sig_structure = ["Signature1", protected_bstr, b"", payload_bstr]
    to_be_signed = cbor2.dumps(sig_structure, canonical=True)
    signature = private_key.sign(to_be_signed)
    envelope = [protected_bstr, {}, payload_bstr, signature]
    # Tagged COSE_Sign1: cbor2 supports CBORTag wrapper directly
    return cbor2.dumps(cbor2.CBORTag(18, envelope), canonical=True)


_ENTRY_TYPE = "RECORD_STATE_CHANGE"


def _build_entry(
    private_key: Any,
    key_id: str,
    position: int,
    previous_hash: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    # Sign a faithful in-toto v1 Statement: the engine signs ``{predicate: ...}``
    # where the predicate is the canonical row projection (record_id, entry_type,
    # payload). The binding check (F-731) re-derives exactly this from the row, so
    # the synthetic envelope must carry it too.
    record_id = payload.get("recordId") if isinstance(payload.get("recordId"), str) else "REC-test-001"
    predicate = {"record_id": record_id, "entry_type": _ENTRY_TYPE, "payload": payload}
    envelope = _build_cose_sign1(private_key, position, previous_hash, {"predicate": predicate})
    payload_hash = hashlib.sha256(envelope).hexdigest()
    return {
        # Current exports are chainPosition-only — no legacy `position` (F-682).
        "chainPosition": position,
        "timestamp": "2026-04-17T00:00:00Z",
        "createdAt": "2026-04-17T00:00:00Z",
        "recordId": record_id,
        "entryType": _ENTRY_TYPE,
        "payload": payload,
        "integrity": {
            "payloadHash": payload_hash,
            "previousHash": previous_hash,
            "coseSign1": base64.b64encode(envelope).decode(),
            "signingKeyId": key_id,
            "valid": True,
        },
    }


def _make_export(public_key_b64: str, private_key: Any, key_id: str = "vault-key-1") -> dict[str, Any]:
    record_id = "REC-test-001"
    e1 = _build_entry(private_key, key_id, 1, None, {"event": "created", "recordId": record_id})
    e2 = _build_entry(
        private_key, key_id, 2,
        e1["integrity"]["payloadHash"],
        {"event": "activated", "recordId": record_id},
    )
    e3 = _build_entry(
        private_key, key_id, 3,
        e2["integrity"]["payloadHash"],
        {"event": "completion_submitted", "recordId": record_id, "count": 100},
    )
    return {
        "exportMetadata": {
            "recordId": record_id,
            "orgId": "org-001",
            "type": "notarize-generic-v1",
            "exportDate": "2026-04-17T00:00:00Z",
            "totalEntries": 3,
            "chainIntegrity": True,
            "exportFormatVersion": "2.0",
            "canonicalization": "RFC8949-CDE",
            "signingPublicKey": public_key_b64,
            "signingPublicKeys": {key_id: public_key_b64},
        },
        "entries": [e1, e2, e3],
    }


def test_valid_export_verifies() -> None:
    pub, priv = _make_keypair()
    result = verify_export(_make_export(pub, priv))
    assert result.valid is True
    assert result.verified_entries == 3
    assert result.broken_at is None
    assert result.signature_coverage.signed == 3
    # Embedded keys (no out-of-band override) — provenance reflects the trust source.
    assert result.key_provenance.embedded == 3
    assert result.key_provenance.out_of_band == 0


def test_rejects_unsupported_format_version() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["exportMetadata"]["exportFormatVersion"] = "1.0"
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "UNSUPPORTED_FORMAT"


def test_rejects_unsupported_canonicalization() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["exportMetadata"]["canonicalization"] = "RFC8785"
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "UNSUPPORTED_FORMAT"


def test_rejects_empty_chain() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"] = []
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_EMPTY"


def test_detects_link_broken() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["integrity"]["previousHash"] = "f" * 64
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.position == 2
    assert result.broken_at.code == "CHAIN_LINK_BROKEN"


def test_detects_genesis_invalid() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][0]["integrity"]["previousHash"] = "f" * 64
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.position == 1
    assert result.broken_at.code == "CHAIN_GENESIS_INVALID"


def test_detects_position_gap() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["chainPosition"] = 5
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_POSITION_GAP"
    # Entries are sorted by position before the walk: [1, 3, 5]. At expected
    # position 2 the walk meets the position-3 entry and reports that.
    assert result.broken_at.position == 3


def test_verifies_legacy_position_export() -> None:
    """Pre-v0.25 exports used `position` instead of `chainPosition` (F-682 back-compat)."""
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    for e in exp["entries"]:
        e["position"] = e.pop("chainPosition")
    result = verify_export(exp)
    assert result.valid is True
    assert result.verified_entries == 3


def test_detects_hash_mismatch() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    raw = bytearray(base64.b64decode(exp["entries"][1]["integrity"]["coseSign1"]))
    raw[10] ^= 0x01
    exp["entries"][1]["integrity"]["coseSign1"] = base64.b64encode(bytes(raw)).decode()
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.position == 2
    assert result.broken_at.code == "CHAIN_HASH_MISMATCH"


def test_detects_signature_invalid() -> None:
    # Re-sign with an attacker key but keep declared signingKeyId.
    pub, priv = _make_keypair()
    _, attacker_priv = _make_keypair()
    exp = _make_export(pub, priv)
    # Re-sign over the SAME predicate the row projects to, so binding-integrity
    # passes and the signature check is what rejects it (a payload change would
    # trip CHAIN_PAYLOAD_BINDING_MISMATCH first).
    pred2 = {
        "record_id": exp["entries"][1]["recordId"],
        "entry_type": _ENTRY_TYPE,
        "payload": exp["entries"][1]["payload"],
    }
    fake_envelope = _build_cose_sign1(
        attacker_priv, 2, exp["entries"][0]["integrity"]["payloadHash"],
        {"predicate": pred2},
    )
    exp["entries"][1]["integrity"]["coseSign1"] = base64.b64encode(fake_envelope).decode()
    exp["entries"][1]["integrity"]["payloadHash"] = hashlib.sha256(fake_envelope).hexdigest()
    # Re-link entry 3 to entry 2's new hash, also signed by attacker so we
    # surface CHAIN_SIGNATURE_INVALID at position 2 first.
    pred3 = {
        "record_id": exp["entries"][2]["recordId"],
        "entry_type": _ENTRY_TYPE,
        "payload": exp["entries"][2]["payload"],
    }
    fake_envelope_3 = _build_cose_sign1(
        attacker_priv, 3, exp["entries"][1]["integrity"]["payloadHash"],
        {"predicate": pred3},
    )
    exp["entries"][2]["integrity"]["coseSign1"] = base64.b64encode(fake_envelope_3).decode()
    exp["entries"][2]["integrity"]["payloadHash"] = hashlib.sha256(fake_envelope_3).hexdigest()
    exp["entries"][2]["integrity"]["previousHash"] = exp["entries"][1]["integrity"]["payloadHash"]
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.position == 2
    assert result.broken_at.code == "CHAIN_SIGNATURE_INVALID"


def test_detects_payload_binding_mismatch() -> None:
    # F-731: the attacker rewrites the human-readable row payload but leaves
    # coseSign1 (the signed truth) intact — the offline verifier must catch the
    # drift between the decoded predicate and the row projection.
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["payload"]["event"] = "FORGED"
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.position == 2
    assert result.broken_at.code == "CHAIN_PAYLOAD_BINDING_MISMATCH"
    # The signature is never reached once binding fails upstream.
    assert result.entries[1].signature == "not-checked"


def test_signature_missing_key_when_signing_key_absent() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["integrity"]["signingKeyId"] = "ghost-key"
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_SIGNATURE_MISSING_KEY"


def test_empty_string_signing_key_id_is_not_the_unsigned_marker() -> None:
    # Only None is the engine's unsigned-mode marker. A tampered row carrying
    # signingKeyId:"" must not ride the null-key skip branch to a green chain.
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["integrity"]["signingKeyId"] = ""
    result = verify_export(exp)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_SIGNATURE_MISSING_KEY"
    assert result.signature_coverage.skipped == 0


def test_unsigned_entry_keeps_chain_integrity() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["integrity"]["signingKeyId"] = None
    result = verify_export(exp)
    assert result.valid is True
    assert result.signature_coverage.skipped == 1


def test_require_key_id_policy_violation() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    result = verify_export(exp, require_key_id="a-different-key")
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_KEY_POLICY_VIOLATION"


def test_require_out_of_band_keys_rejects_embedded() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    # Only embedded keys present; high-assurance mode refuses them.
    result = verify_export(exp, require_out_of_band_keys=True)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_KEY_POLICY_VIOLATION"
    assert result.broken_at.position == 1


def test_out_of_band_keys_override_embedded_and_pass_policy() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    # Supplying the same key out of band satisfies require_out_of_band_keys.
    result = verify_export(exp, public_keys={"vault-key-1": pub}, require_out_of_band_keys=True)
    assert result.valid is True
    assert result.key_provenance.out_of_band == 3
    assert result.key_provenance.embedded == 0


def test_public_keys_can_be_supplied_at_call_time() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["exportMetadata"]["signingPublicKeys"] = None
    exp["exportMetadata"]["signingPublicKey"] = None
    result = verify_export(exp, public_keys={"vault-key-1": pub})
    assert result.valid is True
    assert result.key_provenance.out_of_band == 3


def test_null_key_entry_fails_closed_under_key_policy() -> None:
    # A null-signingKeyId entry is a legitimate hash-chain-only row WITHOUT a
    # key policy, but a high-assurance run must reject it (parity with TS).
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    exp["entries"][1]["integrity"]["signingKeyId"] = None

    no_policy = verify_export(exp, public_keys={"vault-key-1": pub})
    assert no_policy.valid is True
    assert no_policy.signature_coverage.skipped == 1

    require_id = verify_export(exp, public_keys={"vault-key-1": pub}, require_key_id="vault-key-1")
    assert require_id.valid is False
    assert require_id.broken_at is not None
    assert require_id.broken_at.code == "CHAIN_KEY_POLICY_VIOLATION"
    assert require_id.broken_at.position == 2

    require_oob = verify_export(
        exp, public_keys={"vault-key-1": pub}, require_out_of_band_keys=True
    )
    assert require_oob.valid is False
    assert require_oob.broken_at is not None
    assert require_oob.broken_at.code == "CHAIN_KEY_POLICY_VIOLATION"


# F-698 regression: public_keys polymorphic acceptance + TypeError on bad shape.
# Mirrors packages/verify-core/src/__tests__/oob-key-shapes.test.ts.

def test_oob_keys_accepts_compact_record_form() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    result = verify_export(exp, public_keys={"vault-key-1": pub})
    assert result.valid is True
    assert result.key_provenance.out_of_band > 0
    assert result.key_provenance.embedded == 0


def test_oob_keys_accepts_sdk_natural_list_shape() -> None:
    """The .data list from `client.verification_keys.list()` is the natural
    customer shape — must be accepted directly, not silently fall through to
    embedded keys (F-698)."""
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    keys_list = [{"keyId": "vault-key-1", "publicKey": pub, "algorithm": "Ed25519"}]
    result = verify_export(exp, public_keys=keys_list)
    assert result.valid is True
    assert result.key_provenance.out_of_band > 0
    assert result.key_provenance.embedded == 0


def test_oob_keys_accepts_pydantic_models() -> None:
    """Customers may pass `client.verification_keys.list().data` — list of
    VerificationKey pydantic models — directly. The polymorphic normalizer
    handles either attribute (`key_id`/`public_key`) or alias (`keyId`/`publicKey`)
    access."""
    from agledger.types import VerificationKey

    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    models = [
        VerificationKey.model_validate({
            "keyId": "vault-key-1",
            "algorithm": "Ed25519",
            "publicKey": pub,
            "publicKeyRaw": pub,
            "status": "active",
            "activatedAt": "2026-01-01T00:00:00Z",
            "retiredAt": None,
        })
    ]
    result = verify_export(exp, public_keys=models)
    assert result.valid is True
    assert result.key_provenance.out_of_band > 0


def test_oob_keys_raises_typeerror_on_missing_fields() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    with pytest.raises(TypeError):
        verify_export(exp, public_keys=[{"publicKey": pub}])  # missing keyId
    with pytest.raises(TypeError):
        verify_export(exp, public_keys=[{"keyId": "vault-key-1"}])  # missing publicKey


def test_oob_keys_raises_typeerror_on_non_string_value() -> None:
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    with pytest.raises(TypeError):
        verify_export(exp, public_keys={"vault-key-1": 12345})  # type: ignore[dict-item]


def test_oob_keys_raises_typeerror_on_string_argument() -> None:
    """A bare string is the most-common malformed shape (e.g. passing the
    base64 key directly). It must fail loudly, not be parsed as a sequence
    of characters."""
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    with pytest.raises(TypeError):
        verify_export(exp, public_keys=pub)  # type: ignore[arg-type]


def test_oob_keys_empty_camelcase_does_not_silently_fall_back_to_snake() -> None:
    """`keyId=""` is a structural error (empty-string keyId is not a valid
    identifier), not a signal to substitute `key_id`. The dual-spelling
    fallback must use presence-not-truthiness, otherwise an upstream serializer
    bug that defaults keyId to '' would be silently masked by a stale snake_case
    sibling."""
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    # Both camelCase and snake_case present, camelCase empty. Old (or) would
    # silently substitute "real-key" from key_id. Correct behavior: TypeError
    # because the explicit keyId is invalid.
    bad = [{"keyId": "", "key_id": "real-key", "publicKey": pub}]
    with pytest.raises(TypeError):
        verify_export(exp, public_keys=bad)


def test_oob_keys_empty_publickey_rejected_with_accurate_diagnostic() -> None:
    """`publicKey=""` must fail loudly — empty strings are structural errors
    at the OOB-key boundary, not a signal to look elsewhere."""
    pub, priv = _make_keypair()
    exp = _make_export(pub, priv)
    bad = [{"keyId": "k1", "publicKey": ""}]
    with pytest.raises(TypeError) as excinfo:
        verify_export(exp, public_keys=bad)
    # Diagnostic must reference the empty field, not lie about it being None.
    assert "empty-string" in str(excinfo.value)


# --- temporal key-window direction split (agents#112) ------------------------
#
# Both directions used to report CHAIN_KEY_EXPIRED, so a consumer branching on
# the code investigated rotation when the real condition was a backdated entry
# or clock skew. The activation side is the security-relevant one.

def test_temporal_split_predates_activation_is_not_yet_active() -> None:
    from agledger.verify.verify_export import _temporal_key_failure

    result = _temporal_key_failure(
        "2026-08-07T06:57:13.022Z", "285ae6b39145b0f4", "2026-08-07T06:58:30.000Z", None
    )
    assert result is not None
    code, detail = result
    assert code == "CHAIN_KEY_NOT_YET_ACTIVE"
    assert "predates key" in detail


def test_temporal_split_postdates_retirement_is_expired() -> None:
    from agledger.verify.verify_export import _temporal_key_failure

    result = _temporal_key_failure(
        "2026-08-07T06:57:13.022Z", "285ae6b39145b0f4", None, "2026-01-01T00:00:00.000Z"
    )
    assert result is not None
    code, detail = result
    assert code == "CHAIN_KEY_EXPIRED"
    assert "postdates key" in detail


def test_temporal_split_inside_window_passes() -> None:
    from agledger.verify.verify_export import _temporal_key_failure

    assert (
        _temporal_key_failure(
            "2026-06-01T00:00:00.000Z",
            "k",
            "2026-01-01T00:00:00.000Z",
            "2026-12-01T00:00:00.000Z",
        )
        is None
    )


def test_new_code_is_registered_with_an_explanation() -> None:
    from agledger.verify.failures import suggestion

    text = suggestion("CHAIN_KEY_NOT_YET_ACTIVE")
    assert "BEFORE" in text
    assert "clock skew" in text
    # The retirement side must stop claiming it also covers "not-yet-active".
    assert "not-yet-active" not in suggestion("CHAIN_KEY_EXPIRED")


def test_suggestion_text_mirrors_the_typescript_verifier_core_verbatim() -> None:
    """The two taxonomies are a mirror, and the module docstring says so.

    An auditor must read the same remediation sentence whether the chain was
    checked by this SDK or by ``@agledger/verify-core``. Nothing enforced that,
    so the two drifted the moment either side edited a string: a 2026-08-07
    punctuation pass on the TypeScript side left six codes saying different
    things in the two languages. Skipped when the sibling checkout is absent
    (it is a separate repo), so CI on a lone clone stays green.
    """
    import re
    from pathlib import Path

    from agledger.verify.failures import _SUGGESTIONS as FAILURE_SUGGESTIONS

    ts_path = Path.home() / "projects" / "agledger-verify-core" / "src" / "failures.ts"
    if not ts_path.exists():
        pytest.skip(f"verify-core checkout not present at {ts_path}")

    ts = ts_path.read_text()
    block = ts[ts.index("const SUGGESTIONS") : ts.index("/** The actionable next step")]
    ts_map = {
        m.group(1): m.group(2).replace("\\'", "'")
        for m in re.finditer(r"(\w+):\s*\n?\s*'((?:[^'\\]|\\.)*)'", block)
    }

    assert set(ts_map) == set(FAILURE_SUGGESTIONS), (
        "failure-code sets diverged: "
        f"only in TS {sorted(set(ts_map) - set(FAILURE_SUGGESTIONS))}, "
        f"only in Python {sorted(set(FAILURE_SUGGESTIONS) - set(ts_map))}"
    )
    mismatched = [c for c in ts_map if ts_map[c].strip() != FAILURE_SUGGESTIONS[c].strip()]
    assert not mismatched, f"suggestion text drifted for: {mismatched}"
