"""Offline agent-signature re-check, and the 1.8.0 chain content it runs on.

The Python mirror of verify-core's ``agent-signature.test.ts``. The fixtures
under ``fixtures/live-1.8.0/`` are unmodified ``/audit-export`` responses from a
live API 1.8.0 instance, shared with that suite: a record walked through its
whole lifecycle on an API key (entries carry the internal ``state`` /
``previousState`` / ``newState`` beside the display status), the same walk on
an ephemeral cert with every write agent-signed, and a bound and an unbound
delegated create. ``agent-cert-key.json`` is the Ed25519 JWK the agent sent at
cert exchange. The synthetic cases cover what a live engine will not produce: a
sealed agent signature that does not verify.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agledger.verify import (
    AGENT_SIGNATURE_CONTEXT,
    ed25519_jwk_thumbprint,
    verify_export,
)

LIVE = Path(__file__).parent / "fixtures" / "live-1.8.0"


def _load(name: str) -> dict[str, Any]:
    return json.loads((LIVE / name).read_text())


AGENT_CERT = _load("agent-cert-key.json")
AGENT_JWK = AGENT_CERT["publicKeyJwk"]


def _jwk_of(key: Ed25519PrivateKey) -> dict[str, str]:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}


# --- 1.8.0 chain content ---


def test_a_lifecycle_signed_in_both_state_vocabularies_verifies():
    doc = _load("export-lifecycle.json")
    # The fixture must actually carry the new keys, or this proves nothing.
    register_hop = doc["entries"][1]["payload"]
    assert register_hop["previousState"] == "DRAFT"
    assert register_hop["newState"] == "REGISTERED"
    assert register_hop["previousStatus"] == "CREATED"
    assert doc["entries"][0]["payload"]["state"] == "DRAFT"

    result = verify_export(doc)
    assert result.valid
    assert result.verified_entries == 9
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (0, 0)
    assert result.agent_signature_check == "skipped_no_input"


def test_a_rewritten_internal_state_is_a_binding_mismatch():
    doc = _load("export-lifecycle.json")
    doc["entries"][1]["payload"]["previousState"] = "REGISTERED"
    result = verify_export(doc)
    assert not result.valid
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (2, "CHAIN_PAYLOAD_BINDING_MISMATCH")


# --- live exports ---


def test_the_thumbprint_matches_the_one_the_engine_recorded():
    assert ed25519_jwk_thumbprint(AGENT_JWK) == AGENT_CERT["publicKeyThumbprint"]


def test_without_agent_keys_sealed_signatures_are_counted_and_reported_unchecked():
    result = verify_export(_load("export-cert-lifecycle.json"))
    assert result.valid
    assert result.agent_signatures.present > 0
    assert result.agent_signatures.verified == 0
    assert result.agent_signature_check == "skipped_no_input"


def test_with_the_cert_key_every_sealed_signature_on_a_cert_signed_lifecycle_verifies():
    result = verify_export(_load("export-cert-lifecycle.json"), agent_keys=[AGENT_JWK])
    assert result.valid
    assert result.agent_signature_check == "applied"
    # Every entry written by a signed request carries one: the create and its
    # two autoActivate hops, the completion, and the verdict's outcome and
    # settlement. The three gate entries are written by the worker.
    assert result.agent_signatures.present == 6
    assert result.agent_signatures.verified == 6


def test_a_bound_delegated_create_carries_the_caller_cert_signature_and_it_verifies():
    result = verify_export(_load("export-delegated-bound.json"), agent_keys=[AGENT_JWK])
    assert result.valid
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (1, 1)


def test_an_unbound_delegated_create_on_an_api_key_carries_no_agent_signature():
    result = verify_export(_load("export-delegated-unbound.json"), agent_keys=[AGENT_JWK])
    assert result.valid
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (0, 0)
    assert result.agent_signature_check == "skipped_no_input"


def test_a_key_for_a_different_cert_matches_nothing():
    result = verify_export(
        _load("export-cert-lifecycle.json"), agent_keys=[_jwk_of(Ed25519PrivateKey.generate())]
    )
    assert result.valid
    assert result.agent_signatures.verified == 0
    assert result.agent_signature_check == "skipped_no_input"


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "RSA", "n": "x", "e": "AQAB"},
        {"kty": "OKP", "crv": "X25519", "x": AGENT_JWK["x"]},
        {"kty": "OKP", "crv": "Ed25519", "x": "dG9vLXNob3J0"},
        None,
    ],
)
def test_anything_but_an_ed25519_jwk_is_refused_at_the_boundary(jwk: Any):
    with pytest.raises(TypeError):
        verify_export(_load("export-cert-lifecycle.json"), agent_keys=[jwk])


def test_agent_keys_must_be_a_list():
    with pytest.raises(TypeError):
        verify_export(_load("export-cert-lifecycle.json"), agent_keys="nope")  # type: ignore[arg-type]


# --- synthetic entries: a sealed agent signature that does not verify ---

KEY_ID = "aabbccddeeff0011"
VAULT = Ed25519PrivateKey.generate()
AGENT = Ed25519PrivateKey.generate()
IMPOSTOR = Ed25519PrivateKey.generate()
AGENT_THUMBPRINT = ed25519_jwk_thumbprint(_jwk_of(AGENT))
CONTENT_HEX = hashlib.sha256(b'{"type":"t","criteria":{}}').hexdigest()


def _agent_sign(key: Ed25519PrivateKey, content_hex: str) -> str:
    return base64.b64encode(key.sign(f"{AGENT_SIGNATURE_CONTEXT}{content_hex}".encode())).decode()


def _export_with(on_behalf_of: dict[str, Any]) -> dict[str, Any]:
    protected = cbor2.dumps({1: -8, 4: bytes.fromhex(KEY_ID), -65537: {1: 1, 2: None}}, canonical=True)
    payload = cbor2.dumps(
        {"predicate": {"record_id": "r", "entry_type": "RECORD_CREATED", "on_behalf_of": on_behalf_of}},
        canonical=True,
    )
    signature = VAULT.sign(cbor2.dumps(["Signature1", protected, b"", payload], canonical=True))
    envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]), canonical=True)
    spki = VAULT.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {
        "exportMetadata": {
            "recordId": "agent-sig-test", "exportFormatVersion": "2.0", "canonicalization": "RFC8949-CDE",
        },
        "entries": [{
            "chainPosition": 1,
            "integrity": {
                "payloadHash": hashlib.sha256(envelope).hexdigest(),
                "previousHash": None,
                "coseSign1": base64.b64encode(envelope).decode(),
                "signingKeyId": KEY_ID,
            },
        }],
        "_vault_key": base64.b64encode(spki).decode(),
    }


def _sealed(*, validated: bool = True, signature: dict[str, Any] | None = None) -> dict[str, Any]:
    return _export_with({
        "validated": validated,
        "cert": {"id": "00000000-0000-4000-8000-000000000001", "thumbprint": AGENT_THUMBPRINT, "expires_at": 1},
        "agent_signature": signature or {
            "alg": "EdDSA",
            "content_hash": f"sha256:{CONTENT_HEX}",
            "signature": _agent_sign(AGENT, CONTENT_HEX),
        },
    })


def _verify(doc: dict[str, Any], *, agent_keys: list[dict[str, str]] | None = None):
    vault_key = doc.pop("_vault_key")
    return verify_export(doc, public_keys={KEY_ID: vault_key}, agent_keys=agent_keys)


def test_an_unpadded_standard_base64_signature_verifies():
    # The Server accepts the signature with or without its '==' padding.
    unpadded = _agent_sign(AGENT, CONTENT_HEX).rstrip("=")
    doc = _sealed(signature={"alg": "EdDSA", "content_hash": f"sha256:{CONTENT_HEX}", "signature": unpadded})
    result = _verify(doc, agent_keys=[_jwk_of(AGENT)])
    assert result.valid
    assert result.agent_signatures.verified == 1


def test_a_good_sealed_signature_verifies():
    result = _verify(_sealed(), agent_keys=[_jwk_of(AGENT)])
    assert result.valid
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (1, 1)
    assert result.agent_signature_check == "applied"


def test_a_signature_by_another_key_fails():
    doc = _sealed(signature={
        "alg": "EdDSA", "content_hash": f"sha256:{CONTENT_HEX}", "signature": _agent_sign(IMPOSTOR, CONTENT_HEX),
    })
    result = _verify(doc, agent_keys=[_jwk_of(AGENT)])
    assert not result.valid
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_AGENT_SIGNATURE_INVALID"
    # The envelope itself verified: the finding is about the sealed claim.
    assert result.entries[0].signature == "ok"
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (1, 0)


def test_a_signature_over_a_different_content_hash_fails():
    other = hashlib.sha256(b"something else").hexdigest()
    doc = _sealed(signature={
        "alg": "EdDSA", "content_hash": f"sha256:{CONTENT_HEX}", "signature": _agent_sign(AGENT, other),
    })
    result = _verify(doc, agent_keys=[_jwk_of(AGENT)])
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_AGENT_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    "signature",
    [
        {"alg": "ES256", "content_hash": f"sha256:{CONTENT_HEX}", "signature": _agent_sign(AGENT, CONTENT_HEX)},
        {"alg": "EdDSA", "content_hash": CONTENT_HEX, "signature": _agent_sign(AGENT, CONTENT_HEX)},
        # base64url, not standard base64. Forced to carry a url-alphabet
        # character: a random signature has none about one time in fifteen, and
        # then its base64url form is the unpadded standard form, which verifies.
        {
            "alg": "EdDSA",
            "content_hash": f"sha256:{CONTENT_HEX}",
            "signature": "-" + base64.urlsafe_b64encode(
                base64.b64decode(_agent_sign(AGENT, CONTENT_HEX))
            ).rstrip(b"=").decode()[1:],
        },
        {"alg": "EdDSA", "content_hash": f"sha256:{CONTENT_HEX}", "signature": 42},
    ],
)
def test_shapes_nothing_can_verify_fail(signature: dict[str, Any]):
    result = _verify(_sealed(signature=signature), agent_keys=[_jwk_of(AGENT)])
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_AGENT_SIGNATURE_INVALID"


def test_a_caller_asserted_identity_is_left_unchecked():
    doc = _sealed(validated=False, signature={
        "alg": "EdDSA", "content_hash": f"sha256:{CONTENT_HEX}", "signature": _agent_sign(IMPOSTOR, CONTENT_HEX),
    })
    result = _verify(doc, agent_keys=[_jwk_of(AGENT)])
    assert result.valid
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (1, 0)
    assert result.agent_signature_check == "skipped_no_input"


def test_the_check_never_runs_without_agent_keys():
    doc = _sealed(signature={
        "alg": "EdDSA", "content_hash": f"sha256:{CONTENT_HEX}", "signature": _agent_sign(IMPOSTOR, CONTENT_HEX),
    })
    result = _verify(doc)
    assert result.valid
    assert result.agent_signature_check == "skipped_no_input"


# --- envelope extensions in the row payload are bound to the signed predicate ---
# Mirror of verify-core's envelope-extension-binding.test.ts, on the same live
# fixtures. A row copy of on_behalf_of / traceparent is what a reader sees, and
# the predicate comparison strips both sides of it, so a copy that is present
# is bound to the signed predicate separately.


def _first_with_obo(doc: dict[str, Any]) -> dict[str, Any]:
    entry = next(e for e in doc["entries"] if (e.get("payload") or {}).get("on_behalf_of"))
    return entry["payload"]


@pytest.mark.parametrize(
    "name", ["export-cert-lifecycle.json", "export-delegated-bound.json", "export-delegated-unbound.json"]
)
def test_envelope_fixture_verifies_untouched(name: str):
    assert verify_export(_load(name)).valid


def _binding_broken(doc: dict[str, Any]) -> None:
    result = verify_export(doc)
    assert not result.valid
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_PAYLOAD_BINDING_MISMATCH"


def test_a_rewritten_on_behalf_of_subject_fails_the_binding():
    doc = _load("export-cert-lifecycle.json")
    _first_with_obo(doc)["on_behalf_of"]["oidc"]["sub"] = "someone-else"
    _binding_broken(doc)


def test_a_rewritten_validated_flag_fails_the_binding():
    doc = _load("export-delegated-bound.json")
    obo = _first_with_obo(doc)["on_behalf_of"]
    obo["validated"] = not obo["validated"]
    _binding_broken(doc)


def test_a_row_copy_that_is_not_an_object_is_ignored():
    # The engine lifts only an object on_behalf_of, so a genuine older row
    # holding another shape signed nothing for it (verify-core bf5d379).
    doc = _load("export-cert-lifecycle.json")
    _first_with_obo(doc)["on_behalf_of"] = "forged"
    assert verify_export(doc).valid


def test_a_row_without_the_block_still_verifies():
    # The engine also signs an on_behalf_of from authentication that never
    # reaches the row.
    doc = _load("export-cert-lifecycle.json")
    del _first_with_obo(doc)["on_behalf_of"]
    assert verify_export(doc).valid


def test_an_on_behalf_of_block_added_to_an_entry_that_signed_none_fails_the_binding():
    doc = _load("export-lifecycle.json")
    entry = next(e for e in doc["entries"] if e.get("payload") and not e["payload"].get("on_behalf_of"))
    entry["payload"]["on_behalf_of"] = {"oidc": {"iss": "https://idp.example", "sub": "forged"}, "validated": True}
    _binding_broken(doc)


def test_an_added_traceparent_fails_the_binding():
    doc = _load("export-lifecycle.json")
    entry = next(e for e in doc["entries"] if e.get("payload"))
    entry["payload"]["traceparent"] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    _binding_broken(doc)


def test_a_malformed_traceparent_the_engine_would_have_dropped_does_not_break_the_entry():
    doc = _load("export-lifecycle.json")
    entry = next(e for e in doc["entries"] if e.get("payload") and not e["payload"].get("traceparent"))
    entry["payload"]["traceparent"] = "not-a-traceparent"
    assert verify_export(doc).valid


def test_the_dump_path_runs_the_same_envelope_binding():
    # The dump verifier walks each chain through the same verify_entry, fed the
    # raw vault row's payload, so a rewritten row copy fails there too.
    from agledger.verify.verify_dump import (  # pyright: ignore[reportPrivateUsage]
        _collect_chain_failures,
        _normalize_entry,
    )
    from agledger.verify.verify_export import (  # pyright: ignore[reportPrivateUsage]
        _build_key_registry,
    )

    doc = _load("export-cert-lifecycle.json")
    keys = _build_key_registry(doc["exportMetadata"], None)

    def rows() -> list[dict[str, Any]]:
        return [
            _normalize_entry({
                "chain_position": e["chainPosition"],
                "payload_hash": e["integrity"]["payloadHash"],
                "previous_hash": e["integrity"]["previousHash"],
                "cose_sign1": e["integrity"]["coseSign1"],
                "signing_key_id": e["integrity"]["signingKeyId"],
                "payload": e["payload"],
                "entry_type": e["entryType"],
                "record_id": e.get("recordId"),
                "created_at": e.get("createdAt"),
            })
            for e in doc["entries"]
        ]

    clean: list[Any] = []
    _collect_chain_failures("rec", rows(), keys, clean)
    assert clean == []
    _first_with_obo(doc)["on_behalf_of"]["oidc"]["sub"] = "someone-else"
    tampered: list[Any] = []
    _collect_chain_failures("rec", rows(), keys, tampered)
    assert [f.code for f in tampered] == ["CHAIN_PAYLOAD_BINDING_MISMATCH"]
