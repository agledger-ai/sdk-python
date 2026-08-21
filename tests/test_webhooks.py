"""Tests for webhook signature verification."""

import base64
import hashlib
import json
import time

import pytest

from agledger import SignatureVerificationError
from agledger.webhooks import (
    construct_event,
    construct_event_rfc9421,
    sign_payload,
    verify_rfc9421,
    verify_signature,
)

SECRET = "whsec_test_secret_key"
BODY = json.dumps({"type": "record.created", "data": {"id": "rec-123"}, "timestamp": "2026-04-27T00:00:00Z", "id": "evt-1"})


def test_sign_and_verify():
    result = sign_payload(BODY, SECRET)
    assert verify_signature(BODY, result["header"], SECRET)


def test_wrong_body():
    result = sign_payload(BODY, SECRET)
    assert not verify_signature("wrong body", result["header"], SECRET)


def test_wrong_secret():
    result = sign_payload(BODY, SECRET)
    assert not verify_signature(BODY, result["header"], "wrong_secret")


def test_expired_signature():
    old_ts = int(time.time()) - 600
    result = sign_payload(BODY, SECRET, old_ts)
    assert not verify_signature(BODY, result["header"], SECRET)


def test_key_rotation():
    result = sign_payload(BODY, SECRET)
    assert verify_signature(BODY, result["header"], ["old_secret", SECRET, "new_secret"])


def test_tolerance_cap():
    old_ts = int(time.time()) - 400
    result = sign_payload(BODY, SECRET, old_ts)
    # Even with 600s tolerance, should be capped at 300
    assert not verify_signature(BODY, result["header"], SECRET, tolerance_seconds=600)


def test_construct_event():
    result = sign_payload(BODY, SECRET)
    event = construct_event(BODY, result["header"], SECRET)
    assert event["type"] == "record.created"
    assert event["data"]["id"] == "rec-123"
    assert event["id"] == "evt-1"


def test_construct_event_bad_signature():
    result = sign_payload(BODY, "wrong_secret")
    with pytest.raises(SignatureVerificationError, match="verification failed") as exc_info:
        construct_event(BODY, result["header"], SECRET)
    assert exc_info.value.payload == BODY.encode()


# --- RFC 9421 (ed25519) verification ---

# cryptography is required for the ed25519 path; skip the whole block if absent.
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

IDEMPOTENCY = "x-agledger-idempotency-key"
COVERED = ["content-digest", IDEMPOTENCY]
RFC_BODY = json.dumps(
    {"type": "signal.emitted", "data": {"recordId": "rec-1", "signal": "SETTLE"}, "timestamp": "2026-05-25T00:00:00Z", "id": "evt-9"}
)
IDK = "11111111-2222-3333-4444-555555555555"
KEY_ID = "a1b2c3d4e5f60718"


def _content_digest(raw: str) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(raw.encode()).digest()).decode()}:"


def _sig_params(created: int, kid: str, alg: str = "ed25519") -> str:
    inner = " ".join(f'"{c}"' for c in COVERED)
    return f'({inner});created={created};keyid="{kid}";alg="{alg}"'


def _sign(private_key, *, raw_body=RFC_BODY, idempotency_key=IDK, key_id=KEY_ID, created=None, alg="ed25519"):
    """Replicate the API's outbound RFC 9421 signer (webhooks.rfc9421-signer.ts)."""
    created = created if created is not None else int(time.time())
    cd = _content_digest(raw_body)
    params = _sig_params(created, key_id, alg)
    base = "\n".join(
        [f'"content-digest": {cd}', f'"{IDEMPOTENCY}": {idempotency_key}', f'"@signature-params": {params}']
    ).encode()
    signature = private_key.sign(base)
    return {
        "content-digest": cd,
        "signature-input": f"sig1={params}",
        "signature": f"sig1=:{base64.b64encode(signature).decode()}:",
        IDEMPOTENCY: idempotency_key,
    }


@pytest.fixture
def keypair():
    from cryptography.hazmat.primitives import serialization

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    spki = base64.b64encode(
        pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    raw = base64.b64encode(
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    keys = [{"keyId": KEY_ID, "algorithm": "Ed25519", "publicKey": spki, "publicKeyRaw": raw, "status": "active"}]
    return priv, spki, raw, keys


def test_rfc9421_valid_spki(keypair):
    priv, spki, _raw, _keys = keypair
    headers = _sign(priv)
    assert verify_rfc9421(headers, RFC_BODY, spki) is True


def test_rfc9421_valid_raw_key(keypair):
    priv, _spki, raw, _keys = keypair
    headers = _sign(priv)
    assert verify_rfc9421(headers, RFC_BODY, raw) is True


def test_rfc9421_resolve_by_keyid(keypair):
    priv, _spki, _raw, keys = keypair
    headers = _sign(priv)
    assert verify_rfc9421(headers, RFC_BODY, keys) is True


def test_rfc9421_header_casing_and_lists(keypair):
    priv, _spki, _raw, keys = keypair
    headers = _sign(priv)
    messy = {
        "Content-Digest": headers["content-digest"],
        "Signature-Input": [headers["signature-input"]],
        "Signature": headers["signature"],
        "X-AGLedger-Idempotency-Key": headers[IDEMPOTENCY],
    }
    assert verify_rfc9421(messy, RFC_BODY, keys) is True


def test_rfc9421_tampered_body(keypair):
    priv, spki, _raw, _keys = keypair
    headers = _sign(priv)
    assert verify_rfc9421(headers, RFC_BODY + " ", spki) is False


def test_rfc9421_tampered_idempotency_key(keypair):
    priv, spki, _raw, _keys = keypair
    headers = _sign(priv)
    headers[IDEMPOTENCY] = "different-key"
    assert verify_rfc9421(headers, RFC_BODY, spki) is False


def test_rfc9421_wrong_key(keypair):
    priv, _spki, _raw, _keys = keypair
    from cryptography.hazmat.primitives import serialization

    other = ed25519.Ed25519PrivateKey.generate().public_key()
    other_spki = base64.b64encode(
        other.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    headers = _sign(priv)
    assert verify_rfc9421(headers, RFC_BODY, other_spki) is False


def test_rfc9421_keyid_not_in_list(keypair):
    priv, _spki, _raw, keys = keypair
    headers = _sign(priv, key_id="unknown-kid")
    assert verify_rfc9421(headers, RFC_BODY, keys) is False


def test_rfc9421_stale_signature(keypair):
    priv, spki, _raw, _keys = keypair
    headers = _sign(priv, created=int(time.time()) - 600)
    assert verify_rfc9421(headers, RFC_BODY, spki) is False


def test_rfc9421_missing_headers(keypair):
    priv, spki, _raw, _keys = keypair
    headers = _sign(priv)
    no_sig = {k: v for k, v in headers.items() if k != "signature"}
    assert verify_rfc9421(no_sig, RFC_BODY, spki) is False
    no_digest = {k: v for k, v in headers.items() if k != "content-digest"}
    assert verify_rfc9421(no_digest, RFC_BODY, spki) is False


def test_construct_event_rfc9421(keypair):
    priv, _spki, _raw, keys = keypair
    headers = _sign(priv)
    event = construct_event_rfc9421(headers, RFC_BODY, keys)
    assert event["type"] == "signal.emitted"
    assert event["id"] == "evt-9"
    headers[IDEMPOTENCY] = "x"
    with pytest.raises(SignatureVerificationError, match="RFC 9421"):
        construct_event_rfc9421(headers, RFC_BODY, keys)


# --- RFC 9421 (ecdsa-p256-sha256) verification ---
#
# Replicates the API's outbound ES256 path (signing-agility api R2): same
# signature base, alg="ecdsa-p256-sha256", raw r||s (64-byte) signatures.

ES256_KEY_ID = "f6e5d4c3b2a10897"


def _sig_params_alg(created: int, kid: str, alg: str) -> str:
    inner = " ".join(f'"{c}"' for c in COVERED)
    return f'({inner});created={created};keyid="{kid}";alg="{alg}"'


def _sign_es256(private_key, *, raw_body=RFC_BODY, idempotency_key=IDK, key_id=ES256_KEY_ID, alg="ecdsa-p256-sha256", der=False):
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256

    created = int(time.time())
    cd = _content_digest(raw_body)
    params = _sig_params_alg(created, key_id, alg)
    base = "\n".join(
        [f'"content-digest": {cd}', f'"{IDEMPOTENCY}": {idempotency_key}', f'"@signature-params": {params}']
    ).encode()
    der_sig = private_key.sign(base, ECDSA(SHA256()))
    if der:
        signature = der_sig
    else:
        r, s = decode_dss_signature(der_sig)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        "content-digest": cd,
        "signature-input": f"sig1={params}",
        "signature": f"sig1=:{base64.b64encode(signature).decode()}:",
        IDEMPOTENCY: idempotency_key,
    }


@pytest.fixture
def es256_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )

    priv = generate_private_key(SECP256R1())
    spki = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    # No publicKeyRaw on EC keys (R1 discovery reshape: SPKI only).
    keys = [{"keyId": ES256_KEY_ID, "algorithm": "ES256", "coseAlgorithm": -7, "publicKey": spki, "status": "active"}]
    return priv, spki, keys


def test_rfc9421_es256_valid_spki(es256_keypair):
    priv, spki, _keys = es256_keypair
    headers = _sign_es256(priv)
    assert verify_rfc9421(headers, RFC_BODY, spki) is True


def test_rfc9421_es256_resolve_by_keyid(es256_keypair):
    priv, _spki, keys = es256_keypair
    headers = _sign_es256(priv)
    assert verify_rfc9421(headers, RFC_BODY, keys) is True


def test_rfc9421_es256_alg_contradicting_key_type(es256_keypair):
    # A P-256 key under alg="ed25519" must fail, never reroute dispatch.
    priv, spki, _keys = es256_keypair
    headers = _sign_es256(priv, alg="ed25519")
    assert verify_rfc9421(headers, RFC_BODY, spki) is False


def test_rfc9421_es256_der_signature_rejected(es256_keypair):
    # The wire is raw r||s; a DER-encoded signature must not verify.
    priv, spki, _keys = es256_keypair
    headers = _sign_es256(priv, der=True)
    assert verify_rfc9421(headers, RFC_BODY, spki) is False


def test_rfc9421_es256_tampered_body(es256_keypair):
    priv, spki, _keys = es256_keypair
    headers = _sign_es256(priv)
    assert verify_rfc9421(headers, RFC_BODY + " ", spki) is False


def test_rfc9421_ed25519_alg_contradicting_ed_key(keypair):
    # The inverse assertion: an Ed25519 key under alg="ecdsa-p256-sha256"
    # fails. The contradiction is embedded in the signed params (not mutated
    # after signing), so the signature itself is VALID over the base and only
    # the alg guard can reject it: this pins the guard as load-bearing.
    priv, spki, _raw, _keys = keypair
    headers = _sign(priv, alg="ecdsa-p256-sha256")
    assert verify_rfc9421(headers, RFC_BODY, spki) is False


def test_rfc9421_unsupported_key_type_fails_closed(es256_keypair):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        generate_private_key as rsa_generate,
    )

    priv, _spki, _keys = es256_keypair
    rsa_pub = rsa_generate(public_exponent=65537, key_size=2048).public_key()
    rsa_spki = base64.b64encode(
        rsa_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    headers = _sign_es256(priv)
    assert verify_rfc9421(headers, RFC_BODY, rsa_spki) is False
