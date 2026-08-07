"""A FIPS-locked receiver must not reject legitimate deliveries as forged.

Mirrors the TS SDK's ``webhooks-fips-runtime.test.ts`` (agents#113).

The FIPS provider carries no EdDSA, so verifying an ed25519 webhook raises
inside ``verify_rfc9421``. That was caught and returned as ``False``, which
every documented caller turns into a 401. The result: a receiver rejecting
every valid delivery it is sent, reporting each one as a bad signature, with
nothing anywhere naming the real cause.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from agledger import SignatureAlgorithmUnavailableError, SignatureVerificationError
from agledger.webhooks import construct_event_rfc9421, verify_rfc9421

from .test_webhooks import RFC_BODY, _sign

_runtime_crypto = importlib.import_module("agledger._runtime_crypto")


@pytest.fixture(autouse=True)
def _clear_capability_cache() -> Any:
    """The probe memoizes per process; each test needs a clean answer."""
    _runtime_crypto._CACHE.clear()
    yield
    _runtime_crypto._CACHE.clear()


@pytest.fixture
def fips_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host with the FIPS provider active: ES256 yes, EdDSA no.

    Patched at the ``cryptography`` layer so the capability probe and the real
    dispatch meet the same refusal, which is what a FIPS provider actually
    does. The public ``Ed25519PublicKey`` name is an ABC that concrete keys
    only register against, so the Rust-backed class is the one to patch.
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ed25519

    def refuse(self: Any, signature: bytes, data: bytes) -> None:
        raise UnsupportedAlgorithm("ed25519 is not supported by this backend")

    concrete = type(ed25519.Ed25519PrivateKey.generate().public_key())
    monkeypatch.setattr(concrete, "verify", refuse)


@pytest.fixture
def signed() -> tuple[dict[str, str], str]:
    """A genuinely valid delivery. Signing is unaffected; only verify is refused."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    spki = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    return _sign(priv), spki


def test_raises_instead_of_reporting_a_valid_delivery_as_unverified(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    headers, spki = signed
    with pytest.raises(SignatureAlgorithmUnavailableError):
        verify_rfc9421(headers, RFC_BODY, spki)


def test_is_not_a_signature_failure(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    # The distinction is the whole point: a 401 blames the sender for a fault
    # that is entirely in the receiver's configuration.
    headers, spki = signed
    with pytest.raises(SignatureAlgorithmUnavailableError) as excinfo:
        verify_rfc9421(headers, RFC_BODY, spki)
    assert not isinstance(excinfo.value, SignatureVerificationError)


def test_names_the_algorithm_the_cause_and_both_remedies(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    headers, spki = signed
    with pytest.raises(SignatureAlgorithmUnavailableError) as excinfo:
        verify_rfc9421(headers, RFC_BODY, spki)
    assert excinfo.value.algorithm == "Ed25519"
    message = str(excinfo.value)
    assert "FIPS" in message
    assert "NOT a failed signature" in message
    assert "ecdsa-p256-sha256" in message


def test_propagates_through_construct_event(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    headers, spki = signed
    with pytest.raises(SignatureAlgorithmUnavailableError):
        construct_event_rfc9421(headers, RFC_BODY, spki)


def test_deliveries_that_are_actually_bad_still_return_false(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    """The escape hatch must stay narrow.

    A tampered body is a rejected delivery, not a runtime problem, and must not
    start raising. These fail before reaching the signature at all, which is
    exactly why they keep the old behaviour.
    """
    headers, spki = signed
    assert verify_rfc9421(headers, RFC_BODY + " ", spki) is False
    assert verify_rfc9421({k: v for k, v in headers.items() if k != "signature"}, RFC_BODY, spki) is False


def test_unrestricted_host_is_unaffected(signed: tuple[dict[str, str], str]) -> None:
    """Guards the known-answer vectors: if either were wrong, the probe would
    fail closed and every receiver would start raising on valid deliveries."""
    headers, spki = signed
    assert verify_rfc9421(headers, RFC_BODY, spki) is True
    assert _runtime_crypto.runtime_can_compute("Ed25519") is True
    assert _runtime_crypto.runtime_can_compute("ES256") is True
