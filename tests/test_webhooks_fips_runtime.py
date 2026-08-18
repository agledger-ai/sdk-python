"""A FIPS-locked receiver must not reject legitimate deliveries as forged.

Mirrors the TS SDK's ``webhooks-fips-runtime.test.ts``.

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
def fips_host_refusing_at_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other FIPS build variant: `cryptography` refuses at KEY LOAD.

    Whether the refusal lands at load or at verify depends on how the library
    was built against OpenSSL, so both have to be covered. This variant is the
    one that bypasses a gate placed after key resolution.
    """
    import cryptography.hazmat.primitives.serialization as serialization
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ed25519

    real_load = serialization.load_der_public_key

    def fake_load(data: bytes, *args: Any, **kwargs: Any) -> Any:
        loaded = real_load(data, *args, **kwargs)
        if isinstance(loaded, ed25519.Ed25519PublicKey):
            raise UnsupportedAlgorithm("ed25519 is not supported by this backend")
        return loaded

    def fake_raw(data: bytes) -> Any:
        raise UnsupportedAlgorithm("ed25519 is not supported by this backend")

    monkeypatch.setattr(serialization, "load_der_public_key", fake_load)
    monkeypatch.setattr(ed25519.Ed25519PublicKey, "from_public_bytes", fake_raw)


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


def test_a_forged_signature_raises_too_because_nothing_was_computed(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    """The honest and easily-misread consequence, pinned so it cannot drift.

    The capability gate necessarily runs BEFORE verification, so on this host a
    forgery is indistinguishable from a valid delivery: nothing was computed,
    so nothing is known. The test above passes only because those cases fail at
    the digest/header layer upstream of any key, which is not the same claim.
    Nobody should "fix" this into a False, and no doc should promise that bad
    deliveries return False on every host.
    """
    import base64

    headers, spki = signed
    raw = bytearray(base64.b64decode(headers["signature"][len("sig1=:") : -1]))
    raw[0] ^= 0xFF
    forged = dict(headers)
    forged["signature"] = f"sig1=:{base64.b64encode(bytes(raw)).decode()}:"
    with pytest.raises(SignatureAlgorithmUnavailableError):
        verify_rfc9421(forged, RFC_BODY, spki)


def test_a_host_refusing_at_key_load_also_raises(
    fips_host_refusing_at_load: None, signed: tuple[dict[str, str], str]
) -> None:
    """The variant a gate placed after key resolution would miss entirely."""
    headers, spki = signed
    with pytest.raises(SignatureAlgorithmUnavailableError):
        verify_rfc9421(headers, RFC_BODY, spki)


def test_a_host_refusing_at_key_load_also_raises_for_raw_32_byte_keys(
    fips_host_refusing_at_load: None,
) -> None:
    """Both key encodings the SDK accepts, not just SPKI."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    raw = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    with pytest.raises(SignatureAlgorithmUnavailableError):
        verify_rfc9421(_sign(priv), RFC_BODY, raw)


def test_an_attacker_controlled_alg_mismatch_still_returns_false(
    fips_host: None, signed: tuple[dict[str, str], str]
) -> None:
    """Nothing the sender controls may turn a definite reject into an error.

    A P-256 key under `alg="ed25519"` is a reject on any host. If the sender
    could steer that into a raise, they would have a lever on the receiver's
    failure mode.
    """
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from cryptography.hazmat.primitives.asymmetric import ed25519

    # A host where ES256 is also unavailable, so the assert would fire if it
    # ran. FIPS does not produce this, which is why the ordering bug was
    # latent rather than live.
    _runtime_crypto._CACHE["ES256"] = False

    ec_spki = base64.b64encode(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    # Declares alg="ed25519" while the resolved key is P-256. The signature
    # bytes are irrelevant: the mismatch is decided before they are examined.
    headers = _sign(ed25519.Ed25519PrivateKey.generate(), alg="ed25519")
    assert verify_rfc9421(headers, RFC_BODY, ec_spki) is False


def test_unrestricted_host_is_unaffected(signed: tuple[dict[str, str], str]) -> None:
    """Guards the known-answer vectors: if either were wrong, the probe would
    fail closed and every receiver would start raising on valid deliveries."""
    headers, spki = signed
    assert verify_rfc9421(headers, RFC_BODY, spki) is True
    assert _runtime_crypto.runtime_can_compute("Ed25519") is True
    assert _runtime_crypto.runtime_can_compute("ES256") is True
