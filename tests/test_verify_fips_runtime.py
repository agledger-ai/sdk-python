"""A FIPS-locked runtime must not report an intact Ed25519 chain as forged.

Mirrors ``@agledger/verify-core``'s ``fips-runtime.test.ts``.

The measured behaviour: with the OpenSSL FIPS provider active there is no
EdDSA, so a perfectly good Ed25519 key either fails to load or raises on
verify. Both paths were caught and reported as ``CHAIN_SIGNATURE_INVALID``,
which is indistinguishable from a forgery, so a healthy chain came back
"0/N verified" and an auditor reads that as tamper.

Simulated by monkeypatching the two refusal points rather than requiring a
FIPS build of OpenSSL, so the test runs anywhere. Both directions are covered
because ``cryptography`` can refuse at either one depending on how it was
built against OpenSSL.
"""

from __future__ import annotations

import base64
import importlib
from typing import Any

import pytest

from agledger.verify import verify_export

from .test_verify import _make_export, _make_keypair

# The package re-exports the FUNCTION under this name, shadowing the module on
# attribute access, so reach the module through sys.modules instead.
verify_export_module = importlib.import_module("agledger.verify.verify_export")


@pytest.fixture(autouse=True)
def _clear_capability_cache() -> Any:
    """The runtime probe memoizes per process; each test needs a clean answer."""
    importlib.import_module("agledger._runtime_crypto")._CACHE.clear()
    verify_export_module._KEY_ALG_CACHE.clear()
    yield
    importlib.import_module("agledger._runtime_crypto")._CACHE.clear()
    verify_export_module._KEY_ALG_CACHE.clear()


def _refuse_ed25519_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """A runtime that loads Ed25519 keys but will not compute with them.

    Patched at the ``cryptography`` layer rather than at either call site, so
    the capability probe and the real dispatch both meet the same refusal. That
    is what a FIPS provider actually does, and patching only one of the two
    would test a situation that cannot occur.
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def refuse(self: Any, signature: bytes, data: bytes) -> None:
        raise UnsupportedAlgorithm("ed25519 is not supported by this backend")

    # The public name is an ABC that concrete keys only register against, so
    # patching it changes nothing. The Rust-backed class is the real one.
    concrete = type(Ed25519PrivateKey.generate().public_key())
    monkeypatch.setattr(concrete, "verify", refuse)


def _refuse_ed25519_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """A runtime that will not even load an Ed25519 key.

    ``load_der_public_key`` is bound at import time in the verifier and looked
    up at call time in the probe, so both bindings are patched.
    """
    import cryptography.hazmat.primitives.serialization as serialization
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    real = serialization.load_der_public_key

    def fake(data: bytes, *args: Any, **kwargs: Any) -> Any:
        loaded = real(data, *args, **kwargs)
        if isinstance(loaded, Ed25519PublicKey):
            raise UnsupportedAlgorithm("ed25519 is not supported by this backend")
        return loaded

    monkeypatch.setattr(serialization, "load_der_public_key", fake)
    monkeypatch.setattr(verify_export_module, "_load_der_public_key", fake)


def test_refused_verify_reports_unsupported_not_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    _refuse_ed25519_verify(monkeypatch)

    result = verify_export(export)

    # Fail closed: an uncheckable chain is not a verified chain.
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_UNSUPPORTED_ALGORITHM"
    assert result.broken_at.code != "CHAIN_SIGNATURE_INVALID"


def test_refused_load_reports_unsupported_not_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    _refuse_ed25519_load(monkeypatch)

    result = verify_export(export)

    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_UNSUPPORTED_ALGORITHM"


def test_detail_names_the_runtime_the_cause_and_the_remedy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    _refuse_ed25519_verify(monkeypatch)

    detail = verify_export(export).broken_at.detail  # type: ignore[union-attr]

    assert "Ed25519" in detail
    assert "HOST RUNTIME" in detail
    assert "FIPS" in detail
    assert "NOT tamper evidence" in detail
    assert "Re-run the verification on a host without that restriction" in detail
    # The sentence that sent an auditor after a healthy chain.
    assert "forged" not in detail


def test_entries_are_marked_unsupported_rather_than_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    _refuse_ed25519_verify(monkeypatch)

    assert [e.signature for e in verify_export(export).entries] == [
        "unsupported",
        "unsupported",
        "unsupported",
    ]


def test_unrestricted_runtime_still_verifies_and_still_catches_forgery() -> None:
    """The downgrade must not leak onto a healthy host.

    Guards the checked-in known-answer vectors too: if either were wrong the
    probe would fail closed and silently downgrade ALL verification to
    "not checked" everywhere.
    """
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    assert verify_export(export).valid is True

    # A genuine forgery must still read as one.
    entry = export["entries"][1]
    envelope = bytearray(base64.b64decode(entry["integrity"]["coseSign1"]))
    envelope[-1] ^= 0xFF
    entry["integrity"]["coseSign1"] = base64.b64encode(bytes(envelope)).decode()
    import hashlib

    entry["integrity"]["payloadHash"] = hashlib.sha256(bytes(envelope)).hexdigest()
    export["entries"][2]["integrity"]["previousHash"] = entry["integrity"]["payloadHash"]

    forged = verify_export(export)
    assert forged.valid is False
    assert forged.broken_at is not None
    assert forged.broken_at.code == "CHAIN_SIGNATURE_INVALID"


def _corrupt_key_material(export: dict[str, Any]) -> dict[str, Any]:
    """Replace the embedded verification key with bytes that are not a key."""
    meta = export["exportMetadata"]
    garbage = base64.b64encode(b"this is not a public key at all").decode()
    meta["signingPublicKey"] = garbage
    meta["signingPublicKeys"] = {k: garbage for k in meta["signingPublicKeys"]}
    return export


def test_tampered_key_material_still_reads_as_tamper_on_a_healthy_host() -> None:
    """The safety property the unparseable refinement must not break.

    Garbage key material is tamper, not an environment problem, and saying
    "upgrade your verifier" about it would send an auditor somewhere that can
    never resolve it.
    """
    pub, priv = _make_keypair()
    result = verify_export(_corrupt_key_material(_make_export(pub, priv)))
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_SIGNATURE_INVALID"


def test_tampered_key_material_still_reads_as_tamper_on_a_fips_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And it must keep reading as tamper on the host the fix targets.

    The refinement keys off the Ed25519 OID rather than off capability alone,
    so bytes that are not a key get the same verdict everywhere. This is also
    what keeps the Python and TypeScript verifiers agreeing.
    """
    pub, priv = _make_keypair()
    export = _corrupt_key_material(_make_export(pub, priv))
    _refuse_ed25519_verify(monkeypatch)

    result = verify_export(export)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_SIGNATURE_INVALID"


def test_an_ed25519_key_refused_at_load_reads_as_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case the refinement exists for: real Ed25519 key material that this
    host will not load. Identified by OID, so it is distinguishable from the
    garbage above even though both fail to parse."""
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    _refuse_ed25519_load(monkeypatch)

    result = verify_export(export)
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_UNSUPPORTED_ALGORITHM"


def test_load_refusal_detail_names_the_host_not_the_verifier_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verdict was already right on this path; the sentence was not.

    With no key object to resolve, the detail fell through to the generic
    "upgrade the verifier" text, which sends a FIPS auditor to replace a build
    that is not the problem and never can be.
    """
    pub, priv = _make_keypair()
    export = _make_export(pub, priv)
    _refuse_ed25519_load(monkeypatch)

    detail = verify_export(export).broken_at.detail  # type: ignore[union-attr]

    assert "Ed25519" in detail
    assert "HOST RUNTIME" in detail
    assert "FIPS" in detail
    assert "NOT tamper evidence" in detail
    assert "upgrade the verifier" not in detail


def test_runtime_probe_confirms_every_verifiable_algorithm() -> None:
    from agledger.verify.verify_export import (
        _EC_KEY_ALGORITHMS,
        _ED25519_ALG,
        _runtime_can_compute,
    )

    assert _runtime_can_compute(_ED25519_ALG) is True
    assert _runtime_can_compute(_EC_KEY_ALGORITHMS["secp256r1"]) is True
