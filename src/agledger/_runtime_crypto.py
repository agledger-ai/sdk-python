"""Whether the host runtime can actually compute a signature algorithm.

Knowing that this build implements an algorithm is only half of whether a
signature can be checked. The other half is whether the HOST RUNTIME will
perform the operation, and a runtime can refuse: an active OpenSSL FIPS
provider carries no EdDSA, so ``cryptography`` rejects a perfectly good Ed25519
key, either at load or at verify depending on how it was built.

Both refusals used to be caught and reported as a failed signature, which is
indistinguishable from a forgery. That told an auditor an intact chain had been
tampered with, and told a webhook receiver that every legitimate delivery was
forged.

Lives here, outside ``agledger.verify``, so the webhook path can use it without
pulling in the verify extra's dependencies.
"""

from __future__ import annotations

import base64
from typing import Any, Literal

# Fixed (key, message, signature) triples, byte-identical to
# ``@agledger/verify-core``'s ALGORITHM_KATS so both SDKs agree on which
# runtimes can compute what.
#
# Deliberately fixed, self-contained bytes rather than a freshly generated
# keypair or anything read from the data under verification: promoting a
# signature failure to "not checked" is a security-relevant downgrade, so the
# signal that triggers it must be one no attacker can influence.
_KAT_MESSAGE = b"AGLedger verifier runtime known-answer test"

_ALGORITHM_KATS: dict[str, tuple[str, str]] = {
    "Ed25519": (
        "MCowBQYDK2VwAyEAjChcTn8MOj5h5PpKz/+MvHfomativmvfmC1zV5Sczfo=",
        "iinDVfJ5uwoE4aWjLhunX340+yPlu4l2S8RFG+IfXqzWoiIXYL/ND7+ouGVzAnejozCE"
        "rkL9GneR1sc3vY1sAg==",
    ),
    "ES256": (
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEyJ40hViXjp41rIWYdbJT9bUHWVjYWps"
        "OLKdc4F1L+c4reEK7WmCx1fI4sl0okBN/lNvhZT+0HZ44aUw5HKmFA==",
        "eQ8fKfXT5GuBUz7gueqcq9hTmzrJlSuaoF/ukCPtKJsxqrynVgIREn/XMPKbdSHp7wMy"
        "FOEAgmbVfoMDnR5x/Q==",
    ),
}

_CACHE: dict[str, bool] = {}

AlgorithmName = Literal["Ed25519", "ES256"]

# SPKI DER prefix for an Ed25519 public key: SEQUENCE(44) { SEQUENCE(5) {
# OID 1.3.101.112 } BIT STRING(33) }. RFC 8410 fixes the whole structure, so an
# Ed25519 SPKI is always these 12 bytes followed by the 32-byte key.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ED25519_SPKI_LENGTH = 44
_ED25519_RAW_LENGTH = 32


def looks_like_ed25519_key(raw: bytes) -> bool:
    """Whether these bytes DECLARE themselves an Ed25519 public key, judged
    without ``cryptography``.

    Needed because a host that refuses EdDSA may refuse at key load, leaving no
    key object to ask about the algorithm. Reading the OID directly separates
    "this is an Ed25519 key my runtime will not touch" from "these are garbage
    bytes", which is the difference between an environment problem and tamper.
    Structure only: it says nothing about whether the key is valid or trusted.
    """
    return raw.startswith(_ED25519_SPKI_PREFIX) and len(raw) == _ED25519_SPKI_LENGTH


def _run_kat(alg_name: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey as _EC,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as _Ed,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    spki_base64, signature_base64 = _ALGORITHM_KATS[alg_name]
    key: Any = load_der_public_key(base64.b64decode(spki_base64))
    signature = base64.b64decode(signature_base64)

    if alg_name == "Ed25519":
        if not isinstance(key, _Ed):
            return False
        key.verify(signature, _KAT_MESSAGE)
        return True

    if not isinstance(key, _EC) or not isinstance(key.curve, SECP256R1):
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    key.verify(encode_dss_signature(r, s), _KAT_MESSAGE, ECDSA(SHA256()))
    return True


def runtime_can_compute(alg_name: str) -> bool:
    """Whether this host can compute ``alg_name``, proven against a known-good
    signature. Covers both refusal points, since the probe loads a key and then
    verifies with it.

    Any outcome other than a confirmed success counts as incapable: a runtime
    that cannot confirm a signature known to be valid cannot be trusted to tell
    a good signature from a forged one. Fail closed, and callers must surface
    this as "could not check", never as a pass and never as a failed signature.

    An algorithm with no known-answer vector is a packaging error rather than a
    runtime gap, so it reports capable and leaves real verification in charge.
    """
    cached = _CACHE.get(alg_name)
    if cached is not None:
        return cached
    if alg_name not in _ALGORITHM_KATS:
        supported = True
    else:
        try:
            supported = _run_kat(alg_name)
        except Exception:
            supported = False
    _CACHE[alg_name] = supported
    return supported
