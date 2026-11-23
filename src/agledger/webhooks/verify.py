"""
AGLedger SDK: Webhook signature verification.
Mirrors the TypeScript SDK's webhooks/verify.ts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, cast

from agledger._errors import (
    ConfigurationError,
    SignatureAlgorithmUnavailableError,
    SignatureVerificationError,
)
from agledger._runtime_crypto import looks_like_ed25519_key, runtime_can_compute
from agledger.webhooks._structured_fields import (
    ByteSequence,
    InnerList,
    Item,
    parse_dictionary,
    serialize_inner_list,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_TOLERANCE_SECONDS = 300

#: Clock skew allowed at each edge of a signing key's window when a delivery's
#: ``created`` time is placed in it. The Server publishes the same allowance to
#: receivers; it is fixed, and separate from the replay tolerance.
KEY_WINDOW_SKEW_MS = 300_000

#: Covered components a signed delivery signs, lowercased per RFC 9421.
RFC9421_COVERED_COMPONENTS = ("content-digest", "x-agledger-idempotency-key")


def sign_payload(raw_body: str, secret: str, timestamp: int | None = None) -> dict[str, Any]:
    """Sign a payload (for testing). Returns header, timestamp, signature."""
    ts = timestamp or int(time.time())
    signed_payload = f"{ts}.{raw_body}"
    signature = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
    return {
        "header": f"t={ts},v1={signature}",
        "timestamp": ts,
        "signature": signature,
    }


def _parse_header(header: str) -> dict[str, Any] | None:
    ts: int | None = None
    signatures: list[str] = []
    for part in header.split(","):
        kv = part.split("=", 1)
        if len(kv) != 2:
            return None
        key, value = kv[0].strip(), kv[1].strip()
        if key == "t":
            try:
                ts = int(value)
            except ValueError:
                return None
        elif key == "v1":
            signatures.append(value)
    if ts is None or not signatures:
        return None
    return {"timestamp": ts, "signatures": signatures}


def _resolve_tolerance(value: object) -> float:
    """The replay window in seconds: the caller's value capped at 300. A value
    that is not a finite number, 0 or more, raises instead of being capped:
    ``nan`` would make every freshness comparison false and so switch the
    window off. As ``@agledger/sdk`` refuses it."""
    # Typed float on the public functions, but checked here as it arrives.
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("tolerance_seconds must be a finite number, 0 or more.")
    return min(value, MAX_TOLERANCE_SECONDS)


def _checked_secrets(secrets: str | Sequence[str]) -> list[str]:
    """The signing secrets as a list, refusing any that would let a caller forge.

    An empty secret is a valid HMAC key, so accepting one would let anyone
    compute a passing signature. An empty list or a blank entry is a
    configuration mistake, raised rather than reported as a failed delivery.
    """
    secret_list = [secrets] if isinstance(secrets, str) else list(secrets)
    if not secret_list or any(not x.strip() for x in secret_list):
        raise ConfigurationError(
            "Webhook signing secret is empty. Pass the endpoint's secret, or a non-empty list of secrets during rotation."
        )
    return secret_list


def verify_signature(
    raw_body: str,
    header: str,
    secrets: str | Sequence[str],
    tolerance_seconds: float = MAX_TOLERANCE_SECONDS,
) -> bool:
    """Verify a webhook signature. Supports key rotation via list of secrets.

    Raises :class:`ConfigurationError` when the secret is empty or blank, and
    ``ValueError`` when ``tolerance_seconds`` is not a finite number, 0 or more.
    """
    secret_list = _checked_secrets(secrets)
    tolerance = _resolve_tolerance(tolerance_seconds)
    parsed = _parse_header(header)
    if not parsed:
        return False

    now = int(time.time())
    if abs(now - parsed["timestamp"]) > tolerance:
        return False

    signed_payload = f"{parsed['timestamp']}.{raw_body}"

    for secret in secret_list:
        expected = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
        for sig in parsed["signatures"]:
            if hmac.compare_digest(sig.encode("utf-8"), expected.encode("ascii")):
                return True

    return False


def construct_event(
    raw_body: str,
    header: str,
    secrets: str | Sequence[str],
    tolerance_seconds: float = MAX_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """Verify signature and parse the webhook payload in one step.

    Raises SignatureVerificationError if signature is invalid.
    """
    if not verify_signature(raw_body, header, secrets, tolerance_seconds):
        raise SignatureVerificationError(
            "Webhook signature verification failed",
            payload=raw_body.encode() if raw_body else None,
        )
    return _parse_webhook_event(raw_body)


def _parse_webhook_event(raw_body: str) -> dict[str, Any]:
    """Parse a verified webhook body into a typed event (shared by both verify paths)."""
    parsed = json.loads(raw_body)
    return {
        "type": parsed.get("type") or parsed.get("event", "unknown"),
        "data": parsed.get("data") or parsed.get("payload", parsed),
        "timestamp": parsed.get("timestamp") or parsed.get("created_at", ""),
        "id": parsed.get("id") or parsed.get("event_id"),
    }


# RFC 9421 webhook verification (ed25519 / ecdsa-p256-sha256).
#
# The asymmetric, opt-in signing tier (``signing_alg = 'ed25519'`` or
# ``'ecdsa-p256-sha256'``; the wire ``alg`` parameter reflects the Server's
# ACTIVE vault key). Deliveries are signed with the Server vault key as RFC
# 9421 HTTP Message Signatures; the receiver verifies against the published
# public key at GET /v1/verification-keys (matched by ``keyid``) and holds no
# secret, so it can check the Server's signature on a Settlement Signal on its
# own. The verification
# algorithm is dispatched from the resolved key's type, never from the
# attacker-writable ``alg`` parameter; when ``alg`` is present it is asserted
# against the key. Covered components are exactly ``content-digest`` (RFC 9530
# body integrity) and ``x-agledger-idempotency-key``; derived components are
# excluded because proxies rewrite them. Requires the optional ``cryptography``
# dependency (``pip install 'agledger[verify]'``).



def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """Lowercase header keys and build each field's component value as RFC 9421
    section 2.1 does: every value trimmed, obsolete line folding replaced by a
    space, multiple values joined with ``, ``."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        if v is None:
            continue
        values = [str(x) for x in cast("Sequence[Any]", v)] if isinstance(v, (list, tuple)) else [str(v)]
        out[k.lower()] = ", ".join(re.sub(r"\n\s*", " ", x.strip()) for x in values)
    return out


def _content_digest(raw_body: str) -> str:
    digest = base64.b64encode(hashlib.sha256(raw_body.encode("utf-8")).digest()).decode("ascii")
    return f"sha-256=:{digest}:"


def _load_public_key(base64_key: str) -> Ed25519PublicKey | EllipticCurvePublicKey:
    """Build a public key object from base64 (raw 32-byte Ed25519 or SPKI DER,
    which also carries P-256). Raises ``ValueError`` for any other key type so
    verification fails closed."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except ImportError as err:  # pragma: no cover
        raise ImportError(
            "The 'cryptography' package is required for RFC 9421 webhook verification. "
            "Install via: pip install 'agledger[verify]'"
        ) from err
    raw = base64.b64decode(base64_key)
    # Gate BEFORE loading, not after. A host that refuses EdDSA may refuse at
    # key load, in which case the check further down never runs and the caught
    # exception becomes a `False` that reads as a forged delivery. Both key
    # encodings are covered: a bare 32-byte key is Ed25519 by definition here,
    # and an SPKI is identified by its OID rather than by loading it.
    if len(raw) == 32 or looks_like_ed25519_key(raw):
        _assert_runtime_can_compute("Ed25519")
    if len(raw) == 32:
        return Ed25519PublicKey.from_public_bytes(raw)
    loaded = load_der_public_key(raw)
    if not isinstance(loaded, (Ed25519PublicKey, EllipticCurvePublicKey)):
        raise ValueError("public key is not Ed25519 or EC")
    return loaded


def _extract_key_fields(item: object) -> tuple[str | None, str | None, tuple[object, object]]:
    """Pull (keyId, publicKey, (activatedAt, retiredAt)) from a VerificationKey
    model or a mapping."""
    if isinstance(item, Mapping):
        m = cast("Mapping[str, Any]", item)
        keyid = m.get("keyId") or m.get("key_id")
        material = m.get("publicKey") or m.get("public_key")
        activated = m.get("activatedAt", m.get("activated_at"))
        retired = m.get("retiredAt", m.get("retired_at"))
    else:
        keyid = getattr(item, "key_id", None)
        material = getattr(item, "public_key", None)
        activated = getattr(item, "activated_at", None)
        retired = getattr(item, "retired_at", None)
    return (
        keyid if isinstance(keyid, str) else None,
        material if isinstance(material, str) else None,
        (activated, retired),
    )


def _resolve_public_key(
    key: str | Sequence[object], keyid: str | None
) -> tuple[Ed25519PublicKey | EllipticCurvePublicKey, tuple[object, object] | None] | None:
    """Resolve a public key, and its window when it came from a
    verification-keys list, from a single string or that list."""
    if isinstance(key, str):
        return _load_public_key(key), None
    for item in key:
        item_keyid, material, window = _extract_key_fields(item)
        if item_keyid != keyid or material is None:
            continue
        return _load_public_key(material), window
    return None


def _inside_key_window(created_seconds: int, window: tuple[object, object]) -> bool:
    """Whether a signature created at ``created_seconds`` falls inside its key's
    window, with the skew allowance at each edge. A window that cannot be read
    (no ``activatedAt``, or an instant that is not RFC 3339) places nothing."""
    # Imported here: the HMAC path must load without the ``verify`` extra.
    from agledger.verify.key_statements import instant_ms

    activated, retired = window
    created_ms = created_seconds * 1000
    activated_ms = instant_ms(activated)
    if activated_ms is None or created_ms < activated_ms - KEY_WINDOW_SKEW_MS:
        return False
    if retired is None:
        return True
    retired_ms = instant_ms(retired)
    return retired_ms is not None and created_ms <= retired_ms + KEY_WINDOW_SKEW_MS


def verify_rfc9421(
    headers: Mapping[str, Any],
    raw_body: str,
    key: str | Sequence[Any],
    tolerance_seconds: float = MAX_TOLERANCE_SECONDS,
) -> bool:
    """Verify an RFC 9421 webhook delivery (ed25519 or ecdsa-p256-sha256), the
    non-repudiable tier.

    Recomputes the Content-Digest over ``raw_body``, reconstructs the RFC 9421
    signature base, resolves the public key by ``keyid``, verifies the
    signature under the algorithm that key commits to, and enforces the
    ``created`` replay window. Given the key list, it also holds ``created`` to
    the signing key's ``[activatedAt, retiredAt]`` window with 300 seconds
    allowed at each edge (``retiredAt`` of None means the window is still
    open). ``status`` is not consulted: a key retired between signing and your
    fetch still verifies what it signed while it was active. A single key
    string carries no window, so pinning one accepts whatever that key signed
    inside the replay window.

    :param headers: delivery HTTP headers, which must include ``content-digest``,
        ``signature-input``, ``signature``, and ``x-agledger-idempotency-key``.
        Casing and multi-value (list) headers are handled.
    :param raw_body: The raw request body string (do NOT parse JSON first).
    :param key: A single base64 public key (raw 32-byte or SPKI DER), or the
        ``.data`` list from ``client.verification_keys.list()`` (resolved by
        ``keyid``).
    :param tolerance_seconds: Replay window for the ``created`` time (default/max 300).
        A value that is not a finite number, 0 or more, raises ``ValueError``.
    :returns: True only if the signature, digest, replay window and key window all hold.
    """
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as err:  # pragma: no cover
        raise ImportError(
            "The 'cryptography' package is required for RFC 9421 webhook verification. "
            "Install via: pip install 'agledger[verify]'"
        ) from err

    tolerance = _resolve_tolerance(tolerance_seconds)
    h = _normalize_headers(headers)

    content_digest = h.get("content-digest")
    idempotency_key = h.get("x-agledger-idempotency-key")
    sig_input_field = h.get("signature-input")
    sig_field = h.get("signature")
    if not (sig_input_field and sig_field and content_digest and idempotency_key):
        return False

    # RFC 9530 body integrity.
    if content_digest != _content_digest(raw_body):
        return False

    inputs = parse_dictionary(sig_input_field)
    signatures = parse_dictionary(sig_field)
    if inputs is None or signatures is None:
        return False

    now = time.time()
    component_values = {"content-digest": content_digest, "x-agledger-idempotency-key": idempotency_key}

    # The delivery verifies when one of its signatures does; a sender may add
    # signatures of its own (an intermediary's), which are passed over. A host
    # that cannot compute a key's algorithm is a receiver fault, raised once no
    # signature verified, never turned into False.
    unavailable: SignatureAlgorithmUnavailableError | None = None
    for label, sig_input in inputs.items():
        if not isinstance(sig_input, InnerList):
            continue
        sig = signatures.get(label)
        if not (isinstance(sig, Item) and isinstance(sig.value, ByteSequence)):
            continue
        try:
            if _verify_one(sig_input, sig.value.data, component_values, key, tolerance, now, InvalidSignature):
                return True
        except SignatureAlgorithmUnavailableError as err:
            unavailable = unavailable or err
    if unavailable is not None:
        raise unavailable
    return False


def _verify_one(
    sig_input: InnerList,
    signature: bytes,
    component_values: dict[str, str],
    key: str | Sequence[Any],
    tolerance: float,
    now: float,
    invalid_signature: type[Exception],
) -> bool:
    """One signature: it must cover exactly ``content-digest`` then
    ``x-agledger-idempotency-key`` with no component parameters, and name
    ``created`` (an Integer) and ``keyid`` (a String). ``expires`` is held when
    present. The same rules as the TypeScript SDK."""
    covered = [item.value for item in sig_input.items]
    if covered != list(RFC9421_COVERED_COMPONENTS) or any(item.params for item in sig_input.items):
        return False

    params = sig_input.params
    created = params.get("created")
    keyid = params.get("keyid")
    expires = params.get("expires")
    alg = params.get("alg")
    if isinstance(created, bool) or not isinstance(created, int) or not isinstance(keyid, str):
        return False
    if expires is not None and (isinstance(expires, bool) or not isinstance(expires, int) or now > expires + tolerance):
        return False
    if alg is not None and not isinstance(alg, str):
        return False

    # The replay window, symmetric as on the HMAC path.
    if abs(now - created) > tolerance:
        return False

    try:
        resolved = _resolve_public_key(key, keyid)
    except SignatureAlgorithmUnavailableError:
        # "Could not check" must not be flattened into "did not verify".
        raise
    except Exception:
        return False
    if resolved is None:
        return False
    public_key, window = resolved
    if window is not None and not _inside_key_window(created, window):
        return False

    lines = [f'"{c}": {component_values[c]}' for c in RFC9421_COVERED_COMPONENTS]
    lines.append(f'"@signature-params": {serialize_inner_list(sig_input)}')
    base = "\n".join(lines).encode("utf-8")
    return _verify_rfc9421_signature(public_key, signature, base, alg, invalid_signature)


def _assert_runtime_can_compute(alg_name: str) -> None:
    """Refuse to proceed when the host cannot compute the key's algorithm.

    A verification failure and an inability to verify are different events with
    opposite responses, so this raises instead of joining the ``False`` path: a
    caller doing ``if not ok: return 401`` would otherwise reject every
    legitimate delivery as forged. An uncaught exception surfacing as a 500 is
    the correct outcome, because the fault is in the receiver's configuration,
    not in the sender's signature.

    Capability is proven against a fixed known-answer signature, never inferred
    from a failed verification of the delivery itself: nothing an attacker
    sends may decide whether a bad signature gets reported as uncheckable.
    """
    if runtime_can_compute(alg_name):
        return
    raise SignatureAlgorithmUnavailableError(
        f"This host cannot compute {alg_name}, so the webhook signature could not "
        f"be checked. The usual cause is an active OpenSSL FIPS provider, which "
        f"carries no EdDSA. This is NOT a failed signature: the delivery may be "
        f"valid, forged, or expired, and on this host none of those can be told "
        f"apart. Terminate the signature on an unrestricted host, or configure "
        f"the sender for ecdsa-p256-sha256.",
        algorithm=alg_name,
    )


def _verify_rfc9421_signature(
    public_key: Ed25519PublicKey | EllipticCurvePublicKey,
    signature: bytes,
    base: bytes,
    declared_alg: str | None,
    invalid_signature: type[Exception],
) -> bool:
    """Dispatch RFC 9421 signature verification from the resolved key's type.

    The declared ``alg`` parameter (when present) is asserted against the
    key's algorithm, mirroring the TS SDK's ``algs`` allowlist: a P-256 key
    under ``alg="ed25519"`` must fail, never fall into a different code path.
    ES256 signatures are raw ``r||s`` (64 bytes) per RFC 9421; ``cryptography``
    expects DER, so the halves are re-encoded. Any other key type fails closed.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256

    try:
        if isinstance(public_key, Ed25519PublicKey):
            if declared_alg is not None and declared_alg != "ed25519":
                return False
            _assert_runtime_can_compute("Ed25519")
            public_key.verify(signature, base)
            return True
        if isinstance(public_key.curve, SECP256R1):
            # Attacker-controlled checks first, capability last. A mismatched
            # `alg` or a wrong-length signature is a definite reject, and must
            # stay a reject rather than becoming an environment error: nothing
            # the sender controls may decide whether we raise.
            if declared_alg is not None and declared_alg != "ecdsa-p256-sha256":
                return False
            if len(signature) != 64:
                return False
            _assert_runtime_can_compute("ES256")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public_key.verify(encode_dss_signature(r, s), base, ECDSA(SHA256()))
            return True
        return False
    except SignatureAlgorithmUnavailableError:
        # First, not last. `invalid_signature` is a caller-supplied class, so a
        # future caller passing something broad would otherwise swallow this
        # and silently reinstate the bug. Ordering makes the guarantee
        # structural rather than incidental.
        raise
    except invalid_signature:
        return False
    except Exception:
        return False


def construct_event_rfc9421(
    headers: Mapping[str, Any],
    raw_body: str,
    key: str | Sequence[Any],
    tolerance_seconds: float = MAX_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """Verify an RFC 9421 delivery and parse the payload in one step.

    Raises SignatureVerificationError if verification fails.
    """
    if not verify_rfc9421(headers, raw_body, key, tolerance_seconds):
        raise SignatureVerificationError(
            "RFC 9421 webhook signature verification failed",
            payload=raw_body.encode() if raw_body else None,
        )
    return _parse_webhook_event(raw_body)
