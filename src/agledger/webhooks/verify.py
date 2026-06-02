"""
AGLedger SDK — Webhook signature verification.
Mirrors the TypeScript SDK's webhooks/verify.ts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import TYPE_CHECKING, Any, Mapping, Sequence, Union, cast

from agledger._errors import SignatureVerificationError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_TOLERANCE_SECONDS = 300

#: Covered components an ed25519 delivery signs, lowercased per RFC 9421.
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


def verify_signature(
    raw_body: str,
    header: str,
    secrets: Union[str, list[str]],
    tolerance_seconds: int = MAX_TOLERANCE_SECONDS,
) -> bool:
    """Verify a webhook signature. Supports key rotation via list of secrets."""
    parsed = _parse_header(header)
    if not parsed:
        return False

    tolerance = min(tolerance_seconds, MAX_TOLERANCE_SECONDS)
    now = int(time.time())
    if abs(now - parsed["timestamp"]) > tolerance:
        return False

    secret_list = [secrets] if isinstance(secrets, str) else secrets
    signed_payload = f"{parsed['timestamp']}.{raw_body}"

    for secret in secret_list:
        expected = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
        for sig in parsed["signatures"]:
            if hmac.compare_digest(sig, expected):
                return True

    return False


def construct_event(
    raw_body: str,
    header: str,
    secrets: Union[str, list[str]],
    tolerance_seconds: int = MAX_TOLERANCE_SECONDS,
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


# RFC 9421 (ed25519) webhook verification.
#
# The asymmetric, opt-in signing tier (``signing_alg = 'ed25519'``). Deliveries
# are signed with the Server vault key as RFC 9421 HTTP Message Signatures; the
# receiver verifies against the published public key at GET /v1/verification-keys
# (matched by ``keyid``) and holds no secret — non-repudiation for the Settlement
# Signal hop. Covered components are exactly ``content-digest`` (RFC 9530 body
# integrity) and ``x-agledger-idempotency-key``; derived components are excluded
# because proxies rewrite them. Requires the optional ``cryptography`` dependency
# (``pip install 'agledger[verify]'``).

_SIG_INPUT_RE = re.compile(r"^([^=]+)=(\(.*\);.*)$", re.DOTALL)
_CREATED_RE = re.compile(r";created=(\d+)(?:;|$)")
_KEYID_RE = re.compile(r';keyid="([^"]*)"')


def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """Lowercase header keys and join multi-value headers into single strings."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            out[k.lower()] = ", ".join(str(x) for x in cast("Sequence[Any]", v))
        else:
            out[k.lower()] = str(v)
    return out


def _content_digest(raw_body: str) -> str:
    digest = base64.b64encode(hashlib.sha256(raw_body.encode("utf-8")).digest()).decode("ascii")
    return f"sha-256=:{digest}:"


def _load_ed25519_public_key(base64_key: str) -> "Ed25519PublicKey":
    """Build an Ed25519PublicKey from base64 (raw 32-byte or SPKI DER)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except ImportError as err:  # pragma: no cover
        raise ImportError(
            "The 'cryptography' package is required for RFC 9421 webhook verification. "
            "Install via: pip install 'agledger[verify]'"
        ) from err
    raw = base64.b64decode(base64_key)
    if len(raw) == 32:
        return Ed25519PublicKey.from_public_bytes(raw)
    loaded = load_der_public_key(raw)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return loaded


def _extract_key_fields(item: object) -> tuple[str | None, str | None]:
    """Pull (keyId, publicKey) from a VerificationKey model or a mapping."""
    if isinstance(item, Mapping):
        m = cast("Mapping[str, Any]", item)
        keyid = m.get("keyId") or m.get("key_id")
        material = m.get("publicKey") or m.get("public_key")
    else:
        keyid = getattr(item, "key_id", None)
        material = getattr(item, "public_key", None)
    return (
        keyid if isinstance(keyid, str) else None,
        material if isinstance(material, str) else None,
    )


def _resolve_public_key(key: Union[str, Sequence[object]], keyid: str | None) -> "Ed25519PublicKey | None":
    """Resolve a base64 public key from a single string or a verification-keys list."""
    if isinstance(key, str):
        return _load_ed25519_public_key(key)
    for item in key:
        item_keyid, material = _extract_key_fields(item)
        if item_keyid != keyid or material is None:
            continue
        return _load_ed25519_public_key(material)
    return None


def verify_rfc9421(
    headers: Mapping[str, Any],
    raw_body: str,
    key: Union[str, Sequence[Any]],
    tolerance_seconds: int = MAX_TOLERANCE_SECONDS,
) -> bool:
    """Verify an RFC 9421 (ed25519) webhook delivery — the non-repudiable tier.

    Recomputes the Content-Digest over ``raw_body``, reconstructs the RFC 9421
    signature base, resolves the public key by ``keyid``, verifies the Ed25519
    signature, and enforces the ``created`` replay window.

    :param headers: Delivery HTTP headers — must include ``content-digest``,
        ``signature-input``, ``signature``, and ``x-agledger-idempotency-key``.
        Casing and multi-value (list) headers are handled.
    :param raw_body: The raw request body string (do NOT parse JSON first).
    :param key: A single base64 public key (raw 32-byte or SPKI DER), or the
        ``.data`` list from ``client.verification_keys.list()`` (resolved by
        ``keyid``).
    :param tolerance_seconds: Replay window for the ``created`` time (default/max 300).
    :returns: True only if the signature, digest, and replay window all hold.
    """
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as err:  # pragma: no cover
        raise ImportError(
            "The 'cryptography' package is required for RFC 9421 webhook verification. "
            "Install via: pip install 'agledger[verify]'"
        ) from err

    h = _normalize_headers(headers)

    sig_input = h.get("signature-input")
    sig_header = h.get("signature")
    content_digest = h.get("content-digest")
    idempotency_key = h.get("x-agledger-idempotency-key")
    if not (sig_input and sig_header and content_digest and idempotency_key):
        return False

    # RFC 9530 body integrity.
    if content_digest != _content_digest(raw_body):
        return False

    m = _SIG_INPUT_RE.match(sig_input)
    if not m:
        return False
    label, params = m.group(1), m.group(2)

    # Signature header: ``<label>=:<base64>:`` (must use the same label).
    sig_prefix = f"{label}="
    if not sig_header.startswith(sig_prefix):
        return False
    sig_field = sig_header[len(sig_prefix):]
    if not (sig_field.startswith(":") and sig_field.endswith(":")):
        return False
    try:
        signature = base64.b64decode(sig_field[1:-1])
    except Exception:
        return False

    # Covered components, in declared order — only the two known header
    # components are supported (derived components are deliberately excluded).
    inner = params[params.index("(") + 1 : params.index(")")]
    covered = [c.strip().strip('"') for c in inner.split()] if inner.strip() else []
    if covered != list(RFC9421_COVERED_COMPONENTS):
        return False

    created_m = _CREATED_RE.search(params)
    if not created_m:
        return False
    created = int(created_m.group(1))
    tolerance = min(tolerance_seconds, MAX_TOLERANCE_SECONDS)
    if abs(int(time.time()) - created) > tolerance:
        return False

    keyid_m = _KEYID_RE.search(params)
    keyid = keyid_m.group(1) if keyid_m else None

    public_key = _resolve_public_key(key, keyid)
    if public_key is None:
        return False

    component_values = {"content-digest": content_digest, "x-agledger-idempotency-key": idempotency_key}
    lines = [f'"{c}": {component_values[c]}' for c in covered]
    lines.append(f'"@signature-params": {params}')
    base = "\n".join(lines).encode("utf-8")

    try:
        public_key.verify(signature, base)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def construct_event_rfc9421(
    headers: Mapping[str, Any],
    raw_body: str,
    key: Union[str, Sequence[Any]],
    tolerance_seconds: int = MAX_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """Verify an RFC 9421 (ed25519) delivery and parse the payload in one step.

    Raises SignatureVerificationError if verification fails.
    """
    if not verify_rfc9421(headers, raw_body, key, tolerance_seconds):
        raise SignatureVerificationError(
            "RFC 9421 webhook signature verification failed",
            payload=raw_body.encode() if raw_body else None,
        )
    return _parse_webhook_event(raw_body)
