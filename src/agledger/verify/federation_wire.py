"""The sealed federation message on a receiving Server's chain entry.

When a peer's signed message (a state transition, a settlement signal, a
dispute leg, a co-sign request) is accepted, the receiver's chain entry for it
carries ``payload.wire``: the message as the sender signed it, with the
sender's registered key, the recipient hub id, the method, path, body hash,
timestamp, nonce, signature, and a copy of the body the hash covers. The
receiver's own vault signature covers all of that, so the entry proves what
the receiver accepted; verifying the sealed signature under the sender's
federation key proves what the sender asserted, from the receiver's export
alone.

The recipe is the Server's peer-auth check, re-run offline:

    bodyHash  = sha256 hex over the RFC 8785 (JCS) canonical JSON of body
    signInput = "<scheme>:<recipientHubId>:<method>:<path>:<bodyHash>:<timestamp>:<nonce>"
    verify signature (hex Ed25519) over the UTF-8 sign-input under senderPublicKey

then the entry's own fields against the body it sealed. Entries from before
the Server sealed messages, and entries a direct projection wrote, carry no
``wire``; absent is not a failure. Mirrors ``federation-wire.ts`` in
``@agledger/verify-core``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

FEDERATION_WIRE_SCHEME = "agledger.federation.v2"

#: The 12-byte SPKI prefix of an Ed25519 key.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

_WIRE_STRING_FIELDS = (
    "scheme",
    "senderHubId",
    "senderPublicKey",
    "recipientHubId",
    "method",
    "path",
    "bodyHash",
    "timestamp",
    "nonce",
    "signature",
)

#: Which entry payload fields must equal which body fields, per entry type.
#: The receiver projects these from the message, so a disagreement means the
#: entry says something the sender did not sign.
_FIELD_PAIRS: Mapping[str, Sequence[tuple[str, str]]] = {
    "FEDERATION_STATE_SYNC": (
        ("state", "state"),
        ("recordType", "type"),
        ("disputeId", "disputeId"),
        ("action", "action"),
    ),
    "FEDERATION_SIGNAL_RECEIVED": (("recommendation", "recommendation"),),
    "FEDERATION_CO_SIGN_RESPONDED": (
        ("recommendation", "recommendation"),
        ("state", "state"),
        ("outcomeHash", "outcomeHash"),
        ("idempotencyKey", "idempotencyKey"),
    ),
}


def _js_number(value: float) -> str:
    """A float as ECMAScript ``Number::toString`` writes it, which is what
    RFC 8785 specifies: the shortest round-trip digits, positional for
    exponents in [-6, 21), exponential outside."""
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)
    sign = "-" if text.startswith("-") else ""
    text = text.lstrip("-")
    if "e" in text:
        mantissa, exponent_text = text.split("e")
        exponent = int(exponent_text)
    else:
        mantissa, exponent = text, 0
    integer_part, _, fraction_part = mantissa.partition(".")
    all_digits = integer_part + fraction_part
    stripped = all_digits.lstrip("0")
    digits = stripped.rstrip("0") or "0"
    trailing = len(stripped) - len(digits)
    k = len(digits)
    # value = digits * 10 ** (n - k)
    n = exponent - len(fraction_part) + trailing + k
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    e_text = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + e_text
    return sign + digits[0] + "." + digits[1:] + "e" + e_text


def canonicalize_json(value: object) -> str:
    """RFC 8785 (JCS) canonical JSON, as the Server's ``canonicalize`` writes
    it: object keys sorted by UTF-16 code unit, no whitespace, ``-0`` as ``0``,
    non-finite numbers as ``null``, numbers in ECMAScript's shortest form."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        items = cast("Sequence[object]", value)
        return "[" + ",".join(canonicalize_json(v) for v in items) + "]"
    if isinstance(value, Mapping):
        obj = cast("Mapping[object, object]", value)
        keys = sorted((k for k in obj if isinstance(k, str)), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonicalize_json(obj[k]) for k in keys) + "}"
    return "null"


def normalize_federation_key(public_key_base64: object) -> str | None:
    """A federation key as base64 SPKI DER, from either form the Server's
    peer table holds: SPKI DER, or the raw 32-byte key. None for anything
    that is neither."""
    if not isinstance(public_key_base64, str) or not public_key_base64:
        return None
    try:
        raw = base64.b64decode(public_key_base64, validate=False)
    except (binascii.Error, ValueError):
        return None
    if len(raw) == 32:
        return base64.b64encode(_ED25519_SPKI_PREFIX + raw).decode()
    if len(raw) == 44 and raw[:12] == _ED25519_SPKI_PREFIX:
        return base64.b64encode(raw).decode()
    return None


def build_federation_key_registry(
    keys: Mapping[str, str] | Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    """Hub id to the sender's key as base64 SPKI DER, from ``{hubId: key}`` or
    ``[{"hubId": ..., "publicKey": ...}]``. Raises ``TypeError`` naming the
    entry on any key that is not an Ed25519 key in one of the two forms, so a
    mistyped key is refused before any verification runs."""
    out: dict[str, str] = {}
    entries: list[tuple[str, object, str]] = []
    given = cast("object", keys)
    if isinstance(given, Mapping):
        mapping = cast("Mapping[object, object]", given)
        for hub_id, key in mapping.items():
            label = f"federation_keys[{json.dumps(str(hub_id))}]"
            entries.append((hub_id if isinstance(hub_id, str) else "", key, label))
    elif isinstance(given, Sequence) and not isinstance(given, (str, bytes)):
        for i, item in enumerate(cast("Sequence[object]", given)):
            hub_id: object = None
            key: object = None
            if isinstance(item, Mapping):
                m = cast("Mapping[object, object]", item)
                hub_id = m.get("hubId")
                key = m.get("publicKey")
            entries.append((hub_id if isinstance(hub_id, str) else "", key, f"federation_keys[{i}]"))
    else:
        raise TypeError("federation_keys must be a {hubId: key} mapping or a list of {hubId, publicKey} entries.")
    for hub_id, key, label in entries:
        if not hub_id:
            raise TypeError(f"{label} names no hubId.")
        spki = normalize_federation_key(key)
        if spki is None:
            raise TypeError(f"{label} is not an Ed25519 public key (base64 SPKI DER, or base64 of the raw 32 bytes).")
        out[hub_id] = spki
    return out


def federation_sign_input(wire: Mapping[str, Any]) -> str:
    """The sign-input the Server builds, a colon-joined line under the scheme."""
    return ":".join(
        str(wire[k]) for k in ("scheme", "recipientHubId", "method", "path", "bodyHash", "timestamp", "nonce")
    )


def extract_federation_wire(payload: Mapping[str, Any]) -> Mapping[str, Any] | Literal["malformed"] | None:
    """The ``wire`` a row payload carries, or None when it carries none. A
    ``wire`` that is present but is not a sealed message is ``"malformed"``, so
    the caller fails it rather than reading an edited row as one with no
    message."""
    if "wire" not in payload:
        return None
    wire = payload["wire"]
    if not isinstance(wire, Mapping):
        return "malformed"
    w = cast("Mapping[str, Any]", wire)
    for k in _WIRE_STRING_FIELDS:
        if not isinstance(w.get(k), str):
            return "malformed"
    if not isinstance(w.get("body"), Mapping):
        return "malformed"
    return w


@dataclass
class FederationWireOutcome:
    outcome: Literal["ok", "unchecked", "invalid", "unsupported"]
    detail: str | None = None
    #: With ``ok``, whether the signature was checked under a supplied key.
    signature_checked: bool = False


@dataclass
class FederationWireCounts:
    """Federation messages sealed on the chain. ``present`` counts entries that
    passed every other check and carry one, each held to its own body hash
    and to the entry that carries it; ``verified`` counts those whose sealed
    signature was also checked under a ``federation_keys`` entry for the
    sending hub and found good. ``present > verified`` on a valid chain means
    no key was supplied for those senders, never that they failed."""

    present: int = 0
    verified: int = 0


def _verify_ed25519(spki_base64: str, message: bytes, signature: bytes) -> bool | None:
    """True or False for a key this host can load; None when it cannot (an
    OpenSSL FIPS provider refuses Ed25519)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        key = load_der_public_key(base64.b64decode(spki_base64))
    except Exception:
        return None
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(signature, message)
        return True
    except Exception:
        return False


def check_federation_wire(
    entry_type: object,
    record_id: object,
    payload: Mapping[str, Any],
    wire: Mapping[str, Any],
    keys: Mapping[str, str] | None,
) -> FederationWireOutcome:
    """Check one sealed message against the entry that carries it, and under
    the sender's key when ``keys`` has one for ``wire["senderHubId"]``. Runs on
    an entry that already passed every other check, so ``payload`` is what the
    receiver signed."""
    if wire["scheme"] != FEDERATION_WIRE_SCHEME:
        return FederationWireOutcome(
            "invalid", f"Sealed message scheme is {json.dumps(wire['scheme'])}, not {FEDERATION_WIRE_SCHEME}."
        )
    body = cast("Mapping[str, Any]", wire["body"])
    body_hash = hashlib.sha256(canonicalize_json(body).encode("utf-8")).hexdigest()
    if body_hash != str(wire["bodyHash"]).lower():
        return FederationWireOutcome(
            "invalid",
            "Sealed body does not hash to the bodyHash the sender signed: the body copy was edited after the "
            "message was verified.",
        )
    peer = payload.get("peerHubId")
    if isinstance(peer, str) and peer != wire["senderHubId"]:
        return FederationWireOutcome(
            "invalid", f"Entry names peer {peer}, the sealed message was sent by {wire['senderHubId']}."
        )
    body_record_id = body.get("recordId")
    if record_id is not None and isinstance(body_record_id, str) and body_record_id != record_id:
        return FederationWireOutcome(
            "invalid", f"Entry is on record {record_id}, the sealed message names record {body_record_id}."
        )
    for entry_field, body_field in _FIELD_PAIRS.get(str(entry_type), ()):
        mine = payload.get(entry_field)
        theirs = body.get(body_field)
        if mine is None or theirs is None:
            continue
        if canonicalize_json(mine) != canonicalize_json(theirs):
            return FederationWireOutcome(
                "invalid",
                f"Entry {entry_field} is {canonicalize_json(mine)}, the sealed message's {body_field} is "
                f"{canonicalize_json(theirs)}: the entry asserts what the sender did not sign.",
            )

    supplied = keys.get(str(wire["senderHubId"])) if keys is not None else None
    if supplied is None:
        return FederationWireOutcome("unchecked")
    if normalize_federation_key(wire["senderPublicKey"]) != supplied:
        return FederationWireOutcome(
            "invalid",
            f"The sealed senderPublicKey for {wire['senderHubId']} is not the federation key supplied for that "
            "hub: the receiver verified this message under a key the sender's operator did not give you.",
        )
    signature_hex = str(wire["signature"])
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        signature = b""
    if len(signature) != 64:
        return FederationWireOutcome("invalid", f"Sealed signature from {wire['senderHubId']} is not 64 bytes of hex.")
    verified = _verify_ed25519(supplied, federation_sign_input(wire).encode("utf-8"), signature)
    if verified is None:
        return FederationWireOutcome(
            "unsupported",
            f"Sealed message from {wire['senderHubId']} could not be checked: this host cannot compute Ed25519 "
            "(an active OpenSSL FIPS provider carries no EdDSA). Not verified, and not tamper evidence.",
        )
    if not verified:
        return FederationWireOutcome(
            "invalid",
            f"Sealed signature from {wire['senderHubId']} does not verify under that hub's federation key over "
            "the sign-input the entry seals.",
        )
    return FederationWireOutcome("ok", signature_checked=True)
