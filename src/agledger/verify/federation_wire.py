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
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from agledger.verify.key_statements import rfc3339_ms

FEDERATION_WIRE_SCHEME = "agledger.federation.v2"

#: The domain a federation key statement's signatures sign under.
FEDERATION_KEY_STATEMENT_DOMAIN = "agledger.federation.key-statement.v1"

_INSTANT_US = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_SIG = re.compile(r"^[0-9a-fA-F]{128}$")

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


@dataclass(frozen=True)
class FederationTrustedKey:
    """One federation key a sender hub is trusted under, base64 SPKI DER, with
    the window its signed statements give it. Both bounds are None for a key
    given without a history: it is trusted at any time."""

    public_key: str
    activated_at: str | None = None
    retired_at: str | None = None


#: Hub id to the federation keys its messages are trusted under.
FederationKeyRegistry = Mapping[str, Sequence[FederationTrustedKey]]


@dataclass(frozen=True)
class _Statement:
    typ: str
    subject_key: str
    subject_digest: str
    activated_at: str | None
    predecessor_key: str | None = None
    predecessor_digest: str | None = None
    retired_at: str | None = None


def _spki_sha256(spki_base64: str) -> str:
    return hashlib.sha256(base64.b64decode(spki_base64)).hexdigest()


def _key_ref(value: object, extra: str) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    ref = cast("Mapping[str, Any]", value)
    if any(k not in ("publicKey", "spkiSha256", extra) for k in ref):
        return None
    public_key = ref.get("publicKey")
    digest = ref.get("spkiSha256")
    if not isinstance(public_key, str) or not isinstance(digest, str) or not _HEX64.match(digest):
        return None
    if normalize_federation_key(public_key) != public_key or _spki_sha256(public_key) != digest:
        return None
    return ref


def _verify_statement_signature(public_key: str, signature: object, payload: str) -> bool:
    if not isinstance(signature, str) or not _HEX_SIG.match(signature):
        return False
    message = f"{FEDERATION_KEY_STATEMENT_DOMAIN}:{payload}".encode()
    return _verify_ed25519(public_key, message, bytes.fromhex(signature)) is True


def _verify_key_statement(stmt: object, hub_id: str) -> _Statement | str:
    """The statement when it holds as the Server holds it, else why not.
    Mirrors verify-core's ``verifyKeyStatement``."""
    if not isinstance(stmt, Mapping):
        return "it is not an object"
    st = cast("Mapping[str, Any]", stmt)
    payload = st.get("payload")
    if not isinstance(payload, str):
        return "it carries no payload string"
    try:
        parsed: object = json.loads(payload)
    except ValueError:
        return "its payload is not JSON"
    if not isinstance(parsed, Mapping):
        return "its payload is not in its RFC 8785 canonical form"
    p = cast("Mapping[str, Any]", parsed)
    if canonicalize_json(p) != payload:
        return "its payload is not in its RFC 8785 canonical form"
    if any(k not in ("typ", "hubId", "subject", "predecessor") for k in p):
        return "its payload carries a field a statement does not"
    typ = p.get("typ")
    if typ not in ("genesis", "succession"):
        return f"its typ is {json.dumps(typ)}"
    if st.get("kind") != typ:
        return f"its kind {json.dumps(st.get('kind'))} is not its payload's typ {typ}"
    if p.get("hubId") != hub_id:
        return f"it names hub {json.dumps(p.get('hubId'))}"
    subject = _key_ref(p.get("subject"), "activatedAt")
    if subject is None:
        return "its subject is not an Ed25519 key with its digest"
    activated_at = subject.get("activatedAt")
    if not (activated_at is None or (isinstance(activated_at, str) and _INSTANT_US.match(activated_at))):
        return "its subject.activatedAt is not a microsecond RFC 3339 instant or null"
    predecessor: Mapping[str, Any] | None = None
    if "predecessor" in p:
        predecessor = _key_ref(p.get("predecessor"), "retiredAt")
        if predecessor is None:
            return "its predecessor is not an Ed25519 key with its digest"
        if not isinstance(predecessor.get("retiredAt"), str) or predecessor.get("retiredAt") != activated_at:
            return "its predecessor.retiredAt is not its subject.activatedAt"
        if predecessor["spkiSha256"] == subject["spkiSha256"]:
            return "it names one key as its own predecessor"
    elif activated_at is not None:
        return "it activates a key at a signed instant without naming a predecessor"
    if typ == "succession" and predecessor is None:
        return "it is a succession with no predecessor"
    if not _verify_statement_signature(str(subject["publicKey"]), st.get("subjectSignature"), payload):
        return "its subjectSignature does not verify under its subject key"
    if typ == "succession":
        assert predecessor is not None
        if not _verify_statement_signature(str(predecessor["publicKey"]), st.get("predecessorSignature"), payload):
            return "its predecessorSignature does not verify under its predecessor key"
    elif st.get("predecessorSignature") is not None:
        return "it is a genesis carrying a predecessorSignature"
    return _Statement(
        typ=str(typ),
        subject_key=str(subject["publicKey"]),
        subject_digest=str(subject["spkiSha256"]),
        activated_at=activated_at,
        predecessor_key=None if predecessor is None else str(predecessor["publicKey"]),
        predecessor_digest=None if predecessor is None else str(predecessor["spkiSha256"]),
        retired_at=None if predecessor is None else str(predecessor["retiredAt"]),
    )


def _trusted_keys_from_history(
    hub_id: str,
    pins: Sequence[tuple[str, str]],
    histories: Sequence[tuple[object, str]],
) -> list[FederationTrustedKey]:
    """The pin and every key a chain of successions links to it, each
    succession counted only when it admits its subject. Mirrors verify-core's
    ``trustedKeysFromHistory``."""
    statements: list[_Statement] = []
    seen_ids: set[str] = set()
    for doc, label in histories:
        if not isinstance(doc, Mapping) or not isinstance(cast("Mapping[str, Any]", doc).get("statements"), list):
            raise TypeError(f"{label} is not a federation key-history document (no statements array).")
        d = cast("Mapping[str, Any]", doc)
        if d.get("hubId") != hub_id:
            raise TypeError(f"{label} is the key history of hub {json.dumps(d.get('hubId'))}, not {hub_id}.")
        if d.get("statementDomain") != FEDERATION_KEY_STATEMENT_DOMAIN:
            raise TypeError(
                f"{label} signs under {json.dumps(d.get('statementDomain'))}, not {FEDERATION_KEY_STATEMENT_DOMAIN}."
            )
        for j, stmt in enumerate(cast("list[object]", d["statements"])):
            sid = cast("Mapping[str, Any]", stmt).get("id") if isinstance(stmt, Mapping) else None
            ident = sid if isinstance(sid, str) else f"#{j}"
            if ident in seen_ids:
                continue
            seen_ids.add(ident)
            verified = _verify_key_statement(cast("object", stmt), hub_id)
            if isinstance(verified, str):
                raise TypeError(
                    f"{label}.statements[{j}] ({ident}) does not hold: {verified}. A served history lists only "
                    "statements that verify, so this document was altered."
                )
            statements.append(verified)

    admission: dict[str, _Statement] = {}
    for st in statements:
        admission.setdefault(st.subject_digest, st)
    public_key_of: dict[str, str] = {}
    for st in statements:
        public_key_of[st.subject_digest] = st.subject_key
        if st.predecessor_digest is not None and st.predecessor_key is not None:
            public_key_of[st.predecessor_digest] = st.predecessor_key
    links: dict[str, list[str]] = {}
    retired_at: dict[str, str] = {}
    for st in statements:
        if st.typ != "succession" or admission.get(st.subject_digest) is not st or st.predecessor_digest is None:
            continue
        links.setdefault(st.predecessor_digest, []).append(st.subject_digest)
        links.setdefault(st.subject_digest, []).append(st.predecessor_digest)
        if st.retired_at is not None:
            retired_at.setdefault(st.predecessor_digest, st.retired_at)

    trusted: list[str] = []
    for spki, label in pins:
        digest = _spki_sha256(spki)
        if digest not in public_key_of:
            raise TypeError(
                f"{label}: the key pinned for hub {hub_id} appears in none of the key histories given for it, "
                "so the history is not linked to anything you hold."
            )
        queue = [digest]
        while queue:
            k = queue.pop()
            if k in trusted:
                continue
            trusted.append(k)
            queue.extend(links.get(k, []))
    return [
        FederationTrustedKey(
            public_key=public_key_of[d],
            activated_at=admission[d].activated_at if d in admission else None,
            retired_at=retired_at.get(d),
        )
        for d in trusted
    ]


def build_federation_key_registry(
    keys: Mapping[str, str] | Sequence[Mapping[str, Any]],
) -> dict[str, list[FederationTrustedKey]]:
    """Hub id to the keys its messages are trusted under, from ``{hubId: key}``
    or ``[{"hubId": ..., "publicKey": ..., "history"?: ...}]``. ``history`` is
    the sender's ``GET /.well-known/agledger-federation-keys.json``: every key
    it links to the pinned ``publicKey`` through successions both keys signed
    is trusted inside its window. A hub may be named more than once, to pin a
    key no succession links. Raises ``TypeError`` naming the entry on a key
    that is not an Ed25519 key, and on a history that is another hub's,
    carries a statement that does not verify, or never reaches the pin, so a
    bad input is refused before any verification runs."""
    entries: list[tuple[str, object, object, str]] = []
    given = cast("object", keys)
    if isinstance(given, Mapping):
        mapping = cast("Mapping[object, object]", given)
        for hub_id, key in mapping.items():
            label = f"federation_keys[{json.dumps(str(hub_id))}]"
            entries.append((hub_id if isinstance(hub_id, str) else "", key, None, label))
    elif isinstance(given, Sequence) and not isinstance(given, (str, bytes)):
        for i, item in enumerate(cast("Sequence[object]", given)):
            hub_id: object = None
            key: object = None
            history: object = None
            if isinstance(item, Mapping):
                m = cast("Mapping[object, object]", item)
                hub_id = m.get("hubId")
                key = m.get("publicKey")
                history = m.get("history")
            entries.append((hub_id if isinstance(hub_id, str) else "", key, history, f"federation_keys[{i}]"))
    else:
        raise TypeError("federation_keys must be a {hubId: key} mapping or a list of {hubId, publicKey} entries.")
    by_hub: dict[str, tuple[list[tuple[str, str]], list[tuple[object, str]]]] = {}
    for hub_id, key, history, label in entries:
        if not hub_id:
            raise TypeError(f"{label} names no hubId.")
        spki = normalize_federation_key(key)
        if spki is None:
            raise TypeError(f"{label} is not an Ed25519 public key (base64 SPKI DER, or base64 of the raw 32 bytes).")
        pins, histories = by_hub.setdefault(hub_id, ([], []))
        pins.append((spki, label))
        if history is not None:
            histories.append((history, f"{label}.history"))
    out: dict[str, list[FederationTrustedKey]] = {}
    for hub_id, (pins, histories) in by_hub.items():
        if not histories:
            out[hub_id] = [FederationTrustedKey(public_key=k) for k in dict.fromkeys(spki for spki, _ in pins)]
        else:
            out[hub_id] = _trusted_keys_from_history(hub_id, pins, histories)
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
    #: With ``ok``, the key the message is sealed under was retired, by a
    #: succession it signed, before the receiver wrote the entry: in order when
    #: the receiver's ``federation.peer_revoked`` audit row comes after it.
    after_retirement: bool = False


@dataclass
class FederationWireCounts:
    """Federation messages sealed on the chain. ``present`` counts entries that
    passed every other check and carry one, each held to its own body hash
    and to the entry that carries it; ``verified`` counts those whose sealed
    signature was also checked under a ``federation_keys`` entry for the
    sending hub and found good; ``failed`` counts those that failed a check
    (the body hash, the entry, or the signature under the hub's key).
    ``present - verified - failed`` is the messages from a hub with no key
    supplied. ``after_retirement`` counts verified ones sealed under a key the
    sender's history retired before the receiver wrote the entry."""

    present: int = 0
    verified: int = 0
    failed: int = 0
    after_retirement: int = 0


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
    keys: FederationKeyRegistry | None,
    received_at: object = None,
) -> FederationWireOutcome:
    """Check one sealed message against the entry that carries it, and under
    the sender's key when ``keys`` has one for ``wire["senderHubId"]``. Runs on
    an entry that already passed every other check, so ``payload`` is what the
    receiver signed. ``received_at`` is the entry's ``createdAt`` on the
    receiver's chain, which places the message in its key's window when the
    sender's keys came with a history."""
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

    trusted = keys.get(str(wire["senderHubId"])) if keys is not None else None
    if trusted is None:
        return FederationWireOutcome("unchecked")
    sealed = normalize_federation_key(wire["senderPublicKey"])
    key = next((k for k in trusted if k.public_key == sealed), None)
    if key is None:
        with_history = any(k.activated_at is not None or k.retired_at is not None for k in trusted)
        return FederationWireOutcome(
            "invalid",
            f"The sealed senderPublicKey for {wire['senderHubId']} is not a federation key its history links to "
            "the key you pinned: the receiver verified this message under a key no succession from your pin "
            "reaches. A key listed linked: false sits behind a genesis that named it without its signature; pin "
            "it too once its operator confirms it."
            if with_history
            else f"The sealed senderPublicKey for {wire['senderHubId']} is not the federation key supplied for "
            "that hub: the receiver verified this message under a key the sender's operator did not give you. If "
            "the sender changed its federation key, supply its key history (GET "
            "/.well-known/agledger-federation-keys.json on the sender) with the key you pinned.",
        )
    after_retirement = False
    if key.activated_at is not None or key.retired_at is not None:
        at = rfc3339_ms(received_at)
        if at is None:
            return FederationWireOutcome(
                "invalid",
                f"Entry has no parseable createdAt, so the sealed message from {wire['senderHubId']} cannot be "
                "placed in its key's window.",
            )
        activated = rfc3339_ms(key.activated_at)
        if activated is not None and at < activated:
            return FederationWireOutcome(
                "invalid",
                f"Entry written {received_at} seals a message from {wire['senderHubId']} under a federation key "
                f"its history activates at {key.activated_at}, after the receiver says it took the message.",
            )
        retired = rfc3339_ms(key.retired_at)
        after_retirement = retired is not None and at > retired
    signature_hex = str(wire["signature"])
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        signature = b""
    if len(signature) != 64:
        return FederationWireOutcome("invalid", f"Sealed signature from {wire['senderHubId']} is not 64 bytes of hex.")
    verified = _verify_ed25519(key.public_key, federation_sign_input(wire).encode("utf-8"), signature)
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
    return FederationWireOutcome("ok", signature_checked=True, after_retirement=after_retirement)
