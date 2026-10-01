"""Vault key statements and the trust walk over them.

A vault key is trusted only when signed key statements link it to a key the
verifier pinned out of band (``trust_anchors``). The Server's database stores
the statements and never vouches for them: anything with write access to it
can add a ``vault_signing_keys`` row and a statement row, and neither makes a
key trusted, because every edge below is a signature that writer cannot
produce. This is the engine's ``computeKeyTrust``, re-implemented as
``@agledger/verify-core`` 2.0 implements it, so the verifier has no engine
dependency. Where the two could disagree, this one must never trust a key the
engine refuses.

**Format.** Each statement is one or two COSE_Sign1 (RFC 9052, tag 18) over the
SAME deterministic-CBOR (RFC 8949 section 4.2.1) payload, protected header
``{1: alg, 3: cty, 4: kid}`` with ``cty`` = :data:`KEY_STATEMENT_CTY`. The
payload is a text-keyed map:

    typ        'succession' | 'closure' | 'genesis'
    iss        the Server's issuer URL (informational)
    subject    { kid, spkiSha256, alg, spki (bstr), activatedAt, retiredAt? }
    endorser   { kid, spkiSha256 }            absent on genesis
    iat        epoch seconds, informational only, never used for ordering
    forced     bool                           closure only

``activatedAt`` / ``retiredAt`` are RFC 3339 UTC instants at microsecond
precision. A succession is signed by the endorser and then by the subject; a
closure by a key other than its subject; a genesis by its subject alone, and it
grants no trust.

**Write order.** The rule orders statements by the database's write order. A
dump carries it (``created_at``, then the file's own row order, which the
producer writes as ``created_at, id``). The key documents (``GET
/v1/verification-keys``, an export's ``exportMetadata.signingKeyStatements``)
do not, so statements read from them are ordered by the instant they sign (a
genesis or succession by ``subject.activatedAt``, a closure by
``subject.retiredAt``). For an honest document the two orders agree, because
the Server signs the instant it writes. What the signed order cannot do is hold
a leaked key to the time it actually wrote a statement: a key retired without
``forced`` whose private half later leaks can date a statement before its
retirement. Such a statement is only ever in a document that did not come from
the Server. A forced closure voids every edge out of its key whatever the
order, and a walk over a dump applies the real write order.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from agledger._runtime_crypto import runtime_can_compute

try:
    import cbor2 as _cbor2
except ImportError as _err:  # pragma: no cover
    raise ImportError(
        "The 'cbor2' package is required for key-statement verification. "
        "Install via: pip install 'agledger[verify]'"
    ) from _err

try:
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA as _ECDSA,
        SECP256R1 as _SECP256R1,
        EllipticCurvePublicKey as _EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as _Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature as _encode_dss_signature,
    )
    from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
except ImportError as _err:  # pragma: no cover
    raise ImportError(
        "The 'cryptography' package is required for key-statement verification. "
        "Install via: pip install 'agledger[verify]'"
    ) from _err

#: Content type of a key statement's COSE_Sign1 (protected header label 3).
KEY_STATEMENT_CTY = "application/vnd.agledger.key-statement+cbor"

#: The statement kinds the format defines.
KEY_STATEMENT_KINDS = ("succession", "closure", "genesis")

KeyStatementKind = Literal["succession", "closure", "genesis"]

#: The finding codes the walk reports about the key registry itself.
KeyRegistryFindingCode = Literal["KEY_STATEMENT_INVALID", "KEY_CLOSURE_INVALID", "CHAIN_KEY_WINDOW_DRIFT"]

#: What the walk concluded about a key once a registry is marked with it.
#: ``anchored``: signed statements link it to a pinned anchor. ``unanchored``:
#: nothing signed does, so what it signed fails the ``*_KEY_UNANCHORED`` codes.
#: ``undecided``: the only link runs through a signature this host cannot
#: compute, so what it signed is CHAIN_UNSUPPORTED_ALGORITHM, not tamper.
KeyTrustState = Literal["anchored", "unanchored", "undecided"]

# The COSE ``alg`` a statement signature must carry for its key's algorithm.
# Exactly one per algorithm, as the engine signs and checks them; the chain
# envelope's wider acceptance (RFC 9864 fully-specified code points) does not
# apply to statements.
_STATEMENT_COSE_ALG: dict[str, int] = {"Ed25519": -8, "ES256": -7}

_COSE_HEADER_ALG = 1
_COSE_HEADER_CTY = 3
_COSE_HEADER_KID = 4
_COSE_SIGN1_TAG = 18
_COSE_SIGN1_TAG_PREFIX = 0xD2
_SIG_STRUCTURE_CONTEXT = "Signature1"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX16 = re.compile(r"[0-9a-f]{16}")
# RFC 3339 UTC at microsecond precision, the shape the statements sign.
_INSTANT_US = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_MAX_SAFE_INTEGER = 2**53 - 1


# --- Inputs ---


@dataclass(frozen=True)
class KeyStatementInput:
    """One key statement as a source carries it. A dump row maps onto it with
    :func:`key_statement_from_dump_row`; a key document's ``statements`` with
    :func:`key_statements_from_verification_keys` or
    :func:`key_statements_from_export`."""

    kind: str
    """The source's own ``kind`` column, bound to the signed ``typ``."""
    cose: Sequence[str | bytes]
    """The COSE_Sign1 signatures, base64 or bytes, in signing order."""
    id: str | None = None
    """Row id (the dump's ``id``), named in findings."""
    subject_key_id: str | None = None
    """The key id the source files the statement under, bound to the signed
    ``subject.kid``. ``None`` when the source names none."""
    endorser_key_id: str | None = None
    """The source's ``endorser_key_id`` column, bound to the signed
    ``endorser.kid`` when ``endorser_column`` is set (``None`` for a genesis)."""
    endorser_column: bool = False
    """Whether the source carries an ``endorser_key_id`` column at all. The key
    documents do not, so theirs is not bound."""
    created_at: str | None = None
    """The database write time (the dump's ``created_at``). Give it for every
    statement or for none: with it the walk applies the write order, without it
    the signed order (see the module docstring). Under the write order a
    statement whose ``created_at`` is not an RFC 3339 instant cannot be placed,
    and is KEY_STATEMENT_INVALID (:func:`key_statement_from_dump_row` gives
    ``""`` for a row without one)."""


@dataclass(frozen=True)
class TrustKeyInput:
    """A key the source lists: the walk's fallback for the material of an
    endorser no statement names as its subject, and the columns the drift check
    holds against the signed window. Window and status fields are compared
    only when given."""

    key_id: str
    public_key: str
    """SPKI DER, base64."""
    algorithm: str | None = None
    status: Literal["active", "retired"] | None = None
    activated_at: Any = None
    retired_at: Any = None


@dataclass(frozen=True)
class DistrustedKey:
    """A key distrusted from outside the database, the verifier-side mirror of
    the Server's ``VAULT_DISTRUSTED_KEYS``. See :func:`parse_distrusted_keys`."""

    spki_sha256: str
    """Full SHA-256 of the key's SPKI DER, lowercase hex."""
    cutoff: str | None
    """RFC 3339 UTC instant at microsecond precision from which what the key
    signs counts for nothing. ``None``: the earliest ``retiredAt`` a counting
    closure by a key that is not distrusted signs for it, and when there is
    none the key is trusted for nothing."""


# --- Outputs ---


@dataclass(frozen=True)
class KeyRegistryFinding:
    """A finding about the key registry itself, not about any chain entry."""

    code: KeyRegistryFindingCode
    key_id: str | None
    statement_id: str | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {"code": self.code, "keyId": self.key_id, "statementId": self.statement_id, "detail": self.detail}


@dataclass
class KeyTrustEntry:
    """What the walk concludes about one key."""

    key_id: str
    spki_sha256: str
    trusted: bool
    """Anchored: reached from the trust anchors over edges that count."""
    undecided: bool
    """Reached only through a statement signed under an algorithm this host
    cannot compute, and the key's own algorithm is one of those. What it signed
    cannot be verified here, which is not tamper evidence."""
    activated_at: str | None
    """The signed lower edge, or ``None`` when no counting statement signs one."""
    retired_at: str | None
    """The signed upper edge, or ``None`` when no counting closure signs one."""
    distrust_cutoff: str | None = None
    """The instant from which ``distrusted_keys`` voids what this key signs,
    when it ends the key's window before its signed retirement, else ``None``.
    The key is not retired there: entries written after it fail
    CHAIN_KEY_EXPIRED as past the distrust cutoff, not as past a retirement."""


@dataclass(frozen=True)
class KeyStatementCounts:
    total: int
    valid: int
    invalid: int
    unverifiable: int


@dataclass
class KeyTrust:
    """The walk's result. See :func:`compute_key_trust`."""

    order: Literal["written", "signed"]
    """``written`` when every statement carried ``created_at``, else ``signed``."""
    anchors: list[str]
    """The anchors walked from, as ``sha256:<hex>``."""
    by_digest: dict[str, KeyTrustEntry]
    """Every key the walk saw, by full SPKI SHA-256 (hex)."""
    trusted: set[str]
    """SPKI digests of the trusted keys."""
    undecided: set[str]
    """SPKI digests of the undecided keys."""
    findings: list[KeyRegistryFinding]
    statements: KeyStatementCounts


_NO_ANCHOR_DETAIL = (
    "No trustAnchors were given, so no key was anchored and this is not a trusted verdict: "
    "every key was taken on the word of whoever embedded or supplied it, and a key written "
    "into the Server's database alone would verify. Pin the SPKI digest of a vault key you "
    "hold or took out of band (sha256:<hex>) as trustAnchors."
)

KeyTrustStatus = Literal["walked", "no_anchor", "no_anchored_signature"]
"""Whether a verification can be read as trusted. Mirrors verify-core's
``KeyTrustStatus``.

- ``walked``: the key statements were walked from the caller's anchors and at
  least one signature verified under a key they anchor. The one status a
  passing result is trusted on.
- ``no_anchor``: no trust anchors were given, so no key was anchored and every
  key was taken on the word of whoever embedded or supplied it. A pass is not a
  trusted verdict.
- ``no_anchored_signature``: the walk ran, but no signature in the artifact
  verified under a key it anchors (every entry is unsigned history, or the
  chain broke first). An unsigned entry proves nothing about who wrote it, so a
  pass is not a trusted verdict either.

Every surface reads ``no_anchor`` and ``no_anchored_signature`` alike: a pass
on either is ``unanchored``, never ``trusted``."""


@dataclass
class KeyTrustReport:
    """What a verification result says about key anchoring."""

    status: KeyTrustStatus
    """See :data:`KeyTrustStatus`."""
    detail: str
    anchors: list[str] = field(default_factory=list[str])
    """The anchors walked from, as ``sha256:<hex>``."""
    anchored_from: str | None = None
    """The artifact's own claim of the key it was anchored from
    (``sha256:<hex>``), when it carries one."""
    anchored_from_pinned: bool | None = None
    """Whether ``anchored_from`` is one of ``anchors``; ``None`` when either is absent."""
    order: Literal["written", "signed"] | None = None
    """How the statements were ordered (see :func:`compute_key_trust`); ``None``
    when no walk ran."""
    anchored_key_ids: list[str] = field(default_factory=list[str])
    unanchored_key_ids: list[str] = field(default_factory=list[str])
    undecided_key_ids: list[str] = field(default_factory=list[str])
    findings: list[KeyRegistryFinding] = field(default_factory=list[KeyRegistryFinding])

    def to_json(self) -> dict[str, Any]:
        """camelCase dict, the shape ``@agledger/verify-core``'s ``KeyTrustReport`` serializes to."""
        return {
            "status": self.status,
            "detail": self.detail,
            "anchors": list(self.anchors),
            "anchoredFrom": self.anchored_from,
            "anchoredFromPinned": self.anchored_from_pinned,
            "order": self.order,
            "anchoredKeyIds": list(self.anchored_key_ids),
            "unanchoredKeyIds": list(self.unanchored_key_ids),
            "undecidedKeyIds": list(self.undecided_key_ids),
            "findings": [f.to_json() for f in self.findings],
        }


def no_anchor_report(anchored_from: str | None = None) -> KeyTrustReport:
    """The report for a verification that ran no walk (no trust anchors)."""
    return KeyTrustReport(status="no_anchor", detail=_NO_ANCHOR_DETAIL, anchored_from=anchored_from)


def report_key_trust(
    states: Mapping[str, KeyTrustState | None],
    trust: KeyTrust | None,
    anchored_from: str | None,
) -> KeyTrustReport:
    """Summarize a registry marked with the walk's verdicts (``states`` maps
    each key id to its :data:`KeyTrustState`), or with ``trust`` ``None`` when
    no walk ran. A walked report says ``walked`` until the caller settles it
    with :func:`settle_key_trust`. An ``anchored_from`` that is not a string is
    read as absent."""
    if not isinstance(anchored_from, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        anchored_from = None
    if trust is None:
        return no_anchor_report(anchored_from)

    def ids(state: KeyTrustState) -> list[str]:
        return sorted(k for k, s in states.items() if s == state)

    unanchored = ids("unanchored")
    anchors = ", ".join(trust.anchors)
    return KeyTrustReport(
        status="walked",
        detail=(
            f"Every key is linked by signed key statements to {anchors}."
            if not unanchored
            else (
                f"Keys {', '.join(unanchored)} are not linked by any signed key statement to "
                f"{anchors}; entries they signed fail CHAIN_SIGNING_KEY_UNANCHORED."
            )
        ),
        anchors=list(trust.anchors),
        anchored_from=anchored_from,
        anchored_from_pinned=None if anchored_from is None else anchored_from.lower() in trust.anchors,
        order=trust.order,
        anchored_key_ids=ids("anchored"),
        unanchored_key_ids=unanchored,
        undecided_key_ids=ids("undecided"),
        findings=list(trust.findings),
    )


def settle_key_trust(report: KeyTrustReport, anchored_signatures: int) -> KeyTrustReport:
    """Settle a walked report once the caller has counted the signatures that
    verified under an anchored key (an export's or a dump's entries whose
    signature checked out, since under a walk every such key is anchored).
    With none, the report becomes ``no_anchored_signature``: the pin was
    walked, but nothing in the artifact is signed by a key it anchors, so a
    pass is not a trusted verdict. Any other report is returned as it is.
    Mirrors verify-core ``settleKeyTrust``."""
    if report.status != "walked" or anchored_signatures > 0:
        return report
    return replace(
        report,
        status="no_anchored_signature",
        detail=(
            f"The key statements were walked from {', '.join(report.anchors)}, but no signature "
            "here verified under a key they anchor, so this is not a trusted verdict: an entry "
            "written before the install began signing carries no signature, and proves nothing "
            "about who wrote it."
        ),
    )


# --- Instants and base64 ---

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_INSTANT = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})"
)


def _parse_iso_ms(value: str) -> int | None:
    """Milliseconds of an ISO-8601 time as ``Date.parse`` reads the forms the
    verifier meets, or ``None`` when it does not parse. A time without an offset
    reads as UTC."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (parsed - _EPOCH) // timedelta(milliseconds=1)


def instant_ms(instant: object) -> int | None:
    """Milliseconds of an RFC 3339 instant, truncating any finer fraction the
    way the engine reads a microsecond instant. Key statements sign microsecond
    instants; entry write times, dump columns and key documents carry
    milliseconds, so every comparison between them is made here. ``None`` when
    the value does not parse. Mirrors verify-core ``instantMs``."""
    if not isinstance(instant, str) or not instant:
        return None
    m = _INSTANT.fullmatch(instant)
    if m is None:
        return _parse_iso_ms(instant)
    frac = (m.group(2) or "")[:3].ljust(3, "0")
    offset = "+00:00" if m.group(3) == "Z" else m.group(3)
    return _parse_iso_ms(f"{m.group(1)}.{frac}{offset}")


def _b64decode(value: str) -> bytes:
    """Decode base64 the way Node's ``Buffer.from(value, 'base64')`` does:
    tolerant of missing padding and of the URL-safe alphabet."""
    cleaned = re.sub(r"[^A-Za-z0-9+/\-_]", "", value.split("=", 1)[0]).replace("-", "+").replace("_", "/")
    if len(cleaned) % 4 == 1:
        cleaned = cleaned[:-1]
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4))
    except (binascii.Error, ValueError):
        return b""


def spki_sha256(spki_base64: str) -> str:
    """The full SHA-256 of a base64 SPKI DER, lowercase hex."""
    return hashlib.sha256(_b64decode(spki_base64)).hexdigest()


# --- Parsing the out-of-band inputs ---


def _list_of(raw: str | Sequence[str], name: str) -> list[str]:
    value = cast(object, raw)
    if isinstance(value, str):
        parts: list[object] = list(value.split(","))
    elif isinstance(value, (bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{name} must be a string or a list of strings (got {type(value).__name__}).")
    else:
        parts = list(cast("Sequence[object]", value))
    out: list[str] = []
    for p in parts:
        if not isinstance(p, str):
            raise TypeError(f"{name}: expected a string entry (got {type(p).__name__}).")
        stripped = p.strip()
        if stripped:
            out.append(stripped)
    return out


_ANCHOR = re.compile(r"sha256:([0-9a-f]{64})")


def parse_trust_anchors(raw: str | Sequence[str]) -> list[str]:
    """Parse trust anchors: ``sha256:<64 hex>`` entries, as a list or a comma
    list (the Server's ``VAULT_TRUST_ANCHORS`` form). Returns the bare lowercase
    hex digests. Raises ``TypeError`` naming any entry in another shape."""
    out: list[str] = []
    for entry in _list_of(raw, "trust_anchors"):
        m = _ANCHOR.fullmatch(entry.lower())
        if m is None:
            raise TypeError(
                f'trust_anchors entry "{entry}" is not sha256:<64 hex>. Each anchor is the full '
                "SHA-256 of a vault public key's SPKI DER, taken out of band: the installer prints "
                "it, and the Server's signing-key-digest.js derives it from the key."
            )
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


# RFC 3339 with a ``Z`` or numeric offset and up to microsecond fractions.
_RFC3339 = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{1,6}|)(Z|[+-][0-9]{2}:[0-9]{2})"
)


def _cutoff_of(text: str) -> str | None:
    """The instant after ``@`` as UTC at microsecond precision, or ``None``
    when it is not an RFC 3339 instant on a real calendar day."""
    m = _RFC3339.fullmatch(text.upper())
    if m is None:
        return None
    try:
        fields = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    offset = m.group(3)
    if offset != "Z":
        hours, minutes = int(offset[1:3]), int(offset[4:6])
        if hours > 23 or minutes > 59:
            return None
        delta = timedelta(hours=hours, minutes=minutes)
        fields = fields - delta if offset[0] == "+" else fields + delta
    frac = m.group(2)[1:].ljust(6, "0")
    return f"{fields.strftime('%Y-%m-%dT%H:%M:%S')}.{frac}Z"


def parse_distrusted_keys(raw: str | Sequence[str]) -> list[DistrustedKey]:
    """Parse distrusted keys in the Server's ``VAULT_DISTRUSTED_KEYS`` form, as
    a list or a comma list: ``sha256:<64 hex>``, each optionally ``@<RFC 3339
    instant>``, the instant from which what the key signs counts for nothing.
    The instant comes back in UTC at microsecond precision. Raises
    ``TypeError`` naming any other entry, or a key named twice."""
    out: list[DistrustedKey] = []
    for entry in _list_of(raw, "distrusted_keys"):
        at = entry.find("@")
        m = _ANCHOR.fullmatch((entry if at == -1 else entry[:at]).lower())
        cutoff = None if at == -1 else _cutoff_of(entry[at + 1 :])
        if m is None or (at != -1 and cutoff is None):
            raise TypeError(
                f'distrusted_keys entry "{entry}" is not sha256:<64 hex>, optionally followed by '
                "@<RFC 3339 instant> (2026-09-01T00:00:00Z). Each entry is the full SHA-256 of a "
                "vault public key's SPKI DER, as in the Server's VAULT_DISTRUSTED_KEYS."
            )
        digest = m.group(1)
        if any(d.spki_sha256 == digest for d in out):
            raise TypeError(
                f"distrusted_keys names sha256:{digest} twice. Give each key one entry, with the "
                "earliest instant it may have leaked."
            )
        out.append(DistrustedKey(spki_sha256=digest, cutoff=cutoff))
    return out


def _normalize_distrusted(raw: str | Sequence[str | DistrustedKey] | None) -> list[DistrustedKey]:
    if raw is None:
        return []
    value = cast(object, raw)
    if isinstance(value, str):
        return parse_distrusted_keys(value)
    if isinstance(value, (bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError("distrusted_keys must be a list.")
    items = list(cast("Sequence[object]", value))
    parsed = parse_distrusted_keys([d for d in items if isinstance(d, str)])
    for d in items:
        if isinstance(d, str):
            continue
        if (
            not isinstance(d, DistrustedKey)
            or not isinstance(d.spki_sha256, str)  # pyright: ignore[reportUnnecessaryIsInstance]
            or _HEX64.fullmatch(d.spki_sha256) is None
            or (d.cutoff is not None and (not isinstance(d.cutoff, str) or _INSTANT_US.fullmatch(d.cutoff) is None))  # pyright: ignore[reportUnnecessaryIsInstance]
        ):
            raise TypeError(
                "distrusted_keys entry is not DistrustedKey(spki_sha256=<64 lowercase hex>, "
                "cutoff=<microsecond RFC 3339 UTC instant> | None)."
            )
        if any(p.spki_sha256 == d.spki_sha256 for p in parsed):
            raise TypeError(
                f"distrusted_keys names sha256:{d.spki_sha256} twice. Give each key one entry, "
                "with the earliest instant it may have leaked."
            )
        parsed.append(DistrustedKey(spki_sha256=d.spki_sha256, cutoff=d.cutoff))
    return parsed


# --- CBOR decoding, as strict as cborg's ---

_ABSENT: Any = object()


def _loads_whole(data: bytes) -> Any:
    """Decode exactly one CBOR item spanning all of ``data`` (cborg refuses
    trailing bytes; ``cbor2.loads`` ignores them)."""
    fp = io.BytesIO(data)
    obj: Any = _cbor2.CBORDecoder(fp).decode()
    if fp.read(1):
        raise ValueError("trailing bytes after the CBOR item")
    return obj


def cbor_plain(value: object, *, text_keys: bool) -> bool:
    """Whether a decoded value holds only what cborg decodes without a tag
    decoder: no tags (cbor2 turns some into ``datetime``, ``Decimal`` and the
    like), and with ``text_keys`` only text map keys (cborg with ``useMaps:
    false`` refuses any other)."""
    if value is None or value is _cbor2.undefined or isinstance(value, (bool, int, float, str, bytes)):
        return True
    if isinstance(value, (list, tuple)):
        return all(cbor_plain(v, text_keys=text_keys) for v in cast("Sequence[object]", value))
    if isinstance(value, Mapping):
        items = cast("Mapping[object, object]", value).items()
        return all(
            (isinstance(k, str) or not text_keys) and cbor_plain(k, text_keys=text_keys) and cbor_plain(v, text_keys=text_keys)
            for k, v in items
        )
    return False


def _get(m: Mapping[Any, Any], key: object) -> Any:
    """A map member, or ``_ABSENT`` when it is missing or CBOR ``undefined``
    (cborg decodes ``undefined`` to JavaScript's, which reads as absent)."""
    if key not in m:
        return _ABSENT
    v = m[key]
    return _ABSENT if v is _cbor2.undefined else v


def _to_bytes(v: object) -> bytes | None:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str) and _BASE64.fullmatch(v) is not None:
        return _b64decode(v)
    return None


@dataclass(frozen=True)
class _Sign1:
    protected_bstr: bytes
    payload_bstr: bytes
    signature: bytes
    alg: int | float | None
    cty: Any
    kid: str | None


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _decode_sign1(raw: object) -> _Sign1 | None:
    data = _to_bytes(raw)
    if data is None or len(data) == 0 or data[0] != _COSE_SIGN1_TAG_PREFIX:
        return None
    try:
        decoded: Any = _loads_whole(data)
        if not isinstance(decoded, _cbor2.CBORTag) or decoded.tag != _COSE_SIGN1_TAG:
            return None
        inner: object = decoded.value
        if not isinstance(inner, (list, tuple)):
            return None
        seq = cast("Sequence[object]", inner)
        if len(seq) != 4 or not cbor_plain(seq, text_keys=False):
            return None
        p, _unprotected, payload, sig = seq
        if not isinstance(p, bytes) or not isinstance(payload, bytes) or not isinstance(sig, bytes):
            return None
        header: object = _loads_whole(p)
        if not isinstance(header, Mapping):
            return None
        hmap = cast("Mapping[object, object]", header)
        if not cbor_plain(hmap, text_keys=False):
            return None
        alg = _get(hmap, _COSE_HEADER_ALG)
        kid = _get(hmap, _COSE_HEADER_KID)
        return _Sign1(
            protected_bstr=p,
            payload_bstr=payload,
            signature=sig,
            alg=cast("int | float", alg) if _is_number(alg) else None,
            cty=_get(hmap, _COSE_HEADER_CTY),
            kid=kid.hex() if isinstance(kid, bytes) else None,
        )
    except Exception:
        return None


@dataclass(frozen=True)
class _KeyRef:
    kid: str
    spki_sha256: str


@dataclass(frozen=True)
class _Subject:
    kid: str
    spki_sha256: str
    alg: str
    spki: str
    activated_at: str
    retired_at: str | None


@dataclass(frozen=True)
class _Payload:
    typ: KeyStatementKind
    iss: str
    subject: _Subject
    endorser: _KeyRef | None
    iat: int
    forced: bool | None


def _read_key_ref(v: object) -> _KeyRef | None:
    if not isinstance(v, Mapping):
        return None
    r = cast("Mapping[str, object]", v)
    kid = _get(r, "kid")
    digest = _get(r, "spkiSha256")
    if not isinstance(kid, str) or _HEX16.fullmatch(kid) is None:
        return None
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        return None
    return _KeyRef(kid=kid, spki_sha256=digest)


def _decode_payload(data: bytes) -> _Payload | None:
    """Decode and shape-check payload bytes. ``None`` when anything is missing,
    mistyped, not canonical, or inconsistent (the subject's digest must be the
    SHA-256 of the spki it carries, and its kid the first 16 hex of that
    digest)."""
    try:
        raw: Any = _loads_whole(data)
    except Exception:
        return None
    if not cbor_plain(raw, text_keys=True):
        return None
    # Canonical bytes only: two encodings of one payload would carry two digests.
    try:
        if _cbor2.dumps(raw, canonical=True) != data:
            return None
    except Exception:
        return None
    if not isinstance(raw, Mapping):
        return None
    r = cast("Mapping[str, object]", raw)
    typ = _get(r, "typ")
    if not isinstance(typ, str) or typ not in KEY_STATEMENT_KINDS:
        return None
    iss = _get(r, "iss")
    iat = _get(r, "iat")
    if not isinstance(iss, str) or not isinstance(iat, int) or isinstance(iat, bool):
        return None
    if abs(iat) > _MAX_SAFE_INTEGER:
        return None
    s = _get(r, "subject")
    if not isinstance(s, Mapping):
        return None
    sub = cast("Mapping[str, object]", s)
    ref = _read_key_ref(sub)
    spki = _get(sub, "spki")
    alg = _get(sub, "alg")
    activated_at = _get(sub, "activatedAt")
    retired_at = _get(sub, "retiredAt")
    if ref is None or not isinstance(spki, bytes) or not isinstance(alg, str):
        return None
    if not isinstance(activated_at, str) or _INSTANT_US.fullmatch(activated_at) is None:
        return None
    if retired_at is not _ABSENT and (not isinstance(retired_at, str) or _INSTANT_US.fullmatch(retired_at) is None):
        return None
    if hashlib.sha256(spki).hexdigest() != ref.spki_sha256 or ref.kid != ref.spki_sha256[:16]:
        return None
    endorser: _KeyRef | None = None
    e = _get(r, "endorser")
    if e is not _ABSENT:
        endorser = _read_key_ref(e)
        if endorser is None:
            return None
    forced: bool | None = None
    f = _get(r, "forced")
    if f is not _ABSENT:
        if not isinstance(f, bool):
            return None
        forced = f
    return _Payload(
        typ=typ,
        iss=iss,
        subject=_Subject(
            kid=ref.kid,
            spki_sha256=ref.spki_sha256,
            alg=alg,
            spki=base64.b64encode(spki).decode(),
            activated_at=activated_at,
            retired_at=cast("str", retired_at) if retired_at is not _ABSENT else None,
        ),
        endorser=endorser,
        iat=iat,
        forced=forced,
    )


def _sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return _cbor2.dumps([_SIG_STRUCTURE_CONTEXT, protected_bstr, b"", payload_bstr], canonical=True)


# --- Key material and signatures ---

_Alg = Literal["Ed25519", "ES256"]
_Material = tuple[str, "_Alg | Literal['unsupported', 'invalid']"]


def _load_key(spki_base64: str) -> Any:
    try:
        # Looked up at call time, so a host that refuses to load a key is the
        # host this runs on (and a test can stand one in).
        return _serialization.load_der_public_key(_b64decode(spki_base64))
    except Exception:
        return None


def _statement_algorithm_of(spki_base64: str) -> _Alg | None:
    """The statement algorithm the key material commits to, when it is one
    statements are signed under."""
    key = _load_key(spki_base64)
    if isinstance(key, _Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, _EllipticCurvePublicKey) and isinstance(key.curve, _SECP256R1):
        return "ES256"
    return None


def _material_for(spki: str, declared: str | None, strict: bool = False) -> _Material:
    """The algorithm to verify a key's signatures under. The key material
    decides wherever it parses; ``strict`` is for a statement's own subject,
    whose signed ``alg`` must then agree with it. An endorser's declared
    algorithm comes from wherever its key was found and is consulted only when
    the material does not parse (an Ed25519 key on a FIPS host). A host that
    cannot compute the algorithm makes the key ``unsupported``, never
    ``invalid``."""
    derived = _statement_algorithm_of(spki)
    if derived is not None:
        if strict and declared != derived:
            return (spki, "invalid")
        return (spki, derived if runtime_can_compute(derived) else "unsupported")
    if declared is not None and declared in _STATEMENT_COSE_ALG and not runtime_can_compute(declared):
        return (spki, "unsupported")
    return (spki, "invalid")


def _verify_bytes(spki: str, alg: _Alg, to_be_signed: bytes, signature: bytes) -> bool:
    key = _load_key(spki)
    try:
        if alg == "Ed25519" and isinstance(key, _Ed25519PublicKey):
            key.verify(signature, to_be_signed)
            return True
        if alg == "ES256" and isinstance(key, _EllipticCurvePublicKey) and isinstance(key.curve, _SECP256R1):
            if len(signature) != 64:
                return False
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            key.verify(_encode_dss_signature(r, s), to_be_signed, _ECDSA(_SHA256()))
            return True
    except Exception:
        return False
    return False


def _check_signature(sign1: _Sign1, key: _Material, expect_kid: str) -> Literal["ok", "bad", "unsupported"]:
    spki, alg = key
    if alg == "unsupported":
        return "unsupported"
    if alg == "invalid":
        return "bad"
    if sign1.cty != KEY_STATEMENT_CTY or sign1.kid != expect_kid or sign1.alg != _STATEMENT_COSE_ALG[alg]:
        return "bad"
    if all(b == 0 for b in sign1.signature):
        return "bad"
    return "ok" if _verify_bytes(spki, alg, _sig_structure(sign1.protected_bstr, sign1.payload_bstr), sign1.signature) else "bad"


@dataclass(frozen=True)
class _Checked:
    """How one statement fared against its own bytes and the keys it names."""

    input: KeyStatementInput
    id: str | None
    verdict: Literal["valid", "invalid", "unverifiable"]
    detail: str | None
    payload: _Payload | None


def _cose_list(st: KeyStatementInput) -> list[object]:
    cose: object = st.cose
    if isinstance(cose, (list, tuple)):
        return list(cast("Sequence[object]", cose))
    return []


def _check_statement(st: KeyStatementInput, key_by_digest: Mapping[str, tuple[str, str | None]]) -> _Checked:
    def invalid(detail: str, payload: _Payload | None = None) -> _Checked:
        return _Checked(st, st.id, "invalid", detail, payload)

    sigs = [_decode_sign1(b) for b in _cose_list(st)]
    if not sigs or any(s is None for s in sigs):
        return invalid("a signature does not decode as a tagged COSE_Sign1")
    parts = [s for s in sigs if s is not None]
    first = parts[0]
    if not all(p.payload_bstr == first.payload_bstr for p in parts):
        return invalid("the signatures do not cover the same payload")
    payload = _decode_payload(first.payload_bstr)
    if payload is None:
        return invalid("the payload does not decode as a key statement")
    if (
        payload.typ != st.kind
        or (st.subject_key_id is not None and payload.subject.kid != st.subject_key_id)
        or (st.endorser_column and (payload.endorser.kid if payload.endorser else None) != st.endorser_key_id)
    ):
        return invalid("the row columns disagree with the signed payload", payload)
    subject = _material_for(payload.subject.spki, payload.subject.alg, True)
    endorser_ref = payload.endorser
    endorser: _Material | None = None
    if endorser_ref is not None:
        known = key_by_digest.get(endorser_ref.spki_sha256)
        if known is None:
            return invalid("the endorser key is unknown to the registry and to every statement", payload)
        if endorser_ref.kid != endorser_ref.spki_sha256[:16]:
            return invalid("the endorser kid is not its key fingerprint", payload)
        endorser = _material_for(known[0], known[1])

    expected: list[tuple[_Material, str]] = []
    if payload.typ == "genesis":
        if endorser_ref is not None:
            return invalid("a genesis names an endorser", payload)
        expected.append((subject, payload.subject.kid))
    elif payload.typ == "succession":
        if endorser is None or endorser_ref is None:
            return invalid("a succession names no endorser", payload)
        if endorser_ref.spki_sha256 == payload.subject.spki_sha256:
            return invalid("a succession endorses its own key", payload)
        expected.extend([(endorser, endorser_ref.kid), (subject, payload.subject.kid)])
    else:
        if endorser is None or endorser_ref is None:
            return invalid("a closure names no signer", payload)
        if endorser_ref.spki_sha256 == payload.subject.spki_sha256:
            return invalid("a closure is signed by the key it closes", payload)
        if payload.subject.retired_at is None or payload.forced is None:
            return invalid("a closure carries no retiredAt or forced", payload)
        expected.append((endorser, endorser_ref.kid))
    if payload.typ != "closure" and payload.forced is not None:
        return invalid("only a closure carries forced", payload)
    if len(parts) != len(expected):
        return invalid(f"a {payload.typ} carries {len(expected)} signature(s), this one carries {len(parts)}", payload)
    unsupported = False
    for i, (material, kid) in enumerate(expected):
        outcome = _check_signature(parts[i], material, kid)
        if outcome == "bad":
            return invalid(f"signature {i + 1} does not verify under the key it names", payload)
        if outcome == "unsupported":
            unsupported = True
    return _Checked(st, st.id, "unverifiable" if unsupported else "valid", None, payload)


# --- The walk ---


@dataclass(frozen=True, eq=False)
class _Statement:
    """A statement whose signatures did not fail, with its place in write order."""

    check: _Checked
    payload: _Payload
    subject: str
    endorser: str | None
    at: int
    """Position in write order (total: ties keep input order)."""
    stored_ms: int | None
    """When it was stored, in ms: ``created_at``, or under the signed order the instant it signs."""


@dataclass(frozen=True, eq=False)
class _Edge:
    """One way trust flows: ``from_`` vouches for ``to`` through statement ``via``."""

    from_: str
    to: str
    via: _Statement
    counts: bool
    """A backward half pass 2 takes: the subject's sole admission. Pass 1 takes every backward half."""


def _reach(anchors: set[str], edges: Sequence[_Edge]) -> set[str]:
    out = set(anchors)
    grew = True
    while grew:
        grew = False
        for e in edges:
            if e.from_ in out and e.to not in out:
                out.add(e.to)
                grew = True
    return out


def _signed_instant_of(c: _Checked) -> str | None:
    """The instant a statement signs, which orders it when the source carries no write time."""
    if c.payload is None:
        return None
    return c.payload.subject.retired_at if c.payload.typ == "closure" else c.payload.subject.activated_at


def _dedup_key(st: KeyStatementInput) -> str:
    parts: list[str] = []
    for c in _cose_list(st):
        b = _to_bytes(c)
        parts.append(f"?{c!s}" if b is None else base64.b64encode(b).decode())
    return "|".join(parts)


def compute_key_trust(
    *,
    keys: Sequence[TrustKeyInput],
    statements: Sequence[KeyStatementInput],
    trust_anchors: str | Sequence[str],
    distrusted_keys: str | Sequence[str | DistrustedKey] | None = None,
) -> KeyTrust:
    """Walk the key statements from ``trust_anchors`` and decide which keys are
    trusted and what window each carries. Two passes, no fixpoint:

    1. Reach every key from the anchors over every edge, ignoring closures.
    2. Apply every closure whose signer pass 1 reaches: a key's window ends at
       the earliest ``retiredAt`` among them, a forced one voids every edge out
       of the key, forward and back, and any edge out of the key stored after
       its first such closure is void.
    3. Reach again without the void edges, taking a key's edge back only
       through its sole admission. That set is the trusted set.

    The edges: a succession E->K links E forward to K and K back to E. A key's
    admission is the first genesis or succession naming it; pass 3 takes K's
    edge back only when the succession is K's admission and K has exactly one.

    Closures only remove edges and shorten windows, so a closure signed by a
    leaked key is at worst a denial of service, never a key trusted that was
    not before. A distrusted key is the one thing that makes a closure stop
    counting: what it stores at or after its cutoff counts for nothing.

    Raises ``TypeError`` on malformed anchors or distrusted keys, on no anchors
    at all, and when some statements carry ``created_at`` and others do not.
    Mirrors verify-core ``computeKeyTrust``.
    """
    anchor_digests = parse_trust_anchors(trust_anchors)
    if not anchor_digests:
        raise TypeError(
            "compute_key_trust needs at least one trust anchor (sha256:<64 hex>). With none, no key can be trusted."
        )
    anchors = set(anchor_digests)
    distrusted_list = _normalize_distrusted(distrusted_keys)
    if not isinstance(statements, (list, tuple)) or not isinstance(keys, (list, tuple)):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("compute_key_trust takes lists of keys and statements.")

    with_time = sum(1 for s in statements if isinstance(s.created_at, str))  # pyright: ignore[reportUnnecessaryIsInstance]
    if with_time not in (0, len(statements)):
        raise TypeError(
            "Key statements must all carry created_at (a dump) or none (a key document); this input mixes them."
        )
    # A listed key with no key material (a dump row whose public_key was
    # nulled) vouches for nothing and is no endorser's fallback.
    listed_keys = [k for k in keys if isinstance(k.public_key, str) and k.public_key]  # pyright: ignore[reportUnnecessaryIsInstance]
    order: Literal["written", "signed"] = "written" if statements and with_time == len(statements) else "signed"
    inputs = list(statements)
    if order == "signed":
        # With no write time and no row id, two identical statements are one.
        seen: set[str] = set()
        deduped: list[KeyStatementInput] = []
        for s in inputs:
            k = _dedup_key(s)
            if k in seen:
                continue
            seen.add(k)
            deduped.append(s)
        inputs = deduped

    findings: list[KeyRegistryFinding] = []
    # An endorser's key material, by digest. A statement's subject SPKI is bound
    # to its digest by the payload check and its algorithm is signed, so it is
    # taken first; a listed key is the fallback for a key no statement names as
    # its subject (one anchored only by a pin). The listed algorithm is the
    # source's word, and a statement never turns invalid because it was rewritten.
    key_by_digest: dict[str, tuple[str, str | None]] = {}
    for st in inputs:
        cose = _cose_list(st)
        sign1 = _decode_sign1(cose[0]) if cose else None
        payload = _decode_payload(sign1.payload_bstr) if sign1 is not None else None
        if payload is not None and payload.subject.spki_sha256 not in key_by_digest:
            key_by_digest[payload.subject.spki_sha256] = (payload.subject.spki, payload.subject.alg)
    for key in listed_keys:
        digest = spki_sha256(key.public_key)
        if digest not in key_by_digest:
            key_by_digest[digest] = (key.public_key, key.algorithm if isinstance(key.algorithm, str) else None)  # pyright: ignore[reportUnnecessaryIsInstance]

    # Under the write order a statement with no write time cannot be placed:
    # the Server writes one on every row, so it was edited, and it admits nothing.
    def checked_of(st: KeyStatementInput) -> _Checked:
        c = _check_statement(st, key_by_digest)
        if order != "written" or instant_ms(st.created_at) is not None:
            return c
        return replace(c, verdict="invalid", detail="the row has no parseable created_at to order it by")

    checked = [checked_of(st) for st in inputs]

    def sort_key(c: _Checked) -> float | str:
        if order == "written":
            at = instant_ms(c.input.created_at)
            return float("inf") if at is None else at
        return _signed_instant_of(c) or "￿"

    def closure_last(c: _Checked) -> int:
        """Under the signed order a closure sorts after every admission that
        signs the same instant, whatever order the document lists them in. A
        rotation signs the successor's activatedAt and the predecessor's
        retiredAt as one instant, and the Server writes the succession first.
        This lets no statement past a closure that the order did not already
        let through: the closure still voids every edge its key signs at any
        later instant, a forced one or a distrusted key voids them all, and a
        document that did not come from the Server could list the succession
        first anyway."""
        return 1 if order == "signed" and c.payload is not None and c.payload.typ == "closure" else 0

    keyed = sorted(
        ((sort_key(c), closure_last(c), i, c) for i, c in enumerate(checked)), key=lambda t: (t[0], t[1], t[2])
    )
    in_write_order: list[_Statement] = []
    for at, (k, _r, _i, c) in enumerate(keyed):
        if c.verdict == "invalid" or c.payload is None:
            continue
        in_write_order.append(
            _Statement(
                check=c,
                payload=c.payload,
                subject=c.payload.subject.spki_sha256,
                endorser=c.payload.endorser.spki_sha256 if c.payload.endorser else None,
                at=at,
                stored_ms=k if isinstance(k, int) else instant_ms(k),
            )
        )
    valid = [s for s in in_write_order if s.check.verdict == "valid"]

    # Each key's admission: the first genesis or succession naming it, over
    # every statement whose signatures did not fail. A second admission is its
    # private half in someone else's hands, so the edge back from a key runs
    # only while it has exactly one, and its window opens at the latest instant
    # any of them signs.
    admissions: dict[str, _Statement] = {}
    admitted_twice: set[str] = set()
    activated_at: dict[str, str] = {}
    for s in in_write_order:
        if s.payload.typ == "closure":
            continue
        if s.subject in admissions:
            admitted_twice.add(s.subject)
        else:
            admissions[s.subject] = s
        signed = s.payload.subject.activated_at
        if s.check.verdict == "valid" and activated_at.get(s.subject, signed) <= signed:
            activated_at[s.subject] = signed

    def edges_of(s: _Statement) -> list[_Edge]:
        e = s.endorser
        if e is None or s.payload.typ != "succession":
            return []
        return [
            _Edge(e, s.subject, s, True),
            _Edge(s.subject, e, s, admissions.get(s.subject) is s and s.subject not in admitted_twice),
        ]

    edges = [edge for s in valid for edge in edges_of(s)]

    # Distrusted keys and the instant each one's statements stop counting from.
    distrust = {d.spki_sha256 for d in distrusted_list}
    cutoffs: dict[str, tuple[int, str] | None] = {}
    if distrust:
        clear = _reach(anchors, [e for e in edges if e.from_ not in distrust])
        for d in distrusted_list:
            instant = d.cutoff
            if instant is None:
                for s in valid:
                    if s.subject != d.spki_sha256 or s.payload.typ != "closure":
                        continue
                    by = s.endorser
                    retired = s.payload.subject.retired_at
                    if by is None or by in distrust or by not in clear or retired is None:
                        continue
                    if instant is None or retired < instant:
                        instant = retired
            cutoffs[d.spki_sha256] = None if instant is None else (cast("int", instant_ms(instant)), instant)

    def distrusted(s: _Statement, signer: str | None) -> bool:
        """Signed by a distrusted key at or after its cutoff: counts for nothing.
        Under the signed order there is no write time to hold a statement to,
        and the instant it signs is the leaked key's own word. So every edge out
        of a distrusted key is void whatever it signs, and every closure it
        signed still counts: dropping an edge or keeping a closure only ever
        takes trust away. Narrower than the engine, never wider."""
        if signer is None or signer not in cutoffs:
            return False
        if order == "signed":
            return s.payload.typ != "closure"
        cutoff = cutoffs[signer]
        return cutoff is None or (s.stored_ms is not None and s.stored_ms >= cutoff[0])

    # Pass 1, then the closures it lets count.
    pass1 = _reach(anchors, [e for e in edges if not distrusted(e.via, e.from_)])
    counting = [
        s
        for s in valid
        if s.payload.typ == "closure" and s.endorser is not None and s.endorser in pass1 and not distrusted(s, s.endorser)
    ]
    closed_at: dict[str, int] = {}
    closed_window: dict[str, str] = {}
    forced: set[str] = set()
    for c in counting:
        closed_at.setdefault(c.subject, c.at)
        retired = c.payload.subject.retired_at
        if retired is not None and closed_window.get(c.subject, retired) >= retired:
            closed_window[c.subject] = retired
        if c.payload.forced is True:
            forced.add(c.subject)

    def voided(edge: _Edge) -> bool:
        if not edge.counts or edge.from_ in forced or distrusted(edge.via, edge.from_):
            return True
        closed = closed_at.get(edge.from_)
        return closed is not None and edge.via.at > closed

    # Pass 2: the trusted set.
    trusted = _reach(anchors, [e for e in edges if not voided(e)])
    untrusted = [d for d, c in cutoffs.items() if c is None]
    for d in untrusted:
        trusted.discard(d)

    # Keys this host cannot decide: reached only through a statement signed
    # under an algorithm it cannot compute, and of such an algorithm themselves.
    # A key it can compute, reached only through a half it cannot check, is
    # reached through bytes anyone with database access writes as easily as the
    # Server: it is unanchored.
    undecided: set[str] = set()
    unverifiable = [s for s in in_write_order if s.check.verdict == "unverifiable"]
    if unverifiable:
        every = [e for e in [*edges, *(x for s in unverifiable for x in edges_of(s))] if not voided(e)]
        for d in _reach(anchors, every):
            if d not in trusted:
                undecided.add(d)
        for d in untrusted:
            undecided.discard(d)
        for d in list(undecided):
            known = key_by_digest.get(d)
            if known is None or _material_for(known[0], known[1])[1] != "unsupported":
                undecided.discard(d)

    # Each trusted key's window. It opens at the latest ``activatedAt`` its
    # verified admissions sign, so a statement added later only narrows it.
    by_digest: dict[str, KeyTrustEntry] = {}

    def entry_for(digest: str) -> KeyTrustEntry:
        existing = by_digest.get(digest)
        if existing is not None:
            return existing
        created = KeyTrustEntry(
            key_id=digest[:16],
            spki_sha256=digest,
            trusted=digest in trusted,
            undecided=digest in undecided,
            activated_at=None,
            retired_at=None,
        )
        by_digest[digest] = created
        return created

    for key in listed_keys:
        entry_for(spki_sha256(key.public_key))
    for d in undecided:
        entry_for(d)
    for d in trusted:
        entry = entry_for(d)
        entry.activated_at = activated_at.get(d)
        entry.retired_at = closed_window.get(d)
        cutoff = cutoffs.get(d)
        if cutoff is not None and (entry.retired_at is None or cutoff[1] < entry.retired_at):
            entry.distrust_cutoff = cutoff[1]

    # Findings on statements.
    def finding(code: KeyRegistryFindingCode, s: _Statement, detail: str) -> None:
        findings.append(KeyRegistryFinding(code, s.payload.subject.kid, s.check.id, detail))

    findings.extend(
        KeyRegistryFinding(
            "KEY_STATEMENT_INVALID",
            c.payload.subject.kid if c.payload is not None else c.input.subject_key_id,
            c.id,
            c.detail or "invalid",
        )
        for c in checked
        if c.verdict == "invalid"
    )
    # The earliest activation any admission signs for a key: a later admission
    # (the key's own half, leaked) can move the window's lower edge, and must not
    # make an honest closure read as dated before it.
    first_activation: dict[str, str] = {}
    for s in valid:
        if s.payload.typ == "closure":
            continue
        start = s.payload.subject.activated_at
        if first_activation.get(s.subject, start) >= start:
            first_activation[s.subject] = start
    for s in valid:
        e = s.endorser
        by = s.payload.endorser.kid if s.payload.endorser else ""
        if e is not None and distrusted(s, e):
            cutoff = cutoffs.get(e)
            closed = s.payload.subject.retired_at
            now = by_digest.get(s.subject)
            ends = (now.distrust_cutoff or now.retired_at) if now is not None else None
            # Dropping a closure the distrusted key signed reopens its subject.
            reopened = (
                f" It retired {s.payload.subject.kid} at {closed}, and no closure that counts retires it that "
                f"early now; if {s.payload.subject.kid} leaked as well, add sha256:{s.subject} to "
                "distrustedKeys too."
                if s.payload.typ == "closure"
                and closed is not None
                and now is not None
                and now.trusted
                and (ends is None or ends > closed)
                else ""
            )
            finding(
                "KEY_CLOSURE_INVALID" if s.payload.typ == "closure" else "KEY_STATEMENT_INVALID",
                s,
                f"a {s.payload.typ} by {by}, which distrustedKeys distrusts "
                f"{f'from {cutoff[1]}' if cutoff else 'entirely'}; it counts for nothing.{reopened}",
            )
            continue
        if s.payload.typ == "closure":
            retired = s.payload.subject.retired_at or ""
            subject_entry = by_digest.get(s.subject)
            activated = first_activation.get(s.subject) if subject_entry is not None and subject_entry.trusted else None
            signer_closed = None if e is None else closed_at.get(e)
            distrust_hint = (
                f"If {by} leaked or was retired, distrustedKeys sha256:{e or ''} (VAULT_DISTRUSTED_KEYS on the "
                "Server) makes what it signed from its retirement on count for nothing."
            )
            if e is None or e not in pass1:
                finding("KEY_CLOSURE_INVALID", s, "the closure is signed by a key that is not anchored")
            elif signer_closed is not None and s.at > signer_closed:
                finding(
                    "KEY_CLOSURE_INVALID",
                    s,
                    f"the closure is signed by {by} after its own retirement, and still counts: it ends "
                    f"{s.payload.subject.kid}'s window at {retired}. {distrust_hint}",
                )
            elif activated is not None and retired < activated:
                finding(
                    "KEY_CLOSURE_INVALID",
                    s,
                    f"the closure retires {s.payload.subject.kid} at {retired}, before the {activated} it was "
                    f"activated, and still counts. {distrust_hint}",
                )
            continue
        closed_subject = closed_at.get(s.subject)
        if s.subject not in trusted and (e is None or e not in trusted):
            finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} that touches no anchored key")
        elif closed_subject is not None and s.at > closed_subject:
            finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} of a key stored after its closure; it admits nothing")
        elif admissions.get(s.subject) is not s:
            finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} its subject signed after it was already admitted")
        elif e is not None and e in trusted:
            closed = closed_at.get(e)
            if closed is not None and s.at > closed:
                finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} by {by} stored after its closure")

    # Findings on listed keys: their columns against the signed values, compared
    # at millisecond precision, the precision a dump or key document carries.
    for key in listed_keys:
        entry = entry_for(spki_sha256(key.public_key))
        if not entry.trusted or key.key_id != entry.key_id:
            continue
        if (
            entry.activated_at is not None
            and isinstance(key.activated_at, str)
            and instant_ms(key.activated_at) != instant_ms(entry.activated_at)
        ):
            findings.append(
                KeyRegistryFinding(
                    "CHAIN_KEY_WINDOW_DRIFT",
                    key.key_id,
                    None,
                    f"activatedAt {key.activated_at} differs from the signed {entry.activated_at}",
                )
            )
        if entry.distrust_cutoff is not None:
            continue
        if key.status == "retired":
            if entry.retired_at is None:
                findings.append(
                    KeyRegistryFinding(
                        "KEY_CLOSURE_INVALID",
                        key.key_id,
                        None,
                        "the key is listed as retired and no counting closure signs its retirement",
                    )
                )
            elif not isinstance(key.retired_at, str) or instant_ms(key.retired_at) != instant_ms(entry.retired_at):
                listed = key.retired_at if isinstance(key.retired_at, str) else "null"
                findings.append(
                    KeyRegistryFinding(
                        "CHAIN_KEY_WINDOW_DRIFT",
                        key.key_id,
                        None,
                        f"retiredAt {listed} differs from the signed {entry.retired_at}",
                    )
                )
        elif key.status == "active" and entry.retired_at is not None:
            findings.append(
                KeyRegistryFinding(
                    "CHAIN_KEY_WINDOW_DRIFT",
                    key.key_id,
                    None,
                    f"the key is listed as active but a counting statement signs its retirement at {entry.retired_at}",
                )
            )

    return KeyTrust(
        order=order,
        anchors=[f"sha256:{d}" for d in anchor_digests],
        by_digest=by_digest,
        trusted=trusted,
        undecided=undecided,
        findings=findings,
        statements=KeyStatementCounts(
            total=len(checked),
            valid=sum(1 for c in checked if c.verdict == "valid"),
            invalid=sum(1 for c in checked if c.verdict == "invalid"),
            unverifiable=sum(1 for c in checked if c.verdict == "unverifiable"),
        ),
    )


# --- Source adapters ---


def key_statement_from_dump_row(row: Mapping[str, Any]) -> KeyStatementInput:
    """Map a dump ``vault_key_statements.ndjson`` row onto the walk's input,
    binding every column. The Server writes ``subject_key_id`` and
    ``created_at`` on every row, so one that is missing or not a string maps to
    ``""``, which matches no signed key id and places the statement nowhere: it
    is KEY_STATEMENT_INVALID. Mirrors verify-core ``keyStatementFromDumpRow``."""
    statement = row.get("statement")
    created = row.get("created_at")
    subject = row.get("subject_key_id")
    return KeyStatementInput(
        id=cast("str | None", row.get("id")),
        kind=cast("str", row.get("kind")),
        subject_key_id=subject if isinstance(subject, str) else "",
        endorser_key_id=cast("str | None", row.get("endorser_key_id")),
        endorser_column="endorser_key_id" in row,
        cose=cast("list[str]", statement) if isinstance(statement, list) else [],
        created_at=created if isinstance(created, str) else "",
    )


def _status_of(value: object) -> Literal["active", "retired"] | None:
    if value == "active":
        return "active"
    if value == "retired":
        return "retired"
    return None


def trust_key_from_dump_row(row: Mapping[str, Any]) -> TrustKeyInput:
    """Map a dump ``vault_signing_keys.ndjson`` row onto the walk's input."""
    algorithm = row.get("algorithm")
    public_key = row.get("public_key")
    return TrustKeyInput(
        key_id=str(row.get("key_id")),
        # A row with no key material maps to "", which the walk leaves out.
        public_key=public_key if isinstance(public_key, str) else "",
        algorithm=algorithm if isinstance(algorithm, str) else None,
        status=_status_of(row.get("status")),
        activated_at=row.get("activated_at"),
        retired_at=row.get("retired_at"),
    )


def _statement_fields(st: object) -> tuple[object, object]:
    if isinstance(st, Mapping):
        m = cast("Mapping[str, object]", st)
        return m.get("kind"), m.get("cose")
    return getattr(st, "kind", None), getattr(st, "cose", None)


def _statements_from_map(by_key: Sequence[tuple[str, object]], source: str) -> list[KeyStatementInput]:
    out: list[KeyStatementInput] = []
    for key_id, statements in by_key:
        if statements is None:
            continue
        if not isinstance(statements, (list, tuple)):
            raise TypeError(f"{source}: the statements for key {key_id} are not a list.")
        for i, st in enumerate(cast("Sequence[object]", statements)):
            kind, cose = _statement_fields(st)
            if not isinstance(kind, str) or not isinstance(cose, (list, tuple)):
                raise TypeError(f"{source}: statement {i} for key {key_id} is not {{kind, cose: [base64...]}}.")
            out.append(
                KeyStatementInput(
                    id=f"{key_id}#{i}",
                    kind=kind,
                    subject_key_id=key_id,
                    cose=list(cast("Sequence[str]", cose)),
                )
            )
    return out


def key_statements_from_export(signing_key_statements: Mapping[str, Any] | None) -> list[KeyStatementInput]:
    """The key statements of an audit export's ``exportMetadata.signingKeyStatements``."""
    if signing_key_statements is None:
        return []
    value = cast(object, signing_key_statements)
    if not isinstance(value, Mapping):
        raise TypeError("signingKeyStatements must be an object keyed by key id.")
    pairs = [(str(k), v) for k, v in cast("Mapping[object, object]", value).items()]
    return _statements_from_map(pairs, "signingKeyStatements")


def key_statements_from_verification_keys(
    document: Mapping[str, Any] | Any,
) -> tuple[list[TrustKeyInput], list[KeyStatementInput]]:
    """The walk's inputs from a ``GET /v1/verification-keys`` document (the raw
    JSON, or the ``VerificationKeysResponse`` that
    ``client.verification_keys.list()`` returns): its keys and the statements
    each carries. Raises ``TypeError`` when the document names a statement
    format this verifier does not read."""
    doc: object = document
    dump = getattr(doc, "model_dump", None)
    if callable(dump):
        doc = dump(by_alias=True)
    if not isinstance(doc, Mapping):
        raise TypeError(
            "Expected the /v1/verification-keys document: {data: [...], keyStatementFormat, anchoredFrom}."
        )
    m = cast("Mapping[str, object]", doc)
    data = m.get("data")
    if not isinstance(data, list):
        raise TypeError(
            "Expected the /v1/verification-keys document: {data: [...], keyStatementFormat, anchoredFrom}."
        )
    fmt = m.get("keyStatementFormat")
    if fmt is not None and fmt != KEY_STATEMENT_CTY:
        raise TypeError(f"keyStatementFormat {fmt!r} is not {KEY_STATEMENT_CTY}; upgrade the verifier.")
    keys: list[TrustKeyInput] = []
    by_key: list[tuple[str, object]] = []
    for item in cast("list[object]", data):
        k: Mapping[str, object] = cast("Mapping[str, object]", item) if isinstance(item, Mapping) else {}
        status = k.get("status")
        algorithm = k.get("algorithm")
        keys.append(
            TrustKeyInput(
                key_id=str(k.get("keyId")),
                public_key=str(k.get("publicKey")),
                algorithm=algorithm if isinstance(algorithm, str) else None,
                status=_status_of(status),
                activated_at=k.get("activatedAt"),
                retired_at=k.get("retiredAt"),
            )
        )
        by_key.append((str(k.get("keyId")), k.get("statements")))
    return keys, _statements_from_map(by_key, "verification-keys")
