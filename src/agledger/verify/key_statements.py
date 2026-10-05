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

**Write order.** The rule orders statements by the database's write order,
``created_at`` then the row ``id``, never by an instant a statement signs. A
dump carries it (``created_at`` at milliseconds, then the file's own row order,
which the producer writes as ``created_at, id``). Every key document (``GET
/v1/verification-keys``, ``/.well-known/agledger-vault-keys.json``, an export's
``exportMetadata.signingKeyStatements``) carries it too, as each statement's
``id`` and ``createdAt`` at microseconds, and lists under a trusted key its
admission, every later genesis or succession it signed, and its counting
closures. A walk over a document therefore dates a window and cuts an edge back
as the engine does, except for a later succession whose endorser the document
does not carry: it cannot be verified here, is KEY_STATEMENT_INVALID, and the
window opens earlier than the engine's, which the listed ``activatedAt``
reports as CHAIN_KEY_WINDOW_DRIFT.

A document from a Server that published neither field is ordered by the
instant each statement signs (a genesis or succession by
``subject.activatedAt``, a closure by ``subject.retiredAt``). For an honest
document the two orders agree, because the Server signs the instant it writes.
What the signed order cannot do is hold a leaked key to the time it actually
wrote a statement: a key retired without ``forced`` whose private half later
leaks can date a statement before its retirement. Such a statement is only
ever in a document that did not come from the Server. A forced closure voids
every edge out of its key whatever the order.
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
from functools import cmp_to_key
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
    """Row id (the dump's or a key document's ``id``), named in findings. Under
    the write order it breaks a tie between two statements whose
    ``created_at`` are the same microsecond, as the engine's ``created_at, id``
    does."""
    subject_key_id: str | None = None
    """The key id the source files the statement under, bound to the signed
    ``subject.kid``. ``None`` when the source names none."""
    endorser_key_id: str | None = None
    """The source's ``endorser_key_id`` column, bound to the signed
    ``endorser.kid`` when ``endorser_column`` is set (``None`` for a genesis)."""
    endorser_column: bool = False
    """Whether the source carries an ``endorser_key_id`` column at all. The key
    documents do not, so theirs is not bound."""
    source: Literal["dump", "document"] | None = None
    """Where the statement was read from. ``"dump"``: a row of a dump's
    ``vault_key_statements.ndjson`` (:func:`key_statement_from_dump_row` sets
    it), whose ``created_at`` the walk holds a distrusted key's statements to,
    as the engine does. Anything else, ``None`` included, is a key document's
    (an export's or a supplied ``/v1/verification-keys`` entry's): its
    ``createdAt`` orders it but never keeps an edge out of a distrusted key."""
    created_at: str | None = None
    """The database write time (the dump's ``created_at``, a key document's
    ``createdAt``). Give it for every statement or for none: with it the walk
    applies the write order, without it the signed order (see the module
    docstring). Statements are ordered by it at the precision given, then, for
    two at the same microsecond, by ``id``, and otherwise in input order. Under
    the write order a statement whose ``created_at`` is not an RFC 3339 instant
    cannot be placed, and is KEY_STATEMENT_INVALID (the adapters give ``""``
    for a row or document statement without one)."""


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
    source: Literal["dump", "document"] | None = None
    """Where the key was read from. ``"dump"``: a row of a dump's
    ``vault_signing_keys.ndjson`` (:func:`trust_key_from_dump_row` sets it), a
    registry fact the walk holds a distrusted key to: one no trusted key has
    retired is KEY_CLOSURE_INVALID. Anything else, ``None`` included, is a key
    document's listing."""


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


@dataclass(frozen=True)
class KeyTrustNote:
    """Something the walk did that is not a finding and never fails a verdict:
    a statement from a key document, signed by a distrusted key, that admits
    nothing here because the document's write time is the holder's word and is
    never held against the key's cutoff, though the engine, holding it to the
    time it was stored, counts it. It still dates windows and cuts edges back.
    Mirrors verify-core ``KeyTrustNote``."""

    key_id: str | None
    statement_id: str | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {"keyId": self.key_id, "statementId": self.statement_id, "detail": self.detail}


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


@dataclass(frozen=True)
class DistrustSpan:
    """What a ``distrusted_keys`` entry covers for one key, as the engine's
    ``distrustSpans`` gives it. ``cutoff``: the instant from which what the key
    signs counts for nothing (the entry's own, else ``retired_at``; ``None``:
    trusted for nothing). ``retired_at``: the earliest retirement of the key
    that a key which is not distrusted signs, reached from the anchors without
    passing through a distrusted key, each closure's signed ``retiredAt``
    capped at its own write time (``None``: none). On a dump, what the key
    signed before ``retired_at`` and outside its trust is accounted for, and
    listed rather than failed; what it signed after is not. Mirrors
    verify-core ``DistrustSpan``."""

    cutoff: str | None
    retired_at: str | None


@dataclass
class KeyTrust:
    """The walk's result. See :func:`compute_key_trust`."""

    order: Literal["written", "signed"]
    """``written`` when every statement carried ``created_at`` (a dump, or a key
    document from a Server that publishes each statement's write time), else
    ``signed`` (an older document; see the module docstring)."""
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
    notes: list[KeyTrustNote] = field(default_factory=list[KeyTrustNote])
    """Non-fatal: see :class:`KeyTrustNote`."""
    accounted: list[KeyTrustNote] = field(default_factory=list[KeyTrustNote])
    """Non-fatal: statements of a dump that a ``distrusted_keys`` key signed,
    that count for nothing, and that were stored before a key the walk trusts
    retired it (its :class:`DistrustSpan` ``retired_at``). The distrust entry
    and that retirement account for them: evidence of what the key signed,
    listed and never a finding. One stored after that retirement, or whose
    dropping reopens a key, stays a finding. Empty for a key document."""
    distrust_spans: dict[str, DistrustSpan] = field(default_factory=dict[str, DistrustSpan])
    """Each ``distrusted_keys`` key, by full SPKI SHA-256 (hex): see :class:`DistrustSpan`."""
    source: Literal["dump", "document"] = "document"
    """``dump`` when every statement is a dump row (and there is at least
    one), else ``document``. Only a dump's write times are the Server's word,
    so only a walk over a dump marks the keys :func:`apply_key_trust` lets a
    chain entry be accounted for under."""


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
    notes: list[KeyTrustNote] = field(default_factory=list[KeyTrustNote])
    """Non-fatal notes from the walk (see :class:`KeyTrustNote`); they never fail a verdict."""
    accounted: list[KeyTrustNote] = field(default_factory=list[KeyTrustNote])
    """Non-fatal: the statements of a dump a ``distrusted_keys`` key signed that
    its entry and a trusted key's retirement of it account for (see
    :attr:`KeyTrust.accounted`). Listed, never a finding."""

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
            "notes": [n.to_json() for n in self.notes],
            "accounted": [n.to_json() for n in self.accounted],
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
        notes=list(trust.notes),
        accounted=list(trust.accounted),
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

# RFC 3339 date-time: a ``T``, a numeric offset or ``Z``, any fraction.
_RFC3339_STRICT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?([Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 of a proleptic Gregorian date (year 0 included)."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _parse_rfc3339(instant: object) -> tuple[int, str] | None:
    """Milliseconds and the fraction digits of a strict RFC 3339 instant: an
    offset or ``Z``, a real calendar date and time of day. ``None`` for
    anything else."""
    if not isinstance(instant, str):
        return None
    m = _RFC3339_STRICT.fullmatch(instant)
    if m is None:
        return None
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    if h > 23 or mi > 59 or sec > 59 or not 1 <= mo <= 12 or d < 1:
        return None
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    if d > (29 if leap else 28) if mo == 2 else d > (30 if mo in (4, 6, 9, 11) else 31):
        return None
    offset = 0
    if m.group(9) is not None:
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 23 or om > 59:
            return None
        offset = (-1 if m.group(9) == "-" else 1) * (oh * 60 + om) * 60_000
    ms = ((_days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60_000 + sec * 1000
    return (ms + int(frac[:3].ljust(3, "0")) - offset, frac)


def rfc3339_ms(instant: object) -> int | None:
    """Milliseconds of a strict RFC 3339 instant (an offset or ``Z``, a real
    calendar date and time of day), truncating any finer fraction. ``None`` for
    anything else, so a write time is never placed by how a parser reads a date
    with no offset, a space separator or an impossible day. Mirrors
    verify-core ``rfc3339Ms``."""
    parsed = _parse_rfc3339(instant)
    return None if parsed is None else parsed[0]


def instant_ms(instant: object) -> int | None:
    """Milliseconds of an RFC 3339 instant, truncating any finer fraction the
    way the engine reads a microsecond instant. Key statements sign microsecond
    instants; entry write times, dump columns and key documents carry
    milliseconds, so every comparison between them is made here. Strict: a
    ``T``, an offset or ``Z``, a real calendar date and time of day; ``None``
    for anything else, so no instant is ever placed by how a lenient parser
    reads a date with no offset, a space separator or an impossible day.
    Mirrors verify-core ``instantMs``."""
    return rfc3339_ms(instant)


def _instant_us(instant: object) -> tuple[float, bool]:
    """Microseconds of a strict RFC 3339 instant (``nan`` when it is not one,
    see :func:`rfc3339_ms`), and whether it carries a full microsecond
    fraction. The key surfaces publish a statement's write time at microsecond
    precision and a dump at milliseconds, so two dump rows in one millisecond
    tie here without being simultaneous. Mirrors verify-core ``instantUs``."""
    parsed = _parse_rfc3339(instant)
    if parsed is None:
        return (float("nan"), False)
    ms, frac = parsed
    return (float(ms * 1000 + int(frac[3:6].ljust(3, "0"))), len(frac) >= 6)


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


def assert_not_pinned_and_distrusted(
    trust_anchors: str | Sequence[str] | None,
    distrusted_keys: str | Sequence[str | DistrustedKey] | None,
) -> None:
    """Raise ``TypeError`` when a key is pinned and distrusted with no instant,
    as the Server refuses to boot on that pair (``VaultKeyDistrustedError``):
    an undated entry withdraws the key from before anything it signed, which
    leaves a pin nothing to vouch for. A pin beside a dated entry
    (``sha256:<hex>@<instant>``) is how a leaked key whose history is still
    needed is kept from signing anything new: the pin vouches for what it
    stored before the instant. :func:`compute_key_trust` itself walks any pair
    as the engine's walk does; a verifier calls this on what its caller passed
    before it walks. Mirrors verify-core ``assertNotPinnedAndDistrusted``."""
    if trust_anchors is None or distrusted_keys is None:
        return
    anchors = set(parse_trust_anchors(trust_anchors))
    both = next(
        (d for d in _normalize_distrusted(distrusted_keys) if d.cutoff is None and d.spki_sha256 in anchors), None
    )
    if both is None:
        return
    raise TypeError(
        f"sha256:{both.spki_sha256} is a trust anchor and a distrusted key with no instant, which leaves the pin "
        "nothing to vouch for. Give the distrust entry the instant the key leaked (sha256:<hex>@<RFC 3339 "
        "instant>, no later than its retirement) and keep the pin, which then vouches for what it signed before "
        "that instant only; or, if you vouch for nothing it signed, keep the entry without an instant and drop the "
        "pin. The Server refuses to start with the same pair in VAULT_TRUST_ANCHORS and VAULT_DISTRUSTED_KEYS."
    )


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
    digest: str | None = None
    """SHA-256 of the signed payload bytes, once they decode as a statement."""
    subject_signed: bool = False
    """The subject's own signature verified here (a genesis, or a succession's second half)."""
    endorser_signed: bool = False
    """The endorser's signature verified here."""


def _cose_list(st: KeyStatementInput) -> list[object]:
    cose: object = st.cose
    if isinstance(cose, (list, tuple)):
        return list(cast("Sequence[object]", cose))
    return []


def _check_statement(st: KeyStatementInput, key_by_digest: Mapping[str, tuple[str, str | None]]) -> _Checked:
    digest: str | None = None

    def invalid(detail: str, payload: _Payload | None = None) -> _Checked:
        return _Checked(st, st.id, "invalid", detail, payload, None if payload is None else digest)

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
    digest = hashlib.sha256(first.payload_bstr).hexdigest()
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
    subject_signed = False
    endorser_signed = False
    for i, (material, kid) in enumerate(expected):
        outcome = _check_signature(parts[i], material, kid)
        if outcome == "bad":
            return invalid(f"signature {i + 1} does not verify under the key it names", payload)
        if outcome == "unsupported":
            unsupported = True
        by_subject = payload.typ == "genesis" or (payload.typ == "succession" and i == 1)
        if outcome == "ok" and by_subject:
            subject_signed = True
        if outcome == "ok" and not by_subject:
            endorser_signed = True
    return _Checked(
        st, st.id, "unverifiable" if unsupported else "valid", None, payload, digest, subject_signed, endorser_signed
    )


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
    written: tuple[int, bool] | None = None
    """Under the write order, ``created_at`` in microseconds and whether it
    carried them (a key document) or only milliseconds (a dump); ``None``
    under the signed order, where nothing says when a statement was stored."""


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


def _instant_of_us(us: int) -> str:
    """A microsecond count as the RFC 3339 UTC instant the statements sign."""
    ms = us // 1000
    stamp = datetime.fromtimestamp(ms // 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{stamp}.{ms % 1000:03d}{us - ms * 1000:03d}Z"


def _signed_after_write(signed: str, s: _Statement) -> bool:
    """Whether an instant a statement signs is later than when it was stored,
    at the precision its write time carries: a dump's millisecond
    ``created_at`` hides the microseconds, so an instant in the same
    millisecond is not later. False under the signed order, where nothing says
    when it was stored. Mirrors verify-core ``signedAfterWrite``."""
    if s.written is None:
        return False
    at = _instant_us(signed)[0]
    if at != at:
        return False
    us, micro = s.written
    return at > us if micro else int(at) // 1000 > (s.stored_ms if s.stored_ms is not None else us // 1000)


def _not_after_write(signed: str, s: _Statement) -> str:
    """The earlier of an instant a statement signs and its write time (see
    :func:`_signed_after_write`). Mirrors verify-core ``notAfterWrite``."""
    if not _signed_after_write(signed, s) or s.written is None:
        return signed
    us, micro = s.written
    return _instant_of_us(us if micro else (s.stored_ms if s.stored_ms is not None else us // 1000) * 1000)


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
    # One stored row, read from two sources (an export and a key document), is
    # one statement. With no write time and no row id, two identical
    # statements are one; with them, a row is its id and write time, and a
    # copy of a row under another id is a second row, as the engine reads it.
    seen: set[str] = set()
    inputs: list[KeyStatementInput] = []
    for s in statements:
        if order == "written" and not isinstance(s.id, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            inputs.append(s)
            continue
        if order == "signed":
            k = _dedup_key(s)
        else:
            # One row however it is spelled: the instant parsed (``+00:00`` is
            # ``Z``), the id lowercased (a uuid in capitals is the same uuid).
            us = _instant_us(s.created_at)[0]
            k = repr((str(s.id).lower(), s.created_at if us != us else us, _dedup_key(s)))
        if k in seen:
            continue
        seen.add(k)
        inputs.append(s)

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
        if order != "written" or rfc3339_ms(st.created_at) is not None:
            return c
        return replace(c, verdict="invalid", detail="the row has no parseable created_at to order it by")

    checked = [checked_of(st) for st in inputs]

    def sort_key(c: _Checked) -> tuple[float | str, bool]:
        """Under the write order ``created_at`` at the precision given, and
        whether it is a full microsecond (only then does ``id`` break a tie)."""
        if order == "written":
            us, micro = _instant_us(c.input.created_at)
            return (float("inf") if us != us else us, micro)
        return (_signed_instant_of(c) or "￿", False)

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

    # Under the write order: ``created_at``, then ``id`` for two stored in the
    # same microsecond (the engine's ``created_at, id``), then input order,
    # which a dump writes as ``created_at, id`` at the microseconds its
    # milliseconds hide.
    placed = [(sort_key(c), closure_last(c), i, c) for i, c in enumerate(checked)]

    def compare(a: tuple[tuple[float | str, bool], int, int, _Checked], b: tuple[tuple[float | str, bool], int, int, _Checked]) -> int:
        (ka, ma), (kb, mb) = a[0], b[0]
        if ka != kb:
            return -1 if ka < kb else 1  # pyright: ignore[reportOperatorIssue]
        if a[1] != b[1]:
            return a[1] - b[1]
        x, y = a[3].input.id, b[3].input.id
        if ma and mb and isinstance(x, str) and isinstance(y, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            lx, ly = x.lower(), y.lower()
            if lx != ly:
                return -1 if lx < ly else 1
        return a[2] - b[2]

    keyed = sorted(placed, key=cmp_to_key(compare))
    # A dump row whose signed payload an earlier row already carries says
    # nothing new: a copy of a row (anything with write access to the database
    # can write one), or the same payload signed again. Only the first, in
    # write order, takes part, as the engine reads it; the database stamps the
    # write time, so a copy always lands after what it copies. A key document's
    # write time is its holder's word, so there a copy dated earlier would push
    # the published statement aside: on a document a copy stays a second
    # statement, which only ever narrows trust, and the Server publishes none.
    seen_payload: set[str] = set()
    kept: list[tuple[tuple[float | str, bool], int, int, _Checked]] = []
    for item in keyed:
        c = item[3]
        if c.verdict != "invalid" and c.payload is not None and c.digest is not None and c.input.source == "dump":
            if c.digest in seen_payload:
                continue
            seen_payload.add(c.digest)
        kept.append(item)
    in_write_order: list[_Statement] = []
    for at, ((k, micro), _r, _i, c) in enumerate(kept):
        if c.verdict == "invalid" or c.payload is None:
            continue
        in_write_order.append(
            _Statement(
                check=c,
                payload=c.payload,
                subject=c.payload.subject.spki_sha256,
                endorser=c.payload.endorser.spki_sha256 if c.payload.endorser else None,
                at=at,
                stored_ms=rfc3339_ms(c.input.created_at) if order == "written" else instant_ms(k),
                written=(int(cast("float", k)), micro) if order == "written" else None,
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
    distrust_spans: dict[str, DistrustSpan] = {}
    if distrust:
        clear = _reach(anchors, [e for e in edges if e.from_ not in distrust])
        for d in distrusted_list:
            # The retirement a key the walk still trusts signed for it, no
            # later than that closure's own write time: a retirement dated
            # ahead must not stretch what the entry accounts for.
            retired_by: str | None = None
            for s in valid:
                if s.subject != d.spki_sha256 or s.payload.typ != "closure":
                    continue
                by = s.endorser
                signed_retired = s.payload.subject.retired_at
                if by is None or by in distrust or by not in clear or signed_retired is None:
                    continue
                retired = _not_after_write(signed_retired, s)
                if retired_by is None or retired < retired_by:
                    retired_by = retired
            instant = d.cutoff if d.cutoff is not None else retired_by
            cutoffs[d.spki_sha256] = None if instant is None else (cast("int", instant_ms(instant)), instant)
            distrust_spans[d.spki_sha256] = DistrustSpan(cutoff=instant, retired_at=retired_by)

    def accounted_for(s: _Statement, signer: str) -> bool:
        """A dump statement a distrusted key signed and stored before a key the
        walk still trusts retired it: the distrust entry and that retirement
        account for it."""
        span = distrust_spans.get(signer)
        bound = None if span is None or span.retired_at is None else instant_ms(span.retired_at)
        return (
            bound is not None
            and s.check.input.source == "dump"
            and s.written is not None
            and s.stored_ms is not None
            and s.stored_ms < bound
        )

    def distrusted(s: _Statement, signer: str | None) -> bool:
        """Signed by a distrusted key at or after its cutoff: counts for nothing.
        Only a dump row's ``created_at`` holds a statement to when it was
        written. Under the signed order the instant it signs is the leaked key's
        own word, and a key document's ``createdAt`` is unsigned, so whoever
        holds the leaked key writes whatever time it likes. For those every
        edge out of a distrusted key is void whatever time it gives, and every
        closure it signed still counts: dropping an edge or keeping a closure
        only ever takes trust away. Narrower than the engine, never wider."""
        if signer is None or signer not in cutoffs:
            return False
        if order == "signed" or s.check.input.source != "dump":
            return s.payload.typ != "closure"
        cutoff = cutoffs[signer]
        return cutoff is None or (s.stored_ms is not None and s.stored_ms >= cutoff[0])

    def voided_by_stored_time(s: _Statement, signer: str) -> bool:
        """What the engine would void: signed by a distrusted key with no
        cutoff, or stored at or after its cutoff. On a key document the stored
        time is the holder's word, so this decides only whether voiding it is a
        finding."""
        cutoff = cutoffs.get(signer)
        return cutoff is None or (order == "written" and s.stored_ms is not None and s.stored_ms >= cutoff[0])

    notes: list[KeyTrustNote] = []
    accounted: list[KeyTrustNote] = []

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
    closures_of: dict[str, list[_Statement]] = {}
    for c in counting:
        closures_of.setdefault(c.subject, []).append(c)
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
    # What a distrust entry accounts for is bounded only by a retirement a key
    # the walk trusts signed. The engine bounds it by any key reached without a
    # distrusted key, a forced closure's cut-off keys included, so a key cut
    # off from a leaked one could retire a distrusted key it also holds and
    # have what that key forged read as accounted for. Only a signer the walk
    # trusts and reaches without a distrusted key bounds it here: narrower than
    # the engine, never wider; the cutoff a bound gives an undated entry is the
    # engine's. Mirrors verify-core.
    if distrust_spans:
        clear_of_distrust = _reach(anchors, [e for e in edges if e.from_ not in distrust])
        for d, span in list(distrust_spans.items()):
            bound: str | None = None
            for s in valid:
                if (
                    s.subject != d
                    or s.payload.typ != "closure"
                    or s.endorser is None
                    or s.endorser in distrust
                    or s.endorser not in clear_of_distrust
                    or s.endorser not in trusted
                    or s.payload.subject.retired_at is None
                ):
                    continue
                capped = _not_after_write(s.payload.subject.retired_at, s)
                if bound is None or capped < bound:
                    bound = capped
            distrust_spans[d] = DistrustSpan(cutoff=span.cutoff, retired_at=bound)

    # Keys this host cannot decide: reached only through a statement signed
    # under an algorithm it cannot compute, and of such an algorithm themselves.
    # A key it can compute, reached only through a half it cannot check, is
    # reached through bytes anyone with database access writes as easily as the
    # Server: it is unanchored.
    undecided: set[str] = set()
    # The undecided keys one step from the trusted set, through the half of the
    # statement this host verified. Past that step every signature on the path
    # is one anything with database access could have written, so nothing
    # further is vouched for. The Server publishes these with their admission.
    vouched: set[str] = set()
    unverifiable = [s for s in in_write_order if s.check.verdict == "unverifiable"]
    if unverifiable:
        every = [e for e in [*edges, *(x for s in unverifiable for x in edges_of(s))] if not voided(e)]
        for d in _reach(anchors, every):
            if d not in trusted:
                undecided.add(d)
        for edge in (x for s in unverifiable for x in edges_of(s)):
            if edge.from_ not in trusted or voided(edge) or edge.to in trusted:
                continue
            forward = edge.from_ == edge.via.endorser
            if edge.via.check.endorser_signed if forward else edge.via.check.subject_signed:
                vouched.add(edge.to)
        undecided |= vouched
        for d in untrusted:
            undecided.discard(d)
        for d in list(undecided):
            known = key_by_digest.get(d)
            if known is None or _material_for(known[0], known[1])[1] != "unsupported":
                undecided.discard(d)
                vouched.discard(d)

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
    def pin_remedy(e: str, by: str) -> str:
        """Pin it if honest, never once it is distrusted."""
        if e in cutoffs:
            return ""
        return f" If {by} is honest, pin sha256:{e} in trustAnchors (VAULT_TRUST_ANCHORS on the Server, which publishes it)."

    for s in valid:
        e = s.endorser
        by = s.payload.endorser.kid if s.payload.endorser else ""
        voided_here = e is not None and distrusted(s, e)
        # The admission of a key the walk trusts by another path (its own pin,
        # as when a fresh key was staged with the leaked one as its predecessor
        # after the leak), signed by a distrusted key from its cutoff on: the
        # voided endorsement takes nothing away and grants nothing, so it is no
        # finding. Only the key's first admission: a later one is a second
        # admission, which cuts the key's edge back and redates it, and stays a
        # finding.
        if (
            e is not None
            and voided_here
            and voided_by_stored_time(s, e)
            and s.payload.typ != "closure"
            and s.subject in trusted
            and admissions.get(s.subject) is s
        ):
            continue
        if e is not None and voided_here and not voided_by_stored_time(s, e):
            # Voided only because a key document's time is not held against the
            # cutoff: it admits nothing, but a statement the engine would count
            # is no finding. It still dates windows and cuts edges back, so it
            # can only narrow trust. The checks below still apply to it.
            note_cutoff = cast("tuple[int, str]", cutoffs[e])
            written = s.check.input.created_at
            notes.append(
                KeyTrustNote(
                    s.payload.subject.kid,
                    s.check.id,
                    f"a {s.payload.typ} by {by}, which distrustedKeys distrusts from {note_cutoff[1]}; it admits "
                    f"nothing here, because a key document's write time"
                    f"{f' ({written})' if isinstance(written, str) else ''} is not signed and is not held against "
                    "the cutoff. A dump taken from the Server holds it to the time it was stored.",
                )
            )
        elif e is not None and voided_here:
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
            code: KeyRegistryFindingCode = "KEY_CLOSURE_INVALID" if s.payload.typ == "closure" else "KEY_STATEMENT_INVALID"
            what = (
                f"a {s.payload.typ} by {by}, which distrustedKeys distrusts "
                f"{f'from {cutoff[1]}' if cutoff else 'entirely'}; it counts for nothing."
            )
            if s.check.input.source != "dump" or s.written is None:
                finding(code, s, f"{what}{reopened}")
            else:
                # A dump row: held to when the Server stored it.
                span = distrust_spans.get(e)
                retired_by = span.retired_at if span is not None else None
                # A later admission of a trusted key that the key itself signed
                # is the record of its own half leaking, whoever co-signed it:
                # never accounted for. Narrower than the engine, never wider.
                leaked_subject = (
                    s.payload.typ != "closure"
                    and admissions.get(s.subject) is not s
                    and s.check.subject_signed
                    and s.subject in trusted
                )
                if leaked_subject:
                    kid = s.payload.subject.kid
                    finding(
                        code,
                        s,
                        f"{what} It is also a {s.payload.typ} {kid} signed after it was already admitted: {kid}'s "
                        f"private half in other hands, which no distrust entry for {by} accounts for. Move every Server "
                        f"process off {kid}, retire it with force from the key they hold, and give distrustedKeys "
                        f"sha256:{s.subject}@<the instant it leaked> (VAULT_DISTRUSTED_KEYS on every Server process).",
                    )
                elif reopened == "" and accounted_for(s, e):
                    accounted.append(
                        KeyTrustNote(
                            s.payload.subject.kid,
                            s.check.id,
                            f"{what} Stored before {retired_by or ''}, when a key the walk trusts retired {by}, so "
                            f"the distrust entry accounts for it: evidence of what {by} signed, not a finding.",
                        )
                    )
                else:
                    after = (
                        f" No closure a key the walk trusts signs retires {by}, so nothing bounds what the distrust "
                        f"entry accounts for: retire {by} with force on the Server from a process on a key you hold."
                        if retired_by is None
                        else f" It was stored after {retired_by}, when a key the walk trusts retired {by}: {by}'s "
                        "private half is still in use by someone with write access to the Server's database."
                        if not accounted_for(s, e)
                        else ""
                    )
                    finding(code, s, f"{what}{reopened}{after}")
            continue
        if s.payload.typ == "closure":
            retired = s.payload.subject.retired_at or ""
            subject_entry = by_digest.get(s.subject)
            activated = first_activation.get(s.subject) if subject_entry is not None and subject_entry.trusted else None
            signer_closed = None if e is None else closed_at.get(e)
            before = len(findings)
            # The instant to suggest when nothing earlier is known: the
            # signer's own retirement, each closure's signed instant capped at
            # its write time (a closure dated ahead voids nothing), or else
            # this closure's write time. A pin on the signer stays, since the
            # entry is dated.
            own = [] if e is None else closures_of.get(e, [])
            until: str | None = None
            if s.written is not None:
                w_us, w_micro = s.written
                until = _instant_of_us(w_us if w_micro else (s.stored_ms if s.stored_ms is not None else w_us // 1000) * 1000)
            for c in own:
                capped = _not_after_write(c.payload.subject.retired_at or "", c)
                if capped != "" and (until is None or capped < until):
                    until = capped
            known = (
                ""
                if until is None
                else f"; if nothing earlier is known, {until}, {'its retirement' if own else 'when this closure was stored'}"
            )
            distrust_hint = (
                f"If {by} leaked, give distrustedKeys sha256:{e or ''}@<instant> (VAULT_DISTRUSTED_KEYS on every "
                f"Server process), the instant being the earliest time {by} may have leaked{known}. What it signed "
                f"from that instant on, this closure included, counts for nothing. Keep a trustAnchors pin on {by} if "
                f"it has one, and date the entry no later than the leak: beside a pin, everything {by} stored before "
                "the instant still counts."
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
            elif e not in trusted and (s.subject in trusted or s.subject in vouched):
                # The Server publishes only trusted and vouched keys, and every
                # counting closure of a published key with it, so a walk over
                # the subject's key document cannot verify this one: every
                # document and every audit export carrying it fails offline,
                # whether or not a published closure dates the window as early.
                published = [c for c in closures_of.get(s.subject, []) if (c.endorser or "") in trusted]
                earlier = all(retired < (c.payload.subject.retired_at or "") for c in published)
                forced_alone = s.payload.forced is True and not any(c.payload.forced is True for c in published)
                effect = (
                    f": it ends {s.payload.subject.kid}'s window at {retired}, earlier than any closure a published "
                    "key signs"
                    if earlier
                    else f": it retires {s.payload.subject.kid} with force, which no closure a published key signs does"
                    if forced_alone
                    else ""
                )
                written = s.check.input.created_at
                at = f"@{written}" if isinstance(written, str) else ""
                # A distrusted signer is never named as a pin. Its closure
                # counts here only where it was stored before the cutoff, or is
                # in a key document, where a closure only narrows trust.
                if e in cutoffs:
                    why = (
                        f"it was stored before the cutoff, so if {by} leaked earlier, date its entry no later than "
                        f"{written or ''}"
                        if s.check.input.source == "dump" and s.written is not None
                        else "a closure it signed in a key document still counts here, since a closure only narrows "
                        "trust; the Server counts it for nothing only when it was stored at or after the cutoff"
                    )
                    remedy = f" {by} is in distrustedKeys, and this closure still counts: {why}."
                else:
                    remedy = (
                        f"{pin_remedy(e, by)} If it leaked, distrustedKeys sha256:{e}{at} (VAULT_DISTRUSTED_KEYS on "
                        f"the Server) makes this closure, and what {by} signed after it, count for nothing."
                    )
                finding(
                    "KEY_CLOSURE_INVALID",
                    s,
                    f"the closure is signed by {by}, which is reached but not anchored, and still counts{effect}. No "
                    f"key surface publishes {by}, so an offline walk over the published statements cannot verify it, "
                    f"and every audit export carrying them fails offline verification.{remedy}",
                )
            # A retirement dated ahead of when it was stored: the Server never
            # signs one, and it keeps its subject open until then.
            if e is not None and e in pass1 and _signed_after_write(retired, s) and len(findings) == before:
                finding(
                    "KEY_CLOSURE_INVALID",
                    s,
                    f"the closure dates {s.payload.subject.kid}'s retirement at {retired}, after "
                    f"{s.check.input.created_at or ''} when it was stored, and still counts: {s.payload.subject.kid}'s "
                    f"window ends then. The Server never signs a retirement ahead of the call; if {by} did not sign "
                    f"this, {distrust_hint}",
                )
            continue
        closed_subject = closed_at.get(s.subject)
        if s.subject not in trusted and (e is None or e not in trusted):
            finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} that touches no anchored key")
        elif closed_subject is not None and s.at > closed_subject:
            finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} of a key stored after its closure; it admits nothing")
        elif admissions.get(s.subject) is not s:
            # A key is admitted once. What it signs itself in with later is a
            # leaked key naming a predecessor or redating itself.
            kid = s.payload.subject.kid
            finding(
                "KEY_STATEMENT_INVALID",
                s,
                f"a {s.payload.typ} its subject signed after it was already admitted: {kid}'s private half in other "
                f"hands. It is the record of the leak, and no setting clears it: move every Server process off {kid}, "
                f"retire it with force from the key they hold, and give distrustedKeys sha256:{s.subject}@<the "
                "instant it leaked> (VAULT_DISTRUSTED_KEYS on every Server process), which stops what its leaked half "
                "signs from then on counting.",
            )
        elif e is not None and s.subject in trusted and e not in trusted and e not in vouched:
            # The admission of a key trusted by another path (a pin, or the
            # edge back from a key it admitted) whose endorser the walk does
            # not trust: history a forced closure cut off. The Server publishes
            # it with the key and does not publish its endorser, so no offline
            # walk verifies it.
            finding(
                "KEY_STATEMENT_INVALID",
                s,
                f"{s.payload.subject.kid} is trusted, and its admission is a {s.payload.typ} signed by {by}, which the "
                "walk does not trust (a forced closure cut it off, or it was never linked). No key surface publishes "
                f"{by}, so an offline walk over the published statements cannot verify it, and every audit export "
                f"carrying them fails offline verification.{pin_remedy(e, by)}",
            )
        elif e is not None and e in trusted:
            closed = closed_at.get(e)
            if closed is not None and s.at > closed:
                finding("KEY_STATEMENT_INVALID", s, f"a {s.payload.typ} by {by} stored after its closure")

    # A vouched key is published with its admission, which this host cannot
    # check. Where that admission's endorser is not published either, no
    # verifier off-host can check it from what is published.
    for d in vouched:
        adm = admissions.get(d)
        endorser = adm.endorser if adm is not None else None
        if adm is None or endorser is None or endorser in trusted or endorser in vouched:
            continue
        by = adm.payload.endorser.kid if adm.payload.endorser else ""
        finding(
            "KEY_STATEMENT_INVALID",
            adm,
            f"{adm.payload.subject.kid} is reached through a trusted key's signature, and its admission is a "
            f"{adm.payload.typ} signed by {by}, which no key surface publishes, so an offline walk over the published "
            f"statements cannot verify it, and every audit export carrying them fails offline verification."
            f"{pin_remedy(endorser, by)}",
        )

    # Keys an admission names that this walk could not verify. A key document
    # carries a key's admissions but not every endorser, so the walk can date a
    # trusted key's window earlier than the engine did, or not at all.
    unverified_admission = {
        c.payload.subject.spki_sha256
        for c in checked
        if c.verdict == "invalid" and c.payload is not None and c.payload.typ != "closure"
    }

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
        elif (
            entry.activated_at is None
            and isinstance(key.activated_at, str)
            and entry.spki_sha256 in unverified_admission
        ):
            # The window then has no lower edge here, which is wider than the
            # listed one: the same drift, read the other way.
            findings.append(
                KeyRegistryFinding(
                    "CHAIN_KEY_WINDOW_DRIFT",
                    key.key_id,
                    None,
                    f"activatedAt {key.activated_at} is signed by no admission this walk could verify",
                )
            )
        if entry.distrust_cutoff is not None:
            # The cutoff is no retirement, so a listed key left active is no
            # drift; one listed retired earlier than the cutoff is graded more
            # loosely here than where it was listed (a closure this walk could
            # not verify).
            listed_retired = instant_ms(key.retired_at)
            cutoff_ms = instant_ms(entry.distrust_cutoff)
            if isinstance(key.retired_at, str) and not (
                listed_retired is not None and cutoff_ms is not None and listed_retired >= cutoff_ms
            ):
                findings.append(
                    KeyRegistryFinding(
                        "CHAIN_KEY_WINDOW_DRIFT",
                        key.key_id,
                        None,
                        f"retiredAt {key.retired_at} is earlier than {entry.distrust_cutoff}, the distrust "
                        "cutoff this walk ends the key at, and no closure it could verify signs it",
                    )
                )
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

    # A distrusted key the dump's registry lists that no key the walk trusts
    # has retired: nothing bounds what its entry accounts for, so what it
    # signed stays unaccounted until a retirement does. A registry fact, so a
    # key document's listing leaves it out.
    for key in listed_keys:
        digest = spki_sha256(key.public_key)
        span = distrust_spans.get(digest)
        if key.source != "dump" or span is None or span.retired_at is not None or key.key_id != digest[:16]:
            continue
        findings.append(
            KeyRegistryFinding(
                "KEY_CLOSURE_INVALID",
                key.key_id,
                None,
                f"distrustedKeys names {key.key_id} and no closure signed by a key the walk trusts retires it, so "
                f"nothing bounds what the entry accounts for: chain entries {key.key_id} signed fail until a "
                f"retirement does. Retire it with force on the Server (POST /v1/admin/vault/signing-keys/{key.key_id}"
                '/retire with {"force": true}) from a process on a key you hold; what it signed before that retirement '
                "is then accounted for and listed, and anything it signs after it is reported.",
            )
        )

    return KeyTrust(
        order=order,
        anchors=[f"sha256:{d}" for d in anchor_digests],
        by_digest=by_digest,
        trusted=trusted,
        undecided=undecided,
        findings=findings,
        notes=notes,
        accounted=accounted,
        distrust_spans=distrust_spans,
        source="dump" if inputs and all(st.source == "dump" for st in inputs) else "document",
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
        source="dump",
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
        source="dump",
    )


def _statement_fields(st: object) -> tuple[object, object, object, object, bool]:
    """``kind``, ``cose``, ``id``, ``createdAt`` and whether ``createdAt`` is
    there at all (JSON ``null`` included) of one published statement."""
    if isinstance(st, Mapping):
        m = cast("Mapping[str, object]", st)
        return m.get("kind"), m.get("cose"), m.get("id"), m.get("createdAt"), "createdAt" in m
    created = getattr(st, "created_at", None)
    return getattr(st, "kind", None), getattr(st, "cose", None), getattr(st, "id", None), created, created is not None


def _statements_from_map(
    by_key: Sequence[tuple[str, object]], source: str, prefix: str = ""
) -> list[KeyStatementInput]:
    """The statements of a document keyed by key id. When any statement of the
    document carries ``createdAt``, the document publishes write order, so one
    without it (or with another type) maps to ``""`` and is
    KEY_STATEMENT_INVALID rather than turning the whole document back to the
    signed order. A statement with no ``id`` is named
    ``<prefix><key id>#<index>``. Mirrors verify-core ``statementsFromMap``."""
    for key_id, statements in by_key:
        if statements is not None and not isinstance(statements, (list, tuple)):
            raise TypeError(f"{source}: the statements for key {key_id} are not a list.")
    lists = [(k, list(cast("Sequence[object]", v))) for k, v in by_key if isinstance(v, (list, tuple))]
    timed = any(_statement_fields(st)[4] for _k, sts in lists for st in sts)
    out: list[KeyStatementInput] = []
    for key_id, statements in lists:
        for i, st in enumerate(statements):
            kind, cose, row_id, created, _has = _statement_fields(st)
            if not isinstance(kind, str) or not isinstance(cose, (list, tuple)):
                raise TypeError(f"{source}: statement {i} for key {key_id} is not {{kind, cose: [base64...]}}.")
            out.append(
                KeyStatementInput(
                    id=row_id if isinstance(row_id, str) else f"{prefix}{key_id}#{i}",
                    kind=kind,
                    subject_key_id=key_id,
                    source="document",
                    cose=list(cast("Sequence[str]", cose)),
                    created_at=(created if isinstance(created, str) else "") if timed else None,
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
