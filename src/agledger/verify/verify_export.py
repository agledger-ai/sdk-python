"""Offline verification of AGLedger record audit exports.

Format version 2.0: each entry carries a canonical COSE_Sign1
(RFC 9052 §4.4, tag 18, EdDSA) envelope over an in-toto v1 Statement payload,
deterministically CBOR-encoded per RFC 8949 §4.2.1. The hash chain links via
sha256 of the COSE_Sign1 envelope bytes; the per-entry signature is the COSE
signature itself.

Verification walks every entry and asserts:
    1. monotonic chain position (1, 2, 3, ...)
    2. sha256(coseSign1 bytes) == stored payloadHash
    3. previousHash links to the prior entry's payloadHash (genesis must be null)
    4. COSE_Sign1 envelope decodes cleanly
    5. Protected-header chain claim (private label -65537) matches the row's
       position + previousHash — catches a row where the envelope and the
       visible columns disagree about chain identity
    6. COSE_Sign1 signature verifies against the signingPublicKey for the
       entry's signingKeyId

This is the export (per-record) path. It runs ONLY the always-run checks above;
the binding-integrity, OIDC-actor, and temporal-key checks are dump-only (the
``/audit-export`` wire does not carry their inputs) and are not run here.

This is an independent re-implementation of the shared TS verification core
(``@agledger/verify-core``); it emits the SAME canonical SCREAMING_SNAKE
``FailureCode`` taxonomy and the same per-entry/``broken_at`` shape, so the two
languages agree byte-for-byte over the shared conformance corpus
(``testdata/conformance``). Zero engine dependency — the load-bearing property
of an offline auditor.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping, Sequence, cast

from pydantic import BaseModel

from agledger.verify.failures import FailureCode

try:
    import cbor2 as _cbor2
except ImportError as _err:  # pragma: no cover
    raise ImportError(
        "The 'cbor2' package is required for COSE_Sign1 audit verification. "
        "Install via: pip install 'agledger[verify]'"
    ) from _err

try:
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
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
    from cryptography.hazmat.primitives.serialization import (
        load_der_public_key as _load_der_public_key,
    )
except ImportError as _err:  # pragma: no cover
    raise ImportError(
        "The 'cryptography' package is required for audit verification. "
        "Install via: pip install 'agledger[verify]'"
    ) from _err


# The canonical ``FailureCode`` taxonomy is defined once in ``failures.py`` and
# imported above; the EXPORT path emits a subset (the dump-only
# CHAIN_OIDC_ACTOR_MISMATCH / CHAIN_KEY_EXPIRED / CHECKPOINT_* / TENANT_* codes
# need inputs the ``/audit-export`` wire lacks), while the dump verifier
# (``verify_dump.py``) reaches the rest. CHAIN_PAYLOAD_BINDING_MISMATCH became
# export-reachable when the export began carrying the row payload (engine ≥
# v0.26.x) — see verify_entry / F-731.

# Mirrors ``@agledger/verify-core``'s ``SignatureOutcome``:
#   ok / invalid / decode-fail  — the signature was checked
#   unsigned                    — no signature by design
#   skipped                     — chain intact, entry has no signing key (engine booted keyless)
#   not-checked                 — a structural check failed first, so the signature was never reached
# unsupported: the trusted key commits to an algorithm this build cannot
# compute (CHAIN_UNSUPPORTED_ALGORITHM); a failure state, never a benign skip.
SignatureOutcome = Literal[
    "ok", "invalid", "unsigned", "skipped", "not-checked", "decode-fail", "unsupported"
]

#: Provenance of a verification key — ``out-of-band`` (caller-supplied from a
#: trusted source) or ``embedded`` (shipped inside the export the engine
#: produced). Mirrors ``@agledger/verify-core``'s ``KeySource``.
KeySource = Literal["out-of-band", "embedded"]

_SUPPORTED_FORMAT_VERSION = "2.0"
_SUPPORTED_CANONICALIZATION = "RFC8949-CDE"
_COSE_SIGN1_TAG = 18
# CBOR major type 6 (tag), value 18, short form: the required leading byte.
_COSE_SIGN1_TAG_PREFIX = 0xD2
_SIG_STRUCTURE_CONTEXT = "Signature1"
_COSE_HEADER_ALG = 1
_COSE_HEADER_KID = 4
_AGLEDGER_LABEL_CHAIN = -65537
_CHAIN_SUBLABEL_POSITION = 1
_CHAIN_SUBLABEL_PREVIOUS_HASH = 2


def as_mapping(value: Any) -> Mapping[str, Any]:
    """Narrow a decoded value to a ``Mapping`` for safe ``.get()`` access, or an
    empty mapping if it is not one. The single home for the row/payload/integrity
    narrowing the export AND dump walkers both do — one function so the two
    verifiers can never drift in how they coerce a non-mapping field."""
    return cast("Mapping[str, Any]", value) if isinstance(value, Mapping) else {}


@dataclass
class EntryVerificationResult:
    position: int
    valid: bool
    code: FailureCode | None = None
    detail: str | None = None
    #: Defaults to ``not-checked``: a failure entry that does not explicitly set
    #: ``invalid``/``decode-fail`` short-circuited before the signature check.
    #: Valid entries always set ``ok``/``unsigned``/``skipped`` explicitly.
    signature: SignatureOutcome | None = "not-checked"
    #: Provenance of the key the signature was checked against (``ok``/``invalid``).
    key_source: KeySource | None = None


@dataclass
class BrokenAt:
    position: int
    code: FailureCode
    detail: str | None = None


@dataclass
class SignatureCoverage:
    signed: int = 0
    unsigned: int = 0
    skipped: int = 0
    total: int = 0


@dataclass
class KeyProvenance:
    """How many signature checks resolved against out-of-band vs embedded keys.

    ``embedded > 0`` means the verdict trusts keys shipped by the engine that
    produced the export — supply out-of-band keys for an independent audit.
    """

    out_of_band: int = 0
    embedded: int = 0


@dataclass
class VerifyExportResult:
    valid: bool
    total_entries: int
    verified_entries: int
    record_id: str
    entries: list[EntryVerificationResult] = field(default_factory=list[EntryVerificationResult])
    broken_at: BrokenAt | None = None
    signature_coverage: SignatureCoverage = field(default_factory=SignatureCoverage)
    key_provenance: KeyProvenance = field(default_factory=KeyProvenance)


def verify_export(
    export_data: Mapping[str, Any] | BaseModel,
    *,
    public_keys: Mapping[str, str] | Sequence[Any] | None = None,
    require_key_id: str | None = None,
    require_out_of_band_keys: bool = False,
) -> VerifyExportResult:
    """Verify a record audit export offline.

    :param export_data: Parsed export. Accepts either a raw ``dict`` (parsed
        JSON) or the typed ``RecordAuditExport`` Pydantic model returned by
        ``client.records.get_audit_export()``.
    :param public_keys: Optional out-of-band keys supplied from a trusted source
        (``GET /v1/verification-keys``, ``/.well-known/scitt-keys``). These
        override any key embedded in the export. For a real independent audit,
        supply keys here rather than trusting the export's own
        ``signingPublicKeys``. Accepts either form — pass the ``.data`` list
        from ``client.verification_keys.list()`` directly, or a compact
        ``{keyId: base64SpkiDer}`` mapping. The wrong shape raises ``TypeError``
        rather than silently falling back to embedded keys
        (agledger-agents#77 / F-698).
    :param require_key_id: If set, every entry must reference this keyId
        (else :data:`CHAIN_KEY_POLICY_VIOLATION`).
    :param require_out_of_band_keys: High-assurance auditor mode. An entry whose
        only available key is export-embedded fails
        :data:`CHAIN_KEY_POLICY_VIOLATION` — verifying the engine against its own
        embedded key is not an independent audit.
    :returns: A :class:`VerifyExportResult` with per-entry outcomes, a
        signature-coverage discriminator, and a key-provenance tally.
    """
    if isinstance(export_data, BaseModel):
        export_data = export_data.model_dump(by_alias=True)

    meta = export_data.get("exportMetadata", {})
    entries: list[Mapping[str, Any]] = export_data.get("entries", []) or []
    record_id = str(meta.get("recordId", ""))
    overrides = _normalize_oob_keys(public_keys)
    registry = _build_key_registry(meta, overrides)
    coverage = SignatureCoverage(total=len(entries))

    fmt_version = meta.get("exportFormatVersion")
    if fmt_version and fmt_version != _SUPPORTED_FORMAT_VERSION:
        detail = (
            f"Unsupported exportFormatVersion {fmt_version} "
            f"(this verifier reads {_SUPPORTED_FORMAT_VERSION})."
        )
        return _early_failure(record_id, len(entries), detail, coverage)

    canonicalization = meta.get("canonicalization")
    if canonicalization and canonicalization != _SUPPORTED_CANONICALIZATION:
        detail = (
            f"Unsupported canonicalization {canonicalization} "
            f"(only {_SUPPORTED_CANONICALIZATION} supported)."
        )
        return _early_failure(record_id, len(entries), detail, coverage)

    if len(entries) == 0:
        return VerifyExportResult(
            valid=False,
            total_entries=0,
            verified_entries=0,
            record_id=record_id,
            entries=[],
            broken_at=BrokenAt(position=0, code="CHAIN_EMPTY", detail="No entries to verify."),
            signature_coverage=coverage,
        )

    # Sort by chain position before the walk so a reordered export array still
    # validates the true chain (tampering surfaces through the hash links).
    # Mirrors verify-core's `verifyChain`.
    sorted_entries = sorted(entries, key=_entry_position)

    entry_results: list[EntryVerificationResult] = []
    provenance = KeyProvenance()
    verified = 0
    broken_at: BrokenAt | None = None
    prev_payload_hash: str | None = None

    for i, entry in enumerate(sorted_entries):
        result = verify_entry(
            entry,
            i + 1,
            prev_payload_hash,
            registry,
            require_key_id,
            require_out_of_band_keys,
        )
        entry_results.append(result)
        if result.valid:
            verified += 1
        elif broken_at is None and result.code is not None:
            broken_at = BrokenAt(position=result.position, code=result.code, detail=result.detail)
        if result.signature == "ok":
            coverage.signed += 1
            if result.key_source == "out-of-band":
                provenance.out_of_band += 1
            elif result.key_source == "embedded":
                provenance.embedded += 1
        elif result.signature == "unsigned":
            coverage.unsigned += 1
        elif result.signature == "skipped":
            coverage.skipped += 1
        prev_payload_hash = as_mapping(entry.get("integrity")).get("payloadHash")

    return VerifyExportResult(
        valid=(verified == len(sorted_entries)),
        total_entries=len(sorted_entries),
        verified_entries=verified,
        record_id=record_id,
        entries=entry_results,
        broken_at=broken_at,
        signature_coverage=coverage,
        key_provenance=provenance,
    )


def _entry_position(entry: Mapping[str, Any]) -> int:
    # Current exports emit `chainPosition`; pre-v0.25 exports used `position`.
    raw = entry.get("chainPosition", entry.get("position", -1))
    return int(raw) if raw is not None else -1


def _early_failure(
    record_id: str,
    total: int,
    detail: str,
    coverage: SignatureCoverage,
) -> VerifyExportResult:
    return VerifyExportResult(
        valid=False,
        total_entries=total,
        verified_entries=0,
        record_id=record_id,
        entries=[
            EntryVerificationResult(
                position=0,
                valid=False,
                code="UNSUPPORTED_FORMAT",
                detail=detail,
            )
        ],
        broken_at=BrokenAt(position=0, code="UNSUPPORTED_FORMAT", detail=detail),
        signature_coverage=coverage,
    )


@dataclass
class RegisteredKey:
    spki_base64: str
    source: KeySource
    #: Temporal-validity window (dump path only). ``None`` on the export path,
    #: where the wire carries no key windows — the temporal check then no-ops.
    activated_at: str | None = None
    retired_at: str | None = None
    #: Algorithm the key registry DECLARES for this key (the engine's
    #: ``vault_signing_keys.algorithm`` column), when the input carries it.
    #: Cross-checked against the algorithm the SPKI key material actually
    #: commits to; a divergence fails CHAIN_ALG_MISMATCH. The declared string
    #: never selects the verification code path.
    algorithm: str | None = None


@dataclass(frozen=True)
class KeyAlgorithm:
    """What a verification key's SPKI AlgorithmIdentifier says about how its
    signatures must be checked. Derived from the TRUSTED key material, never
    from the protected header (attacker-controlled at dispatch time): the
    header's alg is asserted EQUAL to the key's expectation, it never selects
    the code path. The table is restricted to asymmetric signature algorithms
    by construction, so a COSE MAC label can never bind the public key as a
    MAC key. Mirrors verify-core primitives.ts KEY_ALGORITHMS."""

    name: str
    cose_algs: tuple[int, ...]
    signature_length: int
    verifiable: bool


# COSE alg code points per key type. Both the original and the RFC 9864
# fully-specified registrations are accepted where assigned, so a producer
# moving from -8 (EdDSA) to -19 (Ed25519) does not read as tampering.
_ED25519_ALG = KeyAlgorithm("Ed25519", (-8, -19), 64, True)
_EC_KEY_ALGORITHMS: dict[str, KeyAlgorithm] = {
    "secp256r1": KeyAlgorithm("ES256", (-7, -9), 64, True),
    "secp384r1": KeyAlgorithm("ES384", (-35,), 96, False),
    "secp521r1": KeyAlgorithm("ES512", (-36,), 132, False),
    "secp256k1": KeyAlgorithm("ES256K", (-47,), 64, False),
}

_KEY_ALG_CACHE: dict[str, KeyAlgorithm | Literal["unparseable", "unrecognized"]] = {}
_KEY_ALG_CACHE_MAX = 256


def _resolve_key_algorithm(
    spki_base64: str,
) -> KeyAlgorithm | Literal["unparseable", "unrecognized"]:
    """Resolve the algorithm a base64 SPKI DER public key commits to.

    ``"unrecognized"`` is a well-formed key of a type outside the table (RSA,
    X25519, an unregistered curve): surfaces as CHAIN_UNSUPPORTED_ALGORITHM,
    never as a forgery. ``"unparseable"`` means the bytes are not a public key.
    """
    cached = _KEY_ALG_CACHE.get(spki_base64)
    if cached is not None:
        return cached
    resolved: KeyAlgorithm | Literal["unparseable", "unrecognized"]
    try:
        loaded = _load_der_public_key(base64.b64decode(spki_base64))
    except Exception:
        loaded = None
    if loaded is None:
        resolved = "unparseable"
    elif isinstance(loaded, _Ed25519PublicKey):
        resolved = _ED25519_ALG
    elif isinstance(loaded, _EllipticCurvePublicKey):
        resolved = _EC_KEY_ALGORITHMS.get(loaded.curve.name, "unrecognized")
    else:
        resolved = "unrecognized"
    if len(_KEY_ALG_CACHE) >= _KEY_ALG_CACHE_MAX:
        _KEY_ALG_CACHE.clear()
    _KEY_ALG_CACHE[spki_base64] = resolved
    return resolved


# --- runtime algorithm capability (mirror verify-core runtimeCanCompute) ---

# Fixed (key, message, signature) triples, one per verifiable algorithm,
# shared byte-for-byte with verify-core's ALGORITHM_KATS.
#
# They answer a question the algorithm table cannot: ``verifiable`` says what
# this BUILD implements, which is only half of whether a signature can be
# checked. The other half is whether the HOST RUNTIME will perform the
# operation, and a runtime can refuse. An OpenSSL FIPS provider carries no
# EdDSA, so a perfectly good Ed25519 key either fails to load or raises on
# verify. Both used to be caught and reported as "invalid", which is
# indistinguishable from a forgery (agents#113).
#
# Deliberately fixed, self-contained bytes rather than a freshly generated
# keypair or anything read from the export under audit: promoting a signature
# failure to "not checked" is a security-relevant downgrade, so the signal that
# triggers it must be one no attacker can influence.
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

_RUNTIME_SUPPORT_CACHE: dict[str, bool] = {}


def _runtime_can_compute(key_alg: KeyAlgorithm) -> bool:
    """Whether the host runtime can actually compute ``key_alg``, proven by
    running this build's own dispatch against a known-good signature.

    Covers both ways a restricted runtime refuses: the key failing to load and
    the verify call raising. Any outcome other than a confirmed "ok" is treated
    as incapable, because a runtime that cannot confirm a signature known to be
    valid cannot be trusted to tell a good signature from a forged one. Fail
    closed: callers surface this as "NOT verified, verify elsewhere", never as
    a pass and never as tamper evidence.
    """
    cached = _RUNTIME_SUPPORT_CACHE.get(key_alg.name)
    if cached is not None:
        return cached
    kat = _ALGORITHM_KATS.get(key_alg.name)
    if kat is None:
        # A verifiable algorithm with no KAT is a packaging error, not a
        # runtime gap. Do not silently downgrade real verification.
        supported = True
    else:
        spki_base64, signature_base64 = kat
        try:
            loaded = _load_der_public_key(base64.b64decode(spki_base64))
            supported = (
                isinstance(loaded, (_Ed25519PublicKey, _EllipticCurvePublicKey))
                and _verify_signature_bytes(
                    loaded, key_alg, _KAT_MESSAGE, base64.b64decode(signature_base64)
                )
                == "ok"
            )
        except Exception:
            supported = False
    _RUNTIME_SUPPORT_CACHE[key_alg.name] = supported
    return supported


def _describe_unsupported_algorithm(key_id: str, spki_base64: str) -> str:
    """Detail line for CHAIN_UNSUPPORTED_ALGORITHM. Separates the two causes
    that share the code, because the remedies differ: upgrade the verifier,
    versus re-run somewhere the algorithm is permitted. Mirrors verify-core
    ``describeUnsupportedAlgorithm``.
    """
    key_alg = _resolve_key_algorithm(spki_base64)
    if not isinstance(key_alg, KeyAlgorithm):
        return (
            f"Key {key_id} commits to an algorithm this verifier build cannot "
            f"compute. The chain is NOT verified; upgrade the verifier."
        )
    if not key_alg.verifiable:
        return (
            f"Key {key_id} commits to {key_alg.name}, which this verifier build "
            f"cannot compute. The chain is NOT verified; upgrade the verifier."
        )
    return (
        f"Key {key_id} commits to {key_alg.name}, which this verifier build "
        f"supports but this HOST RUNTIME refused to compute (an active OpenSSL "
        f"FIPS provider carries no EdDSA). This is NOT tamper evidence: the "
        f"signature was never checked, so the chain is neither verified nor "
        f"refuted. Re-run the verification on a host without that restriction."
    )


def _normalize_oob_keys(
    public_keys: Mapping[str, Any] | Sequence[Any] | None,
) -> dict[str, str] | None:
    """Normalize ``public_keys`` into a ``{keyId: spki_b64}`` dict, or raise
    ``TypeError`` at the boundary if the shape is wrong.

    Fail-closed by design: an OOB-key argument that silently falls back to
    embedded keys would lie about the audit-independence claim
    (agledger-agents#77 / F-698).

    Accepts:
      - ``Mapping[str, str]`` — compact ``{keyId: base64SpkiDer}`` form
      - ``Sequence`` of ``{keyId, publicKey}`` entries (the ``.data`` list from
        ``client.verification_keys.list()``, ``VerificationKey`` pydantic models,
        or raw dicts of that shape)
    """
    if public_keys is None:
        return None

    if isinstance(public_keys, Mapping):
        out: dict[str, str] = {}
        for k, v in public_keys.items():
            if not isinstance(v, str):
                raise TypeError(
                    f"verify_export: public_keys[{k!r}] is not a base64 string "
                    f"(got {type(v).__name__}). If you passed the .data list from "
                    f"client.verification_keys.list(), pass it as the list — not "
                    f"a dict built from it."
                )
            out[str(k)] = v
        return out

    if isinstance(public_keys, (str, bytes, bytearray)):
        raise TypeError(
            f"verify_export: public_keys must be a {{keyId: base64SpkiDer}} mapping "
            f"or a sequence of {{keyId, publicKey}} entries (got {type(public_keys).__name__})."
        )

    try:
        items = list(public_keys)
    except TypeError as e:
        raise TypeError(
            f"verify_export: public_keys must be a mapping or a sequence "
            f"(got {type(public_keys).__name__})."
        ) from e

    out = {}
    for i, item in enumerate(items):
        # Dual-spelling lookup: prefer camelCase (the wire shape), then fall
        # back to snake_case (Pydantic attribute style). Use explicit `in` /
        # `is not None` rather than `or` — `or` would treat an empty-string
        # `keyId` as missing and silently substitute `key_id`, masking the
        # upstream bug. TS sibling reads only camelCase; this branch exists
        # only because Python's `verification_keys.list()` returns Pydantic
        # models that expose attributes under snake_case.
        if isinstance(item, Mapping):
            m = cast("Mapping[str, Any]", item)
            key_id = m["keyId"] if "keyId" in m else m.get("key_id")
            material = m["publicKey"] if "publicKey" in m else m.get("public_key")
        else:
            key_id = getattr(item, "keyId", None)
            if key_id is None:
                key_id = getattr(item, "key_id", None)
            material = getattr(item, "publicKey", None)
            if material is None:
                material = getattr(item, "public_key", None)
        if not isinstance(key_id, str) or not isinstance(material, str):
            raise TypeError(
                f"verify_export: public_keys[{i}] is missing required fields "
                f"(keyId, publicKey) — got keyId={type(key_id).__name__}, "
                f"publicKey={type(material).__name__}. Expected the SDK "
                f"VerificationKey shape; publicKey must be SPKI DER base64."
            )
        if key_id == "" or material == "":
            raise TypeError(
                f"verify_export: public_keys[{i}] has empty-string keyId or "
                f"publicKey (keyId={key_id!r}, publicKey-len={len(material)}). "
                f"Empty fields are a structural error — fix the upstream "
                f"serializer rather than pass the empty value through."
            )
        out[key_id] = material
    return out


def _build_key_registry(
    meta: Mapping[str, Any],
    overrides: Mapping[str, str] | None,
) -> KeyCache:
    """Build the keyId → key registry, tagging each key's provenance.

    Embedded keys come from the export's ``signingPublicKeys``; out-of-band keys
    are caller-supplied and OVERRIDE embedded keys of the same id.
    """
    keys: dict[str, RegisteredKey] = {}
    embedded = meta.get("signingPublicKeys")
    if isinstance(embedded, Mapping):
        for k, v in cast("Mapping[Any, Any]", embedded).items():
            keys[str(k)] = RegisteredKey(spki_base64=str(v), source="embedded")
    if overrides:
        for k, v in overrides.items():
            keys[str(k)] = RegisteredKey(spki_base64=str(v), source="out-of-band")
    return KeyCache(keys)


class KeyCache:
    """Registry of verification keys, with a lazy key-object cache.

    Large exports (10k+ entries) would otherwise re-decode the same key on
    every signature check. Carries each key's provenance (embedded vs
    out-of-band) for the result tally and the ``require_out_of_band_keys`` policy.
    """

    def __init__(self, registry: Mapping[str, RegisteredKey]) -> None:
        self._registry = dict(registry)
        self._cache: dict[str, _Ed25519PublicKey | _EllipticCurvePublicKey] = {}

    def entry(self, key_id: str) -> RegisteredKey | None:
        """Registry membership: the raw registered key, or ``None`` if absent
        (CHAIN_SIGNATURE_MISSING_KEY at the call sites)."""
        return self._registry.get(key_id)

    def source(self, key_id: str) -> KeySource | None:
        entry = self._registry.get(key_id)
        return entry.source if entry is not None else None

    def window(self, key_id: str) -> tuple[str | None, str | None]:
        """The key's ``(activated_at, retired_at)`` temporal window, or
        ``(None, None)`` if unknown — the temporal check then no-ops."""
        entry = self._registry.get(key_id)
        if entry is None:
            return (None, None)
        return (entry.activated_at, entry.retired_at)

    def public_key(self, key_id: str) -> _Ed25519PublicKey | _EllipticCurvePublicKey | None:
        """The loaded key object (Ed25519 or EC), or ``None`` when the
        registered key is absent, unparseable, or of another type. Callers
        must have classified the key via :func:`_resolve_key_algorithm` first;
        this is only the loader/cache for the verifiable case."""
        if key_id in self._cache:
            return self._cache[key_id]
        entry = self._registry.get(key_id)
        if entry is None:
            return None
        try:
            loaded = _load_der_public_key(base64.b64decode(entry.spki_base64))
        except Exception:
            return None
        if not isinstance(loaded, (_Ed25519PublicKey, _EllipticCurvePublicKey)):
            return None
        self._cache[key_id] = loaded
        return loaded


def verify_entry(
    entry: Mapping[str, Any],
    expected_position: int,
    expected_prev_hash: str | None,
    keys: KeyCache,
    require_key_id: str | None,
    require_out_of_band_keys: bool,
) -> EntryVerificationResult:
    position = _entry_position(entry)
    integrity = as_mapping(entry.get("integrity"))

    if position != expected_position:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_POSITION_GAP",
            detail=f"Expected chainPosition {expected_position}, got {position}.",
        )

    payload_hash: str | None = integrity.get("payloadHash")
    previous_hash: str | None = integrity.get("previousHash")
    cose_sign1_b64: str | None = integrity.get("coseSign1")
    signing_key_id: str | None = integrity.get("signingKeyId")

    if not cose_sign1_b64 or not payload_hash:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_MALFORMED_ENTRY",
            detail="Entry is missing coseSign1 or payloadHash.",
        )

    envelope = base64.b64decode(cose_sign1_b64)
    recomputed = hashlib.sha256(envelope).hexdigest()
    if recomputed != payload_hash:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_HASH_MISMATCH",
            detail=(
                f"sha256(cose_sign1) {recomputed[:16]}... does not match stored "
                f"payloadHash {payload_hash[:16]}..."
            ),
        )

    # Genesis (position 1) must link to null; any later mismatch is a broken link.
    expected_prev = None if expected_position == 1 else expected_prev_hash
    if previous_hash != expected_prev:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_GENESIS_INVALID" if expected_position == 1 else "CHAIN_LINK_BROKEN",
            detail=(
                f"Expected previousHash={expected_prev or 'null'}, "
                f"got {previous_hash or 'null'}."
            ),
        )

    parts = _decode_cose_sign1(envelope)
    if parts is None:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_COSE_DECODE_FAILED",
            detail="COSE_Sign1 envelope failed to decode.",
            signature="decode-fail",
        )

    chain_claim = _extract_chain_claim(parts[0])
    if (
        chain_claim is None
        or chain_claim[0] != position
        or chain_claim[1] != previous_hash
    ):
        envelope_pos = chain_claim[0] if chain_claim else "null"
        envelope_prev = chain_claim[1] if chain_claim else "null"
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_COSE_HEADER_MISMATCH",
            detail=(
                f"Signed protected-header chain claim (position={envelope_pos}, "
                f"prev={envelope_prev}) diverges from row columns "
                f"(position={position}, prev={previous_hash or 'null'})."
            ),
        )

    # Binding-integrity (verificationGuide step 4): when the export carries the
    # denormalized row ``payload`` (engine ≥ v0.26.x), re-decode the predicate
    # signed inside coseSign1 and deep-equal it against the predicate rebuilt
    # from the row columns. Catches post-export tampering of the human-readable
    # ``payload``/``criteria`` view while ``coseSign1`` is left intact (F-731).
    # Absent ``payload`` (older exports) → skipped, never a silent pass.
    # Binding-integrity and the OIDC-actor cross-check both read the signed
    # predicate, so decode it ONCE here and share it (a dump entry that carries
    # both inputs would otherwise CBOR-decode the same payload bytes twice).
    row_payload = entry.get("payload")
    entry_type = entry.get("entryType")
    actor_oidc = entry.get("actorOidc")
    run_binding = isinstance(row_payload, Mapping) and isinstance(entry_type, str)
    run_oidc = isinstance(actor_oidc, Mapping)
    predicate = _decode_predicate(parts[1]) if (run_binding or run_oidc) else None

    if run_binding:
        rebuilt = _build_predicate_for_row(
            entry.get("recordId"),
            cast(str, entry_type),
            dict(cast("Mapping[str, Any]", row_payload)),
        )
        decoded = _strip_envelope_extensions(predicate) if predicate is not None else None
        if decoded is None or rebuilt is None or rebuilt != decoded:
            return EntryVerificationResult(
                position=position,
                valid=False,
                code="CHAIN_PAYLOAD_BINDING_MISMATCH",
                detail=(
                    "Denormalised row payload no longer matches the canonical "
                    "projection of the signed predicate."
                ),
            )

    # OIDC-actor cross-check (verificationGuide step 5): when the entry carries
    # the denormalised actor OIDC columns (dump path only — the export wire does
    # not), confirm they agree with the identity signed in
    # predicate.on_behalf_of.oidc. Catches DBA tamper of the actor columns on a
    # synthesized row while coseSign1 stays intact. Export entries never carry
    # ``actorOidc`` → skipped. Mirrors verify-core chain.ts checkOidcActor.
    if run_oidc:
        oidc_failure = _check_oidc_actor(cast("Mapping[str, Any]", actor_oidc), predicate, position)
        if oidc_failure is not None:
            return oidc_failure

    # Signature (last, so a null-key row still ran every structural check above).
    # Only a true None is the engine's unsigned-mode marker. Any other value,
    # including the empty string no engine emits, must resolve in the registry
    # and fails CHAIN_SIGNATURE_MISSING_KEY below: a truthiness shortcut here
    # would let a tampered signingKeyId:"" row skip its signature check.
    if signing_key_id is None:
        # Fail closed under a key policy: a high-assurance run that requires a
        # specific key (or out-of-band keys) must NOT accept an unsigned/null-key
        # entry as valid — otherwise an attacker forges an entry, nulls its
        # signingKeyId, and slips past the policy the auditor explicitly set.
        if require_key_id or require_out_of_band_keys:
            return EntryVerificationResult(
                position=position,
                valid=False,
                code="CHAIN_KEY_POLICY_VIOLATION",
                detail=(
                    "Entry has no signingKeyId but this run requires a signed "
                    "entry (require_key_id / require_out_of_band_keys)."
                ),
            )
        return EntryVerificationResult(position=position, valid=True, signature="skipped")

    if require_key_id and signing_key_id != require_key_id:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_KEY_POLICY_VIOLATION",
            detail=(
                f"Entry signingKeyId={signing_key_id} does not match required "
                f"key id {require_key_id}."
            ),
        )

    registered = keys.entry(signing_key_id)
    if registered is None:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_SIGNATURE_MISSING_KEY",
            detail=f"No public key available for signingKeyId={signing_key_id}.",
        )

    key_source = registered.source
    if require_out_of_band_keys and key_source != "out-of-band":
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_KEY_POLICY_VIOLATION",
            detail=(
                f"Key {signing_key_id} is embedded in the artifact; this run "
                f"requires out-of-band keys."
            ),
        )

    # Registry self-consistency: when the input declares an algorithm for this
    # key (vault_signing_keys.algorithm), it must agree with what the SPKI key
    # material commits to. A registry row that lies about its own key is the
    # signature of a mis-registered key or a rewritten registry.
    if registered.algorithm is not None:
        key_alg = _resolve_key_algorithm(registered.spki_base64)
        if (
            isinstance(key_alg, KeyAlgorithm)
            and key_alg.name.lower() != registered.algorithm.lower()
        ):
            return EntryVerificationResult(
                position=position,
                valid=False,
                code="CHAIN_ALG_MISMATCH",
                detail=(
                    f"Key registry declares algorithm={registered.algorithm} for key "
                    f"{signing_key_id}, but the key material is {key_alg.name}."
                ),
            )

    # Signed-kid binding (engine mirror: signing_key_drift, #893). The row's
    # signingKeyId column selected the key above, but the column is a
    # denormalized convenience; the kid at protected-header label 4 is
    # signature-covered. A divergence means the column was rewritten after
    # signing.
    signed_kid = _extract_kid(parts[0])
    if signed_kid is not None and signed_kid != signing_key_id:
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_SIGNING_KEY_DRIFT",
            detail=(
                f"Row signingKeyId={signing_key_id} does not match the "
                f"signature-covered kid {signed_kid} in the protected header."
            ),
        )

    # Temporal key-validity (CHAIN_KEY_EXPIRED): runs only when BOTH the entry
    # write time and a key window are present (dump path) — and only here, AFTER
    # the key has resolved, because it reads the key's window. Placing it earlier
    # would mask a CHAIN_SIGNATURE_MISSING_KEY. Export entries carry no
    # ``createdAt`` and the export registry has no windows → skipped. Mirrors
    # verify-core chain.ts temporalKeyFailure.
    created_at = entry.get("createdAt")
    activated_at, retired_at = keys.window(signing_key_id)
    if isinstance(created_at, str) and (activated_at or retired_at):
        temporal = _temporal_key_failure(
            created_at, signing_key_id, activated_at, retired_at
        )
        if temporal is not None:
            temporal_code, temporal_detail = temporal
            return EntryVerificationResult(
                position=position,
                valid=False,
                code=temporal_code,
                detail=temporal_detail,
            )

    outcome = _verify_cose_signature(parts, registered, keys, signing_key_id)
    if outcome == "unsigned":
        # An all-zero signature slot on an entry that CLAIMS a signing key.
        # Under a key policy this must fail: an auditor who demanded signed
        # entries must never count a zeroed signature as green.
        if require_key_id or require_out_of_band_keys:
            return EntryVerificationResult(
                position=position,
                valid=False,
                code="CHAIN_KEY_POLICY_VIOLATION",
                detail=(
                    f"Entry claims signingKeyId={signing_key_id} but carries an "
                    f"all-zero signature; this run requires signed entries "
                    f"(require_key_id / require_out_of_band_keys)."
                ),
            )
        return EntryVerificationResult(position=position, valid=True, signature="unsigned")
    if outcome == "ok":
        return EntryVerificationResult(
            position=position, valid=True, signature="ok", key_source=key_source
        )
    if outcome == "alg-mismatch":
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_ALG_MISMATCH",
            detail=(
                f"Protected-header alg (label 1) is absent or is not an algorithm "
                f"key {signing_key_id} can produce. Tamper class: a rewritten alg "
                f"must read as forgery, never as an upgrade notice."
            ),
            signature="invalid",
        )
    if outcome == "unsupported-key-algorithm":
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_UNSUPPORTED_ALGORITHM",
            detail=_describe_unsupported_algorithm(
                str(signing_key_id), registered.spki_base64
            ),
            signature="unsupported",
        )
    return EntryVerificationResult(
        position=position,
        valid=False,
        code="CHAIN_SIGNATURE_INVALID",
        detail=f"COSE_Sign1 signature did not verify against key {signing_key_id}.",
        signature="invalid",
    )


# --- Binding-integrity primitives (mirror packages/verify-core/src/primitives.ts) ---

# Keys the engine lifts out of the row payload into dedicated predicate fields
# (state_transition / traces) or treats as envelope siblings — excluded from the
# passthrough so the rebuilt predicate matches what was signed.
_RECORD_STATE_RESERVED_KEYS = frozenset(
    {"from", "to", "state_transition", "traces", "on_behalf_of", "traceparent"}
)
_SCHEMA_EVENT_OUTCOMES = {
    "SCHEMA_REGISTERED": "REGISTERED",
    "SCHEMA_IMPORTED": "IMPORTED",
    "SCHEMA_DIGEST_MISMATCH": "DIGEST_MISMATCH",
}


def _decode_predicate(payload_bstr: bytes) -> dict[str, Any] | None:
    """Decode the in-toto v1 Statement CBOR and return its ``predicate`` body."""
    try:
        stmt = _cbor2.loads(payload_bstr)
    except Exception:
        return None
    if not isinstance(stmt, dict):
        return None
    predicate = cast("dict[str, Any]", stmt).get("predicate")
    if not isinstance(predicate, dict):
        return None
    return cast("dict[str, Any]", predicate)


def _strip_envelope_extensions(predicate: dict[str, Any]) -> dict[str, Any]:
    """Drop the envelope-sibling claims that live at the predicate root but are
    not part of the row-derived projection."""
    return {k: v for k, v in predicate.items() if k not in ("on_behalf_of", "traceparent")}


# --- OIDC-actor primitive (mirror verify-core chain.ts checkOidcActor) ---


def _check_oidc_actor(
    actor_oidc: Mapping[str, Any],
    predicate: Mapping[str, Any] | None,
    position: int,
) -> EntryVerificationResult | None:
    """Cross-check the denormalised actor OIDC columns against the identity
    signed in ``predicate.on_behalf_of.oidc`` (the predicate is the already-
    decoded, UNSTRIPPED in-toto Statement predicate). Returns a failure result
    or ``None`` (pass). Mirrors verify-core chain.ts checkOidcActor — three
    branches, with ``synthesized`` treated as a tri-state (True/False/None).
    """
    row_iss = actor_oidc.get("iss")
    row_iss = row_iss if isinstance(row_iss, str) else None
    row_sub = actor_oidc.get("sub")
    row_sub = row_sub if isinstance(row_sub, str) else None
    # Preserve the tri-state: True / False / None(undefined). The dump field is
    # optional, so a missing key is None — matching the TS ``undefined`` branch.
    # Never coerce to bool.
    synthesized = actor_oidc.get("synthesized")

    # synthesized=true (or legacy undefined with populated columns): the row
    # columns MUST equal the identity signed in predicate.on_behalf_of.oidc.
    if synthesized is True or (
        synthesized is None and (row_iss is not None or row_sub is not None)
    ):
        obo = predicate.get("on_behalf_of") if isinstance(predicate, Mapping) else None
        signed_oidc = cast("Mapping[str, Any]", obo).get("oidc") if isinstance(obo, Mapping) else None
        signed_iss_raw = (
            cast("Mapping[str, Any]", signed_oidc).get("iss")
            if isinstance(signed_oidc, Mapping)
            else None
        )
        signed_iss = signed_iss_raw if isinstance(signed_iss_raw, str) else None
        signed_sub_raw = (
            cast("Mapping[str, Any]", signed_oidc).get("sub")
            if isinstance(signed_oidc, Mapping)
            else None
        )
        signed_sub = signed_sub_raw if isinstance(signed_sub_raw, str) else None
        if row_iss != signed_iss or row_sub != signed_sub:
            return EntryVerificationResult(
                position=position,
                valid=False,
                code="CHAIN_OIDC_ACTOR_MISMATCH",
                detail=(
                    f"Row actor OIDC iss/sub ({row_iss or 'null'}/{row_sub or 'null'}) "
                    f"diverges from signed predicate.on_behalf_of.oidc "
                    f"({signed_iss or 'null'}/{signed_sub or 'null'})."
                ),
            )
        return None

    # synthesized=false: engine writers leave the columns null. Any populated
    # state is a DB-level CHECK-constraint bypass.
    if synthesized is False and (row_iss is not None or row_sub is not None):
        return EntryVerificationResult(
            position=position,
            valid=False,
            code="CHAIN_OIDC_ACTOR_MISMATCH",
            detail=(
                f"actor_oidc_synthesized=false but iss/sub populated "
                f"({row_iss or 'null'}/{row_sub or 'null'})."
            ),
        )
    return None


def _build_predicate_for_row(
    record_id: Any, entry_type: str, payload: dict[str, Any]
) -> dict[str, Any] | None:
    """Re-project ``(record_id, entry_type, payload)`` into the predicate body
    using the same logic the engine applies at write time. Returns ``None`` when
    the payload is structurally insufficient — the caller reads that as a binding
    mismatch rather than crashing on attacker-zeroed payloads."""
    if entry_type in _SCHEMA_EVENT_OUTCOMES:
        return _build_schema_event_predicate(entry_type, payload)
    if not isinstance(record_id, str):
        return None
    return _build_record_state_predicate(record_id, entry_type, payload)


def _build_record_state_predicate(
    record_id: str, entry_type: str, payload: dict[str, Any]
) -> dict[str, Any]:
    transition = _extract_state_transition(payload)
    passthrough = {k: v for k, v in payload.items() if k not in _RECORD_STATE_RESERVED_KEYS}
    predicate: dict[str, Any] = {"record_id": record_id, "entry_type": entry_type}
    if transition is not None:
        predicate["state_transition"] = transition
    if passthrough:
        predicate["payload"] = passthrough
    traces = payload.get("traces")
    if isinstance(traces, Mapping):
        predicate["traces"] = dict(cast("Mapping[str, Any]", traces))
    return predicate


def _extract_state_transition(payload: dict[str, Any]) -> dict[str, Any] | None:
    explicit = payload.get("state_transition")
    if isinstance(explicit, Mapping):
        em = cast("Mapping[str, Any]", explicit)
        if isinstance(em.get("to"), str):
            frm = em.get("from")
            return {"from": frm if isinstance(frm, str) else None, "to": em["to"]}
    to = payload.get("to")
    if isinstance(to, str):
        frm = payload.get("from")
        return {"from": frm if isinstance(frm, str) else None, "to": to}
    return None


def _build_schema_event_predicate(
    entry_type: str, payload: dict[str, Any]
) -> dict[str, Any] | None:
    org_id = payload.get("orgId")
    schema_type = payload.get("type") or payload.get("schemaType") or payload.get("schema_type")
    raw_version = (
        payload.get("version") or payload.get("schemaVersion") or payload.get("schema_version")
    )
    schema_version = str(raw_version) if isinstance(raw_version, (int, float)) else raw_version
    manifest_digest = payload.get("manifestDigest") or payload.get("manifest_digest")
    source = payload.get("source")
    if not isinstance(schema_type, str):
        return None
    if not isinstance(schema_version, str):
        return None
    if not isinstance(manifest_digest, str):
        return None
    predicate: dict[str, Any] = {
        "org_id": org_id if isinstance(org_id, str) else None,
        "schema_type": schema_type,
        "schema_version": schema_version,
        "manifest_digest": manifest_digest,
        "outcome": _SCHEMA_EVENT_OUTCOMES[entry_type],
    }
    if isinstance(source, str):
        predicate["source"] = source
    return predicate


# --- COSE_Sign1 primitives ---


def _decode_cose_sign1(envelope: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Decode a tagged COSE_Sign1 envelope into (protected_bstr, payload_bstr, signature).

    Returns ``None`` on any structural failure.

    Tag 18 is required (short-form ``0xd2``, matching the engine's encoder).
    The engine rejects untagged envelopes: producer and offline verifier must
    agree on what a COSE_Sign1 is, so gate on the leading byte the same way.
    """
    if len(envelope) == 0 or envelope[0] != _COSE_SIGN1_TAG_PREFIX:
        return None
    try:
        decoded = _cbor2.loads(envelope)
    except Exception:
        return None
    # Tagged COSE_Sign1: unwrap CBORTag with tag=18
    if isinstance(decoded, _cbor2.CBORTag):
        if decoded.tag != _COSE_SIGN1_TAG:
            return None
        decoded = decoded.value
    # cbor2 decodes CBOR arrays as tuples; accept both for safety.
    if not isinstance(decoded, (list, tuple)):
        return None
    seq = cast("Sequence[Any]", decoded)
    if len(seq) != 4:
        return None
    protected_bstr, _unprotected, payload_bstr, signature = seq
    if not isinstance(protected_bstr, (bytes, bytearray)):
        return None
    if not isinstance(payload_bstr, (bytes, bytearray)):
        return None
    if not isinstance(signature, (bytes, bytearray)):
        return None
    return bytes(protected_bstr), bytes(payload_bstr), bytes(signature)


def _extract_chain_claim(protected_bstr: bytes) -> tuple[int, str | None] | None:
    """Extract the AGLedger chain-mechanics claim (label -65537) from the COSE
    protected header. Returns ``(position, previous_hash_hex_or_None)`` or
    ``None`` on any structural failure.
    """
    try:
        header_obj: Any = _cbor2.loads(protected_bstr) if protected_bstr else {}
    except Exception:
        return None
    if not isinstance(header_obj, dict):
        return None
    chain = cast("Mapping[Any, Any]", header_obj).get(_AGLEDGER_LABEL_CHAIN)
    if not isinstance(chain, dict):
        return None
    chain_map = cast("Mapping[Any, Any]", chain)
    position = chain_map.get(_CHAIN_SUBLABEL_POSITION)
    prev = chain_map.get(_CHAIN_SUBLABEL_PREVIOUS_HASH)
    # bool is a subclass of int in Python; reject it so a CBOR boolean position
    # cannot pass as 1/0 (TS rejects a non-number/bigint position here too).
    if isinstance(position, bool) or not isinstance(position, int) or position < 1:
        return None
    if prev is None:
        return position, None
    if not isinstance(prev, (bytes, bytearray)):
        return None
    return position, bytes(prev).hex()


def _extract_header_alg(protected_bstr: bytes) -> int | None:
    """Decode the protected header's ``alg`` (label 1); ``None`` when absent
    or not an integer. A bool is rejected (it is an int subclass in Python)."""
    try:
        header_obj: Any = _cbor2.loads(protected_bstr) if protected_bstr else {}
    except Exception:
        return None
    if not isinstance(header_obj, dict):
        return None
    alg = cast("Mapping[Any, Any]", header_obj).get(_COSE_HEADER_ALG)
    if isinstance(alg, bool) or not isinstance(alg, int):
        return None
    return alg


def _extract_kid(protected_bstr: bytes) -> str | None:
    """Extract the signature-covered ``kid`` (protected header label 4) as
    lowercase hex, matching the engine's ``vault_signing_keys.key_id`` shape.
    ``None`` when absent or malformed. The caller cross-checks it against the
    row's ``signingKeyId`` column: the column is a denormalized convenience,
    the kid is signed (engine mirror: signing_key_drift, #893)."""
    try:
        header_obj: Any = _cbor2.loads(protected_bstr) if protected_bstr else {}
    except Exception:
        return None
    if not isinstance(header_obj, dict):
        return None
    kid = cast("Mapping[Any, Any]", header_obj).get(_COSE_HEADER_KID)
    if not isinstance(kid, (bytes, bytearray)):
        return None
    return bytes(kid).hex()


CoseVerifyOutcome = Literal[
    "ok", "invalid", "unsigned", "decode-fail", "alg-mismatch", "unsupported-key-algorithm"
]


def _verify_cose_signature(
    parts: tuple[bytes, bytes, bytes],
    key: RegisteredKey,
    loader: KeyCache | None = None,
    key_id: str | None = None,
) -> Literal["ok", "invalid", "unsigned", "alg-mismatch", "unsupported-key-algorithm"]:
    """Verify the COSE_Sign1 signature over Sig_structure, with dispatch bound
    to the TRUSTED key (mirrors verify-core ``verifyCoseSign1``).

    At this point the signature has not been checked, so the header ``alg`` is
    attacker-controlled input: it is asserted equal to what the key material
    commits to and never selects the code path. The all-zero unsigned sentinel
    is checked only AFTER algorithm resolution, at the key's expected signature
    length. ``Sig_structure = ["Signature1", protected_bstr, h'' (empty
    external_aad), payload_bstr]`` per RFC 9052 §4.4, deterministically
    CBOR-encoded per RFC 8949 §4.2.1.
    """
    protected_bstr, payload_bstr, signature = parts

    key_alg = _resolve_key_algorithm(key.spki_base64)
    # A key that does not parse can verify nothing; report 'invalid' rather
    # than misreporting garbage bytes as an algorithm gap. The exception is a
    # runtime that cannot load a known-good Ed25519 key either: there, "did not
    # parse" is ambiguous between tamper and refusal, and the chain is
    # unverifiable on this host regardless, so say so rather than cry forgery.
    if key_alg == "unparseable":
        return (
            "invalid"
            if _runtime_can_compute(_ED25519_ALG)
            else "unsupported-key-algorithm"
        )
    if key_alg == "unrecognized":
        return "unsupported-key-algorithm"

    header_alg = _extract_header_alg(protected_bstr)
    if header_alg is None or header_alg not in key_alg.cose_algs:
        return "alg-mismatch"
    # Two independent reasons the signature cannot be checked: this build does
    # not implement the algorithm, or the host runtime refuses to compute it
    # (agents#113). Both must read as "not verified", never "did not verify".
    if not key_alg.verifiable or not _runtime_can_compute(key_alg):
        return "unsupported-key-algorithm"

    if len(signature) == key_alg.signature_length and all(b == 0 for b in signature):
        return "unsigned"

    if loader is not None and key_id is not None:
        public_key = loader.public_key(key_id)
    else:
        try:
            loaded = _load_der_public_key(base64.b64decode(key.spki_base64))
        except Exception:
            loaded = None
        public_key = (
            loaded
            if isinstance(loaded, (_Ed25519PublicKey, _EllipticCurvePublicKey))
            else None
        )
    if public_key is None:
        return "invalid"

    sig_structure: list[Any] = [
        _SIG_STRUCTURE_CONTEXT,
        protected_bstr,
        b"",
        payload_bstr,
    ]
    to_be_signed = _cbor2.dumps(sig_structure, canonical=True)
    return _verify_signature_bytes(public_key, key_alg, to_be_signed, signature)


def _verify_signature_bytes(
    public_key: _Ed25519PublicKey | _EllipticCurvePublicKey,
    key_alg: KeyAlgorithm,
    to_be_signed: bytes,
    signature: bytes,
) -> Literal["ok", "invalid"]:
    """Verify raw signature bytes under the algorithm the key commits to.

    ES256 mirrors the engine's ``verifyWithAlgorithm``: the wire carries raw
    ``r||s`` (COSE / ieee-p1363, 64 bytes), which ``cryptography`` expects
    DER-encoded, so the two 32-byte halves are re-encoded via
    ``encode_dss_signature``. The engine emits low-S but, like the engine's
    verifier, high-S is accepted: ECDSA malleability changes the envelope
    bytes, which the hash-link layer already pins. Any key/algorithm pairing
    outside the table reads ``invalid`` (the callers gate ``verifiable``
    upstream, so this is unreachable except through a refactor bug, and it
    must fail closed).
    """
    try:
        if isinstance(public_key, _Ed25519PublicKey) and key_alg.name == "Ed25519":
            public_key.verify(signature, to_be_signed)
            return "ok"
        if (
            isinstance(public_key, _EllipticCurvePublicKey)
            and key_alg.name == "ES256"
            and isinstance(public_key.curve, _SECP256R1)
        ):
            if len(signature) != 64:
                return "invalid"
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public_key.verify(
                _encode_dss_signature(r, s), to_be_signed, _ECDSA(_SHA256())
            )
            return "ok"
        return "invalid"
    except _InvalidSignature:
        return "invalid"
    except Exception:
        return "invalid"


def verify_cose_sign1(envelope: bytes, key: RegisteredKey) -> CoseVerifyOutcome:
    """Decode a tagged COSE_Sign1 envelope and verify its signature in one
    call, dispatch bound to the trusted ``key``. Mirrors verify-core
    ``verifyCoseSign1``. Used by the dump verifier for checkpoint + STH
    signatures."""
    parts = _decode_cose_sign1(envelope)
    if parts is None:
        return "decode-fail"
    return _verify_cose_signature(parts, key)


# --- temporal key-validity (mirror verify-core chain.ts temporalKeyFailure) ---


def _parse_instant(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp to a comparable instant, normalising a
    trailing ``Z`` to ``+00:00``. ``fromisoformat`` handles ``Z`` natively from
    3.11 on, so the replace is now belt-and-braces rather than required. Returns
    ``None`` on any parse failure — the caller reads that as "skip" (fail-open),
    matching the TS ``Number.isNaN(Date.parse(...))`` no-op."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _temporal_key_failure(
    created_at: str,
    key_id: str,
    activated_at: str | None,
    retired_at: str | None,
) -> tuple[FailureCode, str] | None:
    """Return ``(code, detail)`` if ``created_at`` falls outside the key's
    activated..retired window, else ``None``. Bounds are inclusive: an entry
    written exactly at activation or retirement is valid (strict ``<`` / ``>``
    comparisons). Unparseable timestamps are skipped (no failure), mirroring TS.

    The two directions carry different codes (agents#112): reporting "expired"
    for a key that had not started yet sent consumers to investigate rotation
    when the real condition is a backdated entry or clock skew.
    """
    written = _parse_instant(created_at)
    if written is None:
        return None
    if activated_at:
        activated = _parse_instant(activated_at)
        if activated is not None and written < activated:
            return (
                "CHAIN_KEY_NOT_YET_ACTIVE",
                f"Entry written {created_at} predates key {key_id} activation {activated_at}.",
            )
    if retired_at:
        retired = _parse_instant(retired_at)
        if retired is not None and written > retired:
            return (
                "CHAIN_KEY_EXPIRED",
                f"Entry written {created_at} postdates key {key_id} retirement {retired_at}.",
            )
    return None


# --- Merkle primitives (mirror verify-core primitives.ts merkleRoot/hashPair) ---


def _hash_pair(left: str, right: str) -> str:
    """Hash two hex-string children into a parent hex digest. Per verify-core,
    the two hex STRINGS are concatenated and the resulting UTF-8 text is hashed
    — NOT a byte concat, and NO RFC 9162 0x00/0x01 domain-separation prefixes
    (those belong to the SCITT receipt path, not org_admin_reads)."""
    return hashlib.sha256((left + right).encode()).hexdigest()


def merkle_root(leaves: Sequence[str]) -> str:
    """Recompute a plain Merkle root over hex-string leaf hashes. Odd levels
    duplicate the last leaf; an empty leaf set hashes the empty string. Mirrors
    verify-core ``merkleRoot`` exactly (the function org_admin_reads STHs use).
    """
    if len(leaves) == 0:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_hash_pair(left, right))
        level = nxt
    return level[0]
