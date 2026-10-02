"""Test-only signer for vault key statements, written from the statement
format (the engine's encodeKeyStatementPayload / signKeyStatement), so the walk
under test never checks bytes it produced itself. A port of verify-core's
``key-statements-helpers.ts``."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from agledger.verify.key_statements import KeyStatementInput, TrustKeyInput

Alg = Literal["Ed25519", "ES256"]
CTY = "application/vnd.agledger.key-statement+cbor"


@dataclass(frozen=True, eq=False)
class TestKey:
    __test__ = False

    private_key: Any
    public_key: str
    digest: str
    kid: str
    alg: Alg
    #: Key material nothing on this host parses, whose signatures are random bytes.
    opaque: bool = False
    name: str = ""


def make_key(alg: Alg = "Ed25519", name: str = "") -> TestKey:
    private: Any = Ed25519PrivateKey.generate() if alg == "Ed25519" else ec.generate_private_key(ec.SECP256R1())
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest()
    return TestKey(private, base64.b64encode(der).decode(), digest, digest[:16], alg, name=name)


def make_opaque_key() -> TestKey:
    """An Ed25519 key as a host without EdDSA sees it: bytes that do not parse."""
    raw = os.urandom(44)
    digest = hashlib.sha256(raw).hexdigest()
    return TestKey(None, base64.b64encode(raw).decode(), digest, digest[:16], "Ed25519", opaque=True)


def encode_payload(p: dict[str, Any]) -> bytes:
    subject: dict[str, Any] = {
        "kid": p["subject"]["kid"],
        "spkiSha256": p["subject"]["spkiSha256"],
        "alg": p["subject"]["alg"],
        "spki": base64.b64decode(p["subject"]["spki"]),
        "activatedAt": p["subject"]["activatedAt"],
    }
    if "retiredAt" in p["subject"]:
        subject["retiredAt"] = p["subject"]["retiredAt"]
    out: dict[str, Any] = {"typ": p["typ"], "iss": p["iss"], "subject": subject, "iat": p["iat"]}
    if "endorser" in p:
        out["endorser"] = {"kid": p["endorser"]["kid"], "spkiSha256": p["endorser"]["spkiSha256"]}
    if "forced" in p:
        out["forced"] = p["forced"]
    return cbor2.dumps(out, canonical=True)


def raw_sign(k: TestKey, to_be_signed: bytes) -> bytes:
    if k.alg == "Ed25519":
        return k.private_key.sign(to_be_signed)
    r, s = decode_dss_signature(k.private_key.sign(to_be_signed, ec.ECDSA(SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def envelope(protected: bytes, payload: bytes, signature: bytes) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]), canonical=True)


_DEFAULT: Any = object()


def sign_statement(
    payload: bytes, k: TestKey, alg: int | None = None, *, cty: Any = _DEFAULT, kid: str | None = None
) -> bytes:
    """Sign as the format does; ``alg``, ``cty`` and ``kid`` override the
    protected-header values the format sets, for negative cases."""
    header = {
        1: alg if alg is not None else (-8 if k.alg == "Ed25519" else -7),
        3: CTY if cty is _DEFAULT else cty,
        4: bytes.fromhex(kid or k.kid),
    }
    protected = cbor2.dumps(header, canonical=True)
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    signature = os.urandom(64) if k.opaque else raw_sign(k, to_be_signed)
    return envelope(protected, payload, signature)


T0 = "2026-09-01T00:00:00.000000Z"
T1 = "2026-09-02T00:00:00.000000Z"
T2 = "2026-09-03T00:00:00.000000Z"
T3 = "2026-09-04T00:00:00.000000Z"

_seq = [0]


def next_id() -> str:
    _seq[0] += 1
    return f"00000000-0000-7000-8000-{_seq[0]:012d}"


def ms(instant: str) -> str:
    """A microsecond instant as a millisecond ISO string, the way the dump writes a column."""
    return f"{instant[:23]}Z"


def row(k: TestKey, activated: str, retired: str | None = None) -> TrustKeyInput:
    """A dump key row, with the window columns at millisecond precision as the dump writes them."""
    return TrustKeyInput(
        key_id=k.kid,
        public_key=k.public_key,
        algorithm=k.alg,
        status="retired" if retired else "active",
        activated_at=ms(activated),
        retired_at=ms(retired) if retired else None,
    )


@dataclass(frozen=True, eq=False)
class Stored(KeyStatementInput):
    """A statement as a dump row carries it, with the payload it signs."""

    payload: dict[str, Any] = field(default_factory=dict[str, Any])
    digest: str = ""
    attacker: bool = False


def payload_of(
    typ: str,
    subject: TestKey,
    *,
    endorser: TestKey | None = None,
    activated_at: str = T0,
    retired_at: str | None = None,
    forced: bool | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    p: dict[str, Any] = {
        "typ": typ,
        "iss": "https://ledger.example",
        "subject": {
            "kid": subject.kid,
            "spkiSha256": subject.digest,
            "alg": subject.alg,
            "spki": subject.public_key,
            "activatedAt": activated_at,
            **({"retiredAt": retired_at} if retired_at else {}),
        },
        "iat": iat if iat is not None else 1788480000,  # T3 in epoch seconds
    }
    if endorser is not None:
        p["endorser"] = {"kid": endorser.kid, "spkiSha256": endorser.digest}
    if typ == "closure":
        p["forced"] = bool(forced)
    return p


def statement(
    typ: str,
    subject: TestKey,
    *,
    signers: list[TestKey],
    endorser: TestKey | None = None,
    activated_at: str | None = None,
    retired_at: str | None = None,
    forced: bool | None = None,
    iat: int | None = None,
    created_at: str | None = None,
) -> Stored:
    payload = payload_of(
        typ,
        subject,
        endorser=endorser,
        activated_at=activated_at or T0,
        retired_at=retired_at,
        forced=forced,
        iat=iat,
    )
    data = encode_payload(payload)
    return Stored(
        id=next_id(),
        kind=typ,
        subject_key_id=subject.kid,
        endorser_key_id=endorser.kid if endorser else None,
        endorser_column=True,
        source="dump",
        cose=[sign_statement(data, k) for k in signers],
        created_at=ms(created_at or T1),
        digest=hashlib.sha256(data).hexdigest(),
        payload=payload,
    )


def as_published(statements: list[Stored]) -> dict[str, list[dict[str, Any]]]:
    """The same statements as an API 2.0 key surface publishes them, filed
    under their subject key in the order given: each with its row ``id`` and
    its ``createdAt`` at microsecond precision."""
    out: dict[str, list[dict[str, Any]]] = {}
    for s in statements:
        created = f"{s.created_at[:-1]}000Z" if s.created_at else s.created_at
        out.setdefault(s.subject_key_id or "", []).append(
            {"id": s.id, "kind": s.kind, "createdAt": created, "cose": list(s.cose)}
        )
    return out


def as_document(statements: list[Stored]) -> list[KeyStatementInput]:
    """The same statements as a key document carries them: no write time, no endorser column."""
    return [KeyStatementInput(id=s.id, kind=s.kind, subject_key_id=s.subject_key_id, cose=s.cose) for s in statements]


EXPORT_DIR = Path(__file__).resolve().parents[1] / "testdata" / "conformance" / "export"


def resigned_under(x: TestKey) -> dict[str, Any]:
    """valid.json with every entry re-signed under ``x``, chain links intact."""
    exp: dict[str, Any] = json.loads((EXPORT_DIR / "valid.json").read_text())
    prev: bytes | None = None
    for e in exp["entries"]:
        tagged: Any = cbor2.loads(base64.b64decode(e["integrity"]["coseSign1"]))
        protected, _unprotected, payload, _sig = tagged.value
        header: dict[int, Any] = cbor2.loads(protected)
        header[4] = bytes.fromhex(x.kid)
        header[-65537] = {**header[-65537], 2: prev}
        new_protected = cbor2.dumps(header, canonical=True)
        signature = raw_sign(x, cbor2.dumps(["Signature1", new_protected, b"", payload], canonical=True))
        env = cbor2.dumps(cbor2.CBORTag(18, [new_protected, {}, payload, signature]), canonical=True)
        digest = hashlib.sha256(env).digest()
        e["integrity"]["coseSign1"] = base64.b64encode(env).decode()
        e["integrity"]["payloadHash"] = digest.hex()
        e["integrity"]["previousHash"] = None if prev is None else prev.hex()
        e["integrity"]["signingKeyId"] = x.kid
        prev = digest
    return exp


def pub(s: Stored, created_at: str | None) -> dict[str, Any]:
    cose = [base64.b64encode(c if isinstance(c, bytes) else c.encode()).decode() for c in s.cose]
    if created_at is None:
        return {"kind": s.kind, "cose": cose}
    return {"id": s.id, "kind": s.kind, "createdAt": created_at, "cose": cose}


def under_admitted_key() -> tuple[dict[str, Any], str, TestKey]:
    """valid.json re-signed under a key K that a genesis root G admitted, with
    both statements and windows in the export: pin the returned anchor (G) and
    distrust K, the shape a leak takes, since a key is never both pinned and
    distrusted."""
    g, k = make_key(), make_key()
    genesis = statement("genesis", g, signers=[g], activated_at=T0)
    succ = statement("succession", k, endorser=g, signers=[g, k], activated_at=T1)
    exp = resigned_under(k)
    m = exp["exportMetadata"]
    m["signingPublicKey"] = k.public_key
    m["signingPublicKeys"] = {g.kid: g.public_key, k.kid: k.public_key}
    m["signingKeyWindows"] = {
        g.kid: {"activatedAt": ms(T0), "retiredAt": None},
        k.kid: {"activatedAt": ms(T1), "retiredAt": None},
    }
    m["anchoredFrom"] = f"sha256:{g.digest}"
    m["signingKeyStatements"] = {
        g.kid: [pub(genesis, "2026-09-01T00:00:00.000100Z")],
        k.kid: [pub(succ, "2026-09-02T00:00:00.000100Z")],
    }
    return exp, f"sha256:{g.digest}", k
