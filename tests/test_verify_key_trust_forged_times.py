"""A statement's ``id`` and ``createdAt`` on an export or a supplied key
document are unsigned. They may order the walk, but they never decide what a
distrusted key's edges are worth: an attacker who holds the leaked key writes
whatever write time puts its statement before the cutoff. Only a dump's own
``vault_key_statements`` rows date a distrusted key's statements."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import cbor2

from agledger.verify import verify_export

from .key_statement_helpers import (
    T0,
    T1,
    T2,
    Stored,
    TestKey,
    make_key,
    raw_sign,
    statement,
)

_EXPORT = Path(__file__).resolve().parents[1] / "testdata" / "conformance" / "export"


def _resigned_under(x: TestKey) -> dict[str, Any]:
    """valid.json with every entry re-signed under ``x``, chain links intact."""
    exp: dict[str, Any] = json.loads((_EXPORT / "valid.json").read_text())
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


def _pub(s: Stored, created_at: str | None) -> dict[str, Any]:
    cose = [base64.b64encode(c if isinstance(c, bytes) else c.encode()).decode() for c in s.cose]
    if created_at is None:
        return {"kind": s.kind, "cose": cose}
    return {"id": s.id, "kind": s.kind, "createdAt": created_at, "cose": cose}


def _single_key_attack(succ_at: str | None) -> Any:
    """Probe 2: anchor C, C distrusted from T1, the holder of leaked C admits X."""
    c, x = make_key(), make_key()
    exp = _resigned_under(x)
    gen = statement("genesis", c, signers=[c], activated_at=T0)
    succ = statement("succession", x, endorser=c, signers=[c, x], activated_at=T2)
    m = exp["exportMetadata"]
    m["signingPublicKey"] = x.public_key
    m["signingPublicKeys"] = {c.kid: c.public_key, x.kid: x.public_key}
    m["signingKeyWindows"] = {
        c.kid: {"activatedAt": "2026-09-01T00:00:00.000Z", "retiredAt": None},
        x.kid: {"activatedAt": "2026-09-03T00:00:00.000Z", "retiredAt": None},
    }
    m["anchoredFrom"] = f"sha256:{c.digest}"
    m["signingKeyStatements"] = {
        c.kid: [_pub(gen, None if succ_at is None else "2026-09-01T00:00:00.000000Z")],
        x.kid: [_pub(succ, succ_at)],
    }
    return verify_export(exp, trust_anchors=[f"sha256:{c.digest}"], distrusted_keys=[f"sha256:{c.digest}@{T1}"])


def test_a_distrusted_keys_succession_is_void_whatever_write_time_the_export_gives_it() -> None:
    for succ_at in (None, "2026-09-01T12:00:00.000000Z", "2026-10-02T15:00:00.000000Z"):
        r = _single_key_attack(succ_at)
        assert r.valid is False, succ_at
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_SIGNING_KEY_UNANCHORED", succ_at
        assert r.key_trust.status == "no_anchored_signature"
        assert r.key_trust.order == ("signed" if succ_at is None else "written")
        assert len(r.key_trust.anchored_key_ids) == 1


def _rotation_attack(export_times: bool, succ_at: str) -> Any:
    """Probe 3: the operator pins its current key N, supplies the honest key
    document it fetched itself, and distrusts the retired C; the export adds a
    succession from leaked C into X."""
    c, n, x = make_key(), make_key(), make_key()
    exp = _resigned_under(x)
    gen = statement("genesis", c, signers=[c], activated_at=T0)
    rot = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    clo = statement("closure", c, endorser=n, signers=[n], retired_at=T1)
    succ = statement("succession", x, endorser=c, signers=[c, x], activated_at="2026-09-01T06:00:00.000000Z")
    honest = {
        c.kid: [_pub(gen, "2026-09-01T00:00:00.000100Z"), _pub(clo, "2026-09-02T00:00:00.000300Z")],
        n.kid: [_pub(rot, "2026-09-02T00:00:00.000200Z")],
    }
    m = exp["exportMetadata"]
    m["signingPublicKey"] = x.public_key
    m["signingPublicKeys"] = {c.kid: c.public_key, n.kid: n.public_key, x.kid: x.public_key}
    m["signingKeyWindows"] = {x.kid: {"activatedAt": "2026-09-01T06:00:00.000Z", "retiredAt": None}}
    m["anchoredFrom"] = f"sha256:{n.digest}"
    own = {**copy.deepcopy(honest), x.kid: [_pub(succ, succ_at)]}
    if not export_times:
        own = {k: [{"kind": s["kind"], "cose": s["cose"]} for s in v] for k, v in own.items()}
    m["signingKeyStatements"] = own
    public_keys: list[dict[str, Any]] = [
        {
            "keyId": c.kid,
            "publicKey": c.public_key,
            "activatedAt": "2026-09-01T00:00:00.000Z",
            "retiredAt": "2026-09-02T00:00:00.000Z",
            "statements": honest[c.kid],
        },
        {
            "keyId": n.kid,
            "publicKey": n.public_key,
            "activatedAt": "2026-09-02T00:00:00.000Z",
            "retiredAt": None,
            "statements": honest[n.kid],
        },
        {"keyId": x.kid, "publicKey": x.public_key},
    ]
    return verify_export(
        exp,
        public_keys=public_keys,
        trust_anchors=[f"sha256:{n.digest}"],
        distrusted_keys=[f"sha256:{c.digest}@2026-09-05T00:00:00Z"],
    )


def test_an_export_only_statement_beside_an_honest_supplied_document_cannot_backdate_a_distrusted_key() -> None:
    for succ_at in ("2026-10-02T15:00:00.000000Z", "2026-09-01T12:00:00.000000Z"):
        r = _rotation_attack(True, succ_at)
        assert r.valid is False, succ_at
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_SIGNING_KEY_UNANCHORED", succ_at
        assert (r.key_trust.status, r.key_trust.order) == ("no_anchored_signature", "written")
        assert len(r.key_trust.anchored_key_ids) == 2


def test_stripping_the_exports_times_beside_an_honest_supplied_document_reopens_nothing() -> None:
    r = _rotation_attack(False, "2026-09-01T12:00:00.000000Z")
    assert r.valid is False
    assert r.broken_at is not None and r.broken_at.code == "CHAIN_SIGNING_KEY_UNANCHORED"
    assert (r.key_trust.status, r.key_trust.order) == ("no_anchored_signature", "signed")
