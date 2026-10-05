"""A statement's ``id`` and ``createdAt`` on an export or a supplied key
document are unsigned. They may order the walk, but they never decide what a
distrusted key's edges are worth: an attacker who holds the leaked key writes
whatever write time puts its statement before the cutoff. Only a dump's own
``vault_key_statements`` rows date a distrusted key's statements."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from agledger.verify import verify_export

from .key_statement_helpers import (
    EXPORT_DIR,
    T0,
    T1,
    T2,
    make_key,
    pub,
    resigned_under,
    statement,
)


def _single_key_attack(succ_at: str | None) -> Any:
    """Probe 2: root R pinned admitted C, C distrusted from T1, and the holder of
    leaked C admits X."""
    r0, c, x = make_key(), make_key(), make_key()
    exp = resigned_under(x)
    root = statement("genesis", r0, signers=[r0], activated_at=T0)
    admit = statement("succession", c, endorser=r0, signers=[r0, c], activated_at=T0)
    succ = statement("succession", x, endorser=c, signers=[c, x], activated_at=T2)
    m = exp["exportMetadata"]
    m["signingPublicKey"] = x.public_key
    m["signingPublicKeys"] = {r0.kid: r0.public_key, c.kid: c.public_key, x.kid: x.public_key}
    m["signingKeyWindows"] = {
        r0.kid: {"activatedAt": "2026-09-01T00:00:00.000Z", "retiredAt": None},
        c.kid: {"activatedAt": "2026-09-01T00:00:00.000Z", "retiredAt": None},
        x.kid: {"activatedAt": "2026-09-03T00:00:00.000Z", "retiredAt": None},
    }
    m["anchoredFrom"] = f"sha256:{r0.digest}"
    m["signingKeyStatements"] = {
        r0.kid: [pub(root, None if succ_at is None else "2026-09-01T00:00:00.000000Z")],
        c.kid: [pub(admit, None if succ_at is None else "2026-09-01T00:00:00.000100Z")],
        x.kid: [pub(succ, succ_at)],
    }
    return verify_export(exp, trust_anchors=[f"sha256:{r0.digest}"], distrusted_keys=[f"sha256:{c.digest}@{T1}"])


def test_a_distrusted_keys_succession_is_void_whatever_write_time_the_export_gives_it() -> None:
    for succ_at in (None, "2026-09-01T12:00:00.000000Z", "2026-10-02T15:00:00.000000Z"):
        r = _single_key_attack(succ_at)
        assert r.valid is False, succ_at
        assert r.broken_at is not None and r.broken_at.code == "CHAIN_SIGNING_KEY_UNANCHORED", succ_at
        assert r.key_trust.status == "no_anchored_signature"
        assert r.key_trust.order == ("signed" if succ_at is None else "written")
        assert len(r.key_trust.anchored_key_ids) == 2  # the root and the key it admitted


def _rotation_attack(export_times: bool, succ_at: str) -> Any:
    """Probe 3: the operator pins its current key N, supplies the honest key
    document it fetched itself, and distrusts the retired C; the export adds a
    succession from leaked C into X."""
    c, n, x = make_key(), make_key(), make_key()
    exp = resigned_under(x)
    gen = statement("genesis", c, signers=[c], activated_at=T0)
    rot = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    clo = statement("closure", c, endorser=n, signers=[n], retired_at=T1)
    succ = statement("succession", x, endorser=c, signers=[c, x], activated_at="2026-09-01T06:00:00.000000Z")
    honest = {
        c.kid: [pub(gen, "2026-09-01T00:00:00.000100Z"), pub(clo, "2026-09-02T00:00:00.000300Z")],
        n.kid: [pub(rot, "2026-09-02T00:00:00.000200Z")],
    }
    m = exp["exportMetadata"]
    m["signingPublicKey"] = x.public_key
    m["signingPublicKeys"] = {c.kid: c.public_key, n.kid: n.public_key, x.kid: x.public_key}
    m["signingKeyWindows"] = {x.kid: {"activatedAt": "2026-09-01T06:00:00.000Z", "retiredAt": None}}
    m["anchoredFrom"] = f"sha256:{n.digest}"
    own = {**copy.deepcopy(honest), x.kid: [pub(succ, succ_at)]}
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


def _honest_rotation(distrusted: list[str], pin_current: bool = True) -> Any:
    """Probe 4: genesis C, rotation C->N, closure of C by N, entries under N,
    the operator's own timed key document supplied, and C distrusted from
    after the rotation. Nothing here was forged."""
    c, n = make_key(), make_key()
    exp = resigned_under(n)
    gen = statement("genesis", c, signers=[c], activated_at=T0)
    rot = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    clo = statement("closure", c, endorser=n, signers=[n], retired_at=T1)
    honest = {
        c.kid: [pub(gen, "2026-09-01T00:00:00.000100Z"), pub(clo, "2026-09-02T00:00:00.000300Z")],
        n.kid: [pub(rot, "2026-09-02T00:00:00.000200Z")],
    }
    m = exp["exportMetadata"]
    m["signingPublicKey"] = n.public_key
    m["signingPublicKeys"] = {c.kid: c.public_key, n.kid: n.public_key}
    m["signingKeyWindows"] = {
        n.kid: {"activatedAt": "2026-09-02T00:00:00.000Z", "retiredAt": None},
        c.kid: {"activatedAt": "2026-09-01T00:00:00.000Z", "retiredAt": "2026-09-02T00:00:00.000Z"},
    }
    m["anchoredFrom"] = f"sha256:{n.digest}"
    m["signingKeyStatements"] = copy.deepcopy(honest)
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
    ]
    pin = n if pin_current else c
    return verify_export(
        exp,
        public_keys=public_keys,
        trust_anchors=[f"sha256:{pin.digest}"],
        distrusted_keys=[d.replace("{C}", c.digest) for d in distrusted],
    )


def test_an_honest_rotation_out_of_a_key_distrusted_after_it_still_passes_pinned_on_the_current_key() -> None:
    plain = _honest_rotation([])
    assert plain.valid is True
    assert plain.key_trust.notes == []
    r = _honest_rotation(["sha256:{C}@2026-09-05T00:00:00Z"])
    assert r.valid is True, r.broken_at
    assert (r.key_trust.status, r.key_trust.findings) == ("walked", [])
    assert len(r.key_trust.anchored_key_ids) == 2
    # The rotation C signed admits nothing here, which is a note, not a finding.
    assert len(r.key_trust.notes) == 1
    assert "is not signed and is not held against the cutoff" in r.key_trust.notes[0].detail
    assert r.key_trust.to_json()["notes"] == [n.to_json() for n in r.key_trust.notes]


_MALFORMED_WINDOWS = [
    "2026-10-02T15:03:54.500",
    "2026-10-02 15:03:54.5",
    "Oct 2 2026 15:03:54",
    "2026-10-02T15:03:54.500+24:00",
    "garbage",
    "2026-02-30T00:00:00Z",
]


def test_a_window_the_caller_supplies_that_is_not_rfc3339_raises_naming_the_key() -> None:
    exp: dict[str, Any] = json.loads((EXPORT_DIR / "valid.json").read_text())
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    public_key = exp["exportMetadata"]["signingPublicKeys"][key_id]
    for bad in [*_MALFORMED_WINDOWS, 7]:
        for edge in ("activatedAt", "retiredAt"):
            entry = {"keyId": key_id, "publicKey": public_key, "activatedAt": "2026-01-01T00:00:00Z", "retiredAt": None}
            entry[edge] = bad
            with pytest.raises(TypeError, match=rf"\(key {key_id}\) has {edge}"):
                verify_export(copy.deepcopy(exp), public_keys=[entry])


def test_a_window_the_export_embeds_that_is_not_rfc3339_fails_its_entries_malformed() -> None:
    for bad in _MALFORMED_WINDOWS:
        for edge in ("activatedAt", "retiredAt"):
            exp: dict[str, Any] = json.loads((EXPORT_DIR / "valid.json").read_text())
            key_id = exp["entries"][0]["integrity"]["signingKeyId"]
            exp["exportMetadata"]["signingKeyWindows"][key_id][edge] = bad
            r = verify_export(exp)
            assert r.broken_at is not None, (edge, bad)
            assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_MALFORMED_ENTRY")
            assert r.broken_at.detail == (
                f"Key {key_id}'s {edge} {json.dumps(bad)} is not an RFC 3339 instant, so the entry cannot be "
                "placed inside its window."
            )


def test_pinned_only_on_the_distrusted_predecessor_with_no_instant_is_refused_and_with_one_does_not_reach_its_successor() -> None:
    with pytest.raises(TypeError, match="a trust anchor and a distrusted key with no instant"):
        _honest_rotation(["sha256:{C}"], pin_current=False)
    # Dated, the pin vouches for what C stored before the instant, but the
    # document cannot date the rotation it signed: pin the successor.
    r = _honest_rotation(["sha256:{C}@2026-09-05T00:00:00Z"], pin_current=False)
    assert r.broken_at is not None and r.broken_at.code == "CHAIN_SIGNING_KEY_UNANCHORED"
    assert len(r.key_trust.anchored_key_ids) == 1
    assert len(r.key_trust.notes) == 1