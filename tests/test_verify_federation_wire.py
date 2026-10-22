"""The sealed federation message on a receiving Server's chain entry
(``payload.wire``): its body hash and its agreement with the entry on every
sealed message, and its signature under the sender's federation key when one
is supplied. A wire is sealed here the way the Server seals it, from a test
sender key the walk under test never saw. Mirrors verify-core's
federation-wire.test.ts."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agledger.verify import (
    build_federation_key_registry,
    canonicalize_json,
    normalize_federation_key,
    verify_export,
)
from agledger.verify.federation_wire import federation_sign_input

VAULT = Ed25519PrivateKey.generate()
SENDER = Ed25519PrivateKey.generate()
STRANGER = Ed25519PrivateKey.generate()
KEY_ID = "a1b2c3d4e5f60718"
SENDER_HUB = "hub-sender"
RECIPIENT_HUB = "hub-receiver"
RECORD_ID = "0199a8f0-0000-7000-8000-0000000000aa"
BODY: dict[str, Any] = {
    "recordId": RECORD_ID,
    "state": "FULFILLED",
    "type": "principal-gate-generic-v1",
    "idempotencyKey": "0199a8f0-0000-7000-8000-00000000c0de",
    "schemaRef": {"type": "principal-gate-generic-v1", "manifestDigest": "sha256:" + "ab" * 32},
    "principalAgentId": "0199a8f0-0000-7000-8000-000000000001",
    "performerAgentId": "0199a8f0-0000-7000-8000-000000000002",
}


def _spki(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


def _raw32(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _sealed(sender: Ed25519PrivateKey, body: dict[str, Any], **over: Any) -> dict[str, Any]:
    """A message sealed the way the Server's peer-auth hook seals it."""
    wire: dict[str, Any] = {
        "scheme": "agledger.federation.v2",
        "senderHubId": SENDER_HUB,
        "senderPublicKey": _spki(sender),
        "recipientHubId": RECIPIENT_HUB,
        "method": "POST",
        "path": "/federation/v1/state-transition",
        "bodyHash": hashlib.sha256(canonicalize_json(body).encode()).hexdigest(),
        "timestamp": "2026-10-22T18:00:00.000Z",
        "nonce": "a1b2c3d4e5f60718a1b2c3d4e5f60718",
        "signature": "",
        "body": body,
    }
    wire.update(over)
    wire["signature"] = sender.sign(federation_sign_input(wire).encode()).hex()
    wire.update(over)
    return wire


def _projection(wire: Any, **over: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "peerHubId": SENDER_HUB,
        "recordType": "principal-gate-generic-v1",
        "state": "FULFILLED",
        "principalAgentId": BODY["principalAgentId"],
        "performerAgentId": BODY["performerAgentId"],
        "schemaRef": BODY["schemaRef"],
        "outcome": "inserted",
        "wire": wire,
    }
    payload.update(over)
    return payload


def _export(payload: dict[str, Any]) -> dict[str, Any]:
    """A one-entry export whose FEDERATION_STATE_SYNC entry carries ``payload``,
    its predicate built the way the engine builds it from the row, signed
    under a vault key this test holds."""
    protected = cbor2.dumps({1: -8, 4: bytes.fromhex(KEY_ID), -65537: {1: 1, 2: None}}, canonical=True)
    predicate = {"record_id": RECORD_ID, "entry_type": "FEDERATION_STATE_SYNC", "payload": payload}
    payload_bstr = cbor2.dumps({"predicate": predicate}, canonical=True)
    signature = VAULT.sign(cbor2.dumps(["Signature1", protected, b"", payload_bstr], canonical=True))
    envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload_bstr, signature]), canonical=True)
    return {
        "exportMetadata": {
            "recordId": RECORD_ID,
            "exportFormatVersion": "2.0",
            "canonicalization": "RFC8949-CDE",
            "signingPublicKeys": {KEY_ID: _spki(VAULT)},
        },
        "entries": [
            {
                "chainPosition": 1,
                "recordId": RECORD_ID,
                "entryType": "FEDERATION_STATE_SYNC",
                "payload": payload,
                "integrity": {
                    "payloadHash": hashlib.sha256(envelope).hexdigest(),
                    "previousHash": None,
                    "coseSign1": base64.b64encode(envelope).decode(),
                    "signingKeyId": KEY_ID,
                },
            }
        ],
    }


def test_a_sealed_message_is_held_to_its_hash_and_entry_without_a_key():
    result = verify_export(_export(_projection(_sealed(SENDER, BODY))))
    assert result.valid
    assert result.optional_checks["federation_wire"] == "applied"
    assert (result.federation_wire.present, result.federation_wire.verified) == (1, 0)


@pytest.mark.parametrize("form", ["spki", "raw32", "list"])
def test_it_is_verified_under_the_senders_key_in_either_form(form: str):
    doc = _export(_projection(_sealed(SENDER, BODY)))
    keys: Any = (
        {SENDER_HUB: _spki(SENDER)}
        if form == "spki"
        else {SENDER_HUB: _raw32(SENDER)}
        if form == "raw32"
        else [{"hubId": SENDER_HUB, "publicKey": _spki(SENDER)}]
    )
    result = verify_export(doc, federation_keys=keys)
    assert result.valid
    assert (result.federation_wire.present, result.federation_wire.verified) == (1, 1)


def test_a_key_for_another_hub_checks_nothing_here():
    result = verify_export(_export(_projection(_sealed(SENDER, BODY))), federation_keys={"hub-other": _spki(STRANGER)})
    assert result.valid
    assert (result.federation_wire.present, result.federation_wire.verified) == (1, 0)


def test_the_sealed_key_must_be_the_key_the_senders_operator_supplied():
    result = verify_export(_export(_projection(_sealed(SENDER, BODY))), federation_keys={SENDER_HUB: _spki(STRANGER)})
    assert not result.valid
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_FEDERATION_WIRE_INVALID")
    assert "not the federation key supplied" in (result.broken_at.detail or "")


def test_a_signature_by_someone_else_under_the_senders_key_id_fails():
    forged = _sealed(STRANGER, BODY, senderPublicKey=_spki(SENDER))
    doc = _export(_projection(forged))
    assert verify_export(doc).valid
    result = verify_export(doc, federation_keys={SENDER_HUB: _spki(SENDER)})
    assert not result.valid
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_FEDERATION_WIRE_INVALID"
    assert "does not verify" in (result.broken_at.detail or "")


def test_an_edited_body_no_longer_hashes_to_what_was_signed():
    wire = _sealed(SENDER, BODY)
    wire["body"] = {**BODY, "state": "CANCELLED"}
    result = verify_export(_export(_projection(wire, state="CANCELLED")))
    assert not result.valid
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_FEDERATION_WIRE_INVALID"
    assert "does not hash" in (result.broken_at.detail or "")


def test_an_entry_that_asserts_a_state_the_body_does_not_carry_fails():
    result = verify_export(_export(_projection(_sealed(SENDER, BODY), state="CANCELLED")))
    assert not result.valid
    assert result.broken_at is not None
    assert 'Entry state is "CANCELLED"' in (result.broken_at.detail or "")


def test_an_entry_naming_another_peer_fails():
    result = verify_export(_export(_projection(_sealed(SENDER, BODY), peerHubId="hub-other")))
    assert not result.valid
    assert result.broken_at is not None
    assert "names peer hub-other" in (result.broken_at.detail or "")


def test_a_wire_that_is_not_a_sealed_message_fails():
    result = verify_export(_export(_projection("yes")))
    assert not result.valid
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_FEDERATION_WIRE_INVALID"


def test_an_entry_with_no_sealed_message_reports_the_check_as_not_applicable():
    payload = _projection(None)
    del payload["wire"]
    result = verify_export(_export(payload))
    assert result.valid
    assert result.optional_checks["federation_wire"] == "skipped_no_input"
    assert (result.federation_wire.present, result.federation_wire.verified) == (0, 0)


def test_a_federation_key_that_is_not_an_ed25519_key_is_refused_at_the_boundary():
    with pytest.raises(TypeError, match="not an Ed25519 public key"):
        build_federation_key_registry({SENDER_HUB: "not a key"})
    with pytest.raises(TypeError, match="names no hubId"):
        build_federation_key_registry([{"hubId": "", "publicKey": _spki(SENDER)}])
    with pytest.raises(TypeError):
        verify_export(_export(_projection(None)), federation_keys={SENDER_HUB: "nope"})


def test_normalize_federation_key_maps_the_raw_bytes_onto_spki():
    assert normalize_federation_key(_raw32(SENDER)) == _spki(SENDER)
    assert normalize_federation_key(_spki(SENDER)) == _spki(SENDER)
    assert normalize_federation_key("") is None
    assert normalize_federation_key("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" + "A" * 86 + "==") is None


def test_canonicalize_json_produces_the_rfc_8785_test_vector():
    text = (
        '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],'
        '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\u002f","literals":[null,true,false]}'
    )
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonicalize_json(json.loads(text)) == expected


def test_canonicalize_json_writes_negative_zero_as_zero_and_sorts_keys_by_code_unit():
    assert canonicalize_json({"b": 1, "c": -0.0, "Z": [float("nan")]}) == '{"Z":[null],"b":1,"c":0}'
    # UTF-16 code-unit order puts a surrogate pair (D83D DE00) before U+FF5E, as JavaScript sorts.
    assert canonicalize_json({"\uff5e": 2, "\U0001f600": 1}) == '{"\U0001f600":1,"\uff5e":2}'


def test_the_cli_flag_is_parsed_and_checked_before_any_verification():
    from agledger.verify.cli import parse_args, parse_federation_keys

    assert parse_args(["x", "--federation-key", "hub-b=AAA", "--federation-key=hub-c=BBB"]).federation_keys == [
        "hub-b=AAA",
        "hub-c=BBB",
    ]
    assert parse_federation_keys([f"hub-b={_spki(SENDER)}"]) == {"hub-b": _spki(SENDER)}
    assert "Invalid --federation-key" in str(parse_federation_keys(["hub-b"]))
    assert "not an Ed25519 public key" in str(parse_federation_keys(["hub-b=nope"]))
    assert "twice" in str(parse_federation_keys([f"hub-b={_spki(SENDER)}", f"hub-b={_spki(SENDER)}"]))


def test_the_json_report_carries_federation_wire_and_the_text_report_a_line(capsys: pytest.CaptureFixture[str]):
    import os
    import tempfile

    from agledger.verify.cli import run_cli as run

    doc = _export(_projection(_sealed(SENDER, BODY)))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "export.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        assert run([path, "--federation-key", f"{SENDER_HUB}={_spki(SENDER)}", "-f", "json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["federationWire"] == {"present": 1, "verified": 1}
        assert out["optionalChecks"]["federation_wire"] == "applied"
        assert run([path]) == 0
        text = capsys.readouterr().out
        assert "peer messages     : present=1 verified=0 (each hashed and matched to its entry; the peer signatures were NOT checked" in text
        assert run([path, "--federation-key", "hub-b=nope"]) == 2
