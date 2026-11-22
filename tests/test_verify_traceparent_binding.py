"""A signed ``traceparent`` is held to an export entry's ``payload`` in both
directions: the Server writes every signed one into the export payload, so a
deleted copy fails the payload binding as a changed one does. A vault dump row
never holds it. Mirrors verify-core's envelope-extension-binding.test.ts."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agledger.verify import verify_export
from agledger.verify.verify_export import envelope_extensions_match

VAULT = Ed25519PrivateKey.generate()
KEY_ID = "a1b2c3d4e5f60718"
RECORD_ID = "0199a8f0-0000-7000-8000-0000000000aa"
TP = "00-29dc9f4fa12cb73eab3adb6b655b27df-73a02c73825c1aa1-01"
OBO = {"oidc": {"iss": "https://idp.example", "sub": "someone"}, "validated": True}
ROW: dict[str, Any] = {"peerHubId": "hub-sender", "state": "FULFILLED", "outcome": "inserted"}


def _export(signed_extra: dict[str, Any], row_extra: dict[str, Any]) -> dict[str, Any]:
    protected = cbor2.dumps({1: -8, 4: bytes.fromhex(KEY_ID), -65537: {1: 1, 2: None}}, canonical=True)
    predicate = {"record_id": RECORD_ID, "entry_type": "FEDERATION_STATE_SYNC", "payload": ROW, **signed_extra}
    payload_bstr = cbor2.dumps({"predicate": predicate}, canonical=True)
    signature = VAULT.sign(cbor2.dumps(["Signature1", protected, b"", payload_bstr], canonical=True))
    envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload_bstr, signature]), canonical=True)
    spki = base64.b64encode(VAULT.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()
    return {
        "exportMetadata": {
            "recordId": RECORD_ID,
            "exportFormatVersion": "2.0",
            "canonicalization": "RFC8949-CDE",
            "signingPublicKeys": {KEY_ID: spki},
        },
        "entries": [
            {
                "chainPosition": 1,
                "recordId": RECORD_ID,
                "entryType": "FEDERATION_STATE_SYNC",
                "payload": {**ROW, **row_extra},
                "integrity": {
                    "payloadHash": hashlib.sha256(envelope).hexdigest(),
                    "previousHash": None,
                    "coseSign1": base64.b64encode(envelope).decode(),
                    "signingKeyId": KEY_ID,
                },
            }
        ],
    }


@pytest.mark.parametrize("ext", [{"traceparent": TP}, {"on_behalf_of": OBO}])
def test_untouched_verifies(ext: dict[str, Any]):
    result = verify_export(_export(ext, ext))
    assert result.broken_at is None
    assert result.valid


@pytest.mark.parametrize(
    ("signed", "row"),
    [
        ({"traceparent": TP}, {}),
        ({"traceparent": TP}, {"traceparent": "not-a-traceparent"}),
        ({"traceparent": TP}, {"traceparent": TP.replace("-01", "-00")}),
        ({"on_behalf_of": OBO}, {}),
        ({}, {"traceparent": TP}),
    ],
    ids=["deleted", "replaced-by-dropped-value", "changed", "obo-deleted", "added"],
)
def test_an_edited_copy_fails_the_binding(signed: dict[str, Any], row: dict[str, Any]):
    result = verify_export(_export(signed, row))
    assert result.broken_at is not None
    assert (result.broken_at.position, result.broken_at.code) == (1, "CHAIN_PAYLOAD_BINDING_MISMATCH")


def test_a_dump_row_without_the_signed_copy_is_not_a_mismatch():
    assert envelope_extensions_match(ROW, {"traceparent": TP, "on_behalf_of": OBO})
    assert not envelope_extensions_match(ROW, {"traceparent": TP}, projected=True)
