"""The agent cert public keys a dump signs itself.

Each ``EPHEMERAL_CERT_ISSUED`` entry on the platform-ops chain signs its cert's
``publicKeyJwk``, so a dump not scoped to one org can re-verify sealed agent
signatures without ``agent_keys``. A key is used only when it sits on a chain
the verifier has verified clean, under an entry whose vault signature checked.

Ported case for case from ``@agledger/verify``'s
``cert-keys-from-chain.test.ts``. Corpus cases mutate ``dump/valid-identity``
(the platform-ops chain, three cert issuances under one agent key, and a record
chain carrying a sealed agent signature made with it) and use
``dump/identity-key-rotated-tampered`` as generated. Where a case needs an
agent signature that does not verify, the dump is synthetic, because a real
entry cannot carry one without also breaking its vault signature.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agledger.verify import (
    AGENT_SIGNATURE_CONTEXT,
    ed25519_jwk_thumbprint,
    load_dump,
    verify_dump,
)
from agledger.verify.cli import run_cli
from agledger.verify.types import Dump

DUMPS = Path(__file__).resolve().parent.parent / "testdata" / "conformance" / "dump"
PLATFORM = "00000000-0000-0000-0000-000000000000"


def _identity() -> Dump:
    return load_dump(DUMPS / "valid-identity")


def _jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}


def _counts(d: Dump) -> tuple[int, int]:
    report = verify_dump(d)
    return report.vault.agent_signatures_present, report.vault.agent_signatures_verified


# --- a full dump re-verifies agent signatures from its own cert keys ----------


def test_valid_identity_verifies_its_sealed_agent_signature_with_no_agent_keys() -> None:
    report = verify_dump(_identity())
    assert report.ok
    # Three issuances, one agent key: counted once.
    assert report.vault.cert_keys_from_chain == 1
    assert report.vault.optional_checks["agent_signature"] == "applied"
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (1, 1)
    assert report.vault.to_json()["certKeysFromChain"] == 1


def test_the_text_report_says_where_the_key_came_from(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli([str(DUMPS / "valid-identity")]) == 0
    out = capsys.readouterr().out
    assert "agent sigs  : present=1 verified=1 (checked against the 1 cert key the dump signs)" in out


def test_an_org_scoped_dump_without_the_platform_ops_chain_harvests_nothing() -> None:
    d = _identity()
    d.vault_entries = [e for e in d.vault_entries if e["chain_key"] != PLATFORM]
    d.vault_checkpoints = [c for c in d.vault_checkpoints if c["chain_key"] != PLATFORM]
    report = verify_dump(d)
    assert report.ok
    assert report.vault.cert_keys_from_chain == 0
    assert report.vault.optional_checks["agent_signature"] == "skipped_no_input"
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (1, 0)


# --- a key is used only from a chain the verifier has verified ----------------


def test_not_when_another_entry_on_the_platform_ops_chain_fails() -> None:
    report = verify_dump(load_dump(DUMPS / "identity-key-rotated-tampered"))
    assert [(f.code, f.scope_id) for f in report.vault.failures] == [("CHAIN_PAYLOAD_BINDING_MISMATCH", PLATFORM)]
    # The cert entries themselves are intact, and still not trusted.
    assert report.vault.cert_keys_from_chain == 0
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (1, 0)


def test_not_when_the_platform_ops_chain_diverges_from_its_own_checkpoint() -> None:
    d = _identity()
    cp = next(c for c in d.vault_checkpoints if c["chain_key"] == PLATFORM)
    cp["payload_hash"] = "a" * 64
    report = verify_dump(d)
    assert [f.code for f in report.vault.failures] == ["CHECKPOINT_HASH_MISMATCH"]
    assert report.vault.cert_keys_from_chain == 0
    assert report.vault.agent_signatures_verified == 0


def _instant(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def test_not_from_an_unsigned_entry_even_on_a_chain_that_verifies() -> None:
    d = _identity()
    platform = [e for e in d.vault_entries if e["chain_key"] == PLATFORM]
    records = [e for e in d.vault_entries if e["chain_key"] != PLATFORM]
    # Written before the install signed: keep the platform-ops entries that
    # predate every record entry, unsign them, and activate the key between.
    first_record_at = min(_instant(e["created_at"]) for e in records)
    early = [e for e in platform if _instant(e["created_at"]) < first_record_at]
    assert any(e["entry_type"] == "EPHEMERAL_CERT_ISSUED" for e in early)
    for e in early:
        e["signing_key_id"] = None
    d.vault_entries = [*early, *records]
    d.vault_checkpoints = [
        c for c in d.vault_checkpoints if c["chain_key"] != PLATFORM or c["chain_position"] <= len(early)
    ]
    activated = (first_record_at - timedelta(milliseconds=1)).astimezone(UTC)
    d.signing_keys[0]["activated_at"] = activated.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    report = verify_dump(d)
    assert report.ok, [f.to_json() for f in report.vault.failures]
    assert report.vault.cert_keys_from_chain == 0
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (1, 0)


def test_not_when_a_row_copy_of_the_key_was_rewritten_which_fails_the_chain() -> None:
    d = _identity()
    other = _jwk(Ed25519PrivateKey.generate())
    for e in d.vault_entries:
        if e["entry_type"] == "EPHEMERAL_CERT_ISSUED":
            e["payload"] = {**e["payload"], "publicKeyJwk": other}
    report = verify_dump(d)
    assert report.vault.failures
    assert all(f.code == "CHAIN_PAYLOAD_BINDING_MISMATCH" for f in report.vault.failures)
    assert report.vault.cert_keys_from_chain == 0


# --- a harvested key decides a verdict the way a supplied one does ------------

KEY_ID = "5eedfacecafe0001"


def _envelope(vault: Ed25519PrivateKey, position: int, previous_hash: str | None, predicate: dict[str, Any]) -> bytes:
    protected = cbor2.dumps(
        {1: -8, 4: bytes.fromhex(KEY_ID), -65537: {1: position, 2: previous_hash}}, canonical=True
    )
    payload = cbor2.dumps({"predicate": predicate}, canonical=True)
    signature = vault.sign(cbor2.dumps(["Signature1", protected, b"", payload], canonical=True))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]), canonical=True)


def _row(
    chain_key: str, entry_type: str, envelope: bytes, previous_hash: str | None, payload: dict[str, Any]
) -> dict[str, Any]:
    # The row copy of the signed payload, as the engine writes it: a dump row
    # carries every column, and the binding check holds it to the envelope.
    return {
        "id": f"entry-{chain_key}",
        "record_id": chain_key,
        "chain_key": chain_key,
        "entry_type": entry_type,
        "payload": payload,
        "payload_hash": hashlib.sha256(envelope).hexdigest(),
        "previous_hash": previous_hash,
        "chain_position": 1,
        "cose_sign1": base64.b64encode(envelope).decode(),
        "signing_key_id": KEY_ID,
        "actor_key_id": PLATFORM,
        "actor_role": "platform",
        "actor_owner_id": PLATFORM,
        "created_at": "2026-02-01T00:00:00.000Z",
    }


def _synthetic(
    *,
    bad_signature: bool,
    cert_chain_first: bool = True,
    break_cert_chain: bool = False,
    issued_type: str = "EPHEMERAL_CERT_ISSUED",
) -> Dump:
    """A platform-ops chain issuing one cert, then a record chain whose sealed
    agent signature was made with that cert's key."""
    vault = Ed25519PrivateKey.generate()
    agent = Ed25519PrivateKey.generate()
    jwk = _jwk(agent)
    thumbprint = ed25519_jwk_thumbprint(jwk)
    content = hashlib.sha256(b'{"type":"example"}').hexdigest()
    signed = hashlib.sha256(b"a different body").hexdigest() if bad_signature else content
    agent_signature = base64.b64encode(agent.sign(f"{AGENT_SIGNATURE_CONTEXT}{signed}".encode())).decode()

    issued_prev = "b" * 64 if break_cert_chain else None
    issued_payload: dict[str, Any] = {"certId": "cert-1", "publicKeyJwk": jwk, "publicKeyThumbprint": thumbprint}
    issued_env = _envelope(vault, 1, issued_prev, {
        "record_id": "platform-ops",
        "entry_type": issued_type,
        "payload": issued_payload,
    })
    issued = _row("platform-ops", issued_type, issued_env, issued_prev, issued_payload)
    record_env = _envelope(vault, 1, None, {
        "record_id": "record-agent-signed",
        "entry_type": "RECORD_CREATED",
        "payload": {"kind": "create"},
        "on_behalf_of": {
            "validated": True,
            "cert": {"id": "cert-1", "thumbprint": thumbprint},
            "agent_signature": {"alg": "EdDSA", "signature": agent_signature, "content_hash": f"sha256:{content}"},
        },
    })
    record = _row("record-agent-signed", "RECORD_CREATED", record_env, None, {"kind": "create"})
    spki = vault.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return Dump(
        vault_entries=[issued, record] if cert_chain_first else [record, issued],
        vault_checkpoints=[],
        signing_keys=[{
            "key_id": KEY_ID,
            "public_key": base64.b64encode(spki).decode(),
            "algorithm": "Ed25519",
            "status": "active",
            "activated_at": "2026-01-01T00:00:00.000Z",
            "retired_at": None,
        }],
        org_admin_reads=[],
        org_admin_reads_checkpoints=[],
    )


def test_a_good_agent_signature_verifies() -> None:
    report = verify_dump(_synthetic(bad_signature=False))
    assert report.ok, [f.to_json() for f in report.vault.failures]
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (1, 1)


def test_a_bad_one_fails_chain_agent_signature_invalid_with_no_agent_keys() -> None:
    report = verify_dump(_synthetic(bad_signature=True))
    assert [f.code for f in report.vault.failures] == ["CHAIN_AGENT_SIGNATURE_INVALID"]


def test_a_key_from_a_cert_chain_that_fails_verification_is_not_used() -> None:
    report = verify_dump(_synthetic(bad_signature=True, break_cert_chain=True))
    assert [f.code for f in report.vault.failures] == ["CHAIN_GENESIS_INVALID"]
    assert report.vault.cert_keys_from_chain == 0
    assert report.vault.optional_checks["agent_signature"] == "skipped_no_input"


def test_a_public_key_jwk_under_any_other_entry_type_is_not_a_cert_key() -> None:
    report = verify_dump(_synthetic(bad_signature=True, issued_type="AUTH_KEY_ROTATED"))
    assert report.ok
    assert report.vault.cert_keys_from_chain == 0


def test_a_record_chain_met_before_the_cert_chain_goes_unchecked_never_misjudged() -> None:
    report = verify_dump(_synthetic(bad_signature=True, cert_chain_first=False))
    assert report.ok
    assert report.vault.cert_keys_from_chain == 1
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (1, 0)
