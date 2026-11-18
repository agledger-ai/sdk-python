"""A self-consistent in-memory dump built with a minimal local COSE_Sign1
producer, for tests that mutate a baseline that verifies clean. A port of
``@agledger/verify``'s ``test/fixtures.ts`` (``buildHappyDump`` and the
builders it uses), written from the envelope format: the same protected
header labels, CWT layout and in-toto v1 Statement payload as the Server
encodes, under RFC 8949 deterministic encoding. Instants are fixed UTC values
rather than the TypeScript builder's local-time dates."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agledger.verify import Dump

from .key_statement_helpers import TestKey, statement


@dataclass(frozen=True, eq=False)
class KeyMaterial:
    private_key: Ed25519PrivateKey
    public_key_der_b64: str
    key_id: str
    digest: str

    def as_test_key(self) -> TestKey:
        """The same key as :mod:`key_statement_helpers` signs statements with."""
        return TestKey(self.private_key, self.public_key_der_b64, self.digest, self.key_id, "Ed25519")


def generate_key() -> KeyMaterial:
    private = Ed25519PrivateKey.generate()
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest()
    return KeyMaterial(private, base64.b64encode(der).decode(), digest[:16], digest)


def pin_of(key: KeyMaterial) -> str:
    """The ``trust_anchors`` pin of a key: sha256 of its SPKI DER."""
    return f"sha256:{key.digest}"


def stable_uuid_from_string(s: str) -> str:
    """A UUID derived from a string, so an entry and a checkpoint built for the
    same record name sign the same record id."""
    h = hashlib.sha256(s.encode()).hexdigest()[:32]
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


_COSE_ALG_EDDSA = -8
_IN_TOTO_CBOR_CTY = "application/vnd.in-toto+cbor"
_IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_AGLEDGER_LABEL_CHAIN = -65537
_AGLEDGER_LABEL_ACTOR = -65539
_ACTOR = {
    "key_id": "11111111-1111-1111-1111-111111111111",
    "role": "agent",
    "owner_id": "22222222-2222-2222-2222-222222222222",
}
_ISS = "https://api.example.test"


def _uuid_bytes(uuid: str) -> bytes:
    return bytes.fromhex(uuid.replace("-", ""))


def _cbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def build_cose_sign1(
    *,
    kind: Literal["record-state", "org-read", "vault-checkpoint"],
    key: KeyMaterial,
    sub: str,
    iat: int,
    chain_position: int,
    previous_hash: str | None,
    subject: list[dict[str, Any]],
    predicate: dict[str, Any],
) -> bytes:
    """A tagged COSE_Sign1 envelope as the Server writes one."""
    header = {
        1: _COSE_ALG_EDDSA,
        3: _IN_TOTO_CBOR_CTY,
        4: bytes.fromhex(key.key_id),
        15: {
            1: _ISS,
            2: sub,
            6: iat,
            _AGLEDGER_LABEL_ACTOR: {
                1: _uuid_bytes(_ACTOR["key_id"]),
                2: _ACTOR["role"],
                3: _uuid_bytes(_ACTOR["owner_id"]),
            },
        },
        _AGLEDGER_LABEL_CHAIN: {1: chain_position, 2: None if previous_hash is None else bytes.fromhex(previous_hash)},
    }
    protected = _cbor(header)
    payload = _cbor(
        {
            "_type": _IN_TOTO_STATEMENT_TYPE,
            "predicate": predicate,
            "predicateType": f"https://agledger.ai/predicates/{kind}/v1",
            "subject": subject,
        }
    )
    signature = key.private_key.sign(_cbor(["Signature1", protected, b"", payload]))
    return _cbor(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def _uuid_subject(uuid: str) -> list[dict[str, Any]]:
    return [{"name": "record_id", "digest": {"sha256": hashlib.sha256(_uuid_bytes(uuid)).digest()}}]


def build_vault_entry(
    record: str,
    position: int,
    previous_hash: str | None,
    entry_type: str,
    payload: dict[str, Any],
    key: KeyMaterial,
    created_at: str = "2026-02-01T00:00:00.000Z",
) -> dict[str, Any]:
    record_uuid = stable_uuid_from_string(record)
    envelope = build_cose_sign1(
        kind="record-state",
        key=key,
        sub=record_uuid,
        iat=1747574400 + position,
        chain_position=position,
        previous_hash=previous_hash,
        subject=[{"name": "record_id", "digest": {"sha256": hashlib.sha256(record.encode()).digest()}}],
        predicate={"record_id": record_uuid, "entry_type": entry_type, "payload": payload},
    )
    return {
        "id": f"entry-{record}-{position}",
        "record_id": record_uuid,
        "entry_type": entry_type,
        "payload": payload,
        "payload_hash": hashlib.sha256(envelope).hexdigest(),
        "previous_hash": previous_hash,
        "chain_position": position,
        "cose_sign1": base64.b64encode(envelope).decode(),
        "signing_key_id": key.key_id,
        "actor_key_id": _ACTOR["key_id"],
        "actor_role": _ACTOR["role"],
        "actor_owner_id": _ACTOR["owner_id"],
        "created_at": created_at,
    }


def build_vault_checkpoint(record: str, position: int, payload_hash: str, key: KeyMaterial) -> dict[str, Any]:
    record_uuid = stable_uuid_from_string(record)
    envelope = build_cose_sign1(
        kind="vault-checkpoint",
        key=key,
        sub=record_uuid,
        iat=1747574500,
        chain_position=position,
        previous_hash=None,
        subject=_uuid_subject(record_uuid),
        predicate={
            "chain_tip_hash": f"sha256:{payload_hash}",
            "range": {"start": 1, "end": position},
            "count": position,
        },
    )
    return {
        "id": f"cp-{record}-{position}",
        "record_id": record_uuid,
        "chain_position": position,
        "payload_hash": payload_hash,
        "cose_sign1": base64.b64encode(envelope).decode(),
        "signing_key_id": key.key_id,
        "created_at": "2026-02-01T06:00:00.000Z",
    }


def rfc9162_leaf_hash(envelope: bytes) -> str:
    """hex(sha256(0x00 || envelope)), written out here rather than taken from the verifier."""
    return hashlib.sha256(b"\x00" + envelope).hexdigest()


def merkle_root_local(leaves: list[str]) -> str:
    """The RFC 9162 Merkle Tree Hash over hex leaf hashes."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    def root(lo: int, hi: int) -> bytes:
        if hi - lo == 1:
            return bytes.fromhex(leaves[lo])
        k = 1
        while k * 2 < hi - lo:
            k *= 2
        return hashlib.sha256(b"\x01" + root(lo, lo + k) + root(lo + k, hi)).digest()

    return root(0, len(leaves)).hex()


def build_org_admin_read(
    org_id: str, leaf_index: int, key: KeyMaterial, record: str | None = None, previous_hash: str | None = None
) -> dict[str, Any]:
    record_uuid = stable_uuid_from_string(record or f"record-{leaf_index}")
    caller = "0a" * 8
    envelope = build_cose_sign1(
        kind="org-read",
        key=key,
        sub=record_uuid,
        iat=1747574000 + leaf_index,
        chain_position=leaf_index + 1,
        previous_hash=previous_hash,
        subject=_uuid_subject(record_uuid),
        predicate={"record_id": record_uuid, "reader_key_id": caller, "signed_checkpoint_ref": None},
    )
    return {
        "id": f"oar-{org_id}-{leaf_index}",
        "org_id": org_id,
        "caller_key_id": caller,
        "record_id": record_uuid,
        "filter_applied": "org-admin",
        "read_context": "interactive",
        "export_batch_id": None,
        "read_at": f"2026-04-25T12:00:{leaf_index:02d}.000Z",
        "leaf_index": leaf_index,
        "leaf_hash": rfc9162_leaf_hash(envelope),
        "cose_sign1": base64.b64encode(envelope).decode(),
    }


def build_org_admin_read_log(org_id: str, count: int, key: KeyMaterial) -> list[dict[str, Any]]:
    """``count`` leaves of one org's log, each linked to the one before by its signed previous_hash."""
    out: list[dict[str, Any]] = []
    for i in range(count):
        out.append(
            build_org_admin_read(org_id, i, key, f"record-{i}", out[i - 1]["leaf_hash"] if i > 0 else None)
        )
    return out


def build_org_admin_reads_checkpoint(
    org_id: str, leaves: list[dict[str, Any]], key: KeyMaterial, tree_size: int | None = None
) -> dict[str, Any]:
    size = len(leaves) if tree_size is None else tree_size
    root_hash = merkle_root_local([leaf["leaf_hash"] for leaf in leaves[:size]])
    envelope = build_cose_sign1(
        kind="vault-checkpoint",
        key=key,
        sub=org_id,
        iat=1747574999,
        chain_position=size,
        previous_hash=None,
        subject=[{"name": "root", "digest": {"sha256": bytes.fromhex(root_hash)}}],
        predicate={"chain_tip_hash": f"sha256:{root_hash}", "range": {"start": 0, "end": size}, "count": size},
    )
    return {
        "id": f"oar-cp-{org_id}-{size}",
        "org_id": org_id,
        "tree_size": size,
        "root_hash": root_hash,
        "checkpoint_at": "2026-04-25T18:00:00.000Z",
        "log_id": org_id,
        "cose_sign1": base64.b64encode(envelope).decode(),
        "signing_key_id": key.key_id,
        "witness_signature": None,
        "witness_key_id": None,
        "witness_cosigned_at": None,
    }


def signing_key_dump(
    key: KeyMaterial,
    *,
    activated_at: str = "2026-01-01T00:00:00.000Z",
    retired_at: str | None = None,
    status: Literal["active", "retired"] = "active",
) -> dict[str, Any]:
    return {
        "key_id": key.key_id,
        "public_key": key.public_key_der_b64,
        "algorithm": "Ed25519",
        "status": status,
        "activated_at": activated_at,
        "retired_at": retired_at,
        "retired_by": None,
    }


def build_happy_dump() -> tuple[Dump, KeyMaterial]:
    """Two records of three entries each, a checkpoint on the second at
    position 3, and two orgs in the read log: one with three leaves and a
    signed tree head, one with a single leaf and no tree head yet."""
    key = generate_key()
    entries: list[dict[str, Any]] = []
    for record in ("record-aaaa", "record-bbbb"):
        previous: str | None = None
        for position in (1, 2, 3):
            entry_type = "RECORD_CREATED" if position == 1 else "RECORD_STATE_CHANGE"
            payload: dict[str, Any] = (
                {"kind": "create", "m": record} if position == 1 else {"kind": "transition", "m": record, "n": position}
            )
            e = build_vault_entry(record, position, previous, entry_type, payload, key)
            entries.append(e)
            previous = e["payload_hash"]
    checkpoint = build_vault_checkpoint("record-bbbb", 3, entries[-1]["payload_hash"], key)
    leaves1 = build_org_admin_read_log("enterprise-1", 3, key)
    head1 = build_org_admin_reads_checkpoint("enterprise-1", leaves1, key, 3)
    leaves2 = [build_org_admin_read("enterprise-2", 0, key)]
    dump = Dump(
        vault_entries=entries,
        vault_checkpoints=[checkpoint],
        signing_keys=[signing_key_dump(key)],
        key_statements=[],
        org_admin_reads=[*leaves1, *leaves2],
        org_admin_reads_checkpoints=[head1],
    )
    return dump, key


def build_key_statement(
    kind: Literal["genesis", "succession", "closure"],
    subject: KeyMaterial,
    *,
    signers: list[KeyMaterial],
    activated_at: str,
    created_at: str,
    endorser: KeyMaterial | None = None,
    retired_at: str | None = None,
    forced: bool = False,
) -> dict[str, Any]:
    """One row of ``vault_key_statements.ndjson``: a genesis, succession or
    closure for ``subject``, signed by ``signers`` in order, as a conforming
    Server writes it. Instants are microsecond RFC 3339; the row's write time
    is ``created_at``."""
    iat = int(datetime.fromisoformat(created_at).timestamp())
    stored = statement(
        kind,
        subject.as_test_key(),
        signers=[s.as_test_key() for s in signers],
        endorser=endorser.as_test_key() if endorser is not None else None,
        activated_at=activated_at,
        retired_at=retired_at,
        forced=forced if kind == "closure" else None,
        iat=iat,
        created_at=created_at,
    )
    return {
        "id": f"ks-{kind}-{subject.key_id}-{created_at}",
        "kind": kind,
        "subject_key_id": subject.key_id,
        "endorser_key_id": endorser.key_id if endorser is not None else None,
        "statement": [base64.b64encode(c).decode() for c in stored.cose],
        "created_at": stored.created_at,
    }
