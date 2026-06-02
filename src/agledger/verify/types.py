"""Dump-format shapes and report types for the offline full-vault verifier.

Dump rows are read straight from NDJSON as plain ``dict`` (snake_case keys, the
DB column names) — like the TS ``loader.ts``, the loader does not validate row
shapes beyond what the walk needs; the verifier itself catches semantic
problems. Only the OUTPUT (report) side is typed, so callers get a stable shape.

This module deliberately imports neither ``pydantic`` nor ``httpx`` — the dump
verification path's only third-party needs are ``cbor2`` + ``cryptography``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agledger.verify.failures import FailureCode

#: One loaded dump row, keyed by DB column name (snake_case), as parsed from
#: NDJSON. Aliased for readability at call sites.
DumpRow = dict[str, Any]


@dataclass
class Dump:
    """The five NDJSON files of a full-vault dump, parsed into row lists."""

    vault_entries: list[DumpRow] = field(default_factory=list[DumpRow])
    vault_checkpoints: list[DumpRow] = field(default_factory=list[DumpRow])
    signing_keys: list[DumpRow] = field(default_factory=list[DumpRow])
    org_admin_reads: list[DumpRow] = field(default_factory=list[DumpRow])
    org_admin_reads_checkpoints: list[DumpRow] = field(default_factory=list[DumpRow])


@dataclass
class Failure:
    code: FailureCode
    message: str
    #: RecordRow id for vault failures, org id for org-reads failures.
    scope_id: str | None = None
    position: int | None = None
    leaf_index: int | None = None
    tree_size: int | None = None
    signing_key_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        """camelCase dict, omitting unset optional fields — byte-compatible with
        the TS ``Failure`` JSON (TS ``JSON.stringify`` drops ``undefined``)."""
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        optional = {
            "scopeId": self.scope_id,
            "position": self.position,
            "leafIndex": self.leaf_index,
            "treeSize": self.tree_size,
            "signingKeyId": self.signing_key_id,
        }
        out.update({k: v for k, v in optional.items() if v is not None})
        return out


@dataclass
class VaultChainsReport:
    record_count: int = 0
    entry_count: int = 0
    checkpoint_count: int = 0
    failures: list[Failure] = field(default_factory=list[Failure])

    def to_json(self) -> dict[str, Any]:
        return {
            "recordCount": self.record_count,
            "entryCount": self.entry_count,
            "checkpointCount": self.checkpoint_count,
            "failures": [f.to_json() for f in self.failures],
        }


@dataclass
class WitnessCosignedCheckpoint:
    checkpoint_id: str
    witness_key_id: str

    def to_json(self) -> dict[str, Any]:
        return {"checkpointId": self.checkpoint_id, "witnessKeyId": self.witness_key_id}


@dataclass
class TenantAdminReadsReport:
    org_count: int = 0
    leaf_count: int = 0
    checkpoint_count: int = 0
    witness_cosigned_checkpoints: list[WitnessCosignedCheckpoint] = field(default_factory=list[WitnessCosignedCheckpoint])
    failures: list[Failure] = field(default_factory=list[Failure])

    def to_json(self) -> dict[str, Any]:
        return {
            "orgCount": self.org_count,
            "leafCount": self.leaf_count,
            "checkpointCount": self.checkpoint_count,
            "witnessCosignedCheckpoints": [
                w.to_json() for w in self.witness_cosigned_checkpoints
            ],
            "failures": [f.to_json() for f in self.failures],
        }


@dataclass
class VerifyReport:
    ok: bool
    vault: VaultChainsReport
    org_admin_reads: TenantAdminReadsReport

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "vault": self.vault.to_json(),
            "orgAdminReads": self.org_admin_reads.to_json(),
        }
