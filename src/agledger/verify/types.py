"""Dump-format shapes and report types for the offline full-vault verifier.

Dump rows are read straight from NDJSON as plain ``dict`` (snake_case keys, the
DB column names): like the TS ``loader.ts``, the loader does not validate row
shapes beyond what the walk needs; the verifier itself catches semantic
problems. Only the OUTPUT (report) side is typed, so callers get a stable shape.

This module deliberately imports neither ``pydantic`` nor ``httpx``: the dump
verification path's only third-party needs are ``cbor2`` + ``cryptography``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from agledger.verify.failures import FailureCode
from agledger.verify.key_statements import KeyTrustReport, no_anchor_report

#: One loaded dump row, keyed by DB column name (snake_case), as parsed from
#: NDJSON. Aliased for readability at call sites.
DumpRow = dict[str, Any]


@dataclass
class Dump:
    """The six NDJSON files of a full-vault dump, parsed into row lists."""

    vault_entries: list[DumpRow] = field(default_factory=list[DumpRow])
    vault_checkpoints: list[DumpRow] = field(default_factory=list[DumpRow])
    signing_keys: list[DumpRow] = field(default_factory=list[DumpRow])
    org_admin_reads: list[DumpRow] = field(default_factory=list[DumpRow])
    org_admin_reads_checkpoints: list[DumpRow] = field(default_factory=list[DumpRow])
    key_statements: list[DumpRow] = field(default_factory=list[DumpRow])
    """``vault_key_statements.ndjson``: the signed key statements, with the
    write time the trust walk orders them by."""


@dataclass
class Failure:
    code: FailureCode
    message: str
    #: Record id (or schema chain key) for vault failures, org id for org-reads failures.
    scope_id: str | None = None
    position: int | None = None
    leaf_index: int | None = None
    tree_size: int | None = None
    signing_key_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        """camelCase dict, omitting unset optional fields: byte-compatible with
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


#: Failures listed in a report's JSON, as ``@agledger/verify`` caps them: a
#: systemic problem on a large vault yields one per entry. ``failureCount``
#: carries the true total.
MAX_REPORTED_FAILURES = 1000

_PLATFORM_OPS_RECORD_ID = "00000000-0000-0000-0000-000000000000"


def chain_of_scope(scope_id: str) -> tuple[Literal["record", "admin", "schema"], str | None, str | None]:
    """Name a chain scope (a record id or a dump ``chain_key``) as the engine
    does: ``(chain, record_id, org_id)``. Mirrors verify-core ``chainOfScope``."""
    if scope_id.startswith("schema:"):
        org = scope_id[len("schema:") :]
        return ("schema", None, None if org == "__platform__" else org)
    if scope_id.lower() == _PLATFORM_OPS_RECORD_ID:
        return ("admin", None, None)
    return ("record", scope_id, None)


@dataclass
class AccountedEntry:
    """A dump entry whose signature verifies under a key ``distrusted_keys``
    names, that falls outside what the key is trusted for (the key is
    unanchored, or the entry was written at or after its cutoff), and that was
    written before a key the walk trusts retired it. The distrust entry and
    that retirement account for it, as the engine's scan lists it in
    ``distrustedEntries``: listed, not verified, and it fails nothing. Mirrors
    verify-core ``AccountedEntry``, field for field."""

    chain: Literal["record", "admin", "schema"]
    record_id: str | None
    org_id: str | None
    scope_id: str
    position: int
    key_id: str
    detail: str
    code: Literal["CHAIN_SIGNED_BY_DISTRUSTED_KEY"] = "CHAIN_SIGNED_BY_DISTRUSTED_KEY"

    def to_json(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "chain": self.chain,
            "recordId": self.record_id,
            "orgId": self.org_id,
            "scopeId": self.scope_id,
            "position": self.position,
            "keyId": self.key_id,
            "detail": self.detail,
        }


@dataclass
class VaultChainsReport:
    record_count: int = 0
    entry_count: int = 0
    checkpoint_count: int = 0
    failures: list[Failure] = field(default_factory=list[Failure])
    accounted: list[AccountedEntry] = field(default_factory=list[AccountedEntry])
    """Entries a distrusted key signed that its entry and a trusted key's
    retirement of it account for (see :class:`AccountedEntry`). They fail
    nothing, and a report should list them. The JSON caps them as it caps
    ``failures``; ``accountedCount`` carries the true total."""
    agent_signatures_present: int = 0
    """Entries that passed every other check and whose signed payload carries
    ``predicate.on_behalf_of.agent_signature``, across every chain."""
    agent_signatures_verified: int = 0
    """Of those, the ones re-checked against a key passed as ``agent_keys`` and
    found good. ``present > verified`` on a clean report means some were not
    checked (no key for their cert, or a caller-asserted identity)."""
    cert_keys_from_chain: int = 0
    """Agent cert public keys taken from the dump itself: the ``publicKeyJwk``
    each ``EPHEMERAL_CERT_ISSUED`` entry signs on the platform-ops chain,
    counted once per key and only from a chain that verified clean. Used
    beside any ``agent_keys`` the caller passed. Zero on an org-scoped dump,
    which leaves that chain out, and for certs an engine older than 1.8.0
    issued."""
    signed_entries: int = 0
    """Vault entries whose signature verified. Under a key walk each verified
    under an anchored key; with none, the report's key trust is
    ``no_anchored_signature`` and a pass is ``unanchored``."""
    optional_checks: dict[str, Literal["applied", "skipped_no_input", "not_checked"]] = field(
        default_factory=lambda: dict.fromkeys(
            (
                "payload_binding",
                "oidc_actor",
                "actor_attribution",
                "key_temporal",
                "agent_signature",
                "key_anchoring",
            ),
            "skipped_no_input",
        )
    )
    """Which input-gated checks ran: ``payload_binding``, ``oidc_actor``,
    ``actor_attribution``, ``key_temporal``, ``agent_signature`` and
    ``key_anchoring``, each ``applied`` once it ran on any chain, so "not
    checked anywhere" never reads as "passed". Mirrors the ``@agledger/verify``
    report."""

    def to_json(self) -> dict[str, Any]:
        return {
            "recordCount": self.record_count,
            "entryCount": self.entry_count,
            "checkpointCount": self.checkpoint_count,
            "failures": [f.to_json() for f in self.failures[:MAX_REPORTED_FAILURES]],
            "failureCount": len(self.failures),
            "accounted": [a.to_json() for a in self.accounted[:MAX_REPORTED_FAILURES]],
            "accountedCount": len(self.accounted),
            "optionalChecks": dict(self.optional_checks),
            "agentSignatures": {
                "present": self.agent_signatures_present,
                "verified": self.agent_signatures_verified,
            },
            "certKeysFromChain": self.cert_keys_from_chain,
            "signedEntries": self.signed_entries,
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
            "failures": [f.to_json() for f in self.failures[:MAX_REPORTED_FAILURES]],
            "failureCount": len(self.failures),
        }


#: The overall verdict of a dump.
#:
#: - ``trusted``: every check ran clean, and every signing key was anchored by
#:   signed key statements to a ``trust_anchors`` pin.
#: - ``unanchored``: nothing failed, but no ``trust_anchors`` were given, so
#:   every key was taken from the dump's own ``vault_signing_keys``. The report
#:   passes (``ok``) and is flagged: a key written into the database alone would
#:   pass too, so it is not a trusted verdict until a pin is given.
#: - ``failed``: at least one failure, or a finding on the key statements.
Verdict = Literal["trusted", "unanchored", "failed"]


@dataclass
class VerifyReport:
    ok: bool
    """False only for the ``failed`` verdict. An ``unanchored`` report passes
    and is flagged; read ``verdict`` (or ``key_trust.status``) before treating
    a pass as trusted."""
    vault: VaultChainsReport
    org_admin_reads: TenantAdminReadsReport
    verdict: Verdict = "unanchored"
    key_trust: KeyTrustReport = field(default_factory=no_anchor_report)
    """The key-statement walk: which keys the ``trust_anchors`` reach, and any
    finding about the statements themselves (``KEY_STATEMENT_INVALID``,
    ``KEY_CLOSURE_INVALID``, ``CHAIN_KEY_WINDOW_DRIFT``), each of which fails
    the dump. ``status`` is ``no_anchor`` when no anchors were given."""

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "verdict": self.verdict,
            "keyTrust": self.key_trust.to_json(),
            "vault": self.vault.to_json(),
            "orgAdminReads": self.org_admin_reads.to_json(),
        }
