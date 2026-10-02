"""AGLedger SDK: offline audit verification (format 2.0, COSE_Sign1).

Two verifiers share one verification core:

  - :func:`verify_export`: the per-record ``/audit-export`` JSON verifier::

        from agledger.verify import verify_export
        result = verify_export(data)
        if not result.valid:
            print(f"Broken at {result.broken_at.position}: {result.broken_at.code}")

  - :func:`verify_dump`: the full-vault dump verifier (six NDJSON files: the
    audit_vault chain, vault checkpoints, signing keys and their signed key
    statements, and the org_admin_reads Merkle log + signed tree heads)::

        from agledger.verify import load_dump, verify_dump
        report = verify_dump(load_dump("./dump-dir"), trust_anchors=["sha256:<hex>"])
        if not report.ok:
            for f in report.vault.failures + report.org_admin_reads.failures:
                print(f.code, f.message)

Both take ``trust_anchors``: the SPKI digest of a vault key you hold or took
out of band. The signed key statements are walked from it, and anything signed
by a key the walk does not reach fails. Without it a result that passes is
flagged ``no_anchor`` (a dump's ``verdict`` is ``unanchored``): it rests on keys
nobody pinned. The walk itself is :func:`compute_key_trust`.

The turnkey ``agledger-verify`` CLI auto-detects which one to run.

Both verifiers emit the canonical SCREAMING_SNAKE ``FailureCode`` taxonomy shared
with the TS verification core (``@agledger/verify-core``), so the languages agree
byte-for-byte over the shared conformance corpus (``testdata/conformance``).

Requires ``cbor2`` (COSE_Sign1 decode) and ``cryptography`` (Ed25519 verify).
Install via ``pip install 'agledger[verify]'``.
"""

from agledger.verify.failures import FailureCode, suggestion
from agledger.verify.key_statements import (
    KEY_STATEMENT_CTY,
    DistrustedKey,
    KeyRegistryFinding,
    KeyStatementInput,
    KeyTrust,
    KeyTrustEntry,
    KeyTrustNote,
    KeyTrustReport,
    KeyTrustState,
    KeyTrustStatus,
    TrustKeyInput,
    assert_not_pinned_and_distrusted,
    compute_key_trust,
    instant_ms,
    key_statement_from_dump_row,
    key_statements_from_export,
    key_statements_from_verification_keys,
    parse_distrusted_keys,
    parse_trust_anchors,
    settle_key_trust,
    spki_sha256,
    trust_key_from_dump_row,
)
from agledger.verify.loader import DumpLoadError, load_dump
from agledger.verify.types import (
    Dump,
    Failure,
    TenantAdminReadsReport,
    VaultChainsReport,
    Verdict,
    VerifyReport,
)
from agledger.verify.verify_dump import verify_dump
from agledger.verify.verify_export import (
    AGENT_SIGNATURE_CONTEXT,
    AgentSignatureCounts,
    BrokenAt,
    EntryVerificationResult,
    KeyProvenance,
    KeySource,
    SignatureCoverage,
    VerifyExportResult,
    earliest_key_activation,
    ed25519_jwk_thumbprint,
    org_read_leaf_hash,
    org_read_merkle_root,
    verify_export,
    verify_org_read_inclusion,
    written_while_signing,
)

__all__ = [
    "AGENT_SIGNATURE_CONTEXT",
    "KEY_STATEMENT_CTY",
    "AgentSignatureCounts",
    "BrokenAt",
    "DistrustedKey",
    "Dump",
    "DumpLoadError",
    "EntryVerificationResult",
    "Failure",
    "FailureCode",
    "KeyProvenance",
    "KeyRegistryFinding",
    "KeySource",
    "KeyStatementInput",
    "KeyTrust",
    "KeyTrustEntry",
    "KeyTrustNote",
    "KeyTrustReport",
    "KeyTrustState",
    "KeyTrustStatus",
    "SignatureCoverage",
    "TenantAdminReadsReport",
    "TrustKeyInput",
    "VaultChainsReport",
    "Verdict",
    "VerifyExportResult",
    "VerifyReport",
    "assert_not_pinned_and_distrusted",
    "compute_key_trust",
    "earliest_key_activation",
    "ed25519_jwk_thumbprint",
    "instant_ms",
    "key_statement_from_dump_row",
    "key_statements_from_export",
    "key_statements_from_verification_keys",
    "load_dump",
    "org_read_leaf_hash",
    "org_read_merkle_root",
    "parse_distrusted_keys",
    "parse_trust_anchors",
    "settle_key_trust",
    "spki_sha256",
    "suggestion",
    "trust_key_from_dump_row",
    "verify_dump",
    "verify_export",
    "verify_org_read_inclusion",
    "written_while_signing",
]
