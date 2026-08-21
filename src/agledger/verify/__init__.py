"""AGLedger SDK: offline audit verification (format 2.0, COSE_Sign1).

Two verifiers share one verification core:

  - :func:`verify_export`: the per-record ``/audit-export`` JSON verifier::

        from agledger.verify import verify_export
        result = verify_export(data)
        if not result.valid:
            print(f"Broken at {result.broken_at.position}: {result.broken_at.code}")

  - :func:`verify_dump`: the full-vault dump verifier (five NDJSON files: the
    audit_vault chain, vault checkpoints, signing keys, and the org_admin_reads
    Merkle log + signed tree heads)::

        from agledger.verify import load_dump, verify_dump
        report = verify_dump(load_dump("./dump-dir"))
        if not report.ok:
            for f in report.vault.failures + report.org_admin_reads.failures:
                print(f.code, f.message)

The turnkey ``agledger-verify`` CLI auto-detects which one to run.

Both verifiers emit the canonical SCREAMING_SNAKE ``FailureCode`` taxonomy shared
with the TS verification core (``@agledger/verify-core``), so the languages agree
byte-for-byte over the shared conformance corpus (``testdata/conformance``).

Requires ``cbor2`` (COSE_Sign1 decode) and ``cryptography`` (Ed25519 verify).
Install via ``pip install 'agledger[verify]'``.
"""

from agledger.verify.failures import FailureCode, suggestion
from agledger.verify.loader import DumpLoadError, load_dump
from agledger.verify.types import (
    Dump,
    Failure,
    TenantAdminReadsReport,
    VaultChainsReport,
    VerifyReport,
)
from agledger.verify.verify_dump import verify_dump
from agledger.verify.verify_export import (
    BrokenAt,
    EntryVerificationResult,
    KeyProvenance,
    KeySource,
    SignatureCoverage,
    VerifyExportResult,
    verify_export,
)

__all__ = [
    "BrokenAt",
    "Dump",
    "DumpLoadError",
    "EntryVerificationResult",
    "Failure",
    "FailureCode",
    "KeyProvenance",
    "KeySource",
    "SignatureCoverage",
    "TenantAdminReadsReport",
    "VaultChainsReport",
    "VerifyExportResult",
    "VerifyReport",
    "load_dump",
    "suggestion",
    "verify_dump",
    "verify_export",
]
