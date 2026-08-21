"""``agledger-verify``: offline verifier for AGLedger audit chains.

Auto-detects the single positional argument:
  - a directory  -> full-vault NDJSON dump  -> load_dump + verify_dump
  - a file       -> a single /audit-export JSON document (object with
                    exportMetadata + entries) -> verify_export

Exit codes: 0 clean, 1 verification failure, 2 usage / IO error. (The split of
usage/IO into its own code refines the TS CLI's 0/1 so a missing file or bad
argument is never mistaken for a tamper finding.) No network calls are made.

Honors ``NO_COLOR`` per no-color.org (the output is already uncolored, so this
is a no-op today: declared for forward compatibility) and ``--quiet`` (exit
code only, no stdout).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from agledger.verify.failures import suggestion
from agledger.verify.loader import DumpLoadError, load_dump
from agledger.verify.types import VerifyReport
from agledger.verify.verify_dump import verify_dump
from agledger.verify.verify_export import VerifyExportResult, verify_export

# Exit codes.
_EXIT_OK = 0
_EXIT_VERIFICATION_FAILED = 1
_EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agledger-verify",
        description=(
            "Offline verifier for AGLedger audit chains (hash chain + Ed25519 over "
            "COSE_Sign1). No network calls."
        ),
        epilog=(
            "TARGET is auto-detected: a directory is a full-vault NDJSON dump "
            "(audit_vault.ndjson + the four companion files); a file is a single "
            "/audit-export JSON document. Exit codes: 0 clean, 1 verification failure, "
            "2 usage/IO error."
        ),
    )
    parser.add_argument("target", help="dump directory or /audit-export JSON file")
    parser.add_argument(
        "-f",
        "--report-format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress stdout; communicate the result through the exit code only",
    )
    return parser


def _looks_like_audit_export(value: Any) -> bool:
    return isinstance(value, dict) and "exportMetadata" in value and "entries" in value


def _format_dump_text(report: VerifyReport) -> str:
    lines: list[str] = []
    status = "PASS" if report.ok else "FAIL"
    lines.append(f"[{status}] AGLedger offline verification (dump)")
    lines.append("")
    lines.append("audit_vault chain")
    lines.append(f"  records     : {report.vault.record_count}")
    lines.append(f"  entries     : {report.vault.entry_count}")
    lines.append(f"  checkpoints : {report.vault.checkpoint_count}")
    lines.append(f"  failures    : {len(report.vault.failures)}")
    for f in report.vault.failures:
        lines.append(f"    [{f.code}] {f.message}")
        lines.append(f"      -> {suggestion(f.code)}")
    lines.append("")
    lines.append("org_admin_reads chain")
    lines.append(f"  orgs             : {report.org_admin_reads.org_count}")
    lines.append(f"  leaves           : {report.org_admin_reads.leaf_count}")
    lines.append(f"  checkpoints      : {report.org_admin_reads.checkpoint_count}")
    lines.append(
        f"  witness cosigned : {len(report.org_admin_reads.witness_cosigned_checkpoints)}"
    )
    lines.extend(
        f"    checkpoint={w.checkpoint_id} witnessKeyId={w.witness_key_id} "
        f"(signature recorded, not verified)"
        for w in report.org_admin_reads.witness_cosigned_checkpoints
    )
    lines.append(f"  failures         : {len(report.org_admin_reads.failures)}")
    for f in report.org_admin_reads.failures:
        lines.append(f"    [{f.code}] {f.message}")
        lines.append(f"      -> {suggestion(f.code)}")
    return "\n".join(lines)


def _export_to_json(result: VerifyExportResult) -> dict[str, Any]:
    out: dict[str, Any] = {
        "valid": result.valid,
        "recordId": result.record_id,
        "totalEntries": result.total_entries,
        "verifiedEntries": result.verified_entries,
        "signatureCoverage": {
            "signed": result.signature_coverage.signed,
            "unsigned": result.signature_coverage.unsigned,
            "skipped": result.signature_coverage.skipped,
            "total": result.signature_coverage.total,
        },
        "keyProvenance": {
            "outOfBand": result.key_provenance.out_of_band,
            "embedded": result.key_provenance.embedded,
        },
    }
    if result.broken_at is not None:
        out["brokenAt"] = {
            "position": result.broken_at.position,
            "code": result.broken_at.code,
            "detail": result.broken_at.detail,
        }
    return out


def _format_export_text(result: VerifyExportResult) -> str:
    lines: list[str] = []
    status = "PASS" if result.valid else "FAIL"
    lines.append(f"[{status}] AGLedger offline verification (audit-export)")
    lines.append("")
    lines.append(f"  record            : {result.record_id}")
    lines.append(
        f"  entries           : {result.verified_entries}/{result.total_entries} verified"
    )
    cov = result.signature_coverage
    lines.append(
        f"  signature coverage: signed={cov.signed} unsigned={cov.unsigned} "
        f"skipped={cov.skipped}"
    )
    prov = result.key_provenance
    lines.append(
        f"  key provenance    : out-of-band={prov.out_of_band} embedded={prov.embedded}"
    )
    if result.broken_at is not None:
        lines.append(
            f"  broken at pos {result.broken_at.position}: [{result.broken_at.code}] "
            f"{result.broken_at.detail or ''}"
        )
        lines.append(f"      -> {suggestion(result.broken_at.code)}")
    return "\n".join(lines)


def run_cli(argv: Sequence[str]) -> int:
    """Parse args, verify the target, and return an exit code. Stdout/stderr are
    written directly so the function is also a clean unit-test seam."""
    parser = _build_parser()
    # argparse exits 2 on bad args/--help on its own; that already matches our
    # usage exit code.
    args = parser.parse_args(argv)

    target: str = args.target
    quiet: bool = args.quiet
    report_format: str = args.report_format

    # Directory -> full-vault dump.
    if os.path.isdir(target):
        try:
            report = verify_dump(load_dump(target))
        except DumpLoadError as err:
            print(str(err), file=sys.stderr)
            return _EXIT_USAGE
        if not quiet:
            if report_format == "json":
                print(json.dumps(report.to_json(), indent=2))
            else:
                print(_format_dump_text(report))
        return _EXIT_OK if report.ok else _EXIT_VERIFICATION_FAILED

    # File -> parse JSON, branch on exportMetadata.
    try:
        with open(target, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as err:
        print(str(err), file=sys.stderr)
        return _EXIT_USAGE
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        print(f"Invalid JSON in {target}: {err}", file=sys.stderr)
        return _EXIT_USAGE
    if not _looks_like_audit_export(parsed):
        print(
            f"{target} is neither a dump directory nor an /audit-export JSON document "
            f"(expected exportMetadata + entries).",
            file=sys.stderr,
        )
        return _EXIT_USAGE

    result = verify_export(parsed)
    if not quiet:
        if report_format == "json":
            print(json.dumps(_export_to_json(result), indent=2))
        else:
            print(_format_export_text(result))
    return _EXIT_OK if result.valid else _EXIT_VERIFICATION_FAILED


def main(argv: Sequence[str] | None = None) -> None:
    """Console-script entry point (``agledger-verify``)."""
    sys.exit(run_cli(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    main()
