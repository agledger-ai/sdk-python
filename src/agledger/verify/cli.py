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
from typing import Any, cast

from agledger.verify.failures import suggestion
from agledger.verify.loader import DumpLoadError, load_dump
from agledger.verify.types import VerifyReport
from agledger.verify.verify_dump import verify_dump
from agledger.verify.verify_export import (
    AgentSignatureCounts,
    CheckApplicability,
    VerifyExportResult,
    build_agent_key_registry,
    verify_export,
)

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
        "--agent-keys",
        metavar="FILE",
        help=(
            "JSON file holding the Ed25519 public keys of agent certs: a JWK, a list "
            "of JWKs, or a {keys:[...]} JWK Set, where an entry may wrap its key as "
            "{publicKeyJwk:{...}}. Each is the publicKeyJwk an agent sent at cert "
            "exchange (also the cnf.jwk claim in its certJws). An entry whose sealed "
            "agent signature names one of them by thumbprint has that signature "
            "re-verified offline, and fails CHAIN_AGENT_SIGNATURE_INVALID if it does "
            "not verify. Applies to a dump directory and to an /audit-export file. "
            "Neither carries agent cert keys, so without this flag the check reports "
            "'not checked' and changes no verdict."
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress stdout; communicate the result through the exit code only",
    )
    return parser


_AGENT_KEYS_SHAPE = (
    'The --agent-keys file must hold Ed25519 public-key JWKs ({"kty":"OKP","crv":"Ed25519",'
    '"x":"<base64url>"}): one JWK, a list of them, or a {"keys":[...]} JWK Set, where an '
    'entry may wrap its key as {"publicKeyJwk":{...}}.'
)


def load_agent_keys(path: str) -> list[dict[str, Any]] | str:
    """Read an ``--agent-keys`` file into a list of JWKs, or return the
    usage-error message. Accepts a single JWK, a list of JWKs, or a
    ``{keys: [...]}`` JWK Set, where an entry that wraps its key as
    ``{"publicKeyJwk": {...}}`` is unwrapped. Every key is validated here,
    before any verification runs, so a bad file is reported as a bad file
    rather than as a verdict. Mirrors ``@agledger/verify``."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw: Any = json.load(fh)
    except (OSError, ValueError) as err:
        return f"Cannot read --agent-keys file {path}: {err}"
    if isinstance(raw, list):
        entries: list[Any] = list(cast("list[Any]", raw))
    elif isinstance(raw, dict) and isinstance(cast("dict[str, Any]", raw).get("keys"), list):
        entries = list(cast("dict[str, Any]", raw)["keys"])
    else:
        entries = [raw]
    if not entries:
        return f"The --agent-keys file {path} holds no keys. {_AGENT_KEYS_SHAPE}"
    jwks: list[Any] = [
        cast("dict[str, Any]", e)["publicKeyJwk"] if isinstance(e, dict) and "publicKeyJwk" in e else e
        for e in entries
    ]
    try:
        build_agent_key_registry(jwks)
    except TypeError as err:
        message = str(err).replace("agent_keys[", "entry ", 1).replace("] is not", " is not", 1)
        return f"Invalid --agent-keys file {path}: {message}\n{_AGENT_KEYS_SHAPE}"
    return cast("list[dict[str, Any]]", jwks)


def _agent_signature_summary(
    counts: AgentSignatureCounts, check: CheckApplicability, keys_given: bool
) -> str:
    """One line on the agent-signature check. ``present > verified`` on a
    passing report means some signatures were not re-checked, never that they
    failed; the line says so rather than leaving a bare ratio to be misread."""
    base = f"present={counts.present} verified={counts.verified}"
    if check == "applied":
        if counts.present > counts.verified:
            return (
                f"{base} (checked; {counts.present - counts.verified} not verified: no key "
                "supplied for their cert, a caller-asserted identity, or a failure listed "
                "in this report)"
            )
        return f"{base} (checked)"
    if counts.present == 0:
        return f"{base} (none on the chain)"
    if keys_given:
        return (
            f"{base} (NOT checked: no supplied key matches their certs, or each is a "
            "caller-asserted identity)"
        )
    return f"{base} (NOT checked: pass --agent-keys with the agent cert keys to re-verify them)"


def _looks_like_audit_export(value: Any) -> bool:
    return isinstance(value, dict) and "exportMetadata" in value and "entries" in value


def _format_dump_text(report: VerifyReport, keys_given: bool = False) -> str:
    lines: list[str] = []
    status = "PASS" if report.ok else "FAIL"
    lines.append(f"[{status}] AGLedger offline verification (dump)")
    lines.append("")
    lines.append("audit_vault chain")
    lines.append(f"  records     : {report.vault.record_count}")
    lines.append(f"  entries     : {report.vault.entry_count}")
    lines.append(f"  checkpoints : {report.vault.checkpoint_count}")
    vault_counts = AgentSignatureCounts(
        report.vault.agent_signatures_present, report.vault.agent_signatures_verified
    )
    lines.append(
        f"  agent sigs  : {_agent_signature_summary(vault_counts, report.vault.optional_checks['agent_signature'], keys_given)}"
    )
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
        "optionalChecks": dict(result.optional_checks),
        "agentSignatures": {
            "present": result.agent_signatures.present,
            "verified": result.agent_signatures.verified,
        },
    }
    if result.broken_at is not None:
        out["brokenAt"] = {
            "position": result.broken_at.position,
            "code": result.broken_at.code,
            "detail": result.broken_at.detail,
        }
    return out


def _format_export_text(result: VerifyExportResult, keys_given: bool = False) -> str:
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
    lines.append(
        "  agent signatures  : "
        f"{_agent_signature_summary(result.agent_signatures, result.agent_signature_check, keys_given)}"
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

    agent_keys: list[dict[str, Any]] | None = None
    if args.agent_keys is not None:
        loaded = load_agent_keys(args.agent_keys)
        if isinstance(loaded, str):
            print(loaded, file=sys.stderr)
            return _EXIT_USAGE
        agent_keys = loaded

    # Directory -> full-vault dump.
    if os.path.isdir(target):
        try:
            report = verify_dump(load_dump(target), agent_keys=agent_keys)
        except DumpLoadError as err:
            print(str(err), file=sys.stderr)
            return _EXIT_USAGE
        if not quiet:
            if report_format == "json":
                print(json.dumps(report.to_json(), indent=2))
            else:
                print(_format_dump_text(report, agent_keys is not None))
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

    result = verify_export(parsed, agent_keys=agent_keys)
    if not quiet:
        if report_format == "json":
            print(json.dumps(_export_to_json(result), indent=2))
        else:
            print(_format_export_text(result, agent_keys is not None))
    return _EXIT_OK if result.valid else _EXIT_VERIFICATION_FAILED


def main(argv: Sequence[str] | None = None) -> None:
    """Console-script entry point (``agledger-verify``)."""
    sys.exit(run_cli(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    main()
