"""``agledger-verify``: offline verifier for AGLedger audit chains.

Auto-detects the single positional argument:
  - a directory  -> full-vault NDJSON dump  -> load_dump + verify_dump
  - a file       -> a single /audit-export JSON document (object with
                    exportMetadata + entries) -> verify_export

The key-policy flags (``--keys``, ``--require-key-id``,
``--require-supplied-keys``) apply to an ``/audit-export`` file only; a dump
directory carries its own key registry and rejects them.

``--trust-anchor`` applies to both: the signed key statements the target
carries are walked from the pinned SPKI digest, and anything signed by a key
the walk does not reach fails. Without it the target is verified against keys
nobody pinned, and a pass is reported as UNANCHORED: it passes, and it is not a
trusted verdict, because a key written into the Server's database alone would
pass too.

Exit codes: 0 pass (trusted, or unanchored when no ``--trust-anchor`` was
given), 1 verification failure, 2 usage / IO error, so a missing file or bad
argument is never mistaken for a tamper finding. The flags, their refusals and
messages, the headlines and the exit codes are ``@agledger/verify``'s. No
network calls are made.

Honors ``NO_COLOR`` per no-color.org (the output is already uncolored, so this
is a no-op today: declared for forward compatibility) and ``--quiet`` (exit
code only, no stdout).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any, cast

from agledger.verify.failures import suggestion
from agledger.verify.key_statements import (
    KeyTrustReport,
    parse_distrusted_keys,
    parse_trust_anchors,
)
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
        # A prefix of a flag is not that flag: @agledger/verify takes whole
        # names only, and so does this CLI.
        allow_abbrev=False,
        description=(
            "Offline verifier for AGLedger audit chains (hash chain + Ed25519 over "
            "COSE_Sign1). No network calls."
        ),
        epilog=(
            "TARGET is auto-detected: a directory is a full-vault NDJSON dump "
            "(audit_vault.ndjson + the five companion files); a file is a single "
            "/audit-export JSON document. Exit codes: 0 pass (trusted, or unanchored "
            "without --trust-anchor), 1 verification failure, 2 usage/IO error."
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
            "not verify. Applies to a dump directory (added to the cert keys the dump "
            "itself signs) and to an /audit-export file. A dump not scoped to one org "
            "carries the cert keys: each EPHEMERAL_CERT_ISSUED entry on the platform-ops "
            "chain signs its cert's publicKeyJwk (engines from 1.8.0 on), used once that "
            "chain verifies clean. An org-scoped dump and an /audit-export carry none, so "
            "for those pass this flag. Where no key is at hand the check reports 'not "
            "checked' and changes no verdict."
        ),
    )
    parser.add_argument(
        "--trust-anchor",
        metavar="DIGEST",
        action="append",
        default=None,
        help=(
            "SPKI digest (sha256:<64 hex>) of a vault key you hold or took out of band: "
            "the installer prints the first key's, and the Server's signing-key-digest.js "
            "derives one from any key. Repeat it once per key. "
            "The signed key statements the target carries are walked from it, and "
            "anything signed by a key the walk does not reach fails "
            "(CHAIN_SIGNING_KEY_UNANCHORED and the checkpoint and read-log twins). An "
            "export's anchoredFrom is the export's own word and never a pin. Without it "
            "a pass is UNANCHORED, not trusted."
        ),
    )
    parser.add_argument(
        "--distrusted-key",
        metavar="ENTRY",
        action="append",
        default=None,
        help=(
            "A key the operator distrusts, in the Server's VAULT_DISTRUSTED_KEYS form: "
            "sha256:<64 hex>, optionally @<RFC 3339 instant>. What it signed from the "
            "instant on (with none, from the retirement a trusted key signed for it) "
            "counts for nothing in the walk. Repeat it once per key. Requires "
            "--trust-anchor."
        ),
    )
    parser.add_argument(
        "-k",
        "--keys",
        metavar="FILE",
        help=(
            "JSON file holding public keys you supply, for an /audit-export file. "
            "Accepts a {keyId: SPKI-DER-base64} map, a [{keyId, publicKey, ...}] list, "
            "or the raw GET /v1/verification-keys response envelope (the .data array is "
            "unwrapped automatically, and each key's statements are walked with the "
            "export's own). Merged over any keys embedded in the export. Where a key "
            "came from does not make it trusted; --trust-anchor does."
        ),
    )
    parser.add_argument(
        "--require-key-id",
        metavar="ID",
        help=(
            "Require every entry to reference this keyId, rejecting an otherwise-valid "
            "export signed by a retired or unexpected key "
            "(else CHAIN_KEY_POLICY_VIOLATION)."
        ),
    )
    parser.add_argument(
        "--require-supplied-keys",
        action="store_true",
        help=(
            "Refuse keys embedded in the export: an entry whose only key is the "
            "export's own fails CHAIN_KEY_POLICY_VIOLATION. Supply keys via --keys."
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
    elif isinstance(raw, dict) and isinstance(
        cast("dict[str, Any]", raw).get("keys"), list
    ):
        entries = list(cast("dict[str, Any]", raw)["keys"])
    else:
        entries = [raw]
    if not entries:
        return f"The --agent-keys file {path} holds no keys. {_AGENT_KEYS_SHAPE}"
    jwks: list[Any] = [
        cast("dict[str, Any]", e)["publicKeyJwk"]
        if isinstance(e, dict) and "publicKeyJwk" in e
        else e
        for e in entries
    ]
    try:
        build_agent_key_registry(jwks)
    except TypeError as err:
        message = (
            str(err)
            .replace("agent_keys[", "entry ", 1)
            .replace("] is not", " is not", 1)
        )
        return f"Invalid --agent-keys file {path}: {message}\n{_AGENT_KEYS_SHAPE}"
    return cast("list[dict[str, Any]]", jwks)


_KEYS_SHAPE = (
    'The --keys file must be a {"keyId": "<SPKI-DER-base64>"} map or a list of '
    '{"keyId", "publicKey"} entries (the .data list from GET /v1/verification-keys).'
)


def load_supplied_keys(path: str) -> Mapping[str, Any] | list[Any] | str:
    """Read a ``--keys`` file into the shape ``verify_export`` accepts, or
    return the usage-error message. A ``GET /v1/verification-keys`` response is
    unwrapped to its ``data`` list so the file can be saved verbatim; every
    other shape passes through, and ``verify_export`` validates it at the
    supplied-key boundary. Mirrors ``unwrapKeys`` in ``@agledger/verify``."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw: Any = json.load(fh)
    except OSError as err:
        return f"Cannot read --keys file {path}: {err}"
    except ValueError as err:
        return f"Invalid JSON in {path}: {err}"
    if isinstance(raw, dict) and isinstance(
        cast("dict[str, Any]", raw).get("data"), list
    ):
        return cast("list[Any]", cast("dict[str, Any]", raw)["data"])
    if isinstance(raw, (dict, list)):
        return cast("Mapping[str, Any] | list[Any]", raw)
    return (
        f"Invalid --keys file {path}: expected a JSON object or array, got "
        f"{type(raw).__name__}.\n{_KEYS_SHAPE}"
    )


def _agent_signature_summary(
    counts: AgentSignatureCounts,
    check: CheckApplicability,
    keys_given: bool,
    keys_from_chain: int = 0,
) -> str:
    """One line on the agent-signature check. ``present > verified`` on a
    passing report means some signatures were not re-checked, never that they
    failed; the line says so rather than leaving a bare ratio to be misread.
    ``keys_from_chain`` counts the cert keys a dump signs itself (always 0 for
    an export)."""
    base = f"present={counts.present} verified={counts.verified}"
    on_chain = f"{keys_from_chain} cert key{'' if keys_from_chain == 1 else 's'} the dump signs"
    if check == "applied":
        if counts.present > counts.verified:
            return (
                f"{base} (checked; {counts.present - counts.verified} not verified: no key "
                "for their cert, a caller-asserted identity, or a failure listed "
                "in this report)"
            )
        if keys_from_chain == 0:
            return f"{base} (checked)"
        against = f"the supplied keys and the {on_chain}" if keys_given else f"the {on_chain}"
        return f"{base} (checked against {against})"
    if counts.present == 0:
        return f"{base} (none on the chain)"
    if keys_given:
        extra = f" or the {on_chain}" if keys_from_chain else ""
        return (
            f"{base} (NOT checked: no supplied key{extra} matches their certs, or each is a "
            "caller-asserted identity)"
        )
    if keys_from_chain:
        return (
            f"{base} (NOT checked: none of the {on_chain} matches; pass --agent-keys with "
            "the agent cert keys to re-verify them)"
        )
    return f"{base} (NOT checked: pass --agent-keys with the agent cert keys to re-verify them)"


def headline(verdict: str, kind: str) -> list[str]:
    """The headline and the lines saying what it means, as ``@agledger/verify``
    prints them. ``unanchored`` gets its own words so that a run which found
    nothing wrong but anchored nothing can never be read, or grepped, as a
    trusted PASS."""
    if verdict == "trusted":
        return [
            f"[PASS] AGLedger offline verification ({kind})",
            "  Nothing failed, and every signature was checked under a key the signed key statements",
            "  link to a --trust-anchor you gave.",
        ]
    if verdict == "failed":
        return [
            f"[FAIL] AGLedger offline verification ({kind})",
            "  Verification FAILED: the chain, the read log or the key statements do not hold up.",
            "  Each finding is listed below.",
        ]
    return [
        f"[VERIFIED, NOT ANCHORED] AGLedger offline verification ({kind})",
        "  Nothing failed, but this is NOT a trusted verdict: no --trust-anchor was given, so every",
        "  signing key was taken on the word of the artifact itself, and a key written into the",
        "  Server's database alone would verify. Ask the operator for the SPKI digest of a vault",
        "  key (the installer prints it; signing-key-digest.js derives it from any key) and",
        "  re-run with --trust-anchor sha256:<hex>.",
    ]


def export_verdict(result: VerifyExportResult) -> str:
    """The verdict of an /audit-export result, by the same rule as a dump's."""
    if not result.valid:
        return "failed"
    return "unanchored" if result.key_trust.status == "no_anchor" else "trusted"


def _key_trust_lines(key_trust: KeyTrustReport) -> list[str]:
    """What the key-statement walk concluded, in the text report. A report with
    no anchor says in plain words that its pass is not a trusted verdict."""
    if key_trust.status == "no_anchor":
        return ["  key anchoring     : NOT RUN (no --trust-anchor given; no key is anchored)"]
    lines = [
        (
            f"  key anchoring     : walked from {', '.join(key_trust.anchors)} ({key_trust.order} order); "
            f"anchored {len(key_trust.anchored_key_ids)}, unanchored {len(key_trust.unanchored_key_ids)}, "
            f"undecided {len(key_trust.undecided_key_ids)}"
        )
    ]
    if key_trust.anchored_from is not None:
        pinned = "is" if key_trust.anchored_from_pinned else "is NOT"
        lines.append(f"  anchored from     : {key_trust.anchored_from} ({pinned} one of your anchors)")
    for f in key_trust.findings:
        lines.append(f"    [{f.code}] key {f.key_id or '-'}: {f.detail}")
        lines.append(f"      -> {suggestion(f.code)}")
    return lines


def _looks_like_audit_export(value: Any) -> bool:
    return isinstance(value, dict) and "exportMetadata" in value and "entries" in value


def _format_dump_text(report: VerifyReport, keys_given: bool = False) -> str:
    lines: list[str] = [*headline(report.verdict, "dump"), ""]
    lines.extend(_key_trust_lines(report.key_trust))
    lines.append("")
    lines.append("audit_vault chain")
    lines.append(f"  records     : {report.vault.record_count}")
    lines.append(f"  entries     : {report.vault.entry_count}")
    lines.append(f"  checkpoints : {report.vault.checkpoint_count}")
    vault_counts = AgentSignatureCounts(
        report.vault.agent_signatures_present, report.vault.agent_signatures_verified
    )
    lines.append(
        f"  agent sigs  : {_agent_signature_summary(vault_counts, report.vault.optional_checks['agent_signature'], keys_given, report.vault.cert_keys_from_chain)}"
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
        "verdict": export_verdict(result),
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
            "supplied": result.key_provenance.supplied,
            "embedded": result.key_provenance.embedded,
        },
        "keyTrust": result.key_trust.to_json(),
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
    lines: list[str] = [*headline(export_verdict(result), "audit-export"), ""]
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
    lines.append(f"  key provenance    : supplied={prov.supplied} embedded={prov.embedded}")
    lines.extend(_key_trust_lines(result.key_trust))
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


_REFUSED_FLAGS = {
    "--distrusted-keys": (
        "--distrusted-keys is now --distrusted-key, given once per key: "
        "--distrusted-key sha256:<hex>[@<RFC 3339 instant>]."
    ),
    "--require-out-of-band-keys": (
        "--require-out-of-band-keys is now --require-supplied-keys: a key fetched from the "
        "Server is supplied, not independent of it. Pin --trust-anchor for that."
    ),
}


def _flag_message(message: str) -> str:
    """A pin parser's message, named by the flag that carried the value."""
    for prefix, flag in (
        ("trust_anchors entry ", "--trust-anchor "),
        ("distrusted_keys entry ", "--distrusted-key "),
        ("distrusted_keys names ", "--distrusted-key names "),
    ):
        if message.startswith(prefix):
            return flag + message[len(prefix) :]
    return message


def _cannot_verify(message: str, report_format: str) -> int:
    """Report "no verdict was reached" in the format the caller asked for:
    under ``--report-format json`` it is still JSON, so a machine consumer can
    tell an unreadable target from a broken chain."""
    if report_format == "json":
        print(json.dumps({"ok": False, "error": {"kind": "input", "message": message}}, indent=2))
    else:
        print(message, file=sys.stderr)
    return _EXIT_USAGE


def run_cli(argv: Sequence[str]) -> int:
    """Parse args, verify the target, and return an exit code. Stdout/stderr are
    written directly so the function is also a clean unit-test seam."""
    parser = _build_parser()
    for arg in argv:
        refused = _REFUSED_FLAGS.get(arg.split("=", 1)[0])
        if refused is not None:
            print(f"{refused}\n\n{parser.format_help()}", file=sys.stderr)
            return _EXIT_USAGE
    # argparse exits 2 on bad args and 0 on --help on its own; that already
    # matches our exit codes.
    args = parser.parse_args(argv)

    target: str = args.target
    quiet: bool = args.quiet
    report_format: str = args.report_format

    require_key_id: str | None = args.require_key_id
    require_supplied_keys: bool = args.require_supplied_keys
    has_key_policy_flags = (
        args.keys is not None or require_key_id is not None or require_supplied_keys
    )
    trust_anchors: list[str] = list(args.trust_anchor or [])
    distrusted_keys: list[str] = list(args.distrusted_key or [])
    # Parsed before anything is read, so a mistyped pin is a usage error and
    # never a verdict: a run that silently dropped it would read as unanchored.
    try:
        parse_trust_anchors(trust_anchors)
        parse_distrusted_keys(distrusted_keys)
    except TypeError as err:
        return _cannot_verify(_flag_message(str(err)), report_format)
    if distrusted_keys and not trust_anchors:
        return _cannot_verify(
            "--distrusted-key acts only inside the key-statement walk, which runs from "
            "--trust-anchor; pass the pin as well.",
            report_format,
        )
    if not os.path.exists(target):
        return _cannot_verify(f"Cannot read {target}: no such file or directory.", report_format)

    agent_keys: list[dict[str, Any]] | None = None
    if args.agent_keys is not None:
        loaded = load_agent_keys(args.agent_keys)
        if isinstance(loaded, str):
            return _cannot_verify(loaded, report_format)
        agent_keys = loaded

    # Directory -> full-vault dump.
    if os.path.isdir(target):
        # A dump carries its own key registry, so a supplied key set has
        # nothing to override and a silent no-op would read as an audit that
        # honoured the policy. Mirrors @agledger/verify.
        if has_key_policy_flags:
            return _cannot_verify(
                "--keys / --require-key-id / --require-supplied-keys apply to "
                "/audit-export files only; a dump directory carries its own key "
                "registry and signed key statements (vault_signing_keys.ndjson, "
                "vault_key_statements.ndjson). Anchor its keys with --trust-anchor.",
                report_format,
            )
        try:
            report = verify_dump(
                load_dump(target),
                agent_keys=agent_keys,
                trust_anchors=trust_anchors,
                distrusted_keys=distrusted_keys,
            )
        except (DumpLoadError, TypeError) as err:
            return _cannot_verify(str(err), report_format)
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
        return _cannot_verify(str(err), report_format)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        return _cannot_verify(f"Invalid JSON in {target}: {err}", report_format)
    if not _looks_like_audit_export(parsed):
        return _cannot_verify(
            f"{target} is neither a dump directory nor an /audit-export JSON document "
            f"(expected exportMetadata + entries).",
            report_format,
        )

    public_keys: Mapping[str, Any] | list[Any] | None = None
    if args.keys is not None:
        loaded_keys = load_supplied_keys(args.keys)
        if isinstance(loaded_keys, str):
            return _cannot_verify(loaded_keys, report_format)
        public_keys = loaded_keys

    # verify_export raises TypeError at the supplied-key boundary when the
    # file's shape is wrong ({keyId: 42}, [null]). Surface it as a usage error
    # rather than an uncaught traceback, so a bad input never reads as a verdict.
    try:
        result = verify_export(
            parsed,
            public_keys=public_keys,
            require_key_id=require_key_id,
            require_supplied_keys=require_supplied_keys,
            agent_keys=agent_keys,
            trust_anchors=trust_anchors,
            distrusted_keys=distrusted_keys,
        )
    except TypeError as err:
        return _cannot_verify(f"{err}\n{_KEYS_SHAPE}", report_format)
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
