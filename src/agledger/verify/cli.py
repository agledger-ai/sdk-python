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
given or it anchored no signature), 1 verification failure, 2 usage / IO
error, so a missing file or bad argument is never mistaken for a tamper
finding. The flags, the refusals and their messages, the headlines and the
exit codes are ``@agledger/verify``'s; where a message quotes the JSON parser
or the library's own ``TypeError``, that part is Python's. No network calls
are made.
"""

from __future__ import annotations

import errno
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from agledger.verify.failures import suggestion
from agledger.verify.key_statements import (
    KeyTrustReport,
    assert_not_pinned_and_distrusted,
    parse_distrusted_keys,
    parse_trust_anchors,
)
from agledger.verify.loader import DumpLoadError, load_dump
from agledger.verify.types import AccountedEntry, VerifyReport
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


@dataclass
class ParsedArgs:
    """The parsed command line, as ``@agledger/verify``'s ``parseArgs`` gives it."""

    target: str | None = None
    report_format: str = "text"
    show_help: bool = False
    keys: str | None = None
    require_key_id: str | None = None
    require_supplied_keys: bool = False
    agent_keys: str | None = None
    trust_anchors: list[str] = field(default_factory=list[str])
    """``--trust-anchor`` values, in the order given."""
    distrusted_keys: list[str] = field(default_factory=list[str])
    """``--distrusted-key`` values, one entry each, in the order given."""


class UsageError(Exception):
    """A command line ``parse_args`` refuses; the message is the CLI's."""


_PLURAL_DISTRUSTED = (
    "--distrusted-keys is now --distrusted-key, given once per key: "
    "--distrusted-key sha256:<hex>[@<RFC 3339 instant>]."
)


def parse_args(argv: Sequence[str]) -> ParsedArgs:
    """Parse the command line exactly as ``@agledger/verify`` does: whole flag
    names only, a flag's value is the next argument unless that starts with
    ``-``, and every refusal carries ``@agledger/verify``'s message. Raises
    :class:`UsageError`."""
    out = ParsedArgs()

    def take_value(flag: str, nxt: str | None) -> str:
        if nxt is None or nxt.startswith("-"):
            raise UsageError(f"{flag} requires a value (got {nxt if nxt is not None else 'nothing'})")
        return nxt

    i = 0
    while i < len(argv):
        arg = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if not arg:
            pass
        elif arg in ("--help", "-h"):
            out.show_help = True
        elif arg in ("--report-format", "-f"):
            if nxt not in ("json", "text"):
                raise UsageError(f'--report-format must be "json" or "text" (got {nxt if nxt is not None else "nothing"})')
            out.report_format = nxt
            i += 1
        elif arg.startswith("--report-format="):
            value = arg[len("--report-format=") :]
            if value not in ("json", "text"):
                raise UsageError(f'--report-format must be "json" or "text" (got {value})')
            out.report_format = value
        elif arg in ("--keys", "-k"):
            out.keys = take_value("--keys", nxt)
            i += 1
        elif arg.startswith("--keys="):
            out.keys = arg[len("--keys=") :]
            if not out.keys:
                raise UsageError("--keys requires a value")
        elif arg == "--require-key-id":
            out.require_key_id = take_value("--require-key-id", nxt)
            i += 1
        elif arg.startswith("--require-key-id="):
            out.require_key_id = arg[len("--require-key-id=") :]
            if not out.require_key_id:
                raise UsageError("--require-key-id requires a value")
        elif arg == "--agent-keys":
            out.agent_keys = take_value("--agent-keys", nxt)
            i += 1
        elif arg.startswith("--agent-keys="):
            out.agent_keys = arg[len("--agent-keys=") :]
            if not out.agent_keys:
                raise UsageError("--agent-keys requires a value")
        elif arg == "--trust-anchor":
            out.trust_anchors.append(take_value("--trust-anchor", nxt))
            i += 1
        elif arg.startswith("--trust-anchor="):
            value = arg[len("--trust-anchor=") :]
            if not value:
                raise UsageError("--trust-anchor requires a value")
            out.trust_anchors.append(value)
        elif arg == "--distrusted-key":
            out.distrusted_keys.append(take_value("--distrusted-key", nxt))
            i += 1
        elif arg.startswith("--distrusted-key="):
            value = arg[len("--distrusted-key=") :]
            if not value:
                raise UsageError("--distrusted-key requires a value")
            out.distrusted_keys.append(value)
        elif arg == "--distrusted-keys" or arg.startswith("--distrusted-keys="):
            raise UsageError(_PLURAL_DISTRUSTED)
        elif arg == "--require-supplied-keys":
            out.require_supplied_keys = True
        elif arg == "--require-out-of-band-keys":
            raise UsageError(
                "--require-out-of-band-keys is now --require-supplied-keys: a key fetched from the "
                "Server is supplied, not independent of it. Pin --trust-anchor for that."
            )
        elif arg.startswith("-"):
            raise UsageError(f"Unknown flag: {arg}")
        elif out.target is None:
            out.target = arg
        else:
            raise UsageError(f"Unexpected positional argument: {arg}")
        i += 1
    return out


HELP_TEXT = """agledger-verify: offline verifier for AGLedger audit chains

Usage:
  agledger-verify <target> [--trust-anchor sha256:<hex>]...
                  [--distrusted-key sha256:<hex>[@<instant>]]...
                  [--agent-keys <file>]
                  [--report-format text|json]
                  [--keys <file>] [--require-key-id <id>]
                  [--require-supplied-keys]

<target> is auto-detected:
  - a directory: a full-vault NDJSON dump (audit_vault.ndjson + the five
    companion files) verified with the full-installation dump verifier.
  - a file: a single /audit-export JSON document (object with exportMetadata +
    entries) verified with the per-record export verifier.

Options:
  --trust-anchor              SPKI digest of a vault key you hold or took out
                              of band, as sha256:<64 hex>. Repeatable. The
                              installer prints the first key's digest, and the
                              Server's signing-key-digest.js derives one from
                              any key. The signed key statements are walked
                              from the pins, and an entry, checkpoint or
                              read-log row signed by a key they do not reach
                              fails (CHAIN_SIGNING_KEY_UNANCHORED and its
                              checkpoint and read-log counterparts). Applies
                              to a dump directory and to an /audit-export file.
  --distrusted-key            A key the operator distrusts, as in the Server's
                              VAULT_DISTRUSTED_KEYS: sha256:<64 hex>,
                              optionally @<RFC 3339 instant>. Repeat it once
                              per key. What such a key stored from the
                              instant on (or, with none, from its retirement)
                              counts for nothing in the walk. Requires
                              --trust-anchor.
  --report-format, -f         Output format. Default: text.
  --agent-keys                Path to a JSON file holding the Ed25519 public
                              keys of agent certs: a JWK, a list of JWKs, or a
                              {keys:[...]} JWK Set. An entry may wrap its key
                              as {publicKeyJwk:{...}}. Each is the
                              publicKeyJwk an agent sent at cert exchange (also
                              the cnf.jwk claim in its certJws). An entry whose
                              sealed agent signature names one of them by
                              thumbprint has that signature re-verified
                              offline, and fails CHAIN_AGENT_SIGNATURE_INVALID
                              if it does not verify. Applies to a dump
                              directory (added to the cert keys the dump
                              itself signs) and to an /audit-export file.
  --keys, -k                  Path to a JSON file holding supplied public
                              keys, for an /audit-export file. Accepts a
                              {keyId: SPKI-DER-base64} map, a
                              [{keyId, publicKey, ...}] list, or the raw
                              GET /v1/verification-keys response envelope
                              (the .data array is unwrapped automatically, and
                              the key statements it carries are walked with
                              the export's). Merged over any keys embedded in
                              the export.
  --require-key-id            Require every entry to reference this keyId.
                              Rejects otherwise-valid exports signed by a
                              retired or unexpected key.
  --require-supplied-keys     Refuse keys embedded in the export: an entry
                              whose only key is the export's own fails. This
                              says where a key came from, not that it is
                              trusted; pin --trust-anchor for that.
  --help, -h                  Show this help.

Without --trust-anchor no key is anchored. Every key is taken from the
artifact itself (the dump's vault_signing_keys, the export's embedded keys, or
keys fetched from the same Server), and a key written into the Server's
database alone would verify. Such a run still finds tampering and still exits
0 when nothing fails, but it reports VERIFIED, NOT ANCHORED (JSON verdict
"unanchored"), never a trusted verdict. Ask the operator for the digest of a
vault key: the installer prints it, and signing-key-digest.js derives it.

The key-policy flags (--keys, --require-key-id, --require-supplied-keys)
apply to /audit-export files only; a dump directory carries its own signed key
history and rejects them.

A dump not scoped to one org carries the cert keys itself: each
EPHEMERAL_CERT_ISSUED entry on the platform-ops chain signs its cert's
publicKeyJwk (engines from 1.8.0 on), and a key is used once that chain has
verified clean. An org-scoped dump leaves the platform-ops chain out, and a
per-record /audit-export carries no cert keys, so for those pass --agent-keys.
Where no key is at hand the agent-signature check reports "not checked" and
changes no verdict.

A dump directory must contain:
  audit_vault.ndjson
  vault_checkpoints.ndjson
  vault_signing_keys.ndjson
  vault_key_statements.ndjson
  org_admin_reads.ndjson
  org_admin_reads_checkpoints.ndjson

Exit codes:
  0  verified, no failures (read the verdict: trusted with a --trust-anchor,
     unanchored without one)
  1  verification FAILED (the chain, log, or key statements do not hold up)
  2  could NOT verify (input missing, unreadable, or malformed; no verdict)

Codes 1 and 2 mean opposite things. Treat only 1 as evidence of tampering.
"""
"""The ``--help`` text: ``@agledger/verify``'s, less its line on streaming
``audit_vault.ndjson``, which this verifier reads whole."""


def _fs_message(err: OSError, path: str) -> str:
    """A file that cannot be read, in the words Node's ``readFileSync`` uses, so
    the message reads as ``@agledger/verify``'s."""
    code = errno.errorcode.get(err.errno) if err.errno is not None else None
    if code == "EISDIR":
        return "EISDIR: illegal operation on a directory, read"
    if code is None or not err.strerror:
        return str(err)
    return f"{code}: {err.strerror[:1].lower()}{err.strerror[1:]}, open '{path}'"


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
    except OSError as err:
        return f"Cannot read --agent-keys file {path}: {_fs_message(err, path)}"
    except ValueError as err:
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
    "The --keys file must be a {keyId: SPKI-DER-base64} map or a list of {keyId, publicKey, ...} "
    "entries (the .data list from /v1/verification-keys)."
)


def load_supplied_keys(path: str) -> Mapping[str, Any] | list[Any] | str:
    """Read a ``--keys`` file into the shape ``verify_export`` accepts, or
    return the usage-error message. A ``GET /v1/verification-keys`` response is
    unwrapped to its ``data`` list so the file can be saved verbatim; every
    other shape passes through, and ``verify_export`` validates it at the
    supplied-key boundary. Mirrors ``unwrapKeys`` in ``@agledger/verify``, and
    its messages: a file that cannot be read in the words Node gives, JSON
    that does not parse as ``Invalid JSON in <path>: ...``, and a value that is
    no key set at all as the supplied-key ``TypeError`` and the shape the file
    must have."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw: Any = json.load(fh)
    except OSError as err:
        return _fs_message(err, path)
    except ValueError as err:
        return f"Invalid JSON in {path}: {err}"
    if isinstance(raw, dict) and isinstance(
        cast("dict[str, Any]", raw).get("data"), list
    ):
        return cast("list[Any]", cast("dict[str, Any]", raw)["data"])
    if isinstance(raw, (dict, list)):
        return cast("Mapping[str, Any] | list[Any]", raw)
    return (
        "verify_export: public_keys must be a {keyId: base64SpkiDer} mapping or a sequence of "
        f"{{keyId, publicKey}} entries (got {type(raw).__name__}).\n{_KEYS_SHAPE}"
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


def headline(verdict: str, kind: str, key_trust: KeyTrustReport | None = None) -> list[str]:
    """The headline and the lines saying what it means, as ``@agledger/verify``
    prints them. ``unanchored`` gets its own words so that a run which found
    nothing wrong but anchored nothing can never be read, or grepped, as a
    trusted PASS; a pin that anchored no signature says so in its own."""
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
    if key_trust is not None and key_trust.status == "no_anchored_signature":
        return [
            f"[VERIFIED, NOT ANCHORED] AGLedger offline verification ({kind})",
            "  Nothing failed, but this is NOT a trusted verdict: the --trust-anchor was walked, but no",
            "  signature here verified under a key it anchors. An entry written before the install",
            "  began signing carries no signature, and proves nothing about who wrote it.",
        ]
    return [
        f"[VERIFIED, NOT ANCHORED] AGLedger offline verification ({kind})",
        "  Nothing failed, but this is NOT a trusted verdict: no --trust-anchor was given, so every",
        "  signing key was taken on the word of the artifact itself, and a key written into the",
        "  Server's database alone would verify. Ask the operator for the SPKI digest of a vault",
        "  key (the installer prints it; signing-key-digest.js derives it from any key) and",
        "  re-run with --trust-anchor sha256:<hex>.",
    ]


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
            + ("; NO signature verified under an anchored key" if key_trust.status == "no_anchored_signature" else "")
        )
    ]
    if key_trust.anchored_from is not None:
        pinned = "is" if key_trust.anchored_from_pinned else "is NOT"
        lines.append(f"  anchored from     : {key_trust.anchored_from} ({pinned} one of your anchors)")
    for f in key_trust.findings:
        lines.append(f"    [{f.code}] key {f.key_id or '-'}: {f.detail}")
        lines.append(f"      -> {suggestion(f.code)}")
    lines.extend(f"    note: key {n.key_id or '-'}: {n.detail}" for n in key_trust.notes)
    lines.extend(f"    accounted for: key {n.key_id or '-'}: {n.detail}" for n in key_trust.accounted)
    return lines


def _looks_like_audit_export(value: Any) -> bool:
    return isinstance(value, dict) and "exportMetadata" in value and "entries" in value


def _chain_name(a: AccountedEntry) -> str:
    if a.chain == "record":
        return f"Record {a.record_id}"
    if a.chain == "admin":
        return "Chain admin"
    return f"Chain schema:{a.org_id or '__platform__'}"


def _format_dump_text(report: VerifyReport, keys_given: bool = False) -> str:
    lines: list[str] = [*headline(report.verdict, "dump", report.key_trust), ""]
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
    if report.vault.accounted:
        # Signed by a key the operator distrusts, before a key the walk trusts
        # retired it: the distrust entry accounts for them. Not verified, and
        # not failures; listed so nobody reads them as vouched for.
        lines.append(f"  accounted for: {len(report.vault.accounted)} (signed by a distrusted key before its retirement; not verified)")
        lines.extend(
            f"    [{a.code}] {_chain_name(a)} pos {a.position} key {a.key_id}: {a.detail}" for a in report.vault.accounted
        )
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
        "verdict": result.verdict,
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
        "unsignedProjectionFields": list(result.unsigned_projection_fields),
    }
    if result.broken_at is not None:
        out["brokenAt"] = {
            "position": result.broken_at.position,
            "code": result.broken_at.code,
            "detail": result.broken_at.detail,
        }
    # Per entry as @agledger/verify prints them, unset fields left out.
    out["entries"] = [
        {
            k: v
            for k, v in (
                ("position", e.position),
                ("valid", e.valid),
                ("code", e.code),
                ("detail", e.detail),
                ("signature", e.signature),
            )
            if v is not None
        }
        for e in result.entries
    ]
    return out


def _format_export_text(result: VerifyExportResult, keys_given: bool = False) -> str:
    lines: list[str] = [*headline(result.verdict, "audit-export", result.key_trust), ""]
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
    # A PASS must not be read as vouching for unsigned display projections
    # (e.g. actorDisplayName). The attribution the export's guide points at
    # instead, actorOwnerId/actorId, IS signature-covered, so say whether this
    # run checked it. ``applied`` says the check ran, not that it passed, so a
    # failed run is not told its attribution agrees. As @agledger/verify says it.
    fields = result.unsigned_projection_fields
    if fields:
        if result.optional_checks.get("actor_attribution") != "applied":
            attribution = (
                "Attribution (actorId/actorOwnerId) carries no signed actor claim in this export, so it was NOT "
                "cross-checked."
            )
        elif result.valid:
            attribution = (
                "Attribution (actorId/actorOwnerId/actorRole) was cross-checked against the signed actor claim and agrees."
            )
        else:
            attribution = (
                "Attribution (actorId/actorOwnerId/actorRole) is cross-checked against the signed actor claim, and "
                "this run did not verify, so nothing above is vouched for."
            )
        lines.append(
            f"  note              : {len(fields)} unsigned display projection field(s) ({', '.join(fields)}) are NOT "
            f"signature-covered. {attribution}"
        )
    return "\n".join(lines)


def _flag_message(message: str) -> str:
    """A pin parser's message, named by the flag that carried the value."""
    for prefix, flag in (
        ("trust_anchors entry ", "--trust-anchor "),
        ("distrusted_keys entry ", "--distrusted-key "),
        ("distrusted_keys names ", "--distrusted-key names "),
    ):
        if message.startswith(prefix):
            return flag + message[len(prefix) :]
    return re.sub(
        r"^(sha256:[0-9a-f]{64}) is a trust anchor and a distrusted key with no instant,",
        r"\1 is a --trust-anchor and a --distrusted-key with no instant,",
        message,
    )


def _cannot_verify(message: str, report_format: str) -> int:
    """Report "no verdict was reached" in the format the caller asked for:
    under ``--report-format json`` it is still JSON, so a machine consumer can
    tell an unreadable target from a broken chain."""
    if report_format == "json":
        print(json.dumps({"ok": False, "error": {"kind": "input", "message": message}}, indent=2))
    else:
        print(message, file=sys.stderr)
    return _EXIT_USAGE


def _usage(message: str) -> int:
    """A refusal before the report format is known: plain text and the help."""
    print(f"{message}\n\n{HELP_TEXT}", file=sys.stderr, end="")
    return _EXIT_USAGE


_EXIT_BY_VERDICT = {"trusted": _EXIT_OK, "unanchored": _EXIT_OK, "failed": _EXIT_VERIFICATION_FAILED}


def run_cli(argv: Sequence[str]) -> int:
    """Parse args, verify the target, and return an exit code. Stdout/stderr are
    written directly so the function is also a clean unit-test seam. The
    flags, the refusals and their messages, the headlines and the exit codes
    are ``@agledger/verify``'s ``runCli``'s."""
    try:
        args = parse_args(argv)
    except UsageError as err:
        # The format is not known yet, so a usage error stays plain text.
        return _usage(str(err))
    if args.show_help:
        print(HELP_TEXT, end="")
        return _EXIT_OK
    if args.target is None:
        return _usage("Missing <target>.")

    target = args.target
    report_format = args.report_format
    has_key_policy_flags = (
        args.keys is not None or args.require_key_id is not None or args.require_supplied_keys
    )
    # Parsed before anything is read, so a mistyped pin is a usage error and
    # never a verdict: a run that silently dropped it would read as unanchored.
    try:
        trust_anchors = [f"sha256:{d}" for d in parse_trust_anchors(args.trust_anchors)]
        distrusted_keys = parse_distrusted_keys(args.distrusted_keys)
    except TypeError as err:
        return _cannot_verify(_flag_message(str(err)), report_format)
    if distrusted_keys and not trust_anchors:
        return _cannot_verify(
            "--distrusted-key acts only inside the key-statement walk, which runs from "
            "--trust-anchor; pass the pin as well.",
            report_format,
        )
    try:
        assert_not_pinned_and_distrusted(trust_anchors, distrusted_keys)
    except TypeError as err:
        return _cannot_verify(_flag_message(str(err)), report_format)
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
        # honoured the policy.
        if has_key_policy_flags:
            return _cannot_verify(
                "--keys / --require-key-id / --require-supplied-keys apply to /audit-export files "
                "only; a dump directory carries its own signed key history (vault_signing_keys.ndjson "
                "and vault_key_statements.ndjson). Pin it with --trust-anchor.",
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
        if report_format == "json":
            print(json.dumps(report.to_json(), indent=2))
        else:
            print(_format_dump_text(report, agent_keys is not None))
        return _EXIT_BY_VERDICT[report.verdict]

    # File -> parse JSON, branch on exportMetadata.
    try:
        with open(target, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as err:
        return _cannot_verify(_fs_message(err, target), report_format)
    try:
        parsed = json.loads(raw)
    except ValueError as err:
        return _cannot_verify(f"Invalid JSON in {target}: {err}", report_format)
    if not _looks_like_audit_export(parsed):
        return _usage(
            f"{target} is neither a dump directory nor an /audit-export JSON document "
            "(expected exportMetadata + entries)."
        )

    public_keys: Any = None
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
            require_key_id=args.require_key_id,
            require_supplied_keys=args.require_supplied_keys,
            agent_keys=agent_keys,
            trust_anchors=trust_anchors,
            distrusted_keys=distrusted_keys,
        )
    except TypeError as err:
        return _cannot_verify(f"{err}\n{_KEYS_SHAPE}", report_format)
    verdict = result.verdict
    if report_format == "json":
        print(json.dumps(_export_to_json(result), indent=2))
    else:
        print(_format_export_text(result, agent_keys is not None))
    return _EXIT_BY_VERDICT[verdict]


def main(argv: Sequence[str] | None = None) -> None:
    """Console-script entry point (``agledger-verify``)."""
    sys.exit(run_cli(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    main()
