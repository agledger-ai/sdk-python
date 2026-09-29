"""Offline verification of a full-vault AGLedger dump (five NDJSON files).

The Python sibling of the TS ``@agledger/verify`` dump verifier. The per-record
(and per-org schema-event) hash-chain walk is delegated to the SAME body the
export verifier uses (``verify_export.verify_entry``), fed the dump-only inputs
the export wire cannot carry: the binding payload, the OIDC-actor columns, the
per-entry write time, and the signing keys' temporal windows. So binding-
integrity, the OIDC-actor cross-check, AND temporal key-validity
(CHAIN_KEY_NOT_YET_ACTIVE / CHAIN_KEY_EXPIRED) all come from the shared walk
for free.

What stays LOCAL here is the dump-structural work the per-entry walk does not
model: the vault-checkpoint cross-check against the live chain, and the
org_admin_reads Merkle log + signed-tree-head + fork-detection passes. They use
the shared ``verify_cose_sign1`` / ``merkle_root`` primitives and emit the
canonical CHECKPOINT_* / TENANT_* codes.

Fail-closed posture: an empty vault is CHAIN_EMPTY (never a silent pass); a row
lacking ``cose_sign1`` is a pre-2.0 shape → UNSUPPORTED_FORMAT (not parsed
best-effort). Mirrors ``packages/verify/src/dump-verifier.ts``.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agledger.verify.types import (
    Dump,
    DumpRow,
    Failure,
    TenantAdminReadsReport,
    VaultChainsReport,
    VerifyReport,
    WitnessCosignedCheckpoint,
)

# The shared verification core lives in verify_export: the per-entry chain walk
# (verify_entry), the key registry (KeyCache / RegisteredKey), and the
# merkle_root / verify_cose_sign1 primitives. Reused here verbatim: the dump
# verifier adds only the dump-structural passes the per-entry walk does not model.
from agledger.verify.verify_export import (
    AgentSignatureCounts,
    CheckApplicability,
    EntryVerificationResult,
    KeyCache,
    RegisteredKey,
    as_mapping,
    build_agent_key_registry,
    check_agent_signature,
    decode_cose_kid,
    decode_cose_parts,
    decode_cose_predicate,
    describe_unsupported_algorithm,
    earliest_key_activation,
    ed25519_jwk_thumbprint,
    merkle_root,
    optional_checks_report,
    verify_cose_sign1,
    verify_entry,
    written_while_signing,
)

#: The kid an unsigned org_admin_reads leaf carries in its protected header:
#: eight zero bytes, the engine's ``UNSIGNED_KID_SENTINEL``.
UNSIGNED_KID_SENTINEL = "0000000000000000"


def _as_int(value: Any) -> int | None:
    """Narrow a dump value to ``int`` for a report field, else ``None``."""
    return value if isinstance(value, int) else None


def _as_str(value: Any) -> str | None:
    """Stringify a present dump value for a report ``scope_id``, else ``None``."""
    return str(value) if value is not None else None


def _checkpoint_signature_outcome(
    cose_sign1_b64: Any, signing_key_id: Any, keys: KeyCache
) -> str:
    """Resolve a checkpoint/STH signing key and verify its COSE_Sign1 signature.

    Returns ``"ok"`` (nothing to verify, or verified), ``"missing-key"`` (the
    signing_key_id is not in the dumped registry), ``"unsupported"`` (the key's
    algorithm is beyond this build; an upgrade signal, never a pass), or
    ``"invalid"``. Fail-closed on every other non-ok outcome, including an
    all-zero signature on a checkpoint that CLAIMS a signing key: the engine
    never writes a signing_key_id it did not sign with, so ``unsigned`` there
    is tampering. Only None means unsigned; "" must resolve in the registry
    and fail as a missing key rather than silently skip the signature check.
    Shared by the vault-checkpoint and org-reads STH passes.
    """
    if signing_key_id is None:
        return "ok"
    entry = keys.entry(str(signing_key_id))
    if entry is None:
        return "missing-key"
    outcome = verify_cose_sign1(base64.b64decode(str(cose_sign1_b64)), entry)
    if outcome == "ok":
        return "ok"
    if outcome == "unsupported-key-algorithm":
        return "unsupported"
    return "invalid"


def _build_vault_key_registry(signing_keys: list[DumpRow]) -> KeyCache:
    registry: dict[str, RegisteredKey] = {}
    for k in signing_keys:
        algorithm = k.get("algorithm")
        registry[str(k.get("key_id"))] = RegisteredKey(
            spki_base64=str(k.get("public_key")),
            source="embedded",
            activated_at=k.get("activated_at"),
            retired_at=k.get("retired_at"),
            # The registry row's DECLARED algorithm; verify_entry cross-checks
            # it against the key material (CHAIN_ALG_MISMATCH on a lie).
            algorithm=str(algorithm) if isinstance(algorithm, str) else None,
        )
    # The dump carries the whole key registry, retired keys included, so the
    # instant the install began signing is its earliest activation.
    return KeyCache(registry, signing_since=earliest_key_activation(signing_keys))


def _chain_key(e: DumpRow) -> str:
    """Group identity for a vault row. Mirrors dump-verifier.ts groupByChain:
    explicit chain_key (v0.23.2+), else record_id, else a per-org schema key.
    """
    ck = e.get("chain_key")
    if ck is not None:
        return str(ck)
    rid = e.get("record_id")
    if rid is not None:
        return str(rid)
    org_id = as_mapping(e.get("payload")).get("orgId")
    # ?? '__platform__': only None/undefined becomes platform; "" is kept.
    return f"schema:{org_id if org_id is not None else '__platform__'}"


def _checkpoint_chain_key(cp: DumpRow) -> str:
    """Group identity for a checkpoint, which is NOT always its record_id.

    A schema chain's checkpoint carries a derived UUIDv8 in record_id (the
    engine needs a non-null uuid for a chain whose rows have none), so joining
    on that column strands the checkpoint and reports CHECKPOINT_ROW_MISSING
    against a healthy vault. Join on the producer's chain_key; fall back to
    record_id for older dumps, which is correct for every chain except schema
    chains.
    """
    ck = cp.get("chain_key")
    if ck is not None:
        return str(ck)
    rid = cp.get("record_id")
    # A checkpoint with neither key is malformed; group it under "" so it still
    # surfaces as an orphan rather than silently joining a real chain.
    return str(rid) if rid is not None else ""


def _chain_label(chain_key: str) -> str:
    """How a chain is named in failure messages. A per-record key IS a record
    id, so "Record <uuid>" is a lookup an auditor can act on; a schema key is
    not, and labelling it that way sent auditors to /v1/records/{id} for a 404,
    so it is named as the chain it actually is.
    """
    return f"Chain {chain_key}" if chain_key.startswith("schema:") else f"Record {chain_key}"


def _group_by_chain(entries: list[DumpRow]) -> dict[str, list[DumpRow]]:
    by_chain: dict[str, list[DumpRow]] = {}
    for e in entries:
        by_chain.setdefault(_chain_key(e), []).append(e)
    for rows in by_chain.values():
        rows.sort(key=lambda r: r.get("chain_position", 0))
    return by_chain


def _normalize_entry(e: DumpRow) -> dict[str, Any]:
    """Adapt a raw vault row into the shape ``verify_entry`` reads, carrying the
    dump-only inputs (binding payload, OIDC-actor columns, write time)."""
    return {
        "chainPosition": e.get("chain_position"),
        "integrity": {
            "payloadHash": e.get("payload_hash"),
            "previousHash": e.get("previous_hash"),
            "coseSign1": e.get("cose_sign1"),
            "signingKeyId": e.get("signing_key_id"),
        },
        "payload": e.get("payload"),
        "entryType": e.get("entry_type"),
        "recordId": e.get("record_id"),
        "createdAt": e.get("created_at"),
        # Always attach for the dump path (TS toNormalizedEntry does too); the
        # all-null/undefined case passes the OIDC check. `synthesized` stays None
        # when the column is absent, preserving the tri-state.
        "actorOidc": {
            "iss": e.get("actor_oidc_iss"),
            "sub": e.get("actor_oidc_sub"),
            "synthesized": e.get("actor_oidc_synthesized"),
        },
        # The actor columns a report displays as "who did this" are
        # signature-covered (CWT_Claims label 15 -> -65539), so they are
        # cross-checked rather than taken on trust. Required in the dump shape,
        # so this check is always applicable on the dump path.
        "actorId": e.get("actor_key_id"),
        "actorRole": e.get("actor_role"),
        "actorOwnerId": e.get("actor_owner_id"),
    }


def _collect_chain_failures(
    scope_id: str,
    normalized: list[dict[str, Any]],
    keys: KeyCache,
    failures: list[Failure],
    agent_keys: Mapping[str, bytes] | None = None,
    agent_counts: AgentSignatureCounts | None = None,
    agent_check: list[CheckApplicability] | None = None,
    applied: set[str] | None = None,
) -> list[EntryVerificationResult]:
    """Walk one chain group via the shared per-entry body, flatten any invalid
    entry into a Failure, and return each entry's result in chain order.

    The dump passes NO key-policy options (all dump keys are embedded).
    previousHash advances even on a failed entry, matching the export walk and
    verify-core. An entry with no signing key id after one that names a key, or
    written at or after ``keys.signing_since``, fails CHAIN_ENTRY_UNSIGNED."""
    prev_payload_hash: str | None = None
    signed_before = False
    results: list[EntryVerificationResult] = []
    for i, entry in enumerate(normalized):
        result = verify_entry(
            entry, i + 1, prev_payload_hash, keys, None, False, applied, signed_before=signed_before
        )
        if as_mapping(entry.get("integrity")).get("signingKeyId") is not None:
            signed_before = True
        if result.valid and agent_counts is not None and agent_check is not None:
            result = check_agent_signature(entry, result, agent_keys, agent_counts, agent_check)
        if not result.valid and result.code is not None:
            failures.append(
                Failure(
                    code=result.code,
                    message=f"{_chain_label(scope_id)} pos {result.position}: {result.detail}",
                    scope_id=scope_id,
                    position=result.position,
                )
            )
        results.append(result)
        prev_payload_hash = as_mapping(entry.get("integrity")).get("payloadHash")
    return results


#: The entry type that records a cert's issuance, with its public key signed in.
_CERT_ISSUED = "EPHEMERAL_CERT_ISSUED"


def _harvest_cert_keys(
    rows: list[DumpRow],
    results: list[EntryVerificationResult],
    registry: dict[str, bytes],
) -> int:
    """Add to ``registry`` the agent cert public keys a verified chain signs,
    and return how many were new.

    Each ``EPHEMERAL_CERT_ISSUED`` entry on the platform-ops chain signs its
    cert's ``publicKeyJwk`` (engines from 1.8.0 on). Called only for a chain
    that verified with no failure, its checkpoints included, and reads only
    entries whose vault signature checked ``ok``, so every key taken is one the
    engine signed and nobody changed since. The key is read from the signed
    predicate, never the row copy, and filed under its own RFC 7638
    thumbprint, which is how a sealed agent signature names its cert, so a key
    can only ever check the signatures made under it. Mirrors
    ``@agledger/verify``."""
    added = 0
    for row, result in zip(rows, results, strict=False):
        if result.signature != "ok":
            continue
        cose = row.get("cose_sign1")
        predicate = decode_cose_predicate(base64.b64decode(cose)) if isinstance(cose, str) else None
        if predicate is None or predicate.get("entry_type") != _CERT_ISSUED:
            continue
        jwk = as_mapping(predicate.get("payload")).get("publicKeyJwk")
        thumbprint = ed25519_jwk_thumbprint(jwk)
        if thumbprint is None or thumbprint in registry:
            continue
        x = as_mapping(jwk).get("x")
        if not isinstance(x, str):
            continue
        registry[thumbprint] = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        added += 1
    return added


def _verify_vault_checkpoints(
    by_chain: dict[str, list[DumpRow]],
    checkpoints: list[DumpRow],
    keys: KeyCache,
    failures: list[Failure],
) -> None:
    """Cross-check signed checkpoints against the live chain. A checkpoint
    survives audit_vault TRUNCATE, so a chain shorter than (or hash-mismatched
    with) its anchor is evidence of out-of-band tampering."""
    for cp in checkpoints:
        chain_key = _checkpoint_chain_key(cp)
        label = _chain_label(chain_key)
        position = cp.get("chain_position")
        chain = by_chain.get(chain_key, [])
        idx = int(position) - 1 if isinstance(position, int) else -1
        entry = chain[idx] if 0 <= idx < len(chain) else None
        if entry is None:
            failures.append(
                Failure(
                    code="CHECKPOINT_ROW_MISSING",
                    message=(
                        f"{label}: checkpoint at position {position} has no "
                        f"matching audit_vault row (chain length {len(chain)})"
                    ),
                    scope_id=chain_key,
                    position=_as_int(position),
                )
            )
            continue
        if entry.get("payload_hash") != cp.get("payload_hash"):
            failures.append(
                Failure(
                    code="CHECKPOINT_HASH_MISMATCH",
                    message=(
                        f"{label} pos {position}: checkpoint payload_hash does "
                        f"not match audit_vault row"
                    ),
                    scope_id=chain_key,
                    position=_as_int(position),
                )
            )
            continue

        signing_key_id = cp.get("signing_key_id")
        # An unsigned checkpoint is legitimate only from before the install
        # began signing (engine mirror: checkpoint_unsigned).
        if signing_key_id is None and written_while_signing(cp.get("created_at"), keys.signing_since):
            failures.append(
                Failure(
                    code="CHECKPOINT_UNSIGNED",
                    message=(
                        f"{label} pos {position}: checkpoint has no signing_key_id but was "
                        f"written {cp.get('created_at')}, at or after the earliest signing "
                        f"key activation {keys.signing_since}"
                    ),
                    scope_id=chain_key,
                    position=_as_int(position),
                )
            )
            continue
        sig = _checkpoint_signature_outcome(cp.get("cose_sign1"), signing_key_id, keys)
        if sig == "missing-key":
            failures.append(
                Failure(
                    code="CHAIN_SIGNATURE_MISSING_KEY",
                    message=(
                        f"{label} pos {position}: checkpoint signing_key_id "
                        f'"{signing_key_id}" not in dumped key registry'
                    ),
                    scope_id=chain_key,
                    position=_as_int(position),
                    signing_key_id=_as_str(signing_key_id),
                )
            )
        elif sig == "unsupported":
            failures.append(
                Failure(
                    code="CHAIN_UNSUPPORTED_ALGORITHM",
                    message=(
                        f"{label} pos {position}: checkpoint signing key "
                        f"commits to an algorithm this verifier build cannot compute"
                    ),
                    scope_id=chain_key,
                    position=_as_int(position),
                    signing_key_id=_as_str(signing_key_id),
                )
            )
        elif sig == "invalid":
            failures.append(
                Failure(
                    code="CHECKPOINT_SIGNATURE_INVALID",
                    message=(
                        f"{label} pos {position}: checkpoint COSE_Sign1 "
                        f"signature does not verify"
                    ),
                    scope_id=chain_key,
                    position=_as_int(position),
                    signing_key_id=_as_str(signing_key_id),
                )
            )


def verify_vault_chains(
    entries: list[DumpRow],
    checkpoints: list[DumpRow],
    signing_keys: list[DumpRow],
    keys: KeyCache | None = None,
    *,
    agent_keys: Sequence[Mapping[str, Any]] | None = None,
) -> VaultChainsReport:
    """Verify the audit_vault chains + checkpoint cross-check. Pass a prebuilt
    ``keys`` registry to share it (and its lazy key-DER cache) with the
    org-reads pass; otherwise one is built from ``signing_keys``.

    ``agent_keys`` are Ed25519 JWKs of agent certs, as on
    :func:`~agledger.verify.verify_export`; the dump does not carry them. Every
    chain walk re-verifies the sealed agent signatures whose cert thumbprint
    matches one. Anything that is not an Ed25519 JWK raises ``TypeError``."""
    failures: list[Failure] = []
    # Caller keys first, then the cert keys each clean chain signs. A chain can
    # only use keys harvested from chains closed before it; the producer sorts
    # the platform-ops chain (the all-zero record id) first, so on a dump in
    # producer order every record chain sees every cert key. Out of order, a
    # signature simply goes unchecked, never misjudged.
    agent_registry: dict[str, bytes] = (
        dict(build_agent_key_registry(agent_keys)) if agent_keys is not None else {}
    )
    cert_keys_from_chain = 0
    agent_counts = AgentSignatureCounts()
    agent_check: list[CheckApplicability] = ["skipped_no_input"]
    applied: set[str] = set()

    # Empty-vault fail-closed: zero vault entries must NOT verify clean.
    if len(entries) == 0:
        failures.append(
            Failure(
                code="CHAIN_EMPTY",
                message=(
                    "audit_vault contains zero entries: empty or truncated vault, "
                    "refusing to report clean."
                ),
            )
        )
        return VaultChainsReport(0, 0, len(checkpoints), failures)

    # Format gate: format 2.0 requires cose_sign1 on every vault row. A row
    # lacking it is a pre-cutover shape: fail closed rather than parse it.
    pre_cutover = [e for e in entries if not e.get("cose_sign1")]
    if pre_cutover:
        first = pre_cutover[0]
        failures.append(
            Failure(
                code="UNSUPPORTED_FORMAT",
                message=(
                    f"audit_vault row {first.get('id')} lacks cose_sign1: pre-2.0 dump "
                    f"shape. This verifier reads exportFormatVersion 2.0 / RFC8949-CDE; "
                    f"re-export from a current AGLedger instance."
                ),
                scope_id=_as_str(first.get("record_id")),
                position=_as_int(first.get("chain_position")),
            )
        )
        return VaultChainsReport(0, len(entries), len(checkpoints), failures)

    if keys is None:
        keys = _build_vault_key_registry(signing_keys)
    by_chain = _group_by_chain(entries)

    checkpoints_by_chain: dict[str, list[DumpRow]] = {}
    for cp in checkpoints:
        checkpoints_by_chain.setdefault(_checkpoint_chain_key(cp), []).append(cp)

    for chain_key, rows in by_chain.items():
        failures_before = len(failures)
        normalized = [_normalize_entry(e) for e in rows]
        results = _collect_chain_failures(
            chain_key, normalized, keys, failures, agent_registry, agent_counts, agent_check, applied
        )
        _verify_vault_checkpoints(by_chain, checkpoints_by_chain.pop(chain_key, []), keys, failures)
        if len(failures) == failures_before:
            cert_keys_from_chain += _harvest_cert_keys(rows, results, agent_registry)
    # Checkpoints whose chain has no row left at all.
    for orphaned in checkpoints_by_chain.values():
        _verify_vault_checkpoints(by_chain, orphaned, keys, failures)

    return VaultChainsReport(
        record_count=len(by_chain),
        entry_count=len(entries),
        checkpoint_count=len(checkpoints),
        failures=failures,
        agent_signatures_present=agent_counts.present,
        agent_signatures_verified=agent_counts.verified,
        cert_keys_from_chain=cert_keys_from_chain,
        optional_checks=optional_checks_report(
            applied | ({"agent_signature"} if agent_check[0] == "applied" else set())
        ),
    )


def _group_by_org(rows: list[DumpRow]) -> dict[str, list[DumpRow]]:
    by_org: dict[str, list[DumpRow]] = {}
    for r in rows:
        by_org.setdefault(str(r.get("org_id")), []).append(r)
    return by_org


def _detect_checkpoint_forks(checkpoints: list[DumpRow], failures: list[Failure]) -> None:
    by_key: dict[str, DumpRow] = {}
    for cp in checkpoints:
        key = f"{cp.get('org_id')}:{cp.get('tree_size')}"
        prior = by_key.get(key)
        if prior is not None and prior.get("root_hash") != cp.get("root_hash"):
            failures.append(
                Failure(
                    code="TENANT_CHECKPOINT_FORK",
                    message=(
                        f"Org {cp.get('org_id')}: two checkpoints at tree_size "
                        f"{cp.get('tree_size')} carry different root_hash "
                        f"({prior.get('id')} vs {cp.get('id')}): engine fork or key compromise"
                    ),
                    scope_id=_as_str(cp.get("org_id")),
                    tree_size=_as_int(cp.get("tree_size")),
                )
            )
        elif prior is None:
            by_key[key] = cp


@dataclass
class _MustSign:
    """Whether an earlier leaf in this org's log names a real signing key."""

    signed_before: bool = False


def _check_leaf_signature(
    org_id: str,
    leaf: DumpRow,
    envelope: bytes,
    keys: KeyCache,
    must_sign: _MustSign,
) -> Failure | None:
    """Grade one read-log leaf's signature the way the engine does, after its
    index and hash have been checked, or return None when it holds up.

    The leaf has no signing-key column, so the envelope's signature-covered kid
    is the only marker it has. The unsigned sentinel kid is reduced coverage
    only before the install began signing and before any signed leaf in the
    org's log (engine mirror: ``leaf_signature_missing``). Any other kid names
    a key: it must be in the dumped registry and its signature must verify,
    because otherwise a forger could name any kid and skip the unsigned rule.
    ``must_sign.signed_before`` is set by any leaf naming a real key, whatever
    its own verdict, as the engine's walk does. Mirrors ``@agledger/verify``.
    """
    at = f"Org {org_id} leaf {leaf.get('leaf_index')}"
    leaf_index = _as_int(leaf.get("leaf_index"))
    kid = decode_cose_kid(envelope)
    if kid is None:
        what = (
            "carries no kid"
            if decode_cose_parts(envelope) is not None
            else "does not decode as a COSE_Sign1 envelope"
        )
        return Failure(
            code="TENANT_READ_SIGNATURE_INVALID",
            message=f"{at}: cose_sign1 {what}, so no signature can be attributed to it",
            scope_id=org_id,
            leaf_index=leaf_index,
        )
    if kid == UNSIGNED_KID_SENTINEL:
        why: str | None = None
        if must_sign.signed_before:
            why = "follows a signed leaf in the same org log"
        elif written_while_signing(leaf.get("read_at"), keys.signing_since):
            why = (
                f"was written {leaf.get('read_at')}, at or after the earliest signing key "
                f"activation {keys.signing_since}"
            )
        if why is None:
            return None
        return Failure(
            code="TENANT_READ_LEAF_UNSIGNED",
            message=f"{at}: leaf is unsigned (kid {UNSIGNED_KID_SENTINEL}) but {why}",
            scope_id=org_id,
            leaf_index=leaf_index,
        )
    must_sign.signed_before = True
    key = keys.entry(kid)
    if key is None:
        return Failure(
            code="CHAIN_SIGNATURE_MISSING_KEY",
            message=f'{at}: leaf kid "{kid}" not in dumped key registry',
            scope_id=org_id,
            leaf_index=leaf_index,
            signing_key_id=kid,
        )
    # Fail closed on ANY non-ok outcome; an all-zero signature under a real kid
    # is a wiped signature, as the engine grades it.
    outcome = verify_cose_sign1(envelope, key)
    if outcome == "ok":
        return None
    if outcome == "unsupported-key-algorithm":
        return Failure(
            code="CHAIN_UNSUPPORTED_ALGORITHM",
            message=(
                f"{at}: this leaf's signature could NOT BE CHECKED. "
                f"{describe_unsupported_algorithm(kid, key.spki_base64)}"
            ),
            scope_id=org_id,
            leaf_index=leaf_index,
            signing_key_id=kid,
        )
    return Failure(
        code="TENANT_READ_SIGNATURE_INVALID",
        message=f"{at}: COSE_Sign1 signature does not verify ({outcome})",
        scope_id=org_id,
        leaf_index=leaf_index,
        signing_key_id=kid,
    )


def _verify_one_org_admin_reads_log(
    org_id: str,
    leaves: list[DumpRow],
    checkpoints: list[DumpRow],
    keys: KeyCache,
    failures: list[Failure],
) -> None:
    leaves.sort(key=lambda r: r.get("leaf_index", 0))
    must_sign = _MustSign()

    for i, leaf in enumerate(leaves):
        if leaf.get("leaf_index") != i:
            failures.append(
                Failure(
                    code="TENANT_READ_LEAF_INDEX_GAP",
                    message=(
                        f"Org {org_id}: expected leaf_index {i}, got "
                        f"{leaf.get('leaf_index')} (id {leaf.get('id')})"
                    ),
                    scope_id=org_id,
                    leaf_index=_as_int(leaf.get("leaf_index")),
                )
            )
            return  # a gap stops the whole org: the log is incomplete
        # leaf_hash is sha256(cose_sign1) post-cutover.
        envelope = base64.b64decode(str(leaf.get("cose_sign1")))
        recomputed = hashlib.sha256(envelope).hexdigest()
        if recomputed != leaf.get("leaf_hash"):
            failures.append(
                Failure(
                    code="TENANT_READ_LEAF_HASH_MISMATCH",
                    message=(
                        f"Org {org_id} leaf {leaf.get('leaf_index')}: sha256(cose_sign1) "
                        f"does not match stored leaf_hash"
                    ),
                    scope_id=org_id,
                    leaf_index=_as_int(leaf.get("leaf_index")),
                )
            )
            return  # a tampered leaf stops the whole org
        leaf_failure = _check_leaf_signature(org_id, leaf, envelope, keys, must_sign)
        if leaf_failure is not None:
            failures.append(leaf_failure)
            return  # one finding per org, the first met in leaf order

    leaf_hashes = [str(leaf.get("leaf_hash")) for leaf in leaves]

    for cp in checkpoints:
        tree_size = cp.get("tree_size")
        if not isinstance(tree_size, int) or tree_size > len(leaf_hashes):
            failures.append(
                Failure(
                    code="TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH",
                    message=(
                        f"Org {org_id}: checkpoint {cp.get('id')} signs tree_size "
                        f"{tree_size} but dump contains only {len(leaf_hashes)} leaves"
                    ),
                    scope_id=org_id,
                    tree_size=_as_int(tree_size),
                )
            )
            continue
        root = merkle_root(leaf_hashes[:tree_size])
        if root != cp.get("root_hash"):
            failures.append(
                Failure(
                    code="TENANT_CHECKPOINT_ROOT_MISMATCH",
                    message=(
                        f"Org {org_id}: checkpoint {cp.get('id')} root_hash "
                        f"{str(cp.get('root_hash'))[:16]} does not match recomputed root "
                        f"{root[:16]}"
                    ),
                    scope_id=org_id,
                    tree_size=tree_size,
                )
            )
            continue

        signing_key_id = cp.get("signing_key_id")
        if signing_key_id is None and written_while_signing(cp.get("checkpoint_at"), keys.signing_since):
            failures.append(
                Failure(
                    code="TENANT_CHECKPOINT_UNSIGNED",
                    message=(
                        f"Org {org_id}: checkpoint {cp.get('id')} has no signing_key_id but was "
                        f"written {cp.get('checkpoint_at')}, at or after the earliest signing "
                        f"key activation {keys.signing_since}"
                    ),
                    scope_id=org_id,
                    tree_size=tree_size,
                )
            )
            continue
        sig = _checkpoint_signature_outcome(cp.get("cose_sign1"), signing_key_id, keys)
        if sig == "missing-key":
            failures.append(
                Failure(
                    code="CHAIN_SIGNATURE_MISSING_KEY",
                    message=(
                        f"Org {org_id}: checkpoint {cp.get('id')} signing_key_id "
                        f'"{signing_key_id}" not in dumped key registry'
                    ),
                    scope_id=org_id,
                    tree_size=tree_size,
                    signing_key_id=_as_str(signing_key_id),
                )
            )
        elif sig == "unsupported":
            failures.append(
                Failure(
                    code="CHAIN_UNSUPPORTED_ALGORITHM",
                    message=(
                        f"Org {org_id}: checkpoint {cp.get('id')} signing key commits "
                        f"to an algorithm this verifier build cannot compute"
                    ),
                    scope_id=org_id,
                    tree_size=tree_size,
                    signing_key_id=_as_str(signing_key_id),
                )
            )
        elif sig == "invalid":
            failures.append(
                Failure(
                    code="TENANT_CHECKPOINT_SIGNATURE_INVALID",
                    message=(
                        f"Org {org_id}: checkpoint {cp.get('id')} COSE_Sign1 "
                        f"signature does not verify"
                    ),
                    scope_id=org_id,
                    tree_size=tree_size,
                    signing_key_id=_as_str(signing_key_id),
                )
            )


def verify_org_admin_reads_chains(
    reads: list[DumpRow],
    checkpoints: list[DumpRow],
    signing_keys: list[DumpRow],
    keys: KeyCache | None = None,
) -> TenantAdminReadsReport:
    """Verify the org_admin_reads Merkle log + signed tree heads. Pass a prebuilt
    ``keys`` registry to share it with the vault pass; otherwise one is built
    from ``signing_keys``."""
    failures: list[Failure] = []
    if keys is None:
        keys = _build_vault_key_registry(signing_keys)
    leaves_by_org = _group_by_org(reads)
    checkpoints_by_org = _group_by_org(checkpoints)

    _detect_checkpoint_forks(checkpoints, failures)

    # Walk every org with leaves OR checkpoints: a checkpoint over an empty
    # leaf set would otherwise slip through silently.
    org_ids = set(leaves_by_org) | set(checkpoints_by_org)
    for org_id in org_ids:
        _verify_one_org_admin_reads_log(
            org_id,
            leaves_by_org.get(org_id, []),
            checkpoints_by_org.get(org_id, []),
            keys,
            failures,
        )

    # Witness cosignatures are reported, not verified: the engine cannot verify
    # customer-chosen witness keys because their algorithm is untyped.
    witness_cosigned = [
        WitnessCosignedCheckpoint(
            checkpoint_id=str(cp.get("id")), witness_key_id=str(cp.get("witness_key_id"))
        )
        for cp in checkpoints
        if cp.get("witness_signature") is not None and cp.get("witness_key_id") is not None
    ]

    return TenantAdminReadsReport(
        org_count=len(org_ids),
        leaf_count=len(reads),
        checkpoint_count=len(checkpoints),
        witness_cosigned_checkpoints=witness_cosigned,
        failures=failures,
    )


def verify_dump(dump: Dump, *, agent_keys: Sequence[Mapping[str, Any]] | None = None) -> VerifyReport:
    """Verify a full-vault dump. Runs the vault-chain pass and the
    org_admin_reads pass independently and ANDs their verdicts.

    ``agent_keys``: Ed25519 JWKs of agent certs. Where an entry's signed
    payload carries an engine-validated agent signature whose cert thumbprint
    matches one, it is re-verified offline in every chain walk; one that does
    not verify fails ``CHAIN_AGENT_SIGNATURE_INVALID``. Without them the check
    reports ``skipped_no_input`` and no verdict changes."""
    # Build the signing-key registry once and share it across both passes; they
    # draw from the same keys, so this also shares the lazy key-DER cache.
    keys = _build_vault_key_registry(dump.signing_keys)
    vault = verify_vault_chains(
        dump.vault_entries, dump.vault_checkpoints, dump.signing_keys, keys, agent_keys=agent_keys
    )
    org_admin_reads = verify_org_admin_reads_chains(
        dump.org_admin_reads, dump.org_admin_reads_checkpoints, dump.signing_keys, keys
    )
    return VerifyReport(
        ok=len(vault.failures) == 0 and len(org_admin_reads.failures) == 0,
        vault=vault,
        org_admin_reads=org_admin_reads,
    )
