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
# merkle_root / verify_cose_sign1 primitives. Reused here verbatim — the dump
# verifier adds only the dump-structural passes the per-entry walk does not model.
from agledger.verify.verify_export import (
    KeyCache,
    RegisteredKey,
    as_mapping,
    verify_entry,
    merkle_root,
    verify_cose_sign1,
)


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
    return KeyCache(registry)


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
    # ?? '__platform__' — only None/undefined becomes platform; "" is kept.
    return f"schema:{org_id if org_id is not None else '__platform__'}"


def _checkpoint_chain_key(cp: DumpRow) -> str:
    """Group identity for a checkpoint, which is NOT always its record_id.

    A schema chain's checkpoint carries a derived UUIDv8 in record_id (the
    engine needs a non-null uuid for a chain whose rows have none), so joining
    on that column strands the checkpoint and reports CHECKPOINT_ROW_MISSING
    against a healthy vault. Join on the producer's chain_key; fall back to
    record_id for older dumps, which is correct for every chain except schema
    chains (agents#103).
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
    id, so "RecordRow <uuid>" is actionable; a schema key is not, and labelling
    it that way sent auditors to /v1/records/{id} for a 404 (agents#103).
    """
    return f"Chain {chain_key}" if chain_key.startswith("schema:") else f"RecordRow {chain_key}"


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
    }


def _collect_chain_failures(scope_id: str, normalized: list[dict[str, Any]], keys: KeyCache,
                            failures: list[Failure]) -> None:
    """Walk one chain group via the shared per-entry body and flatten any invalid
    entry into a Failure. The dump passes NO key-policy options (all dump keys
    are embedded). previousHash advances even on a failed entry, matching the
    export walk and verify-core."""
    prev_payload_hash: str | None = None
    for i, entry in enumerate(normalized):
        result = verify_entry(entry, i + 1, prev_payload_hash, keys, None, False)
        if not result.valid and result.code is not None:
            failures.append(
                Failure(
                    code=result.code,
                    message=f"RecordRow {scope_id} pos {result.position}: {result.detail}",
                    scope_id=scope_id,
                    position=result.position,
                )
            )
        prev_payload_hash = as_mapping(entry.get("integrity")).get("payloadHash")


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
) -> VaultChainsReport:
    """Verify the audit_vault chains + checkpoint cross-check. Pass a prebuilt
    ``keys`` registry to share it (and its lazy key-DER cache) with the
    org-reads pass; otherwise one is built from ``signing_keys``."""
    failures: list[Failure] = []

    # Empty-vault fail-closed: zero vault entries must NOT verify clean.
    if len(entries) == 0:
        failures.append(
            Failure(
                code="CHAIN_EMPTY",
                message=(
                    "audit_vault contains zero entries — empty or truncated vault, "
                    "refusing to report clean."
                ),
            )
        )
        return VaultChainsReport(0, 0, len(checkpoints), failures)

    # Format gate: format 2.0 requires cose_sign1 on every vault row. A row
    # lacking it is a pre-cutover shape — fail closed rather than parse it.
    pre_cutover = [e for e in entries if not e.get("cose_sign1")]
    if pre_cutover:
        first = pre_cutover[0]
        failures.append(
            Failure(
                code="UNSUPPORTED_FORMAT",
                message=(
                    f"audit_vault row {first.get('id')} lacks cose_sign1 — pre-2.0 dump "
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

    for chain_key, rows in by_chain.items():
        normalized = [_normalize_entry(e) for e in rows]
        _collect_chain_failures(chain_key, normalized, keys, failures)
    _verify_vault_checkpoints(by_chain, checkpoints, keys, failures)

    return VaultChainsReport(
        record_count=len(by_chain),
        entry_count=len(entries),
        checkpoint_count=len(checkpoints),
        failures=failures,
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
                        f"({prior.get('id')} vs {cp.get('id')}) — engine fork or key compromise"
                    ),
                    scope_id=_as_str(cp.get("org_id")),
                    tree_size=_as_int(cp.get("tree_size")),
                )
            )
        elif prior is None:
            by_key[key] = cp


def _verify_one_org_admin_reads_log(
    org_id: str,
    leaves: list[DumpRow],
    checkpoints: list[DumpRow],
    keys: KeyCache,
    failures: list[Failure],
) -> None:
    leaves.sort(key=lambda r: r.get("leaf_index", 0))

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
            return  # a gap stops the whole org — the log is incomplete
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

    # Walk every org with leaves OR checkpoints — a checkpoint over an empty
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

    # Witness cosignatures are reported, not verified — the engine cannot verify
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


def verify_dump(dump: Dump) -> VerifyReport:
    """Verify a full-vault dump. Runs the vault-chain pass and the
    org_admin_reads pass independently and ANDs their verdicts."""
    # Build the signing-key registry once and share it across both passes — they
    # draw from the same keys, so this also shares the lazy key-DER cache.
    keys = _build_vault_key_registry(dump.signing_keys)
    vault = verify_vault_chains(
        dump.vault_entries, dump.vault_checkpoints, dump.signing_keys, keys
    )
    org_admin_reads = verify_org_admin_reads_chains(
        dump.org_admin_reads, dump.org_admin_reads_checkpoints, dump.signing_keys, keys
    )
    return VerifyReport(
        ok=len(vault.failures) == 0 and len(org_admin_reads.failures) == 0,
        vault=vault,
        org_admin_reads=org_admin_reads,
    )
