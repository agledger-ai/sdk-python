# Changelog

All notable changes to the AGLedger Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.1.0] - 2026-10-22

### Added

- **Every field of an error body is on the error.** `APIError` and its subclasses carry the whole served `ErrorResponse`: the 400 fields (`required_fields`, `optional_fields`, `example_payload`, `schema_url`, `record_type`, `validation_errors`), the 404 `hint`, the 422 `attempted_action` / `attempted_transition` / `attempted_state`, `title`, `instance`, `allowed_values`, `allowed_actors`, `constraint_violations`, the license tier fields, `next_steps`, and `body`, the parsed body itself.
- **`retry_after` on every API error.** The client waits it out on any status that sends `Retry-After`, not only 429.
- **`a2a.cancel_task()`** for the `CancelTask` call. `reason` is sent in `metadata["agledger:reason"]` and recorded as the record's `lastTransitionReason`.
- **`federation_keys=` on `verify_export` and `verify_dump`, and `--federation-key <hubId>=<key>` on `agledger-verify`.** Sealed peer messages are checked against their body hash and entry, and re-verified under the hub's key when one is given. Reports count them under `federation_wire` (`present`, `verified`, `failed`); a failure is `CHAIN_FEDERATION_WIRE_INVALID`. `agledger.verify.canonicalize_json` is the RFC 8785 canonical form used for the body hash. After a peer changes its federation key, give a list entry `history` (the peer's `discovery.get_federation_keys()`, or `--federation-key-history <file>`) beside the key you pinned: every key the history links to it through successions both keys signed is trusted inside its window, and `federation_wire.after_retirement` counts messages under a key the peer had retired before the receiver took them. A hub may be named twice.
- **`schemas.import_()` takes a `get_manifest()` response whole** and sends its `manifestDigest`; the Server refuses the import with 400, writing nothing, when the manifest does not hash to it. `manifest_digest=` sets the digest by hand. A bare manifest imports as before. Sending a digest needs an AGLedger Server 2.2 or later.
- **`discovery.get_federation_keys()`** reads `GET /.well-known/agledger-federation-keys.json` (no auth): every federation signing key the Server has held, with its validity window, and the signed statements linking them. Needs a Server 2.2 or later.
- **`inapplicable_fields`** on `APIError`: the fields a 422 `notarize_only_field` refused on a notarize-only create.
- `FederationPeer.signing_public_key`, the peer's federation key this Server holds.
- **`agledger-verify --version`** (`-V`) prints the verifier's version and exits 0, so an audit record can name the verifier that produced it.
- Types for newly served fields: the per-item fields and `error_code` on `BulkCreateResultItem`, `BulkCreateSummary.replayed`, `ComplianceExport.bulk_export`, `connections_overcommitted` on `StatusComponentReason`, and `standing` on each key-registry finding.

### Fixed

- **`raw_body` on a JSON route's error when the body is not a JSON object.** The response bytes are on `raw_body` and `body` is empty. A JSON error body that is an array no longer raises `AttributeError`.

### Changed

- The `reason` doc on errors lists the thirteen 409 reason codes the Server can send and notes that a 409 does not always carry one.
- The README states that the package needs an AGLedger Server 2.0 or later and names the last release for a 1.x Server.

## [3.0.0] - 2026-10-05

Targets AGLedger API 2.0 only; 1.x wire shapes are not supported. Breaking changes are under Removed and Changed.

### Removed

- **`offset` on keyset listings.** API 2.0 refuses `?offset=` on cursor-paged listings, so the parameter is removed from `records.list()`, `records.search()`, `events.list()`, `events.list_all()`, `admin.list_api_keys()`, `admin.list_all_api_keys()`, `drift.get_agent_history()` and `audit.org_reads_checkpoints.list()`, sync and async. Page with `cursor`. `RecordRowCompactPage.offset` is removed too. `records.get_sub_records()` and `audit.org_reads_checkpoints.list_reads()` keep `offset`.
- **`APIError.doc_url` and `APIError.docs`, and `PermissionDeniedError.key_scopes`.** API 2.0 error bodies do not carry them. `missing_scopes` is read from the body's top-level `missingScopes`.
- **`-q` / `--quiet` on `agledger-verify`.** It is refused with `Unknown flag: --quiet` and exit `2`. Read the exit code and discard stdout instead.
- **`WebhookTestResult.http_status` and `.latency_ms`.** Read `status_code` and `duration_ms`.
- **`reason=` on `federation.relay_signal()`.** The 2.0 signal body does not accept it.
- **`record.settled`, `record.proposal_counter_proposed` and `dispute.escalated` from `EventType`, and `escalated` from `DisputeProtocolAction`.** The Server refuses them. Use `record.fulfilled` or `signal.emitted` instead.

### Changed

- **The org_admin_reads tree is RFC 9162.** `verify_dump` recomputes leaf hashes and tree-head roots as the RFC 9162 section 2.1 SHA-256 tree. New primitives: `org_read_leaf_hash(cose_sign1)`, `org_read_merkle_root(leaf_hashes)` and `verify_org_read_inclusion(leaf_hash, leaf_index, tree_size, path, root)`. The old `merkle_root` is removed. A value that is not 64 lowercase hex characters is refused.
- **"Out-of-band" keys are now "supplied" keys**, as in `@agledger/verify-core` 2.0. `verify_export(require_out_of_band_keys=)` is `require_supplied_keys=`, `KeySource` `"out-of-band"` is `"supplied"`, `KeyProvenance.out_of_band` is `KeyProvenance.supplied`, the CLI's `--require-out-of-band-keys` is `--require-supplied-keys` (and its JSON `keyProvenance.outOfBand` is `supplied`), and `agledger.verify.cli.load_out_of_band_keys` is `load_supplied_keys`. Behavior is unchanged. Trust now comes from the new `trust_anchors`.
- **Results carry the key-trust walk.** `VerifyExportResult` has `key_trust` (a `KeyTrustReport`), `optional_checks` gains `key_anchoring`, and `VerifyReport` gains `verdict` (`"trusted"`, `"unanchored"` or `"failed"`) and `key_trust`. Without trust anchors a passing result stays `valid` / `ok` but is flagged: `key_trust.status` is `"no_anchor"` and the CLI prints `[VERIFIED, NOT ANCHORED]`. A trusted pass is `[PASS]` and a failure `[FAIL]`.
- **A dump is six files.** `load_dump` also reads `vault_key_statements.ndjson` into `Dump.key_statements`; a directory without it raises `DumpLoadError`.
- **`verify_dump` walks the vault in producer order.** A chain whose rows reappear after it closed, or a row without `cose_sign1`, fails with `UNSUPPORTED_FORMAT`.
- A vault checkpoint, read-log leaf or tree head whose `cose_sign1` is null or not base64 fails its claim or leaf-hash check rather than raising.
- `exportMetadata.signingKeyStatements` that is not an object keyed by key id raises `TypeError`.
- An entry that fails `CHAIN_AGENT_SIGNATURE_INVALID` no longer counts toward `key_provenance`.
- **`Completion.agent_id` is `str | None`.** It is None on the completion synthesized for a delegation parent from its children's failure rollup, which carries `rollup_synthesized=True`. A principal cannot accept that completion; reject it, then revise and resubmit.
- **`webhooks.delete()` returns the Server's answer** (`{webhookId, isActive: false, deadLetters, nextSteps}`) instead of None. Dead-lettered deliveries stay in the DLQ until discarded with the new `discard_dlq()`.
- **`admin.create_api_key()` pairs each role with its owner kind**: `admin` with `org`, `agent` with `agent`, `platform` with `platform`. A mismatched literal pair is a type error.
- **`KeyStatement` requires `id` and `created_at`** on `VerificationKey.statements` and `exportMetadata.signingKeyStatements`.
- `StatusComponent.reason` names `database_unavailable`, `signing_key_unusable`, `no_worker_connected`, `worker_not_consuming` and `not_checked`. `schemas.register()` answers 200 with the latest version when the body repeats it.
- **A signed-kid mismatch is reported before an algorithm mismatch.** An entry whose `signingKeyId` field disagrees with its signed kid now reports `CHAIN_SIGNING_KEY_DRIFT` rather than `CHAIN_ALG_MISMATCH`.
- **A dump's vault checkpoints, read-log leaves and read-log tree heads are checked against the claim they sign**, failing `CHECKPOINT_CLAIM_MISMATCH`, `TENANT_READ_CLAIM_MISMATCH` or `TENANT_CHECKPOINT_CLAIM_MISMATCH`. A leaf whose bytes are not an envelope is `TENANT_READ_CLAIM_MISMATCH` (was `TENANT_READ_SIGNATURE_INVALID`).
- **An API error is built from `detail`.** `str(error)` and the new `error.detail` are the body's `detail`; `code` is the body's `error`. The constructor takes `detail=` where it took `message=`.
- **Federation requests carry what API 2.0 requires.** `relay_signal()` requires `schema_ref`, `outcome`, `reason_code` and `failing_rule_ids` (the last three nullable). `submit_state_transition()` requires `schema_ref`, `principal_agent_id`, `performer_agent_id` and `operating_mode`, and takes `platform_ref`, `risk_classification` and `eu_ai_act_domain`. `submit_co_sign_request()` and `submit_dispute_protocol()` take typed keyword arguments instead of `**params`, with `schema_ref` required; the dispute `action` is `DisputeProtocolAction` and there is no `tier`.
- **`admin.vault.anchors.list()` requires `record_id`.**
- **`events.list()` returns `EventPage`**, a `Page[Event]` that adds `visible_before`: pass it as the next window's `since`.
- `Completion.verdict` is the auto gate's verdict in the Record's vocabulary (`accept` / `reject`).
- **`federation_admin.create_peering_token()` requires `peer_hub_id` and `bound_org_id`**, and `label` is optional.
- **`federation.peer_handshake()` no longer takes `bound_org_id`**; the org comes from the token. A bad token is a 401 (was 422), and a `peer_hub_id` other than the one the token was minted for is a 422 and leaves the token unconsumed.
- **The OIDC credential's `agent_id` is an assertion.** A body `agentId` that differs from the agent the token binds, or one sent with a token that binds no agent, is refused with 403 `CERT_AGENT_BINDING_MISMATCH`.
- **Scope profiles follow the Server's:** `agent-full` and `admin-standard` gain `disputes:write`, and `admin-iac` gains `schemas:read`.
- **An all-zero signature on an entry that names a key fails `CHAIN_SIGNATURE_INVALID`**, with or without a key policy.
- **Supplied keys passed as a list carry their `activatedAt` / `retiredAt`**, which take precedence over the export's window for that key. Key-window times compare at millisecond resolution, and a time without an offset reads as UTC.
- **Four request parameters take a closed enum instead of `str`**, sync and async: `webhooks.create(signing_alg=)` takes `WebhookSigningAlg` (`hmac`, `ed25519`, `ecdsa-p256-sha256`), `federation.relay_signal(recommendation=)` takes `FederationSettlementSignal`, its `outcome=` takes `FederationVerdict`, and `schemas.update_version()` takes a `SchemaVersionUpdate` (`{"compatibilityMode": ...}`). A variable typed `str` needs a narrower type or a cast under a strict type checker.
- `AuditChainIntegrityReasonCode` names `signature_missing` and `checkpoint_unsigned`, and `AuditChainFailureCode` names `signature_missing`.
- `relay_signal()` documents that a receiver requiring co-sign refuses a signal without `counter_signature` with 422 `co_sign_required`. `SettlementSignalSummary.reason` is None on an inbound signal.

### Added

- **`VerifyExportResult.verdict`**: `"trusted"`, `"unanchored"` or `"failed"`, as in `@agledger/verify-core` 2.0.0. A valid result with no `trust_anchors`, or none that anchored a signature, is `"unanchored"`. Read `verdict`, not `valid` alone.
- **A pinned key that is also distrusted with no instant is refused.** `verify_export` and `verify_dump` raise `TypeError`, and `agledger-verify` exits `2`. A pin beside a dated distrust entry (`sha256:<hex>@<instant>`) is accepted. `assert_not_pinned_and_distrusted` applies the check for other callers.
- **Writes by a distrusted key are accounted for.** The walk gives each distrusted key a `DistrustSpan` (`KeyTrust.distrust_spans`). What the key signed before its trusted retirement is listed rather than failed: statements in `key_trust.accounted`, chain entries in `vault.accounted` as an `AccountedEntry` (`code` `CHAIN_SIGNED_BY_DISTRUSTED_KEY`, with signature state `accounted`). `-f json` gives `vault.accounted` and `vault.accountedCount`. What the key signed after that retirement still fails, and a distrusted key in the registry that no trusted key has retired is `KEY_CLOSURE_INVALID`.
- **`distrustedFrom` on distrusted keys.** It is read into `TrustKeyInput.distrusted_from` and `KeyRegistryFinding.distrusted_from` and used to word findings about a key window; it never clears a finding. An entry at an earlier instant than the Server's is noted in `key_trust.notes`.
- **`agledger-verify` names flags in its reports.** Advice and details read `--distrusted-key`, `--trust-anchor`, `--require-key-id`, `--require-supplied-keys` and `--agent-keys` in text and `-f json` output.
- `KEY_STATEMENT_INVALID` and `KEY_CLOSURE_INVALID` are reported for untrusted endorsers and for closures by a key that is reached but not anchored.
- **`unsigned_projection_fields` on `VerifyExportResult`**, the export's `verificationGuide.unsignedFields`. `agledger-verify -f json` prints `unsignedProjectionFields`, and the text report notes that those display fields are not signature-covered.
- **`verify_dump_dir(path, ...)`** loads and verifies a dump directory.
- `public_keys` also takes the `/v1/verification-keys` body as served (`{"data": [...]}`) and the `VerificationKeysResponse` returned by `client.verification_keys.list()`.
- `agledger-verify -f json` lists `entries` on an `/audit-export` file and `failureCount` on each dump section; a dump's `failures` are capped at 1000 in JSON.
- The `toggle_api_key` and `update_api_key` docstrings say revocation is one-way for an admin key: re-enabling a revoked key is a 403 `PLATFORM_REQUIRED` unless a platform credential sends it.
- **`webhooks.discard_dlq(webhook_id, dlq_id)` and `admin.discard_dlq(dlq_id)`**, sync and async: drop a dead-lettered delivery without delivering it. The event itself is kept.
- **`KeyOwnerType`**, the `Literal` of API-key owner kinds.
- **Key anchoring (`trust_anchors`).** `verify_export` and `verify_dump` take `trust_anchors` (`sha256:<hex>` SPKI digests, a list or a comma list) and trust a vault key only when signed key statements link it to a pinned key. Statements come from an export's `exportMetadata.signingKeyStatements`, any `statements` on supplied keys, and a dump's `vault_key_statements.ndjson`. An entry signed by a key that is not anchored fails `CHAIN_SIGNING_KEY_UNANCHORED`; on a dump, a checkpoint, read-log leaf or tree head fails `CHECKPOINT_KEY_UNANCHORED`, `TENANT_READ_KEY_UNANCHORED` or `TENANT_CHECKPOINT_KEY_UNANCHORED`. Each anchored key is held to the window its statements sign. Timestamps must be strict RFC 3339; an entry `createdAt` that is not fails `CHAIN_MALFORMED_ENTRY`, and a malformed key window passed in `public_keys` raises `TypeError`. With trust anchors, unsigned entries are held to the earliest signed key activation, so stripping unsigned window data cannot switch `CHAIN_ENTRY_UNSIGNED` (or the checkpoint and tree-head equivalents) off.
- **`distrusted_keys`**, the verifier-side mirror of the Server's `VAULT_DISTRUSTED_KEYS` (`sha256:<hex>`, optionally `@<RFC 3339 instant>`): what such a key stored from the instant on counts for nothing. A note in `key_trust.notes` (`KeyTrustNote`) is added where a distrusted key's statement is voided but dated before the cutoff, and the `agledger-verify` text report lists each note. `verify_dump` refuses it without `trust_anchors`.
- **Registry findings** from the walk, in `key_trust.findings`, which fail the result: `KEY_STATEMENT_INVALID`, `KEY_CLOSURE_INVALID` and `CHAIN_KEY_WINDOW_DRIFT`.
- **Walk primitives**, exported from `agledger.verify`: `compute_key_trust`, `parse_trust_anchors`, `parse_distrusted_keys`, `spki_sha256`, `instant_ms`, `KEY_STATEMENT_CTY`, the adapters `key_statement_from_dump_row`, `trust_key_from_dump_row`, `key_statements_from_export` and `key_statements_from_verification_keys`, and the types `KeyStatementInput`, `TrustKeyInput`, `DistrustedKey`, `KeyTrust`, `KeyTrustEntry`, `KeyTrustReport`, `KeyRegistryFinding`, `KeyTrustState` and `Verdict`.
- **`--trust-anchor` and `--distrusted-key` on `agledger-verify`**, each given once per key, for a dump directory and an `/audit-export` file. Malformed entries, a distrusted key named twice, `--distrusted-key` without `--trust-anchor`, and a missing target are refused with exit `2`. `--distrusted-keys` and `--require-out-of-band-keys` are refused naming the flag that replaced them, and a flag prefix is no longer accepted as that flag.
- **`agledger-verify` parses its command line like `@agledger/verify`**: the same flags, messages and exit codes. An unknown flag, a flag missing its value, a second or missing target, and a file that is not an `/audit-export` document print the message and the help text and exit `2`; a key-policy flag on a dump directory is refused; and `--help` prints the same help text as `@agledger/verify`.
- The failure taxonomy matches verify-core 2.0, including `CHECKPOINT_UNSIGNED`, `TENANT_READ_LEAF_UNSIGNED` and `TENANT_CHECKPOINT_UNSIGNED`.
- **Signed key statements.** `VerificationKey.statements` lists the `KeyStatement`s (`kind`, `cose`) that admit a key, and `VerificationKeysResponse` carries `anchored_from` and `key_statement_format`. `AuditExportMetadata` carries `signing_key_statements` and `anchored_from`.
- **Unanchored-key codes.** `AuditChainIntegrityReasonCode` names `signing_key_unanchored` and `checkpoint_key_unanchored`, `AuditChainFailureCode` and `VaultScanBreakReason` name `signing_key_unanchored` (the scan also `checkpoint_key_unanchored`), and `OrgReadsBreakReason` names `leaf_key_unanchored` and `checkpoint_key_unanchored`. The vault scan result carries the key-trust walk as `keyRegistry` (`VaultScanKeyRegistry`, `VaultScanKeyRegistryFinding`).
- `LicenseValidity` names `marketplace_refused`, and `AcceptanceStatus` names `BYPASSED`.
- `StatusComponent.reason` (why a component is not operational, including `chain_rewind_detected`), `VerdictResult.reporter_role` (`principal` or `org-admin`), `BulkCreateResultItem.constraint_violations`, and `PeerHandshakeResult.server_hub_id`.
- Docs for `admin.vault.signing_keys.retire()` (forced-retirement fields `alreadyRetired`, `unanchoredKeyIds`, `closureDigest`, `retiredSpkiSha256`), `auth.rotate_key()` (the new key's `keyId` and `scopeProfile`), `auth.issue_ephemeral_cert()` (`agent_id` is an assertion) and `admin.records.import_()` (each entry's `advisoryWarnings`).
- **Distrusted keys and key material.** `AuditChainIntegrityReasonCode` names `signing_key_distrusted` and `signing_key_material_invalid`; `AuditChainFailureCode`, `VaultScanBreakReason` and `VaultScanFirstFindingReason` name `signing_key_distrusted`. `VaultScanResult` carries `distrustedSigned`, `distrustedEntries` (`VaultScanDistrustedEntry`) and `distrustedEntriesTotal`, `VaultScanGlobalChains` carries `distrustedSigned`, and `VaultScanKeyRegistry` carries `distrustedStatements`. None of them fails `healthy`.
- **`VaultScanJob.waitingOn`** (`VaultScanWaitingOn`, reason `VaultScanWaitingReason`): why a scan that has not started is waiting.
- `StatusComponent.reason` names `privilege_missing` and `worker_stalled`.
- **The lifecycle table matches `GET /lifecycle`.** `RECORD_TRANSITIONS` gains the dispute edges, the deadline edges and the rollup edges to ACTIVE, and drops FAILED to REMEDIATED, PROCESSING to REVISION_REQUESTED and PROCESSING to DISPUTED. `TERMINAL_STATUSES` and `is_terminal_status` follow the Server's terminal flag. `records.get_valid_transitions(record)` returns the Record's own `valid_transitions` when present.
- `schemas.check_compatibility()` takes `publisher=`. `records.submit_verdict()` takes `message=`, a third alias of `notes`. `BulkCreateResultItem.allowed_values`, and `APIError.valid_transitions` (the targets reachable now, from a 422 refusal).
- **`completions.list()` and `completions.list_all()` take `structural_validation`** (`"ACCEPTED"` or `"INVALID"`), sync and async.
- **`view="compact"` on `records.get()`, `records.list()`, `records.list_all()` and `records.search()`**, sync and async. The compact view leaves out null top-level fields and trims each `nextSteps` entry to `action`, `method` and `href`. It returns `RecordRowCompact` (single read) or `RecordRowCompactPage` (list and search). `RecordView` (`full`, `compact`) moves to `agledger.types` and is exported from the package root.
- **`APIError.reason`, `current_state`, `allowed_actions` and `existing_id`**, taken from the error body. `existing_id` names the row a 409 `TRUSTED_ISSUER_EXISTS` collided with.
- **`ComplianceExport.format`**: the format an export was created in.
- **`admin.vault.scan.status()` returns `VaultScanJob`, and `admin.trusted_issuers.get()`, `create()` and `update()` return `TrustedIssuer`**, sync and async. Both are `TypedDict`s keyed by the wire names, so existing subscripting still works. Break reasons use `VaultScanBreakReason`, `VaultScanFirstFindingReason` and `OrgReadsBreakReason`, and the job `state` is `VaultScanState`. An issuer's `allowedAlgs` is the closed `TrustedIssuerAlg`, which `create(allowed_algs=)` takes along with `applies_to: TrustedIssuerAppliesTo` and `auto_provision_scope_profile: AutoProvisionScopeProfile`. `TrustedIssuer` also carries `jwksLastFetchAt`, `jwksLastFetchOutcome`, `jwksLastFetchError` and `jwksLastSuccessAt`. Code passing one of these results where `dict[str, Any]` is declared needs a `Mapping[str, object]` or a cast under a strict checker.
- **`RecordFederationStatus`** names `RecordRow.federation_status` (`pending`, `delivered`, `partial`, `failed`, `inbound`).
- **Twelve more enums are named and exported**: `ComplianceRecordType`, `DisputeGrounds`, `EvidenceType`, `SchemaCompatibilityMode`, `SchemaVersionStatus`, `SettlementSignal` and `StructuralValidation` (open, with `| str`), and `DisputeProtocolAction`, `FederationSettlementSignal`, `FederationVerdict`, `SchemaFieldMappingValueType` and `WebhookSigningAlg` (closed). `SchemaVersionUpdate` types the body of `schemas.update_version()`.
- **`Scopes.DISPUTES_WRITE`** (`disputes:write`), which opening, evidencing, withdrawing and resolving a dispute require.
- **Unsigned rows are graded by age.** An entry with no `signingKeyId` is reduced coverage only from before the install began signing. After an entry in the same chain that names a key, or written at or after the earliest `activatedAt` across the key set, it fails the new `CHAIN_ENTRY_UNSIGNED`. On a dump the same applies to vault checkpoints (`CHECKPOINT_UNSIGNED`), read-log leaves (`TENANT_READ_LEAF_UNSIGNED`) and tree heads (`TENANT_CHECKPOINT_UNSIGNED`). `earliest_key_activation` and `written_while_signing` are exported from `agledger.verify`.
- **A full dump re-verifies agent signatures from the cert keys it signs itself.** Each `EPHEMERAL_CERT_ISSUED` entry on the platform-ops chain signs its cert's `publicKeyJwk`; the dump verifier uses those keys beside any `agent_keys`. `VaultChainsReport.cert_keys_from_chain` counts them. An org-scoped dump leaves that chain out and still needs `agent_keys`.

### Fixed

- **A CBOR error body is no longer used as the message.** On the SCITT routes, which answer errors as RFC 9290 CBOR problem details, `detail` is the HTTP status text and the body stays on `raw_body`.
- **A 429's `retry-after` is waited out in full.** The wait is the larger of the exponential step and `retry-after`, plus 0 to 25% jitter. Use `max_retries=0` to not wait.
- **`a2a.call()` leaves `params` out when you pass none.**
- **An `/a2a` HTTP 4xx raises an error with a useful message.** `code` is the ErrorInfo `reason` the Server sends (else the JSON-RPC code as a string), `detail`, `recovery_hint`, `request_id` and `retryable` come from `error.data[0].metadata`, `details` holds the JSON-RPC error object, and `raw_body` holds the response bytes.
- **A timeout or connection failure carries the `Idempotency-Key` it sent.** `APIConnectionError.idempotency_key` (and `APITimeoutError`) names the key reused across retries, so you can replay the write with `client.request(..., headers={"Idempotency-Key": key})`. None on a read.
- **`agledger-verify` without the `[verify]` extra prints one line and exits 3.** The line names `pip install 'agledger[verify]'`.
- **The README Async Support example is a complete script.**
- `VerificationKey.distrusted_from` declares the `distrustedFrom` instant published on a distrusted key, and `schemas.preview()` documents the `unchanged` flag of its answer.
- **A copied key-statement row counts once.** A dump row repeating an earlier row's signed payload is counted at its first write; on a key document a copy stays a second statement.
- Distrust accounting: only a retirement signed by a key the walk trusts bounds what a distrust entry accounts for, and a later admission of a trusted key that the key itself signed is always a finding. The admission of a trusted key signed by a distrusted key from its cutoff on is not a finding when it is that key's first admission.
- **The README Quick Start runs.** It uses a principal client and a performer client, and the disputes and vault-checkpoint examples name the key each call takes.
- **A record received from a federation peer parses.** `RecordRow.federation_status` names `inbound`.
- **A read-log leaf's signature is verified.** A leaf that names a key must name one in the dumped registry (`CHAIN_SIGNATURE_MISSING_KEY`) and carry a signature that verifies (`TENANT_READ_SIGNATURE_INVALID`).
- **A pin over an artifact with nothing signed by an anchored key is not a trusted pass.** `key_trust.status` (`KeyTrustStatus`) gains `"no_anchored_signature"`, `verify_dump` gives the verdict `"unanchored"`, and the CLI prints `[VERIFIED, NOT ANCHORED]`. `settle_key_trust(report, anchored_signatures)` makes that call, `VaultChainsReport.signed_entries` counts verified vault entries, and `optional_checks["key_anchoring"]` is `"not_checked"` when anchors were given but no entry reached the check.
- **An entry with no readable `createdAt` fails closed** with `CHAIN_MALFORMED_ENTRY` wherever the walk needs the time, and `written_while_signing` returns True for such a row once signing began.
- **Malformed rows are failure codes, not exceptions.** A null or dropped `payload` fails `CHAIN_PAYLOAD_BINDING_MISMATCH`, a dropped or retyped actor column fails `CHAIN_ACTOR_ATTRIBUTION_MISMATCH` or `CHAIN_OIDC_ACTOR_MISMATCH`, a key row with no `public_key` is `CHAIN_SIGNATURE_MISSING_KEY`, a statement row with no readable `created_at` or `subject_key_id` is `KEY_STATEMENT_INVALID`, and a non-object entry or `integrity` block fails `CHAIN_MALFORMED_ENTRY`. A document with no `exportMetadata` object or `entries` that is not a list raises `TypeError`. Verdicts and codes match `@agledger/verify`.
- **A distrust cutoff is not a retirement.** `distrust_cutoff` is carried apart from `retired_at` on `KeyTrustEntry`, and an entry written after the cutoff fails `CHAIN_KEY_EXPIRED` worded as written after the `distrustedKeys` instant.
- `verify_export` refuses `distrusted_keys` without `trust_anchors` with `TypeError`.
- **A dump failure names the chain it is on.** Failures read `Chain schema:<org> pos N` for schema chains and `Record <id> pos N` for record chains; checkpoint failures use the same labels.

## [1.12.0] - 2026-09-21

Targets AGLedger API 1.8.0. Adds OIDC workload identity: an agent can authenticate with a short-lived certificate obtained from its own identity provider instead of an API key.

### Added

- **`bearer_token=` on `AgledgerClient` and `AsyncAgledgerClient`**, beside `api_key=`. Pass exactly one; both at once raises `ConfigurationError`. It takes a string, a function the client calls before every request (async functions on the async client), or a credential object implementing `BearerCredential` (`AsyncBearerCredential` on the async client). `AGLEDGER_API_KEY` still backs `api_key` only.
- **`oidc_cert_credential(get_oidc_token=..., agent_id=None, refresh_fraction=0.5)`** and **`async_oidc_cert_credential(...)`**. The credential generates an Ed25519 key pair in memory, exchanges a fresh OIDC token at `POST /v1/auth/oidc/cert` for a certificate bound to that key, and sends `Authorization: Bearer <certJws>`. It exchanges again once `refresh_fraction` of the certificate lifetime has passed and when the Server refuses the certificate with a 401. Every request with a body also carries `X-Agent-Signature` and `X-Agent-Signature-Content-Hash`, an Ed25519 signature over the bytes sent, which the Server seals into the chain entry. Needs the new `oidc` extra: `pip install 'agledger[oidc]'`. A refused exchange raises `OidcCertExchangeError` (an `APIError`) carrying the Server's `recovery_hint`, with the OIDC token scrubbed from its message and `details`. `get_oidc_token` must return a new token, with a new `jti`, on every call, since the Server accepts each token id once. If a scheduled refresh fails while the current certificate is still valid, the request goes out on that certificate and the exchange is retried shortly after.
- **`agent_keys=` on `agledger.verify.verify_export` and `verify_dump`, and `--agent-keys` on `agledger-verify`.** Pass the certificate's public key (`credential.public_key_jwk`) and every agent signature sealed in the chain is re-verified offline. A failure is `CHAIN_AGENT_SIGNATURE_INVALID`. `VerifyExportResult` gains `agent_signatures` (present and verified counts) and `agent_signature_check` (`applied` or `skipped_no_input`). The key file may hold one JWK, a list, a `{"keys": [...]}` JWK Set, or entries wrapping a key as `{"publicKeyJwk": ...}`; anything that is not an Ed25519 JWK is exit 2.
- **`--keys`, `--require-key-id` and `--require-out-of-band-keys` on `agledger-verify`.** `--keys` takes a `{keyId: ...}` map, a `[{keyId, publicKey}]` list, or a saved `GET /v1/verification-keys` response. They apply to an `/audit-export` file only; a dump directory rejects them with exit 2. A malformed or unreadable key file is exit 2.
- **The export text report warns when a pass is not independent**, that is, when it verified only against keys embedded in the export.
- **`optional_checks` on `VerifyExportResult`.** The export path runs the OIDC-actor cross-check and the temporal key-validity check whenever the export carries their inputs (`actorOidcSynthesized` and the `actorOidc*` columns, `exportMetadata.signingKeyWindows`).
- **`on_behalf_of=` on `records.create`, `records.transition`, `records.submit_verdict`, `completions.submit`, `a2a.dispatch` and `a2a.call`**, sent as the `AGLedger-On-Behalf-Of` header (an RFC 8693 delegation token). `client.request()` also takes `headers=`.
- **API key administration**: `create_api_key(allowed_ips=)`; `list_api_keys` and `list_all_api_keys` take `last_used_before=` and `never_used=`; `update_api_key(allowed_ips=)` replaces or (with `None`) removes the IP allow-list; and `bulk_revoke_api_keys` takes `owner_id`, `role`, `created_before`, `last_used_before`, `never_used` and `reason` as well as ids. Listed keys carry `revokedAt`, `revokedByKeyId`, `revocationReason` and `rotatedFromKeyId`.
- **Trusted issuers** take `jti_single_use=` and `subject_allowlist=` on create and update.
- **`record_read`** on `Completion`, `GateStatus`, `GateEvaluationResult` and `DisputeResponse`: the inclusion-proof coordinates of the org-admin read the call logged.
- **`Webhook.managed_by`**: `provisioning` on a subscription declared in the operator's provisioning config. Deleting one is refused with 409 (`ConflictError`).
- **`ConformanceResponse.license`** (`ConformanceLicense`: `validity`, `notice`, `escalated`), and **`LicenseTier`** gains `unlicensed`. `LicenseValidity` and `LicenseNoticeKind` name the values the license state carries.
- **`AuditChainIntegrityReasonCode` and `AuditChainFailureCode`** are exported, and both gain `cert_window_drift`.
- **`references.lookup()` returns the page of matches the route serves** (`{"data": [{"entityType", "entityId", "reference"}], "hasMore", "nextCursor"}`) and takes `limit` and `cursor`; `references.lookup_all()` walks every page. `predicates.get()` always requests the literal `v1` path. `RecordAuditExport` gains `verification_guide`, `record_read` and `next_steps`, and `AuditExportMetadata` gains `signing_key_windows`. `next_steps` and `record_read` are added on `AgentCapabilities`, `AiImpactAssessment`, `ComplianceRecord`, `ComplianceExport` and the org-reads checkpoint co-sign.

### Changed

- `LICENSE` follows SDK License Template 1.9: section 1 states that AGLedger LLC does not receive, inspect or use the data you process through your deployment and collects no product usage information from it; section 7 names AGLedger and Settlement Signal as trademarks of AGLedger LLC; section 8 refers to issued or pending U.S. patents.
- **The payload binding compares with JSON types kept apart**, as in `@agledger/verify-core`: a row that rewrote `true` as `1` no longer binds. An agent key the host runtime refuses to load (an OpenSSL FIPS provider) is reported per entry as `CHAIN_UNSUPPORTED_ALGORITHM` instead of raising. `Webhook.secret` no longer appears in the model's `repr`.
- **The offline verifier binds the row copy of `on_behalf_of` and `traceparent` to what the entry signed.** A row copy that differs from the signed `predicate.on_behalf_of` / `predicate.traceparent` fails `CHAIN_PAYLOAD_BINDING_MISMATCH`; a row without them is fine.
- **`chainIntegrityReason` and `chainIntegrityDetail.failure` on an audit export are open unions.** A value added by a newer Server reads as a plain string.
- The missing-credential error reads "No credential provided. Pass api_key or bearer_token, or set AGLEDGER_API_KEY." It is still an `AuthenticationError`.
- `get_ndjson` (the SIEM stream) records `last_request_id` and `rate_limit_info` like every other call.

### Removed

- **`admin.get_rate_limit_exemption()`.** The route does not exist. `list_rate_limit_exemptions()` returns `{"data": [ownerId, ...], "total"}`; check one owner with `owner_id in result["data"]`. `set_rate_limit_exemption(owner_id)` no longer takes keyword arguments.
- **`VerificationKeysResponse.hash_algorithm`.** It gains `envelope`, `payload_format` and `cose_algorithm`, and each `VerificationKey` gains `cose_algorithm` and `min_verifier_version`.
- **`HealthResponse.uptime` and `.database`, and `StatusResponse.active_incidents`.** Process uptime and database state are on `admin.get_system_health()`.
- **`ComplianceExport.id` and `.format`.** The export id is `export_id`.
- **`WebhookTestResult.response_time_ms`.** `webhooks.ping()` returns `duration_ms`, `latency_ms`, `http_status`, `body`, `delivery_id` and `next_steps`.
- **`AuditExportEntry.position`, `.timestamp` and `.actor`, and the `AuditActor` model.** Read `chain_position`, `created_at` and the `actor_*` fields. The offline verifier still reads a legacy `position` key in raw export JSON.
- **`create_api_key(environment=)`.** The Server refuses the field.

### Fixed

- **Actor attribution is verified.** `actorId`, `actorOwnerId` and `actorRole` are cross-checked per entry against the signed protected header, and a divergence fails the new `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`. The check runs on `verify_export` and `verify_dump`, and `optional_checks['actor_attribution']` says whether it applied.
- The async `update_api_key` accepts exactly what the sync method does (`expires_at` is no longer sent).
- The README Quick Start reads the performer from `AGLEDGER_PERFORMER_AGENT_ID`, waits for `PROCESSING`, and runs end to end.

## [1.11.0] - 2026-09-10

Tracks the API build that follows 1.6.0. It replaces agent reputation with agent drift, removes the dispute tier ladder in favour of a single rendered outcome, drops the negotiation counter-offer, and removes commission from the record. There are no deprecation shims: a call to a removed method is an attribute error.

### Removed

- **`records.counter_propose()` and `records.accept_counter()`.** A performer answering a proposal accepts or rejects it. `AcceptanceStatus` loses `COUNTER_PROPOSED`, and `record.proposal_counter_proposed` is no longer a `WebhookEventType` (it stays an `EventType` member for querying past events).
- **`disputes.escalate()` and the tier ladder.** `DisputeStatus` is now `EVIDENCE_WINDOW | PENDING_RESOLUTION | RESOLVED | WITHDRAWN`. Code that branched on `TIER_2_REVIEW`, `ESCALATED` or `TIER_3_ARBITRATION`, or passed one to the `status` filter on `disputes.list()` or the `dispute_status` filter on `records.list()` and `records.search()`, must use the new four. A dispute that would have escalated sits at `PENDING_RESOLUTION` waiting on the principal. `dispute.escalated` is no longer subscribable.
- **`RecordStatus` loses `PENDING_ARBITRATION`**, and `DISPUTED` no longer transitions to it: a disputed Record settles at `FULFILLED` or `FAILED`. It is gone from the record listing `status` filter and the admin import `terminalStatus`. `federation.submit_state_transition()` still accepts it as `state` for one release.
- **`federation_admin.resync_peer()` and `federation.sync_agent_directory()`.**
- **`client.reputation`; `client.drift` replaces it.** `ReputationScore` is removed. Drift reports what the agent did in the current window, the same counts for the window before it, and the difference, with no score or threshold.
- **`Scopes.REPUTATION_READ` is now `Scopes.DRIFT_READ`** (`"drift:read"`). Both profiles that carried the old scope carry the new one.
- **`Scopes.DISPUTES_MANAGE`.** `"disputes:manage"` is not an API scope.
- **`federation.contribute_reputation()` and `federation.get_agent_reputation()`.**
- **`admin.create_agent()` no longer takes `name`, and `display_name` is required.** An agent has one name, `display_name`, unique within its org.
- **Commission fields.** `RecordRow.commission_pct` and `RecordRow.commission_amount`, `records.create(commission_pct=)` and the same key on a `records.bulk_create()` item, and `commissionSourceField` in a contract type's `rulesConfig`.
- **`Dispute` loses `current_tier`, `fee_charged_to`, `fee_amount` and `fee_currency`.**
- **`FederationPeer` loses `agent_directory_hash` and `last_sync_at`.** `FederationPeerStatus` is now `active | revoked`. `federation_admin.get_instance()` no longer returns `encryptionPublicKey`, and the revoke response is `{"revoked": true}`.
- **`PeerHandshakeResult.server_encryption_public_key`**, and `federation.peer_handshake()` no longer sends `encryptionPublicKey` or `agentDirectory`.
- **`AiImpactAssessment.overseer_name`.** Who oversees is in `human_oversight`.
- **`admin.get_ops_summary()` no longer reports `federation.peers.suspended`.**

### Added

- **`disputes.resolve(dispute_id, outcome=, rationale=)`**, sync and async, for `POST /v1/disputes/{id}/resolve`. It takes the dispute id (`filed.id` from `disputes.create()`), unlike the other dispute methods, which take the record id. `outcome` is the new `DisputeOutcome` (`UPHELD` or `OVERTURNED`), exported from the package root. `UPHELD` returns the Record to the status it held before the dispute. `OVERTURNED` settles a Record whose pre-dispute status was FAILED at FULFILLED with the verdict re-rendered as `accept`, restores one already FULFILLED or REMEDIATED, and a RELEASE Settlement Signal follows with reason code `DISPUTE_OVERTURNED`. Accepted while the dispute is at `EVIDENCE_WINDOW` or `PENDING_RESOLUTION`; otherwise it raises `UnprocessableError` carrying `currentState` and `allowedActions`.
- **`records.create(max_revisions=)`**, and the same key on a `records.bulk_create()` item. It caps rework cycles from 1 to 20; omit it to inherit the org default (`enforcement.defaultMaxRevisions`, 3 unless the org set one). It is immutable once created. At the cap, the next resubmit is refused with a 422 and the Record stays where it was.
- **`agents.list(include_deactivated=)`, and `deactivated_at` on agent rows.** Set the flag on the first call of a walk, since it is bound into `next_cursor`.
- **`DisputeOutcome`, `CoSignStatus`, `EnforcementMode` and `EnforcementSource` are exported from the package root.** `CoSignStatus` gains `partial`, for a multi-party co-sign where only some counter-signatures came back, so code that treated `succeeded` and `failed` as the only settled outcomes needs a third case.
- **Two `EventType` members**, `system.cascading_gate_enqueue_failed` and `system.verification_enqueue_failed`: queryable through `events.list()`, not subscribable.
- **`DisputeResponse.next_steps`**, on the envelope `disputes.get()` returns.
- **Org config.** `admin.update_org_config()` accepts `disputes.autoReadjudicate` (`deadlineGraceSeconds`, `toleranceExpansion`, or null to turn it off) and `enforcement.defaultMaxRevisions`, and every `enforcement` field is nullable, where null clears the override. Omitting a key and passing null are different requests. `admin.get_org_config()` gains `enforcement` (values in force), `enforcementDefaults` (install-wide floor) and `enforcementSource` (per field, org or default).
- **`firstFailedAt` on federation DLQ items.**
- **`client.drift`**, sync and async. `get_agent(agent_id, window=..., type=...)` returns `AgentDrift`. `list_fleet(window=..., limit=..., cursor=...)` returns `FleetDriftPage`, and `list_all_fleet(...)` walks it, resending `window` with every cursor. `get_agent_history(agent_id, ...)` returns `Page[AgentHistoryEntry]`, filtered by `type`, `outcome`, `from_` and `to` (`from_` is sent as `from`).
- **New models exported from the package root:** `AgentDrift`, `AgentHistoryEntry`, `DriftWindow`, `DriftBucket`, `DriftChange`, `DriftSeries`, `DriftTypeSeries`, `FleetDriftRow` and `FleetDriftPage`. `acceptance_rate` is null when the window holds no verdict, `median_completion_ms` is null when it holds no completion, and `change` is null wherever either side is.
- **`admin.reactivate_org()` and `admin.reactivate_agent()`**, each taking an optional `reason`. Idempotent: an already-active account returns `wasDeactivated: false`. Reactivation does not restore API keys that deactivation revoked. Platform key only; a provisioning-managed row refuses with 409.
- **`admin.list_api_keys()` and `admin.list_all_api_keys()` take `expires_before` and `never_expires`.**
- **`admin.create_agent()` takes `oidc_iss` and `oidc_sub`**, set together to bind the agent to an external identity for `POST /v1/auth/oidc/cert`.
- **`agents.update()` takes `agent_card_url`, `oidc_iss` and `oidc_sub`, and `AgentProfile` reads back `oidc_iss` and `oidc_sub`.** Passing `None` explicitly sends JSON null and clears the field (also for `owner_ref` and `org_unit`); leaving the keyword off leaves the stored value alone. Set `oidc_iss` and `oidc_sub` together.
- **Trusted-issuer create and update take `auto_provision_agents`, `auto_provision_scope_profile` and `auto_provision_max_agents`.** With auto-provisioning on, the first token exchange from an unknown subject creates the agent under the issuer's org. The scope profile is also the ceiling for certs minted from that issuer. A `None` is dropped; to send a literal null, use `client.request()`.
- **`AgentClass` and `AutoProvisionScopeProfile`** are exported named types.
- **`audit_vault_empty`** is a `chain_integrity_reason` member: the record exists but its chain holds no entries.

### Changed

- **The scope profiles match what the Server grants.** The agent profiles gain `audit:read` and `compliance:read`; `agent-full` also gains `drift:read`. `admin-standard` no longer lists `admin:backfill` or `schemas:admin`. `admin-iac` carries `schemas:write` rather than `schemas:admin`.
- **The `reputationScoring` conformance capability is `agentDrift`.**
- **`federation.peer_handshake()` takes five typed keywords**: `peer_hub_id`, `peer_url`, `signing_public_key`, `peering_token` and `bound_org_id`, all required. The route admits on the single-use `peering_token` in the body.
- **`RecordRow.awaiting_actor` no longer names `arbitration`**, leaving `principal`, `performer`, `system` and `None`.
- **`disputes.list(status=)` takes `DisputeStatus`** rather than a bare `str`.
- **`AgentHistoryEntry.status` is typed as the record-status enum.**
- **The dispute create envelope renames `tier1Result` to `autoReadjudication`**, and its `reason` gains `not_configured`. `disputes.create()` still returns the dispute itself; only a caller reading the raw envelope through `client.request()` sees the change.

## [1.10.0] - 2026-08-30

### Fixed

- **`WebhookEventType` no longer names `record.settled`, `record.released` and `dispute.evidence_window_closed`.** `POST /v1/webhooks` rejects them. They remain `EventType` members for querying through `GET /v1/events`, a larger union that `events.list()` and `events.list_all()` take. Settlement outcomes reach webhooks through `signal.emitted` / `signal.received`. This is a breaking type change for anyone who named one of the three directly.
- **The SIEM audit stream no longer drops events at a page boundary.** `compliance.stream_all()`, sync and async, sends the stream cursor back verbatim. If you wrote your own polling loop on `compliance.stream()`, never split a cursor and never rebuild a `since` from one.
- **A stream page that carries events but no cursor raises `PaginationLimitError`** instead of returning. A bound you set yourself still ends the walk quietly.

### Added

- **`compliance.stream()` and `compliance.stream_all()` take `cursor`.** `since` starts a walk and `cursor` continues one; passing both raises `ValueError`.
- **`AuditStreamResult.holdback_seconds`**, from `X-AGLedger-Stream-Holdback-Seconds`: the whole seconds by which a page stops short of now because a transaction that stamped rows has not committed. `0` means the page runs up to the present, `None` means the Server did not say.
- **`audit.org_reads_checkpoints.list_reads()`** lists the read-transparency log leaves the signed checkpoints cover (`GET /v1/audit/org-reads`). Rows carry `leaf_index` and `leaf_hash`, which `proof()` verifies against a checkpoint.
- **`events.list()` and `events.list_all()` take `until`, `record_id`, `event_type` and `offset`.** `since` is inclusive and `until` is exclusive, so consecutive windows compose without overlap. `event_type` takes the new `EventType` union. `order` is no longer defaulted to `"desc"`; the Server's default (`asc`) applies unless you pass it.
- **`EventType`, `FederationPeer`, `FederationPeerStatus`, `PeerHandshakeResult`, `OrgAdminRead`, `OrgReadsCheckpointing`, `OrgReadsCheckpointingSource` and `OrgReadsCheckpointPage`** are exported from the package root.

### Changed

- **`AuditStreamResult.has_more` reports whether the page produced rows.** A zero-row page means this poll is exhausted.
- **`audit.org_reads_checkpoints.list()` returns a typed page, not a dict.** It gains a `checkpointing` block (`cron`, `interval_minutes`, `last_checkpoint_at`, `next_run_at`, `source`) alongside `data`, `has_more`, `next_cursor` and `total`, and takes `offset` and `cursor`. Read `checkpointing` before reporting missing checkpoints: checkpoints are created on a schedule, so a fresh install returns an empty `data`. Callers subscripting the old dict need to read attributes.
- **`federation_admin.get_peer()` returns `FederationPeer` and `list_peers()` returns `Page[FederationPeer]`.** The row has `peer_id`, `peer_hub_id`, `peer_url`, `status`, `created_at`, `agent_directory_hash`, `consecutive_delivery_failures`, `last_delivery_at`, `last_delivery_error` and `last_sync_at`. Callers subscripting the old dicts need to read attributes.
- **`federation.peer_handshake()` returns `PeerHandshakeResult`.** `peer_hub_id` is the identifier every admin peer path takes; `peer_id` is the receiver-local row id.
- **The federation peer methods name their parameter `peer_hub_id`, not `hub_id`** (`get_peer`, `revoke_peer`, `resync_peer`, `delete_peer`). Positional calls are unaffected; a call passing `hub_id=` needs the new name.
- **`audit.org_reads_checkpoints.proof()` takes `leaf` as an `int`**, so pass `leaf_index` straight through.
- **`compliance.stream()` and `compliance.stream_all()` raise `ValueError` when given neither `since` nor `cursor`.**
- **`__enter__` and `__aenter__` return `Self`**, so a subclass keeps its own type inside the `with` block.

## [1.9.0] - 2026-08-21

### Fixed

- **`DisputeStatus` drops `OPENED` and `TIER_1_REVIEW`**, which are not API values. The full set is `EVIDENCE_WINDOW`, `TIER_2_REVIEW`, `ESCALATED`, `TIER_3_ARBITRATION`, `RESOLVED`, `WITHDRAWN`. `RecordRow` uses the named type.
- **The `dispute_status` request parameters name their values.** Seven signatures across `records` take `DisputeStatus | str`.
- **`schemas.update_version()`'s docstring** says the route updates `compatibilityMode` only (lowercase values). Disabling a Type is `schemas.disable()`.
- **Mapping query params are expanded into the API's bracket notation**, so `search(metadata={"state": "blocked"})` filters by metadata. A `datetime` in a query param serializes as ISO-8601.
- **`admin.list_api_keys()` and `admin.list_all_api_keys()` take typed, keyword-only filters and send them camelCase**: `owner_id`, `org_id`, `owner_type`, `role`, `is_active`, `created_before`, `limit`, `offset`, `cursor`. A camelCase kwarg is now a `TypeError`.
- **`records.search(principal_agent_id=...)` is removed**, since no record endpoint accepts it. On an agent key, use `role="principal"`. On an admin or platform key `role` is a 400, so narrow with `performer_agent_id`.
- **`ConformanceResponse.capabilities` parses real responses** (`capabilities.signingAlgorithms` is a list).
- **`records.get_chain()` walks every page**, with `max_pages` to cap the walk.
- **`records.get_sub_records()` takes paging params.**
- **`RateLimitError.retry_after` reads the 429 body** (`retryAfterSeconds`) when the header is absent. The header wins when both are present.
- **`Page` carries `next_steps` and `record_read`.**
- **`HealthResponse.uptime` and `.database` are documented as not served.** Use `admin.get_system_health()`.

### Added

- **`records.create(supersedes_record_id=...)`, `references=` and `share=`**. `RecordRow.supersedes_record_id` and `RecordRow.superseded_by_count` report supersession; a count above 1 is a fork, not an error.
- **`records.search()` gains `superseded`, `supersedes_record_id`, `criteria`, `metadata`, `role`, `category`, `project_ref`, `has_dispute`, `dispute_status`, `imported`, `source`, `ref_system` / `ref_type` / `ref_id`, and `offset`.** `criteria` filters on signed bytes; `metadata` filters on an unsigned annotation.
- **`ConformanceResponse.limits`**: the numeric caps this install enforces, including `cursorMaxLength`, `paginationLimitMax` and `searchCursorMaxLength`. Several are org-configurable, so read them rather than hardcoding.
- **`BulkCreateResultItem.recovery_hint`**, and **`APIError.registry_version`** for the `CONFLICTING_VERSION` 409.
- **`admin.list_all_api_keys()`**, sync and async. Both listing modes cap at `limit` (default 200) and report `hasMore` honestly. The iterator resends the filters with each cursor.

### Changed

- **An auto-paginating walk that hits the page ceiling raises `PaginationLimitError`** instead of returning a prefix. A bound you pass yourself still ends the walk quietly. `compliance.stream_all` follows the same rule.
- **`max_pages` is reachable from every walker, and `limit` from those whose route takes it.** `records.list_all()` and `events.list_all()` gain both; `completions.list_all()` and `admin.list_all_api_keys()` gain `max_pages`. On `records.get_chain()` and `compliance.stream_all()` the `max_pages` default is now `None`, and a walk that exhausts the ceiling raises.
- **`records.list()`, `list_all()` and `search()` document that `role` is agent-key only**; an admin or platform key passing it gets a 400.
- **`discovery.get_conformance()` returns `ConformanceResponse`** instead of a dict. Use `result.version`, or `result.model_dump()` for the mapping; extra fields are still allowed.

### Removed

- **`EuAiActReport`.** No API route produces that shape.

## [1.8.0] - 2026-08-08

### Added

- **Multi-publisher schemas.** When two publishers offer the same `record_type` in one org, record creation is refused with `422 /problems/ambiguous-publisher` and the candidates are listed. `records.create(publisher=...)`, sync and async, pins one. Only send `publisher` in response to that 422; a Server older than this release rejects it.
- **`RecordRow.publisher`** reports the binding used. `None` means the Record was received from a federation peer and was judged by the originator against its own registration, not that the schema is missing here.
- **`APIError.publishers`** carries the candidate labels off that 422, and **`APIError.type`** carries the RFC 9457 problem URI. Branch on `type`, not message text.
- **`BulkCreateResultItem.problem_type` and `.context`**, matching the single-record error body.
- **A `publisher=` argument on every scoped schema call**: `get`, `delete`, `get_rules`, `get_template`, `get_versions`, `get_version`, `update_version`, `disable`, `enable`, `validate_completion`, `diff` and `export_schema`, sync and async.
- **`schemas.get_manifest()`** for `GET /v1/schemas/{type}/manifest`, returning the canonical manifest plus the `manifestDigest` a peer computes on import.
- **`SignatureAlgorithmUnavailableError`**, carrying the `algorithm` that could not be computed. It is distinct from `SignatureVerificationError`: one is your server's configuration, the other a rejected delivery.
- **`ConfigurationError`**, exported from the package root. It extends `AgledgerError`, not `APIError`, because nothing was sent.
- **`APIError.pinned_records` and `.unattributable_records`**, the two counts that explain why a schema delete was refused. A non-zero `pinned_records` is fixable by deleting the other publisher's registration instead.
- **`AccountProfile.expires_at` and `.allowed_ips`.**

`schema_url` on a Record carries `?publisher=` whenever the publisher is known; single-publisher orgs get `?publisher=local` where they used to get a bare path, so anything comparing `schema_url` against a literal needs updating.

### Changed

- **`base_url` is now required.** Omitting it raises `ConfigurationError` at construction. Every AGLedger deployment is self-hosted, so there is no sensible default. `api_key` still falls back to `AGLEDGER_API_KEY`.
- **`verify_rfc9421` and `construct_event_rfc9421` can raise** `SignatureAlgorithmUnavailableError` when the host cannot compute the key's algorithm (for example under a FIPS-restricted OpenSSL). On such a host no ed25519 delivery can be classified, valid or forged, so do not read the exception as evidence a delivery was legitimate. Elsewhere, bad deliveries still return `False`.
- **`CHAIN_SIGNATURE_INVALID`'s remediation text no longer hardcodes "Ed25519"**, and `CHAIN_UNSUPPORTED_ALGORITHM`'s text names both of its causes and states that the result is not tamper evidence. Remediation text for thirteen codes was aligned with `@agledger/verify-core`; no verdict or code changed.

### Fixed

- **A real audit export parses.** `chain_integrity_reason` accepts `unsupported_algorithm`, and `chain_integrity_detail.failure` also accepts `signature_invalid`, `signing_key_unknown` and `signing_key_drift`.
- **`APIError.doc_url` is deprecated** and always `None`; the value is in `docs`. `doc_url` is kept so existing callers keep working.
- **`AccountProfile.agent_id` is removed.** `GET /v1/auth/me` does not return it; the agent id is `owner_id` when `owner_type == "agent"`.
- **`schemas.diff()` takes `publisher=`** like its sibling schema methods, sync and async.
- **`admin.records.import_()` docs** state that the route requires a platform key, describe the return shape (`{source, count, imported[], nextSteps}`, each entry `{index, recordId, chainPosition}`), and describe the per-item `"publisher"` key needed on an ambiguous type.
- **A runtime that cannot compute an algorithm no longer reads as tamper.** Under an OpenSSL FIPS provider there is no EdDSA, and `verify_export` now reports `CHAIN_UNSUPPORTED_ALGORITHM` with `signature="unsupported"`, naming the FIPS provider and advising a re-run on an unrestricted host. `valid` stays `False`. ES256 chains still verify on a FIPS host.
- **`discovery.get_scope_profiles()` is annotated `dict[str, Any]`**; it returns the page envelope (`{"data": [...], "total", "hasMore", "nextCursor"}`).

## [1.7.0] - 2026-08-07

### Fixed

- **Vault checkpoints join on `chain_key`, so a healthy schema chain no longer fails** with `CHECKPOINT_ROW_MISSING`. Dumps taken before the producer emitted `chain_key` verify as before. Failures name a schema chain as `Chain schema:<orgId>`.

### Changed

- **`CHAIN_KEY_NOT_YET_ACTIVE`** is reported for an entry written before its signing key's activation. `CHAIN_KEY_EXPIRED` now means the retirement side only. Verdicts are unchanged.

## [1.6.1] - 2026-08-07

No code change from 1.6.0. This release is built and published by the tagged release workflow with PEP 740 attestations; prefer it over 1.6.0 if you check attestations.

## [1.6.0] - 2026-08-05

### Added

- **`agledger.verify` verifies ES256 chains** (export and dump). A verification key whose SPKI commits to P-256 is checked as ECDSA/SHA-256 over the COSE raw `r||s` encoding; COSE `-7` (ES256) and RFC 9864 `-9` (ESP256) are accepted. ES384, ES512 and ES256K fail as `CHAIN_UNSUPPORTED_ALGORITHM`.
- **`verify_rfc9421` and `construct_event_rfc9421` accept `ecdsa-p256-sha256` deliveries** (raw `r||s` per RFC 9421). The declared `alg` is checked against the resolved key's type; unsupported key types fail.

## [1.5.1] - 2026-08-05

### Fixed

- **An empty-string signing-key id is no longer treated as the unsigned-mode marker**, in the export walker and the dump checkpoint and signed-tree-head pass. Only `None` is; any other value must resolve in the key registry or fails `CHAIN_SIGNATURE_MISSING_KEY`.

## [1.5.0] - 2026-08-05

Verifier hardening, mirroring `@agledger/verify-core` 1.1.0. Legitimate Ed25519 exports and dumps verify as before; tampered and non-Ed25519 inputs are classified more strictly.

### Changed

- **Algorithm dispatch follows the trusted verification key, not the protected header.** A header `alg` that is missing, unassigned or different from the key's fails `CHAIN_ALG_MISMATCH`. A key whose algorithm this build cannot compute fails as `CHAIN_UNSUPPORTED_ALGORITHM` (was `CHAIN_SIGNATURE_MISSING_KEY`). Ed25519 accepts COSE alg `-8` and `-19`.
- **Signed-kid binding (`CHAIN_SIGNING_KEY_DRIFT`).** The signature-covered kid is checked against the row's `signingKeyId` field.
- **Registry algorithm cross-check.** A dump's `vault_signing_keys.algorithm` is compared against the key material; a mismatch fails `CHAIN_ALG_MISMATCH`.
- **An untagged COSE_Sign1 is rejected** (the leading byte must be `0xd2`).
- **The all-zero unsigned sentinel is evaluated after algorithm resolution**, and an all-zero signature on an entry that claims a signing key fails `CHAIN_KEY_POLICY_VIOLATION` under `require_key_id` / `require_out_of_band_keys`.
- **Checkpoint and signed-tree-head signature checks fail on every non-ok outcome**, including an all-zero signature on a key-claiming checkpoint.
- `FailureCode` gains `CHAIN_ALG_MISMATCH`, `CHAIN_UNSUPPORTED_ALGORITHM` and `CHAIN_SIGNING_KEY_DRIFT`; the per-entry `signature` state gains `"unsupported"`.

## [1.4.0] - 2026-08-03

### Changed

- **Minimum Python is now 3.11** (was 3.10), ahead of 3.10 end-of-life on 2026-10-31. On Python 3.10, `pip install agledger` resolves to 1.3.0, the last release that supports it, with no warning. Upgrade to Python 3.11 or newer to receive later releases.

## [1.3.0] - 2026-08-01

Tracks API 1.3.4. Additive.

### Added

- `ComplianceExport.truncated` and `.total_records`. The org-wide export is capped at 10000 rows, newest first. Window with `filters.from` / `filters.to` to cover the rest. On a download the same answer is in the `X-AGLedger-Export-Truncated` and `X-AGLedger-Export-Total-Records` response headers, which are the only carriers for a `csv` download. Both are `None` against a pre-1.3.4 Server, meaning unknown, which is not the same as `False`.
- `VaultCheckpoint.chain` and the `VaultCheckpointChain` alias (`"record" | "schema" | "admin"`). Only `chain == "record"` is keyed by a real record id; on `"schema"` and `"admin"` the `record_id` is a derived key that resolves to no record. `None` against a pre-1.3.4 Server.
- `VaultCheckpoint` and `VaultCheckpointChain` are exported from the package root.

## [1.2.2] - 2026-07-16

Documentation only.

### Changed

- The licensing section states that federation and multi-node are free on the bundled database, and only an external or managed database requires an Enterprise license. The PyPI summary and README positioning were corrected.

## [1.2.1] - 2026-07-13

### Added

- **`APIError.deadline`**: the ISO deadline carried on a system TIME_OUT 422.

## [1.2.0] - 2026-07-13

Tracks AGLedger API 1.3.2. Additive.

### Added

- **`SignedStatement.signed_at`**: the signed instant of the head Signed Statement (the CWT `iat` claim, second precision), the authoritative timestamp for time-anchored contracts. Nullable, wire name `signedAt`.
- **`VerdictResult.record_status`**: the settled record status (`FULFILLED` on accept, `FAILED` on reject), returned inline on `records.submit_verdict()`.
- **`record.gate_held` webhook event**, emitted when a principal-mode record is held at PROCESSING awaiting the verdict; the payload carries the `completionId` to verdict against. Added to `WebhookEventType`.
- **`records.get_audit_export(id, evidence=True)`** inlines the completion evidence body at each COMPLETION_SUBMITTED entry (`AuditExportEntry.evidence`), an unsigned projection the chain binds by hash via `payload.evidenceHash`. JSON/NDJSON only.
- **`chain_integrity_reason`** gains `signature_invalid`, `signing_key_unknown` and `signing_key_drift`.

## [1.1.0] - 2026-07-06

Tracks AGLedger API 1.2.0. Additive, plus a corrected schema-import surface.

### Added

- **Webhook `record_types` filter**: `webhooks.create()` and `webhooks.update()` accept `record_types`, and the `Webhook` model carries it (wire name `recordTypes`). `["*"]` means all record types; any other list delivers record-scoped events only for the listed types. Omit for no filter.
- **`records.accept(record_id, message=None)`**: optional acceptance rationale, symmetric with `reject()`.

### Fixed

- **`schemas.import_()` takes the manifest.** It takes the manifest dict plus the options `org_id`, `federatable`, `defaultShare`, `defaultGateMode`, `coSignRequired`, `flipRecordStatusOnDispute` and `federateDisputes`, and returns the created or existing subject row (HTTP 200 on an idempotent re-post, 201 on create).

### Removed

- **`schemas.preview_import()` and the `dry_run` flag.** The API has no dry-run on `/v1/schemas/import`. Use `schemas.preview()` to validate locally authored schemas before registration.

## [1.0.4] - 2026-06-29

- Maintenance release with no user-facing changes.

## [1.0.3] - 2026-06-29

Tracks AGLedger API 1.1.0. Backward-compatible.

### Added

- **`Completion.settlement_signal`**: the auto-gate's settle, hold or reject decision, returned inline on a submitted Completion. Typed `CompletionSettlementSignal` (`recommendation`, `outcome`, `reason_code`); `None` when the gate did not render inline (encrypted Records, principal-mode held at PENDING_VERDICT, or skipped).

### Changed

- `reason_code` docs note the new `AUTO_SETTLE_WITHIN_TOLERANCE` value: an auto-settle that cleared only via a non-zero tolerance band. The field stays `str | None`.
- Gate-mode docs state that auto mode settles against the principal's pre-configured predicates, and that the verdict is always the principal's.

## [1.0.2] - 2026-06-22

Tracks AGLedger API 1.0.3. Additive.

### Added

- **`records.get(record_id, integrity=True)`** (sync and async) re-verifies the Record's audit chain and cross-checks the served row against it. The result is on the new `RecordRow.integrity` field (`RecordIntegrity`: `verified`, `integrity_level`, `reason`, `entries`, `projection_checked`, `drift_fields`).
- **`records.list(actionable=True)` and `list_all(actionable=True)`** (sync and async) return every Record whose next action awaits the caller. Agent keys only.
- **`auth.rotate_key(grace_period_seconds=...)`** (sync and async) keeps the old key valid for an overlap window.

### Changed

- `admin.create_org()` is documented as dev and test only; production orgs are provisioned from operator `provisioning/` YAML.

## [1.0.1] - 2026-06-10

### Changed

- `LICENSE` is updated to the current AGLedger SDK license template (v1.5): trademarks are AGLedger and Settlement Signal, export language follows ENC section 740.17(b)(1), and section 1 states that AGLedger does not inspect your data, train on it or collect usage data. No code changes.

## [1.0.0] - 2026-06-08

General availability, tracking AGLedger API 1.0.0. No breaking changes from the 0.8.x line.

### Added

- `WebhookEventType`: `record.proposal_counter_proposed`, `record.ai_impact_assessment_filed`, `record.compliance_attestation_filed`.

### Fixed

- `agledger.__version__` and the `User-Agent` header report the installed package version.

## [0.8.15] - 2026-06-04

- Maintenance release with no user-facing changes.

## [0.8.14] - 2026-06-04

- Maintenance release with no user-facing changes.

## [0.8.13] - 2026-06-04

- Maintenance release with no user-facing changes.

## [0.8.12] - 2026-06-02

### Added

- **`agledger-verify` console script** (installed with the `[verify]` extra: `pip install 'agledger[verify]'`) for offline verification of an audit dump. A directory is a five-file NDJSON dump; a file is a single `/audit-export` JSON document. Exit codes: `0` clean, `1` verification failure, `2` usage or IO error. Supports `--report-format text|json` and `--quiet`; makes no network calls.
- **`verify_dump(load_dump(dir)) -> VerifyReport`.** Walks every per-record and per-org schema-event hash chain, cross-checks vault checkpoints against the live chain, and verifies the `org_admin_reads` Merkle log and signed tree heads, including fork detection.
- New dump-path failure codes: `CHAIN_OIDC_ACTOR_MISMATCH`, `CHAIN_KEY_EXPIRED`, `CHECKPOINT_ROW_MISSING`, `CHECKPOINT_HASH_MISMATCH`, `CHECKPOINT_SIGNATURE_INVALID` and the `TENANT_*` set. The `FailureCode` taxonomy is in `agledger.verify.failures` with a `suggestion(code)` helper.

### Changed

- `RiskClassification` gains `unacceptable`; the AI-impact-assessment `domain` enum follows the API's Annex III high-risk set (`EuAiActRiskTier`, `EuAiActDomain`).
- `WebhookEventType` matches the API set (37 event types plus the `*` wildcard; open literal).
- The built-in ACH-* contract-type model is removed. Orgs own their entire type namespace, with four editable samples seeded.

### Fixed

- `compliance.create_assessment` (sync and async) takes typed snake_case keyword arguments (`risk_level`, `domain`, `human_oversight`, `testing_results`) instead of raw camelCase `**params`.

## [0.8.11] - 2026-06-02

### Fixed

- **`RecordRow`** renames `vault_completion` to `signed_statement` and `self_commitment` to `self_principal`, drops `no_op`, and adds `settlement_signal`, `counter_signature`, `co_sign_required`, `co_sign_status`, `federation_status`, `dispute_id`, `dispute_status`, `has_dispute`, `has_children`, `latest_completion_id`, `terminal_reason`, `expired_at`, `awaiting_actor`, `share`, `shared_to_peers`, `source` and `imported`.
- `VaultCompletion` is renamed `SignedStatement` (drops `signature`, adds `url`). New `SettlementSignalSummary` model.
- `Completion` gains `verdict` and `last_verdict_reason`. `NextStep` gains `after_this`, `workflow_label`, `workflow_step` and `workflow_total`.
- `Webhook` has the full subscription shape: `secret_grace_active`, `secret_grace_expires_at`, `circuit_state`, `consecutive_failures`, `last_successful_at`, `last_failure_at`.
- `WebhookEventType` adds `dispute.escalated`, `dispute.evidence_window_closed`, `record.released` and `record.settled`.
- New `EntityReference` and `DisputeEvidence` models (`DisputeResponse.evidence` is typed).
- `records.list` and `list_all` (sync and async) gain `type`, `performer_agent_id`, `role`, `from_`, `to`, `has_dispute`, `dispute_status`, `imported` and `source` filters.

## [0.8.10] - 2026-05-29

### Fixed

- `records.get_chain()` returns the chain's `RecordRow` items.

### Added

- `verify_export()` detects a rewritten denormalised `payload`: when an export entry carries the row `payload` and `entryType`, it is compared against the signed predicate decoded from `coseSign1`, and a mismatch fails `CHAIN_PAYLOAD_BINDING_MISMATCH`.

## [0.8.9] - 2026-05-28

### Fixed

- `records.get_audit_export()` parses current exports. `AuditExportEntry` uses `human_readable_label` (optional) instead of `description`, and gains `actor_owner_id`, `actor_display_name` and `actor_owner_type`.
- `completions.submit()` no longer sends a root-level `notes` key, which the API rejects. It gains `evidence_hash` (for encrypted mode); carry AI-agent rationale inside `evidence` via a `completionSchema` field.
- Response models match the current wire shapes: `AgentProfile` / `AgentDirectoryEntry` (`displayName`), `Event` (`type` and `data`), `OrgReadsCheckpoint` (`checkpointAt`, `coseSign1Base64`), `OrgReadsInclusionProof` (`path`, no `checkpointId`), `ReputationScore` (nullable scores, numeric `confidence_level`, integer `formula_version`, `lifetime_*` counters and `reversals`) and `AiImpactAssessment.human_oversight` (an object).
- Request bodies match the API: `records.create()` drops `category` and `proposal_message`; `records.reject()` sends `message`; `webhooks.update()` takes `is_paused` and drops `format`; `admin.update_api_key()` no longer takes `expires_at` / `allowed_ips`; federation `submit_state_transition()` and `relay_signal()` follow the current contract.

### Removed

- **`compliance.get_ai_act_report()`.** The route does not exist.

## [0.8.8] - 2026-05-28

### Fixed

- `client.verification_keys.list()` parses real responses (`hashAlgorithm` is optional).
- `RecordAuditExport.entries[].position` / `timestamp` read the current `chainPosition` and `createdAt`, and `AuditExportEntry` gains `actorId`, `actorRole`, `actorOidcIss`, `actorOidcSub`, `actorOidcSynthesized` and `recordId`.
- `agledger.verify.verify_export(public_keys=...)` accepts the `client.verification_keys.list().data` list (`VerificationKey` models or dicts) as well as the `{keyId: spki_b64}` mapping. A wrong shape raises `TypeError`.
- `Verdict` is widened to `Literal["accept", "reject"] | str`.

### Added

- `agledger.RateLimitInfo` and the `client.rate_limit_info` / `async_client.rate_limit_info` properties, populated from `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`.

### Changed

- **Retry policy:** `DEFAULT_MAX_RETRIES = 3` (was 2), `MAX_BACKOFF = 30.0s` (was 8.0s), retried statuses `{429, 500, 502, 503, 504}` (409 and 408 are no longer retried; a 409 IDEMPOTENCY_CONFLICT is not transient). Worst-case retry latency on persistent 5xx is about 63s.

## [0.8.7] - 2026-05-27

### Changed

- **Breaking, `agledger.verify` result shape:** failure reasons are canonical `FailureCode` values, and `broken_at.reason` is renamed `broken_at.code`.
- The result reports key provenance: whether each verified entry's key was supplied by the caller or embedded in the export.
- New `require_out_of_band_keys` option fails unless every signature is verified against a caller-supplied key.

## [0.8.6] - 2026-05-27

### Fixed

- `agledger.verify` reads `chainPosition` on each export entry (v0.25 and later exports), falling back to `position` for older exports.

## [0.8.5] - 2026-05-27

Tracks AGLedger API 0.25.5. The second pillar is renamed Verify to Gate; "verify" now refers only to cryptographic verification. `agledger.verify`, webhook signature verification and `client.verification_keys` are unchanged.

### Changed

- **Breaking, Verify to Gate:**
  - `client.verification` is `client.gate`; `verification.verify()` is `gate.evaluate()`; `gate.get_status()` calls `/gate-status`; `lastVerifiedAt` is `lastEvaluatedAt`.
  - `records.report_outcome()` is `records.submit_verdict()`; param `outcome` is `verdict`; values `PASS` / `FAIL` are `accept` / `reject`; adds optional `notes` and `reason`.
  - `VerificationMode` is `GateMode` (`"auto" | "principal"`); `verification_mode` is `gate_mode` on create, search and `RecordRow`.
  - `RecordRow.verification_checks` is `verdict_checks`; `RecordRow.verification_outcome` is `verdict` (accept / reject).
  - `VerificationResult` is `GateEvaluationResult`; `VerificationStatus` is `GateStatus`; `OutcomeResult` is `VerdictResult` (field `signal` is `recommendation`). Adds the `Verdict` literal.
  - `VerdictStatistics` is `{ agent_id, as_principal, as_performer }`, each `{ data, total }`, with `verdictAcceptCount` and `verdictRejectCount` per pair.
  - Webhook events: `record.verification_complete` is `record.gate_complete`; `cascading.verification.complete` is `cascading.gate.complete`.

### Fixed

- `GateStatus` models the real `/gate-status` shape (`phase1_status`, `phase2_status`, `last_evaluated_at`, `pending_rules`).

## [0.8.4] - 2026-05-25

Tracks AGLedger API 0.25.4.

### Added

- **`verify_rfc9421()` and `construct_event_rfc9421()`** in `agledger.webhooks` verify ed25519 webhook deliveries (RFC 9421 HTTP Message Signatures) against `/v1/verification-keys`, matched by `keyid`. They check the RFC 9530 Content-Digest and enforce the `created` replay window (default and maximum 300s). Needs the `cryptography` extra (`pip install 'agledger[verify]'`).
- **`webhooks.create(signing_alg=...)` and `Webhook.signing_alg`** (`"hmac" | "ed25519"`). Settlement-event subscriptions default to `ed25519` when the Server has a vault signing key; requesting `ed25519` without one returns 422.
- **`VerificationKey.public_key_raw`**: base64 of the raw 32-byte Ed25519 key, alongside the SPKI-DER `public_key`.
- **`AccountProfile.auth_type`, `cert` and `oidc`** for OIDC ephemeral-cert and OIDC bearer sessions.

### Fixed

- `WebhookEventType` matches the API's set (35). Added `signal.received`, `federation.dispute` and the eight `record.federation_*` events. Removed `federation.record.offered`, `federation.record.accepted`, `federation.gateway.registered`, `federation.gateway.revoked`, `record.settled` and `record.remediated`.

## [0.8.3] - 2026-05-25

### Fixed

- `RecordAuditExport` parses chain-integrity reasons `oidc_actor_drift`, `cert_actor_drift`, `cert_expired`, `cert_missing` and `agent_signature_invalid`.

### Added

- `ConformanceResponse.capabilities` (feature flags such as `oidcWorkloadIdentity`, `ephemeralCerts`, `trustedIssuers`, `agentSignatureCoSign`) and `VerificationKeysResponse.signature_input_template`.

## [0.8.2] - 2026-05-25

Tracks AGLedger API 0.25.2.

### Added

- `auth.issue_ephemeral_cert()`: OIDC token to ephemeral signing cert exchange (`POST /v1/auth/oidc/cert`).
- `admin.trusted_issuers` sub-resource: `list`, `create`, `get`, `update`, `delete`, `revoke_certs`.
- `admin.revoke_ephemeral_cert(cert_id)`, `admin.get_ops_summary()` and `admin.vault.scan.list()`.
- `agents.list_peers()` for federated agents synced from peers.
- `scitt.get_configuration()` (unauthenticated) and `scitt.get_checkpoint()`.

All new methods exist on both the sync and async clients.

### Removed

- The `admin.strings` sub-resource (`list_keys`, `list_overrides`, `get_override`, `set_override`, `delete_override`, `list_drift`); the routes were removed from the API.

## [0.8.1] - 2026-05-21

Tracks AGLedger API 0.24.0.

### Changed

- **Breaking, `tenant` and `enterprise` become `org`:**
  - `admin.list_enterprises()` is `admin.list_orgs()`; `admin.create_enterprise()` is `admin.create_org()` (takes `display_name` and `config`; no `slug` or `email`); `admin.get_enterprise_config()` is `admin.get_org_config()`; `admin.update_enterprise_config()` is `admin.update_org_config()` (PATCH semantics); `admin.replace_enterprise_config()` is removed.
  - `admin.deactivate_account(...)` is split into `admin.deactivate_org(org_id, *, reason=None)` and `admin.deactivate_agent(agent_id, *, reason=None)`.
  - `admin.create_agent()` takes a required `org_id` instead of `enterprise_id` (no `slug` or `email`). `admin.records.import_()` takes `org_id`.
  - `audit.tenant_reads_checkpoints` is `audit.org_reads_checkpoints`; `TenantReadsCheckpoint` / `TenantReadsInclusionProof` are `OrgReadsCheckpoint` / `OrgReadsInclusionProof`; paths move from `/v1/audit/tenant-reads/*` to `/v1/audit/org-reads/*`.
  - `RecordRow.enterprise_id` is `org_id`; `OrgReadsCheckpoint.enterprise_id` is `org_id`; `RecordRow.parent_principal_enterprise_matches_performer` is `parent_principal_org_matches_performer`.
  - The `enterprise_id` kwarg is `org_id` on `records.list()`, `records.list_all()`, `records.search()`, `records.create()` and the schema export and import options.
  - Predicate kind `tenant-read` is `org-read`.
- `RecordRow.agent_id` is `RecordRow.performer_agent_id`, and `records.create()` and `records.search()` no longer accept an `agent_id` kwarg; use `performerAgentId`.

### Removed

- `FederationResource` (sync and async): `register()`, `heartbeat()`, `register_agent()`, `list_agents()`, `catch_up()`, `stream()`, `list_types()`, `get_type()`, `publish_schema()`, `confirm_schema_publish()`, `get_record_criteria()`, `submit_record_criteria()`, `broadcast_revocations()`, `rotate_key()`, `revoke()`.
- `FederationAdminResource` (sync and async): `create_registration_token()`, `list_gateways()`, `revoke_gateway()`, `get_health()`, `get_gateway_status()`, `query_records()`, `get_audit_log()`, `reset_sequence()`, `rotate_hub_key()`, `list_hub_keys()`, `activate_hub_key()`, `expire_hub_key()`, `register_peer()`, `delete_schema_version()`, `list_reputation_contributions()`, `reset_reputation()`, `get_record_criteria_encryption_metadata()`. The outbound-DLQ methods `list_dlq`, `retry_dlq` and `delete_dlq` are replaced by the consolidated DLQ methods below.

### Added

- `federation.peer_handshake()`, `federation.submit_co_sign_request()` and `federation.submit_dispute_protocol()`.
- `federation_admin.list_dlq()`, `recover_dlq()`, `get_instance()` and `delete_peer()`.
- `federation_admin.create_peering_token(label=...)` requires `label`, and `federation_admin.revoke_peer(hub_id, reason=...)` requires `reason`.

## [0.8.0] - 2026-05-19

Tracks AGLedger API 0.23.0. SCITT vocabulary alignment, a canonical COSE_Sign1 chain envelope, and a SCITT Transparency Service (SCRAPI) surface.

### Changed

- **Breaking, Receipt becomes Completion.** "Receipt" now means only the SCITT Merkle inclusion proof; the performer's evidence submission is a Completion.
  - `client.receipts` is `client.completions`; `ReceiptsResource` / `AsyncReceiptsResource` are `CompletionsResource` / `AsyncCompletionsResource`; `Receipt`, `VaultReceipt` and `RecordReadReceipt` are `Completion`, `VaultCompletion` and `RecordReadCompletion`.
  - Fields: `receipt_id` is `completion_id` on `OutcomeResult`, `VerificationResult` and `ReportOutcomeParams`; `receipt_hint` is `completion_hint` and `vault_receipt` is `vault_completion` on `RecordRow`; `VerificationResult.receipts` is `.completions`; `cancel_after_receipt_count` is `cancel_after_completion_count`.
  - `schemas.validate_receipt(...)` is `schemas.validate_completion(...)`, with `receipt_ids` as `completion_ids`.
  - Route `/v1/records/{id}/receipts` is `/v1/records/{id}/completions`.
  - Scopes `receipts:read` / `receipts:write` are `completions:read` / `completions:write` (`Scopes.COMPLETIONS_READ` / `COMPLETIONS_WRITE`).
  - Webhook events `record.receipt_submitted` and `record.receipt_invalid` are `record.completion_submitted` and `record.completion_invalid`. `WebhookEventType` has the full 30-value set the API publishes.
  - `AuditExportEntry.integrity.receipt` keeps its name: it is the optional SCITT Receipt, opt-in via `receipts=True` on `get_audit_export`.
- **Breaking, offline verifier format 1.0 to 2.0.** `agledger.verify.verify_export()` decodes canonical COSE_Sign1 envelopes (RFC 9052, tag 18, EdDSA) over in-toto v1 Statement payloads. The `[verify]` extra now requires `cbor2>=5.6` as well as `cryptography>=42.0`. New `EntryFailureReason` values `"cose_decode_failed"` and `"cose_header_mismatch"`. New `VerifyExportResult.signature_coverage` (signed, unsigned, skipped, total): read it or `integrity_level` rather than concluding "Ed25519-verified" from `chain_integrity: True`. New `chain_integrity_reason` value `"payload_drift"`, and a `chain_integrity_detail` field on `AuditExportMetadata`. The `canonicalize()` helper is removed.

### Added

- **SCITT Transparency Service (`client.scitt`)**, implementing `draft-ietf-scitt-scrapi-09` over `application/cose`, with RFC 9290 CBOR problem details on errors. `client.scitt.entries.register(signed_statement: bytes) -> bytes` returns the Receipt; `client.scitt.entries.get(entry_id) -> bytes` returns a Transparent Statement; `client.scitt.keys.list()` and `client.scitt.keys.get(kid)` return a COSE_KeySet (unauthenticated). Async parity on `AsyncAgledgerClient`. `APIError.raw_body: bytes | None` holds error bytes (decode with `cbor2.loads(error.raw_body)`).
- **Predicate schema discovery:** `client.predicates.list()` and `client.predicates.get(kind, version='v1')`, sync and async.
- **Attestation export:** `client.records.get_attestation(record_id) -> bytes` (an `application/cose-sequence` stream of COSE_Sign1 envelopes), `client.records.get_attestation_bundle(record_id) -> dict` (sigstore-bundle v0.3.2 projection, for structural interop only), and `get_audit_export(record_id, receipts=True)` to include SCITT Receipts.
- **Vault checkpoints:** `client.audit.vault_checkpoints.list(record_id=..., cursor=..., limit=...)`, signed Merkle anchors for offline checkpoint cross-checks.
- **Binary I/O** on `HttpClient` / `AsyncHttpClient` (`get_bytes()`, `post_bytes()`) with the same retry and idempotency behavior as the JSON path.

## [0.7.3] - 2026-05-02

### Fixed

- `BulkCreateResultItem.status` is `Literal["created", "replayed", "error"]` (was `int`), so `bulk_create()` parses.

## [0.7.2] - 2026-05-02

### Fixed

- `agledger.verify.verify_export()` accepts the typed `RecordAuditExport` model returned by `client.records.get_audit_export()` as well as a raw `dict`.
- `auth.get_me()` returns the typed `AccountProfile`, and `records.bulk_create()` returns the typed `BulkCreateResult`.
- `RecordAuditExport.export_metadata` is a typed `AuditExportMetadata` sub-model.
- `agledger.verify` raises `ImportError` at import time when `cryptography` is missing. The install message is unchanged: `pip install 'agledger[verify]'`.

### Added

- Typed models `AuditExportMetadata`, `BulkCreateResult`, `BulkCreateResultItem` and `BulkCreateSummary`.

## [0.7.1] - 2026-04-30

Tracks AGLedger API 0.22.13. Adds 10 routes: tenant string overrides admin (`AdminStringsResource`), `federation_admin.get_gateway_status()`, the `agents.list()` peer directory, `compliance.list_vault_checkpoints()` and `disputes.withdraw()`.

## [0.7.0] - 2026-04-27

Tracks AGLedger API 0.21.0, the customer-facing vocabulary change.

### Changed

- **Breaking, Mandate becomes Record.** Every `/v1/mandates/*` route is `/v1/records/*` and the resource is `client.records` (was `client.mandates`). Path params `{contractType}` are `{type}`.
  - Types: `Mandate` is `RecordRow`; `MandateStatus` is `RecordStatus` (adds `RECORDED`); `MandateTransitionAction` is `RecordTransitionAction` (`register | propose | activate | cancel`); `ContractType` is `RecordType`.
  - Record fields: `principal_type` is removed; added `category`, `outcome`, `correlation_id`, `requested_by`, `vault_receipt`, `acceptance_status`, `acceptance_responded_at`, `parent_principal_enterprise_matches_performer`, `commission_amount`, `self_commitment`, `parent_record_id`, `root_record_id`, `child_record_ids`. `parent_mandate_id` is `parent_record_id` and `mandate_id` is `record_id`.
  - Webhook events `mandate.*` are `record.*`; scopes `MANDATES_READ` / `MANDATES_WRITE` are `RECORDS_READ` / `RECORDS_WRITE`.
  - The per-Record audit export is `client.records.get_audit_export()`; `compliance.export_mandate()` is removed.
  - The capabilities body field stays `contractTypes`; the Python kwarg is `contract_types`.
  - Conformance is on `client.discovery.get_conformance()` only; `client.health.conformance()` is removed.
  - Removed types: `AuditChain`, `AccountType`, `MandateStatusSummary`, `DashboardSummary`, `DashboardAgent`, `DashboardAlert`, `Project`, `EnterpriseAgentRecord`, `ApprovalConfig`. `client.events.get_audit_chain()` is removed.
- `VerifyExportResult.mandate_id` is `record_id`; the verifier reads `recordId` from export metadata, falling back to `mandateId` for older exports.

### Added

- `client.records.my_verdict_statistics()`, `list_proposals()`, `batch_get([...])`, `bulk_create([...])` (per-item `idempotency_key` supported) and `get_audit_export()`.
- `client.disputes.list(...)` (`GET /v1/disputes`).
- `client.audit.tenant_reads_checkpoints.{list, get, cosign, proof}`.
- `client.admin.records.{list, import_}` and `client.admin.vault.{anchors{list, verify}, scan{run, status}, signing_keys{list, rotate}}`.
- `client.schemas.meta_schema()`, `blank()`, `import_()`, `preview()`, `disable()` and `enable()`.
- `agledger.record_lifecycle` with `RECORD_TRANSITIONS`, `TERMINAL_STATUSES`, `can_transition_to()`, `get_valid_transitions()` and `is_terminal_status()`, re-exported from `agledger`.
- Errors surface `recovery_hint` and `refresh_url` (RFC 9457), and the top-level `missingScopes` of problem+json bodies is parsed in addition to `details.missingScopes`.

## [0.6.0] - 2026-04-23

Tracks AGLedger API 0.20.0, the principal-model change.

### Changed

- **Breaking, API key role `enterprise` is `admin`.** `ApiKeyRole` is `Literal["admin", "agent", "platform"]`, and the key prefix `ach_(ent|age|pla)_*` is `agl_(adm|agt|plt)_*`.
- **Breaking, scope profiles are renamed and trimmed to 7:** `admin-standard` (default admin), `admin-observer`, `admin-iac`, `admin-schema`, `agent-full` (default agent), `agent-readonly`, `agent-performer-only`. `ScopeProfile` exposes `allowed_roles`. The scope constants `DASHBOARD_READ` and `AUDIT_ANALYZE` are removed and `ADMIN_TRUST` is `ADMIN_BACKFILL`.
- **Breaking, principal model.** Every mandate has a required `principal_agent_id`, and self-commitment is valid. Agent keys default the principal to themselves; admin keys must name the principal. `POST /v1/mandates` is unified across admin, agent and platform callers.
- The audit route `/v1/audit/stream` is `/v1/siem/stream`, and the auth surface is `GET /v1/auth/me` and `POST /v1/auth/keys/rotate`.

### Added

- `client.auth.get_me()` and `client.auth.rotate_key()`; `client.discovery.get_scope_profiles()`, `get_conformance()` and `get_lifecycle()`; the `default_profile_for(role)` helper; and the `agent-performer-only` scope profile.

### Removed

- Resources `dashboard`, `proxy`, `notarize`, `projects`, `registration` and `enterprises`.
- Types `DashboardSummary`, `DashboardAgent`, `DashboardAlert`, `EnterpriseAgentRecord`, `Project`, `ApprovalConfig`, `MandateStatusSummary` and the trust-level types.
- Methods `compliance.analyze()`, `mandates.get_summary()`, the trust-level admin methods and `/v1/audit/enterprise-report*`.

## [0.1.0] - 2026-04-02

### Added

- `AgledgerClient` (sync) and `AsyncAgledgerClient` (async) with 23 resource sub-clients each.
- Error hierarchy: `APIError`, `AuthenticationError`, `PermissionDeniedError` (with `missing_scopes`), `NotFoundError`, `BadRequestError`, `ConflictError`, `UnprocessableError`, `RateLimitError`, `APIConnectionError`, `APITimeoutError`, `SignatureVerificationError`, with `doc_url` and `suggestion` on API errors.
- Auto-pagination via generators (`list_all()` methods).
- Retry with exponential backoff and jitter, honoring `Retry-After`; auto-generated idempotency keys on mutations.
- Webhook signature verification via `agledger.webhooks`.
- Context manager support and an `AGLEDGER_API_KEY` environment fallback.
- Typed Pydantic v2 models with `py.typed` (PEP 561).
- Requires Python 3.10 or newer; depends on httpx >= 0.27.0 and pydantic >= 2.0.0.
