# Changelog

All notable changes to the AGLedger Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.8.0] - 2026-08-07

### Fixed

- **A runtime that cannot compute an algorithm no longer reads as tamper.** With the OpenSSL FIPS provider active there is no EdDSA, so `cryptography` refuses a perfectly good Ed25519 key: depending on how it was built, either the key fails to load or `verify()` raises `UnsupportedAlgorithm`. Both were caught and reported as `CHAIN_SIGNATURE_INVALID`, which is indistinguishable from a forgery, so a FIPS-locked auditor verifying an intact chain got `0/N verified` and a tamper report on a chain that is fine (agents#113, found in the TS verifier and mirrored here).

  `verify_export` now proves runtime capability before dispatching, by checking a fixed known-answer signature for the algorithm. When the runtime refuses, the result is `CHAIN_UNSUPPORTED_ALGORITHM` with `signature="unsupported"`, whose detail names the FIPS provider as the cause and says to re-run on an unrestricted host. Still fail-closed: `valid` stays `False`, because an uncheckable chain is not a verified chain. The known-answer vectors are fixed bytes shared with `@agledger/verify-core`, so nothing in the audited export can influence whether a signature failure is reported as "not checked".

  ES256 chains were never affected and still verify on a FIPS host.

  When the host refuses the key at LOAD rather than at verify, the verdict was already right but the detail line was not: with no key object to resolve, it fell through to the generic "upgrade the verifier" text, which sends a FIPS auditor to replace a build that is not the problem and never can be. That path now produces the same host-refusal sentence as the other one.

- **A FIPS-locked receiver no longer rejects every legitimate webhook as forged.** The same defect on the webhook surface: verifying an ed25519 delivery raises, the raise was caught and returned as `False`, and every documented caller turns that into a 401. `verify_rfc9421` and `construct_event_rfc9421` now raise `SignatureAlgorithmUnavailableError` when the host cannot compute the key's algorithm.

  **On such a host, no ed25519 delivery can be classified at all**, valid or forged: the check necessarily precedes signature verification, so a genuine forgery raises too. That is the honest result, since nothing was computed and nothing is known, but do not read the exception as evidence a delivery was legitimate. On every host that can compute the algorithm, which is all of them absent a FIPS-style restriction, behavior is unchanged and bad deliveries still return `False`. Deliveries rejected upstream of the key (a tampered body, a missing signature header) still return `False` everywhere.

### Added

- **`SignatureAlgorithmUnavailableError`**, carrying the `algorithm` that could not be computed. Distinct from `SignatureVerificationError` because the two call for opposite responses: one is your server's configuration, the other is a rejected delivery.

### Changed

- **`verify_rfc9421` can now raise**, where before it only ever returned a bool. It raises only where the old code returned a wrong answer, so no correct caller changes behavior: a receiver that could verify ed25519 still verifies it, and a bad signature still returns `False`. On a host that cannot compute the algorithm, the standard `if not ok: return 401` becomes an uncaught exception and a 500, which is the right status for a server misconfiguration.
- **`CHAIN_SIGNATURE_INVALID`'s remediation text no longer hardcodes "Ed25519"**, which has been wrong since ES256 verification landed and which compounded the bug above by naming the one algorithm that had not been computed. **`CHAIN_UNSUPPORTED_ALGORITHM`'s** text now names both of its causes and states that the result is not tamper evidence.

### Changed (breaking for a client that never worked)

- **`base_url` is now required.** It defaulted to `https://agledger.example.com`, a placeholder that resolves nowhere, so `AgledgerClient(api_key=...)` constructed fine and then failed every call against a host the caller never named and could only find by reading the SDK source. Omitting it now raises `ConfigurationError` at construction, where the mistake is. Every AGLedger deployment is self-hosted, so there was never a sensible default. This is the same fix the TypeScript SDK shipped at 1.7.0 (agents#109) and the CLI at 1.3.0 (agents#105); the Python client kept the placeholder through both, so the three clients disagreed about the same mistake. No working integration can be affected: a client with no base URL could never reach a Server. `api_key` still falls back to `AGLEDGER_API_KEY`.

### Added

- **`ConfigurationError`**, exported from the package root. Extends `AgledgerError`, not `APIError`, because nothing was sent: it is not a rejected request, and a caller catching `APIError` for server-side failures must not swallow it.

### Fixed

- **`discovery.get_scope_profiles()` was annotated `list[dict]` and has always returned the page envelope** (`{"data": [...], "total", "hasMore", "nextCursor"}`). Iterating the result gave you the envelope's keys. Now annotated `dict[str, Any]`, matching the other envelope-returning admin reads.

- **Verifier remediation text drifted from `@agledger/verify-core`.** The module says it mirrors that file exactly, and after a punctuation pass on the TypeScript side six failure codes were telling auditors different things in the two languages. The strings match again, and a new test compares all 29 codes verbatim against the sibling checkout so this cannot drift silently. `suggestion(code)` wording changed for thirteen codes; no verdict or code changed.

## [1.7.0] - 2026-08-07

### Fixed

- **Vault checkpoints join on `chain_key`, so a healthy schema chain no longer fails.** A schema chain's checkpoint carries a derived UUIDv8 in `record_id` (the engine needs a non-null uuid for a chain whose rows have none), which matches no `audit_vault` row. Grouping checkpoints by that column stranded them, and a stock install returned a `CHECKPOINT_ROW_MISSING` failure on a vault nobody had touched: a tamper alarm for any audit gate wired to the exit code. Checkpoints now group on the producer's `chain_key`, falling back to `record_id` so dumps taken before the producer emitted it verify exactly as before. Failures also name a schema chain as `Chain schema:<orgId>` rather than `RecordRow <uuidv8>`, which sent auditors to `/v1/records/{id}` for a 404 (agents#103).

### Changed (widened union)

- **`CHAIN_KEY_NOT_YET_ACTIVE`** is now reported for an entry written BEFORE its signing key's activation. Both directions of the temporal key-window check previously reported `CHAIN_KEY_EXPIRED`, so a consumer branching on the code was told "expired" about a key that had not started yet and would investigate rotation or retention when the real condition is a backdated entry or clock skew. `CHAIN_KEY_EXPIRED` now means the retirement side only. Verdicts are unchanged: what failed before still fails (agents#112).

## [1.6.1] - 2026-08-07

No code change from 1.6.0. That release was uploaded from a local session rather than by the tag-triggered workflow, so it carries no PEP 740 attestations; this version restores attested, provenance-carrying builds as the published artifact. Prefer it over 1.6.0 if you check attestations.

## [1.6.0] - 2026-08-05

Signing-agility wave 2: ES256 verification across the offline and webhook surfaces. Ed25519 paths behave identically to 1.5.1.

### Added

- **`agledger.verify` verifies ES256 chains** (export and dump paths). A verification key whose SPKI commits to P-256 dispatches to ECDSA/SHA-256 over the COSE raw `r||s` signature encoding; both the `-7` (ES256) and RFC 9864 `-9` (ESP256) header code points are accepted. Dispatch still binds to the trusted key material, never the header, and ES384/ES512/ES256K still fail closed as `CHAIN_UNSUPPORTED_ALGORITHM`.
- **`verify_rfc9421` / `construct_event_rfc9421` accept `ecdsa-p256-sha256` deliveries** (raw `r||s` per RFC 9421), emitted by Servers signing with a P-256 vault key. The declared `alg` parameter is asserted against the resolved key's type, never trusted for dispatch; unsupported key types fail closed.

### Changed

- **Conformance corpus regenerated from engine 1.3.4 @ `ed3369ab`** (full corpus, including the ES256 wave: `valid-es256` export + dump, `es256-signature-invalid`, `es256-header-alg-mismatch`).

## [1.5.1] - 2026-08-05

### Fixed

- **An empty-string signing-key id is no longer treated as the unsigned-mode marker**, in both the export walker and the dump checkpoint/signed-tree-head pass. Only a true `None` is; any other value, including the `""` no engine emits, must resolve in the key registry and fails `CHAIN_SIGNATURE_MISSING_KEY`. Previously a truthiness shortcut let a tampered `signingKeyId: ""` row or checkpoint skip its signature check.

## [1.5.0] - 2026-08-05

The verifier forward-compatibility floor, mirroring `@agledger/verify-core` 1.1.0. Legitimate Ed25519 exports and dumps verify identically; what changes is fail-closed classification of tampered and non-Ed25519 inputs.

### Changed

- **Algorithm dispatch binds to the trusted verification key, never the protected header.** The header `alg` (label 1) is asserted equal to what the key's SPKI material commits to; a missing, unassigned, or foreign value fails `CHAIN_ALG_MISMATCH` (tamper class). A key whose algorithm this build cannot compute fails closed as `CHAIN_UNSUPPORTED_ALGORITHM` (previously it surfaced as a misleading `CHAIN_SIGNATURE_MISSING_KEY`). Ed25519 accepts COSE alg `-8` and the RFC 9864 fully-specified `-19` interchangeably.
- **Signed-kid binding (`CHAIN_SIGNING_KEY_DRIFT`).** The signature-covered kid (label 4) is cross-checked against the row's `signingKeyId` column, mirroring the engine's `signing_key_drift` check (#893).
- **Registry algorithm cross-check.** The dump's `vault_signing_keys.algorithm` is compared against the key material itself; a registry row that lies about its own key fails `CHAIN_ALG_MISMATCH`.
- **Untagged COSE_Sign1 is rejected** (leading byte must be `0xd2`), matching the engine's decoder.
- **The all-zero unsigned sentinel is evaluated after algorithm resolution, at the key's expected signature length**, and an all-zero signature on an entry that claims a signing key fails `CHAIN_KEY_POLICY_VIOLATION` under `require_key_id` / `require_out_of_band_keys`.
- **Checkpoint and signed-tree-head signature checks fail closed on every non-ok outcome**, including the previously-passing all-zero signature on a key-claiming checkpoint.
- `FailureCode` gains `CHAIN_ALG_MISMATCH`, `CHAIN_UNSUPPORTED_ALGORITHM`, `CHAIN_SIGNING_KEY_DRIFT`; the per-entry `signature` state gains `"unsupported"`.
- Conformance corpus refreshed from engine 1.3.4, including the new kid-drift and registry-lie vectors.

## [1.4.0] - 2026-08-03

### Changed

- **Minimum Python is now 3.11** (was 3.10). Python 3.10 reaches end-of-life on 2026-10-31 and stops receiving security fixes; this drops it ahead of that date rather than on it. The SDK carried no 3.10-specific compatibility code, so nothing in the library changes behaviour.
- **If you are on Python 3.10, note how pip handles this.** `requires-python` is enforced at resolve time and pip does not error on an older interpreter: `pip install agledger` on 3.10 will silently resolve to 1.3.0, the last release that permitted it, and stay there. You will not see a warning, you will just stop receiving updates. Upgrade to Python 3.11 or newer to continue tracking releases.

## [1.3.0] - 2026-08-01

Tracks API v1.3.4. Additive; no wire or behavior change.

### Added

- `ComplianceExport.truncated` and `.total_records` (API #968/#991). The org-wide export is capped at 10000 rows, newest first. Before this the response carried only `record_count`, so a truncated export was indistinguishable from a complete one and a compliance packet could silently omit most of the trail. Window with `filters.from` / `filters.to` to cover the rest. On a download the same answer rides the `X-AGLedger-Export-Truncated` and `X-AGLedger-Export-Total-Records` response headers, which are the only carriers for a `csv` download, since the body is raw rows and a notice line would corrupt the parse. Both are `None` on a pre-1.3.4 server, which means unknown and is deliberately not the same as `False`.
- `VaultCheckpoint.chain` plus the `VaultCheckpointChain` alias (`"record" | "schema" | "admin"`, API #995). Three chains are checkpointed by the same signed construction, and **only `chain == "record"` is keyed by a real record id**. On `"schema"` and `"admin"` the `record_id` is a derived key that resolves to no record, so fetching it 404s by design. `None` on a pre-1.3.4 server.
- `VaultCheckpoint` and `VaultCheckpointChain` are now exported from the package root. `VaultCheckpoint` was reachable only as `agledger.types.VaultCheckpoint`, even though `audit.vault_checkpoints.list()` returns them and its sibling `OrgReadsCheckpoint` was already exported.

### Notes

- Route surface is unchanged: 193 routes, no additions, no removals, no request-field drift against the live v1.3.4 spec. Every delta above is in a response body, which is the surface neither parity snapshot pins, so `tests/test_v1_3_4_contract.py` was added to guard it.
- The parity snapshots were stale at API 1.2.0 and are refreshed to 1.3.4. They were missing `deadline` on `ErrorResponse` and `RateLimitError`, a field the SDK's own error model has carried since 1.3.2, so the pin had drifted behind the code rather than the code behind the API.
- Verified against a live API v1.3.4, not only mocks: the export fields were read off a real response (`truncated: false`, `total_records: 6`, all three `X-AGLedger-Export-*` headers present).

## [1.2.2] - 2026-07-16

Docs only. No wire change.

### Fixed

- Corrected the licensing claim (cross-repo #99): federation and multi-node are free on the bundled database; only an external or managed database requires an Enterprise license. The prior text wrongly listed federation and multi-node as gated.

### Changed

- Corrected the PyPI summary and positioning, and removed dead vocabulary from the README (#99).

## [1.2.1] - 2026-07-13

Patch: robustness and parity follow-ups from a self-review of 1.2.0. No wire changes.

### Added

- **`APIError.deadline`**: the ISO deadline carried on a system TIME_OUT 422 (API v1.3.2) is now surfaced as an attribute, matching the TS SDK's `ApiErrorResponse.deadline`. Previously it was parsed off the top-level error body by nothing and was unreachable.

### Note

- `SignedStatement.signed_at` was already optional (`Field(None, ...)`) in 1.2.0, so no change was needed on the Python side for the signedAt consistency fix that the TS SDK made in 1.3.1.

## [1.2.0] - 2026-07-13

Tracks AGLedger API **v1.3.2** (was v1.2.0). Route surface is unchanged (193 routes); the API delta is additive response fields, a new event type, and a new audit-export option. Live-validated end-to-end against a local API v1.3.2 (record create, principal-gate verdict, `?evidence=true` export).

### Added

- **`SignedStatement.signed_at`** (API #877): the signed instant of the head Signed Statement (the CWT `iat` claim sealed in the COSE_Sign1 protected header, second precision). The authoritative timestamp for time-anchored contracts (statutory wait windows, notice clocks); the record's millisecond `created_at` only approximates it. Nullable, wire name `signedAt`.
- **`VerdictResult.record_status`** (API #876): the settled record status (`FULFILLED` on accept, `FAILED` on reject) returned inline on `records.submit_verdict()`, so the outcome is known without a follow-up `records.get()`.
- **`record.gate_held` webhook event** (API #913): a principal-mode record held at PROCESSING awaiting the verdict emits this event; the payload carries the `completionId` to verdict against plus the engine/rollup advisory. Added to `WebhookEventType`.
- **`records.get_audit_export(id, evidence=True)`** (API #870): inlines the completion evidence body at each COMPLETION_SUBMITTED entry (`AuditExportEntry.evidence`) — an UNSIGNED projection the chain binds by hash via `payload.evidenceHash`. JSON/NDJSON only.
- **`chain_integrity_reason`** gains `signature_invalid`, `signing_key_unknown`, `signing_key_drift` (API #888/#893): the vault now fails closed on per-entry signature verification and surfaces the specific failing invariant.

## [1.1.0] - 2026-07-06

Tracks AGLedger API **v1.2.0** (was v1.1.0). Route surface is identical (193 routes); the API delta is additive, and this release also replaces a schema-import surface that had drifted so far from the shipped API that it could not work. Live-validated against a local API v1.2.0.

### Added

- **Webhook `record_types` filter** (API #825): `webhooks.create()` and `webhooks.update()` accept `record_types`, and the `Webhook` model carries it back (wire name `recordTypes`). `["*"]` means all record types (wildcard sentinel); any other list means record-scoped events are delivered ONLY for the listed types (fail-closed). Omit for no filter.
- **`records.accept(record_id, message=None)`** (API #855): optional acceptance rationale, symmetric with `reject()`. The API stores one rationale field; `reason`/`notes` are wire-level aliases of `message` on all four handshake endpoints (#780).

### Fixed

- **`schemas.import_()` now works.** It previously sent a schema *export bundle* body with `orgId` (and a nonexistent `dryRun`) in the query string; the shipped API has required a `manifest` body since the Schema Catalog redesign, so every call failed with 400. The method now takes the manifest dict plus row-only options as keyword arguments (`org_id`, `federatable`, `defaultShare`, `defaultGateMode`, `coSignRequired`, `flipRecordStatusOnDispute`, `federateDisputes`) in the body, and returns the created/existing subject row (HTTP 200 on an idempotent re-post, 201 on create).

### Removed

- **`schemas.preview_import()` and the `dry_run` flag.** The API has no dry-run on `/v1/schemas/import`; the flag was silently ignored, so a "preview" would have performed a real import had the body ever validated. Use `schemas.preview()` for pre-registration validation of locally authored schemas.

### Changed

- Parity snapshots regenerated to `apiVersion 1.2.0`.

Semver note: this is a minor, not a major, because the removed/reshaped import surface was inoperable against every shipped v1.x API (each call 400d), so no working integration can regress.

## [1.0.4] - 2026-06-29

### Changed

- Docs only: removed em-dashes from the README prose (cross-repo #98 writing-style sweep). Rewrote each sentence rather than swapping the glyph. No code, type, or runtime change.

## [1.0.3] - 2026-06-29

Tracks AGLedger API **v1.1.0** (was pinned to v1.0.3). Route surface is identical (193 routes); this is a field- and doc-level sync. All changes are backward-compatible.

### Added

- **`Completion.settlement_signal`** (API #816): the auto-gate's settle/hold/reject decision, surfaced inline on a submitted Completion so the caller learns the outcome without a follow-up `records.get`. Typed `CompletionSettlementSignal` (`recommendation`, `outcome`, `reason_code`); `None` when the gate did not render inline (encrypted Records, principal-mode held at PENDING_VERDICT, or skipped).
- New exported type: `CompletionSettlementSignal`.

### Changed

- `reason_code` docs note the new `AUTO_SETTLE_WITHIN_TOLERANCE` value (API #824): an auto-settle that cleared only via a non-zero tolerance band rather than the base criteria threshold. The field stays `str | None`.
- Gate-mode docs no longer say "the rules engine renders the verdict": auto mode auto-settles against the principal's pre-configured predicates; the verdict is always the principal's and AGLedger only holds the signed decision.
- Parity snapshot regenerated to `apiVersion 1.1.0`. (`schemas.list()` already returns raw dict rows, so the new `defaultGateMode` field on catalog rows is passed through without a type change.)

## [1.0.2] - 2026-06-22

Tracks AGLedger API **v1.0.3** (was pinned to v1.0.0). A full route + field-level drift sweep against the live v1.0.3 OpenAPI surfaced three additive method gaps and one spec removal; parity snapshots regenerated to `apiVersion 1.0.3` (193 routes). All additions are backward-compatible.

### Added

- **`records.get(record_id, integrity=True)`** (sync + async) — re-verify the Record's audit chain and cross-check the served row against it (API #732). The result is exposed on the new `RecordRow.integrity` field (typed `RecordIntegrity`: `verified`, `integrity_level`, `reason`, `entries`, `projection_checked`, `drift_fields`).
- **`records.list(actionable=True)` / `list_all(actionable=True)`** (sync + async) — the agent-recovery query: every Record whose next action awaits the caller's structural side (API #731). Agent keys only.
- **`auth.rotate_key(grace_period_seconds=...)`** (sync + async) — keep the old key valid for an overlap window instead of an immediate hard cutover (API #793).
- New exported type: `RecordIntegrity`.

### Changed

- `admin.create_org()` is documented as **dev/test-only** — `POST /v1/admin/orgs` was dropped from the canonical API spec in v1.0.1 (never registered in production; provision prod orgs via operator `provisioning/` YAML). The route-parity test no longer asserts it as a canonical route.

### Notes

- `compliance.export(**params)` and the schema methods already pass `embed` / `default_gate_mode` through verbatim (untyped passthrough), so the API #771 / defaultGateMode additions need no method change.

## [1.0.1] - 2026-06-10

### Changed

- **License re-sync.** `LICENSE` is now a verbatim copy of the canonical AGLedger SDK license template **v1.5**: §7 trademarks trimmed to **AGLedger + Settlement Signal (pending)** (removed the retired "Agentic Ledger" / AOAP claims), §6 export language modernized to ENC §740.17(b)(1) mass-market self-classification, and §1 carries the no-inspection / no-training / no-usage-data representation. README: dropped the retired AOAP protocol link.
- No code changes; republished so the distributed tarball carries the corrected license text.

## [1.0.0] - 2026-06-08

General-availability release, tracking AGLedger API **v1.0.0 GA**. No breaking changes from the 0.8.x line. Route surface and field-level parity snapshots verified identical to API v1.0.0 (194/194 routes, zero drift across tracked models); parity snapshots bumped to `apiVersion 1.0.0`.

### Added

- `WebhookEventType`: `record.proposal_counter_proposed`, `record.ai_impact_assessment_filed`, `record.compliance_attestation_filed`.

### Fixed

- The SDK version (`agledger.__version__` **and** the `User-Agent` header) is now derived from installed package metadata via `importlib.metadata`, single-sourced in `_http.SDK_VERSION`. Both had drifted to a hardcoded `0.8.12` while the package shipped 0.8.13–0.8.15, so released versions were under-reporting their version to API telemetry. They can no longer fall out of sync with the published distribution.

## [0.8.15] - 2026-06-04

No functional change to the SDK. CI + release-pipeline hardening:

### Changed

- **CI now tests the full advertised Python range (3.10–3.13).** The CI job is a `fail-fast: false` matrix across Python 3.10, 3.11, 3.12, and 3.13, running every gate (ruff, pyright `--verifytypes` at 100%, pytest) on each — the package advertises `requires-python = ">=3.10"` and 3.10–3.13 classifiers, so the matrix now matches what is promised.
- **Pinned release-job build/SBOM tooling** (`build==1.5.0`, `cyclonedx-bom==7.3.0`) so a breaking upstream release can't red-fail a tag push or alter the SBOM shape.

## [0.8.14] - 2026-06-04

No functional change to the SDK. Release-pipeline hardening:

### Changed

- **Signed CycloneDX SBOM attestation** via `actions/attest` (the deprecated `actions/attest-sbom` was replaced), in addition to PyPI's PEP 740 publish attestations.
- **SBOM scoped to the shipped wheel.** The CycloneDX SBOM now describes only the published wheel's runtime dependencies (generated from a throwaway venv containing just the built wheel), not the release runner's full dev/test toolchain.
- **Concurrency guard** on the release workflow so two tags pushed in quick succession can't race into a double-publish.

## [0.8.13] - 2026-06-04

No functional change. First release published from CI with **build provenance** via PyPI trusted publishing (OIDC) — PEP 740 attestations are produced automatically by `gh-action-pypi-publish`. A CycloneDX SBOM is attached to the release. This package now lives in its own source-of-truth repo `agledger-ai/sdk-python` (parity snapshots + conformance corpus vendored in-repo).

## [0.8.12] - 2026-06-02

### Added — turnkey offline dump verifier + `agledger-verify` CLI (closes [agledger-agents#81](https://github.com/agledger-ai/agledger-agents/issues/81), F-708 follow-up)

The Python sibling of the TypeScript `@agledger/verify` full-vault dump verifier. Healthcare/financial compliance reviewers who standardize on Python can now verify an AGLedger audit dump offline without writing the COSE_Sign1 / Ed25519 / chain-integrity logic by hand.

- **`agledger-verify` console script** (ships with the `[verify]` extra: `pip install 'agledger[verify]'`). Auto-detects its argument: a directory is a five-file NDJSON dump; a file is a single `/audit-export` JSON document. Exit codes: `0` clean, `1` verification failure, `2` usage/IO error. Supports `--report-format text|json` and `--quiet`; no network calls.
- **`verify_dump(load_dump(dir)) -> VerifyReport`** API. Walks every per-record and per-org schema-event hash chain, cross-checks vault checkpoints against the live chain, and verifies the `org_admin_reads` Merkle log + signed tree heads (including fork detection). Reuses the export verifier's COSE/chain core, so the binding-integrity, OIDC-actor, and temporal key-validity checks come from one shared body — no duplication.
- New dump-path failure codes now reachable from Python: `CHAIN_OIDC_ACTOR_MISMATCH`, `CHAIN_KEY_EXPIRED`, `CHECKPOINT_ROW_MISSING/HASH_MISMATCH/SIGNATURE_INVALID`, and the full `TENANT_*` Merkle/STH/fork set. The canonical `FailureCode` taxonomy now lives in `agledger.verify.failures` with a `suggestion(code)` next-step helper.
- Replays the shared `manifest-dump.json` conformance corpus (apiVersion 0.26.5) in the test suite alongside the export corpus — the cross-language anti-drift seam now covers both verifiers. Validated live: turnkey install + end-to-end runs against real and freshly-tampered dumps.

The dump path's only third-party needs are `cbor2` + `cryptography` (the `verify` extra); it imports neither `pydantic` nor `httpx`.

### Changed — EU AI Act sync to API v0.27.0/v0.27.1 (validated live)

- `RiskClassification` gains `unacceptable` (Article 5 prohibited tier); the AI-impact-assessment `domain` enum is reconciled to the API's Annex III high-risk set, surfaced as the shared `EuAiActRiskTier` + `EuAiActDomain` literals.
- `WebhookEventType` reconciled to the API set (37 event types + the `*` wildcard; open literal).
- Dropped the retired ACH-* built-in contract-type model (the API deleted the built-ins; orgs own their entire type namespace, with four editable samples auto-seeded).

### Fixed — `compliance.create_assessment` ergonomics ([agledger-agents#88](https://github.com/agledger-ai/agledger-agents/issues/88), F-740)

- `create_assessment` (sync + async) was a raw `**params` passthrough that required camelCase keys, so the idiomatic snake_case call 400'd against the `additionalProperties:false` route. It now takes explicit typed kwargs (`risk_level`, `domain`, `human_oversight`, `testing_results`) and maps snake→camel internally, matching its sibling `create_record`.

### Internal

- Public type surface raised to 100% `pyright --verifytypes` completeness (annotations only, no API/behavior change); the completeness check is now a CI gate so it can't silently regress.

## [0.8.11] - 2026-06-02

### Fixed — 0.26.x response/field drift sweep (validated live against API v0.26.5)

Mirrors the TypeScript SDK 0.8.13 sweep. A full minor of API field-shape drift had accumulated while the route surface stayed in sync:

- **`RecordRow`**: renamed `vault_completion` → `signed_statement` (closes #87) and `self_commitment` → `self_principal`; dropped `no_op`. Added 17 fields: `settlement_signal`, `counter_signature`, `co_sign_required`, `co_sign_status`, `federation_status`, `dispute_id`, `dispute_status`, `has_dispute`, `has_children`, `latest_completion_id`, `terminal_reason`, `expired_at`, `awaiting_actor`, `share`, `shared_to_peers`, `source`, `imported`.
- **Model rename** `VaultCompletion` → `SignedStatement` (drops `signature`, adds `url`). New `SettlementSignalSummary` model.
- **`Completion`**: added `verdict`, `last_verdict_reason`.
- **`NextStep`**: added `after_this`, `workflow_label`, `workflow_step`, `workflow_total`.
- **`Webhook`**: full subscription shape — `secret_grace_active`, `secret_grace_expires_at`, `circuit_state`, `consecutive_failures`, `last_successful_at`, `last_failure_at`.
- **`WebhookEventType`**: added `dispute.escalated`, `dispute.evidence_window_closed`, `record.released`, `record.settled`.
- New **`EntityReference`** and **`DisputeEvidence`** models (`DisputeResponse.evidence` now typed).
- **`records.list` / `list_all`** (sync + async): added `type`, `performer_agent_id`, `role`, `from_`, `to`, `has_dispute`, `dispute_status`, `imported`, `source` filters.

## [0.8.10] - 2026-05-29

Closes [agledger-agents#83 (F-730)](https://github.com/agledger-ai/agledger-agents/issues/83) and [#84 (F-731)](https://github.com/agledger-ai/agledger-agents/issues/84).

### Fixed

- **`records.get_chain()` crashed with a Pydantic `ValidationError` on every call.** It iterated the paginated response dict's keys instead of `data["data"]`, validating the string `"data"` as a `RecordRow`. It now unwraps the envelope via the page helper (tolerant of a bare-array shape too). Same bug class as the 0.8.9 F-713 fix. (F-730)

### Added

- **Offline `verify_export()` now detects denormalised-payload tampering** — the export's own verificationGuide step 4 (F-731). When an export entry carries the row `payload`+`entryType` (engine ≥ v0.26.x), the verifier re-decodes the signed predicate from `coseSign1` and deep-equals it against the row projection; a `payload` rewritten while `coseSign1` stays intact fails `CHAIN_PAYLOAD_BINDING_MISMATCH`. Ports `build_predicate_for_row`/`decode_predicate` from `@agledger/verify-core`; adds the `not-checked` signature state for parity (F-732). Validated against a live engine v0.26.4.

## [0.8.9] - 2026-05-28

Closes [agledger-agents#82 (F-713)](https://github.com/agledger-ai/agledger-agents/issues/82) and [#80 (F-710)](https://github.com/agledger-ai/agledger-agents/issues/80), plus a codebase-wide sweep for the same two bug classes (required-field model drift that crashes Pydantic; request-body params the API rejects). Every fix was verified against the live API schemas.

### Fixed

- **F-713 (MAJOR, breaks the headline verification flow)**: `records.get_audit_export()` no longer crashes Pydantic. `AuditExportEntry` required `description`, but the engine renamed it to `humanReadableLabel` and dropped `description` (F-711). Every entry failed validation. The field is now `human_readable_label` (optional); the model also gained the F-705 actor-display fields (`actor_owner_id`, `actor_display_name`, `actor_owner_type`).
- **F-710 (LOW, advertise-but-doesn't-work)**: `completions.submit()` no longer sends a root-level `notes` key — the API rejects it (`additionalProperties: false`). Removed `notes`; added `evidence_hash` (the genuinely-supported field, for encrypted mode), reaching parity with the TS SDK. Carry AI-agent rationale inside `evidence` via a `completionSchema` field.
- **Same-class crashes found in the sweep** — required fields the server renamed/dropped, which crashed on every call:
  - `AgentProfile` / `AgentDirectoryEntry`: required `name`/`slug`/`updatedAt`/`isActive`; the engine emits `displayName` and none of the others. `agents.get()` / `agents.list()` crashed.
  - `Event`: wire fields are `type` and `data`, not `eventType` / `payload`. `events.list()` crashed.
  - `OrgReadsCheckpoint`: timestamp is `checkpointAt` (not `createdAt`); signed envelope is `coseSign1Base64`. `OrgReadsInclusionProof`: audit path is `path` (not `proof`), no `checkpointId`.
  - `ReputationScore`: scores are nullable (a fresh agent has no history); `confidence_level` is a number not a string; `formula_version` is an integer not a string; the lifetime counters are `lifetime_records`/`lifetime_verdicts`/`lifetime_accepted`/`lifetime_completions`/`reversals`.
  - `AiImpactAssessment.human_oversight` is an object, not a bool.
- **Same-class rejected request bodies found in the sweep** (`additionalProperties: false`):
  - `records.create()`: dropped `category` and `proposal_message` — never valid create inputs.
  - `records.reject()`: sends `message` (the only key the reject route accepts), not `reason`.
  - `webhooks.update()`: takes `is_paused`; dropped `format` (signing scheme + payload format are fixed at create time).
  - `admin.update_api_key()`: no longer anticipates `expires_at` / `allowed_ips` (settable only at create).
  - Federation `submit_state_transition()` / `relay_signal()`: rewritten to the current wire contract (were on a pre-v0.24 shape where every field was rejected and required fields were missing).
- **Removed `compliance.get_ai_act_report()`** — it called `/v1/compliance/eu-ai-act/report`, a route that does not exist (404). The TS SDK never had it.

### Changed

- **Testing**: pytest now sets `pythonpath = ["src"]` so the suite runs against the working tree, not a stale installed wheel. Without this, prior runs silently validated the last *published* version — the root cause that let F-713/F-710/F-706 ship. Added `tests/test_response_contract.py` round-tripping each model against real-server-shaped payloads, and populated the previously-empty `get_audit_export` entry fixture.

## [0.8.8] - 2026-05-28

Closes [agledger-agents#77 (F-698)](https://github.com/agledger-ai/agledger-agents/issues/77), [#78 (F-702)](https://github.com/agledger-ai/agledger-agents/issues/78), and [#79 (F-706)](https://github.com/agledger-ai/agledger-agents/issues/79). Brings the Python SDK into TS-SDK behavior parity on retry policy and rate-limit observability.

### Fixed

- **F-706 (HIGH, auditor-blocking)**: `client.verification_keys.list()` no longer crashes Pydantic on the live engine response. The model required `hashAlgorithm`, which the engine doesn't always emit (it's an implicit COSE/Ed25519 default). Made optional. Without this fix the load-bearing call for the independent-offline-audit story crashed before returning.
- **F-706 follow-on**: `RecordAuditExport.entries[].position` / `timestamp` were the pre-v0.25 wire names; current engines emit `chainPosition` + `createdAt`. Both old and new names now parse cleanly. The `AuditExportEntry` model gained the modern actor fields (`actorId`, `actorRole`, `actorOidcIss`, `actorOidcSub`, `actorOidcSynthesized`) and `recordId` to match the engine wire.
- **F-698 (HIGH, audit-independence)**: `agledger.verify.verify_export(public_keys=…)` now accepts the natural `client.verification_keys.list().data` list shape — list of `VerificationKey` Pydantic models or dicts of that shape — in addition to the compact `{keyId: spki_b64}` mapping. The wrong shape raises `TypeError` at the boundary rather than silently falling back to embedded keys (`key_provenance.out_of_band == 0` with `valid: True`). Polymorphic field-name access via `keyId`/`key_id` and `publicKey`/`public_key` uses `in`/`is None` rather than `or`, so an empty-string keyId no longer silently substitutes the snake_case sibling. Empty strings are rejected with an accurate diagnostic.
- **F-702 (LOW)**: `Verdict` type widened to `Literal["accept", "reject"] | str` for forward compatibility. Note: under PEP 604, the literal arm collapses to plain `str` for static analyzers; this is documentation parity with the TS SDK's open verdict union rather than a type-system enforcement.

### Added

- `agledger.RateLimitInfo` dataclass and `client.rate_limit_info` / `async_client.rate_limit_info` properties — parity with the TS SDK's `RateLimitInfo`. Populated from `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset` on every response that carries them; `None` until the first such response.

### Changed

- Retry policy aligned with the TS SDK: `DEFAULT_MAX_RETRIES = 3` (was 2), `MAX_BACKOFF = 30.0s` (was 8.0s), retry-set `{429, 500, 502, 503, 504}` (was `{408, 409, 429, 500, 502, 503, 504}`). **Dropped 409 from auto-retry** — a 409 IDEMPOTENCY_CONFLICT means the same idempotency key was used with a different request body, which is structural, not transient; auto-retrying was masking real client errors. Dropped 408 because the API never emits it. Worst-case retry latency on persistent 5xx went from ~14s to ~63s (`1 + 2 + 4 + 8 + 16 + 30` jittered) — matches TS SDK behavior.

## [0.8.7] - 2026-05-27

Verifier consolidation (Pass 1). Mirrors the TypeScript wave (`@agledger/verify-core`). The Python `agledger.verify` module emits the same canonical failure taxonomy and key-provenance signals as the shared TypeScript core, and now runs the shared conformance corpus as an anti-drift seam against it.

### Changed (BREAKING — `agledger.verify` result shape, pre-1.0)

- Failure reasons are now canonical SCREAMING_SNAKE `FailureCode` values. `broken_at.reason` is renamed to **`broken_at.code`**.
- The result now surfaces **key provenance** — whether each verified entry's public key came from out-of-band (caller-supplied) keys or was embedded in the export.
- New **`require_out_of_band_keys`** option: fail closed unless every signature is verified against a caller-supplied (out-of-band) key, rejecting keys embedded in the export. For high-assurance audits.

### Changed

- The verifier now runs the shared conformance corpus (the DUMP-kind and record-export vectors generated by the TypeScript core), keeping the Python and TypeScript verifiers byte-for-byte aligned on what passes and what fails.

## [0.8.6] - 2026-05-27

### Fixed

- **Offline audit verifier rejected valid exports (F-682).** `agledger.verify` read the legacy `position` field on each export entry, but current exports (v0.25+) emit `chainPosition`. With `position` absent, every valid export failed with a false `position_gap` on the first entry. The verifier now reads `chainPosition`, falling back to `position` for pre-v0.25 exports. Verified end-to-end against a live export. (Same root cause was present in `@agledger/cli` and `@agledger/mcp-server`, fixed in lockstep.)

## [0.8.5] - 2026-05-27

Tracks AGLedger API v0.25.5. Mirrors the TypeScript SDK 0.8.5. The API renamed its second pillar **Verify → Gate** and now reserves "verify" exclusively for cryptographic verification. This release renames the gate/verdict surface to match. Cryptographic verify surfaces — `agledger.verify`, webhook signature verification (`verify_signature`/`verify_rfc9421`), and `client.verification_keys` — are **unchanged**.

### Breaking — Verify → Gate

- `client.verification` → **`client.gate`**. `verification.verify()` → **`gate.evaluate()`** (`POST /v1/records/{id}/verify` → `/evaluate`). `gate.get_status()` now hits `/gate-status` (was `/verification-status`); response field `lastVerifiedAt` → `lastEvaluatedAt`.
- `records.report_outcome()` → **`records.submit_verdict()`** (`POST /v1/records/{id}/outcome` → `/verdict`); param `outcome` → `verdict`; values `PASS`/`FAIL` → `accept`/`reject`; adds optional `notes` / `reason`.
- Type `VerificationMode` → **`GateMode`** (`"auto" | "principal"`; `"gated"` removed). Record field/param `verification_mode` (`verificationMode`) → `gate_mode` (`gateMode`) on create, search, and `RecordRow`.
- `RecordRow.verification_checks` → `verdict_checks` (`verdictChecks`); `RecordRow.verification_outcome` (PASS/FAIL) → `verdict` (accept/reject).
- Renamed models: `VerificationResult` → `GateEvaluationResult`; `VerificationStatus` → `GateStatus`; `OutcomeResult` → `VerdictResult` (response field `signal` → `recommendation`). Adds `Verdict` literal.
- `VerdictStatistics` reshaped to `{ agent_id, as_principal, as_performer }` (each `{ data, total }`) carrying `verdictAcceptCount` / `verdictRejectCount` per pair (was a flat `data[]` with PASS/FAIL counts).
- Webhook event types `record.verification_complete` → `record.gate_complete`, `cascading.verification.complete` → `cascading.gate.complete`.

### Fixed

- `GateStatus` now models the real `/gate-status` shape (`phase1_status`, `phase2_status`, `last_evaluated_at`, `pending_rules`) — the prior `VerificationStatus` model (`status`, `outcome`, `signal`) did not match the API response.

## [0.8.4] - 2026-05-25

Tracks AGLedger API v0.25.4. Adds RFC 9421 ed25519 webhook verification (the asymmetric, non-repudiable signing tier for Settlement Signals) and catches the typed surface up with the v0.25.3/v0.25.4 additive changes. Mirrors TypeScript SDK 0.8.4.

### Added

- **`verify_rfc9421()` + `construct_event_rfc9421()`** in `agledger.webhooks` — verify opt-in ed25519 webhook deliveries (RFC 9421 HTTP Message Signatures signed with the Server vault key) against the published `/v1/verification-keys`, matched by `keyid`. Recomputes the RFC 9530 Content-Digest, reconstructs the signature base, verifies Ed25519, and enforces the `created` replay window (default/max 300s). Needs the `cryptography` extra (`pip install 'agledger[verify]'`). Closes the gap where only the HMAC path had an SDK helper.
- **`webhooks.create(signing_alg=...)` + `Webhook.signing_alg`** (`"hmac" | "ed25519"`) — select the delivery signing scheme. Settlement-event subscriptions default to `ed25519` when the Server has a vault signing key; requesting `ed25519` without one returns 422.
- **`VerificationKey.public_key_raw`** — base64 of the raw 32-byte Ed25519 key (what RFC 9421 / Standard-Webhooks-style verifiers consume), alongside the SPKI-DER `public_key`.
- **`AccountProfile.auth_type` / `cert` / `oidc`** — introspection for OIDC ephemeral-cert (Mode 2) and OIDC bearer sessions, distinguishing them from long-lived `agl_` keys.

### Fixed

- **`WebhookEventType` reconciled to the API's authoritative set** (now 35). Added `signal.received`, `federation.dispute`, and the eight `record.federation_*` projected-lifecycle events. Removed four retired values the API no longer emits (`federation.record.offered`, `federation.record.accepted`, `federation.gateway.registered`, `federation.gateway.revoked`) and two it never emitted (`record.settled`, `record.remediated`).

## [0.8.3] - 2026-05-25

Follow-up to 0.8.2 from a full response-schema diff of every route shared between API v0.24.0 and v0.25.2.

### Fixed

- **`RecordAuditExport` raised `ValidationError` on real chain-integrity reasons.** The `chain_integrity_reason` and `chain_integrity_detail.failure` `Literal`s were missing `oidc_actor_drift` (since v0.24.0) and the v0.25.x cert/signature modes `cert_actor_drift`, `cert_expired`, `cert_missing`, `agent_signature_invalid` — so a genuine cert/OIDC failure response would fail to validate. Added the missing values.

### Added

- `ConformanceResponse.capabilities` — feature flags (`oidcWorkloadIdentity`, `ephemeralCerts`, `trustedIssuers`, `agentSignatureCoSign`, …).
- `VerificationKeysResponse.signature_input_template` — canonical signature-input template (v0.25.x).

## [0.8.2] - 2026-05-25

Tracks AGLedger API v0.25.2. Mirrors the `@agledger/sdk` 0.8.2 wave — catches up with the v0.25.x route surface (OIDC ephemeral-cert auth + trusted issuers + ops surfaces) and removes the string-override admin feature dropped by the API's dead-code audit. Validated end-to-end (sync + async) against a live v0.25.2 instance.

### Added

- `auth.issue_ephemeral_cert()` — OIDC-token → ephemeral signing cert exchange (`POST /v1/auth/oidc/cert`).
- `admin.trusted_issuers` sub-resource — `list` / `create` / `get` / `update` / `delete` / `revoke_certs` over `/v1/admin/trusted-issuers` (platform-scoped).
- `admin.revoke_ephemeral_cert(cert_id)` — revoke a single ephemeral cert (`POST /v1/admin/ephemeral-certs/{id}/revoke`).
- `admin.get_ops_summary()` — consolidated ops snapshot (`GET /v1/admin/ops-summary`).
- `admin.vault.scan.list()` — list current and recent vault scan jobs (`GET /v1/admin/vault/scan`).
- `agents.list_peers()` — federated agents synced from peers (`GET /v1/peer-agents`).
- `scitt.get_configuration()` (`GET /.well-known/scitt-configuration`, unauthenticated) and `scitt.get_checkpoint()` (`GET /v1/scitt/checkpoint`).

All new methods exist on both the sync and async clients.

### Removed

- `admin.strings` sub-resource (`list_keys` / `list_overrides` / `get_override` / `set_override` / `delete_override` / `list_drift`) — the backing `/v1/admin/strings/*` routes were removed in the API's v0.25 dead-code audit.

## [0.8.1] - 2026-05-21

Tracks AGLedger API v0.24.0. Mirrors the `@agledger/sdk` 0.8.1 wave — pre-launch rename sweep collapsing `tenant`/`enterprise` into `org` across paths, methods, and Pydantic field aliases; `agentId` → `performerAgentId` on the record-performer alias; account-deactivation split into org + agent variants; federation surface trimmed to v0.24.0 reality.

### Changed (BREAKING — pre-launch, no compat aliases)

- `admin.list_enterprises()` → `admin.list_orgs()`; `admin.create_enterprise()` → `admin.create_org()` (drops `slug`, `email` params; takes `display_name`, `config`); `admin.get_enterprise_config()` → `admin.get_org_config()`; `admin.update_enterprise_config()` → `admin.update_org_config()` (PATCH semantics); `admin.replace_enterprise_config()` removed (PUT-replace endpoint retired).
- `admin.deactivate_account(account_id, *, account_type, reason)` split into `admin.deactivate_org(org_id, *, reason=None)` + `admin.deactivate_agent(agent_id, *, reason=None)`. Path determines the type; `account_type` kwarg removed.
- `admin.create_agent()`: `enterprise_id` → `org_id` (now required, no `slug`/`email`).
- `admin.records.import_()`: `enterprise_id` → `org_id` (wire field also flipped to `orgId`).
- Audit resource: `audit.tenant_reads_checkpoints` → `audit.org_reads_checkpoints` (sync + async). Class names `TenantReadsCheckpointsResource` / `AsyncTenantReadsCheckpointsResource` → `OrgReadsCheckpointsResource` / `AsyncOrgReadsCheckpointsResource`. Paths `/v1/audit/tenant-reads/*` → `/v1/audit/org-reads/*`. Pydantic types `TenantReadsCheckpoint` / `TenantReadsInclusionProof` → `OrgReadsCheckpoint` / `OrgReadsInclusionProof`.
- Pydantic models: `RecordRow.enterprise_id` (alias `enterpriseId`) → `org_id` (alias `orgId`). `OrgReadsCheckpoint.enterprise_id` → `org_id`. `RecordRow.parent_principal_enterprise_matches_performer` → `parent_principal_org_matches_performer` (alias `parentPrincipalOrgMatchesPerformer`).
- `records.list()`, `records.list_all()`, `records.search()`, `records.create()`, schema export/import options: `enterprise_id` kwarg → `org_id` (wire `enterpriseId` → `orgId`).
- Predicate kind `tenant-read` → `org-read`.

### Removed (federation surface trimmed to v0.24.0)

`FederationResource` (sync + async): `register()`, `heartbeat()`, `register_agent()`, `list_agents()`, `catch_up()`, `stream()`, `list_types()`, `get_type()`, `publish_schema()`, `confirm_schema_publish()`, `get_record_criteria()`, `submit_record_criteria()`, `broadcast_revocations()`, `rotate_key()`, `revoke()` — backing endpoints retired.

`FederationAdminResource` (sync + async): `create_registration_token()`, `list_gateways()`, `revoke_gateway()`, `get_health()`, `get_gateway_status()`, `query_records()`, `get_audit_log()`, `reset_sequence()`, `rotate_hub_key()`, `list_hub_keys()`, `activate_hub_key()`, `expire_hub_key()`, `register_peer()`, `delete_schema_version()`, `list_reputation_contributions()`, `reset_reputation()`, `get_record_criteria_encryption_metadata()` — backing endpoints retired. Old outbound-dlq methods (`list_dlq`, `retry_dlq`, `delete_dlq`) replaced by the consolidated DLQ surface below.

### Added

- `federation.peer_handshake()` — `POST /federation/v1/peer`.
- `federation.submit_co_sign_request()` — `POST /federation/v1/co-sign-requests`.
- `federation.submit_dispute_protocol()` — `POST /federation/v1/disputes`.
- `federation_admin.list_dlq()` — `GET /federation/v1/admin/dlq` (consolidated).
- `federation_admin.recover_dlq()` — `POST /federation/v1/admin/dlq/recover`.
- `federation_admin.get_instance()` — `GET /federation/v1/admin/instance`.
- `federation_admin.delete_peer()` — `DELETE /federation/v1/admin/peers/{hubId}`.
- `federation_admin.create_peering_token(label=...)` now requires `label`.
- `federation_admin.revoke_peer(hub_id, reason=...)` now requires `reason`.

### Fixed (post-review sweep)

- **`RecordRow.agent_id` renamed to `RecordRow.performer_agent_id`** (alias `performerAgentId`) — was silently returning `None` on every v0.24.0 record response.
- **`records.create()` / async `create()` / `search()` / async `search()` no longer accept `agent_id` kwarg.** The kwarg was forwarding `body['agentId']` / `params['agentId']` which the v0.24.0 API rejects (the alias was removed; only `performerAgentId` is accepted now).
- **Vocab leaks**: `scopes.py:97` admin-standard description, `resources/disputes.py:23` and `resources/agents.py:23/63` docstrings swept from `tenant` → `org`.
- **Test fixtures** updated to the v0.24.0 wire shape: `test_pagination.py`, `test_retry.py` mocks use `performerAgentId` instead of `agentId`; `test_verify.py:96` uses `orgId` instead of `enterpriseId`.
- **Test function names** `test_audit_tenant_reads_checkpoint_get/cosign` renamed to `test_audit_org_reads_checkpoint_get/cosign`.

### Internal

- `User-Agent` header bumped to `agledger-python/0.8.1`.
- `__version__` bumped to `0.8.1`.

## [0.8.0] - 2026-05-19

Tracks AGLedger API v0.23.0. SCITT vocabulary alignment + canonical COSE_Sign1 chain envelope + new SCITT Transparency Service (SCRAPI) surface. Mirrors the `@agledger/sdk` 0.8.0 wave. Closes cross-repo issue agledger-agents#68.

### Changed (BREAKING — Receipt → Completion rename, no compat aliases)

"Receipt" is now reserved for the SCITT cryptographic Merkle-inclusion-proof concept. The performer's evidence submission is now a **Completion**.

- `client.receipts` → `client.completions` (both sync + async clients)
- `ReceiptsResource` → `CompletionsResource`, `AsyncReceiptsResource` → `AsyncCompletionsResource`
- `Receipt` model → `Completion`, `VaultReceipt` → `VaultCompletion`, `RecordReadReceipt` → `RecordReadCompletion`
- Pydantic field renames (snake_case attribute + camelCase alias both flip):
  - `receipt_id` ↔ `receiptId` → `completion_id` ↔ `completionId` on `OutcomeResult`, `VerificationResult`, `ReportOutcomeParams`
  - `receipt_hint` ↔ `receiptHint` → `completion_hint` ↔ `completionHint` on `RecordRow`
  - `vault_receipt` ↔ `vaultReceipt` → `vault_completion` ↔ `vaultCompletion` on `RecordRow`
  - `VerificationResult.receipts` → `.completions`
- Schema methods: `schemas.validate_receipt(...)` → `schemas.validate_completion(...)` (sync + async). Argument `receipt_ids` → `completion_ids`. Body field `receiptIds` → `completionIds`.
- Route paths: `/v1/records/{id}/receipts` → `/v1/records/{id}/completions`
- Scope strings + constants: `receipts:read`/`receipts:write` → `completions:read`/`completions:write`; `Scopes.RECEIPTS_READ`/`RECEIPTS_WRITE` → `Scopes.COMPLETIONS_READ`/`COMPLETIONS_WRITE`
- Webhook events: `record.receipt_submitted` → `record.completion_submitted`, `record.receipt_invalid` → `record.completion_invalid`. `WebhookEventType` expanded to the full 30-value set the API publishes.
- `RecordRow.cancel_after_receipt_count` → `cancel_after_completion_count` (camelCase alias too).

PRESERVED uses of "Receipt":
- `AuditExportEntry.integrity.receipt` (optional base64 SCITT Receipt — Merkle inclusion proof per draft-ietf-cose-merkle-tree-proofs-18; opt-in via `receipts=True` on `get_audit_export`).

### Changed (BREAKING — offline verifier: format 1.0 → 2.0)

- `agledger.verify.verify_export()` now decodes canonical COSE_Sign1 envelopes (RFC 9052, tag 18, EdDSA) over in-toto v1 Statement payloads, deterministic CBOR per RFC 8949 §4.2.1.
- The `[verify]` extra now requires `cbor2>=5.6` in addition to `cryptography>=42.0`. `pip install 'agledger[verify]'` pulls both.
- New `EntryFailureReason` values: `"cose_decode_failed"`, `"cose_header_mismatch"`. `"signature_invalid"` retained but now refers to the COSE_Sign1 signature.
- New `VerifyExportResult.signature_coverage: SignatureCoverage` discriminator (signed / unsigned / skipped / total). Auditors should not conclude "Ed25519-verified" from `chain_integrity: True` alone — read `signature_coverage` or `integrity_level`.
- New `chain_integrity_reason` enum value: `"payload_drift"`. New `chain_integrity_detail` field on `AuditExportMetadata` localizes a break.
- `canonicalize()` helper retired — no longer exported from `agledger.verify` (CBOR-deterministic encoding replaces JCS).

### Added — SCITT Transparency Service (`client.scitt`)

Implements `draft-ietf-scitt-scrapi-09`. Binary `application/cose` wire; RFC 9290 CBOR problem-details on errors.

- `client.scitt.entries.register(signed_statement: bytes) -> bytes` — returns the Receipt (COSE_Sign1 + Merkle inclusion proof).
- `client.scitt.entries.get(entry_id) -> bytes` — returns a Transparent Statement.
- `client.scitt.keys.list() -> bytes` / `client.scitt.keys.get(kid) -> bytes` — COSE_KeySet fetch (unauthenticated).
- Async parity on `AsyncAgledgerClient`.

`APIError.raw_body: bytes | None` now declared as a first-class field — decode SCITT problem-details with `cbor2.loads(error.raw_body)`.

### Added — predicate schema discovery (`client.predicates`)

- `client.predicates.list() -> dict` and `client.predicates.get(kind, version='v1') -> dict` — sync + async parity. Returns the canonical JSON Schema for each predicate kind (record-state, settlement-signal, vault-checkpoint, schema-event, tenant-read, counter-attestation, federation-projection).

### Added — attestation export on `client.records`

- `client.records.get_attestation(record_id) -> bytes` — `application/cose-sequence` stream of tagged COSE_Sign1 envelopes; feed to `agledger.verify` for cryptographic verification.
- `client.records.get_attestation_bundle(record_id) -> dict` — sigstore-bundle v0.3.2 projection (structural interop only — verify cryptographically via `get_attestation`).
- `client.records.get_audit_export(record_id, receipts=True)` — opt SCITT Receipts into the export.

### Added — vault checkpoints on `client.audit`

- `client.audit.vault_checkpoints.list(record_id=..., cursor=..., limit=...)` — 6h signed Merkle anchors for offline checkpoint cross-check.

### Added — binary I/O on `HttpClient` / `AsyncHttpClient`

- `get_bytes()` + `post_bytes()` + `_request_bytes()` — full retry / idempotency / abort semantics matching the JSON path. Used by `scitt` + `records.get_attestation()`.

### Internal

- All 204 SDK tests pass.
- `User-Agent` header bumped to `agledger-python/0.8.0`.

## [0.7.3] - 2026-05-02

Resolves cross-repo issue agledger-agents#64 (testbed F-526). Patch fix for a 0.7.2 regression in `records.bulk_create()`.

### Fixed
- **`BulkCreateResultItem.status` is now `Literal["created", "replayed", "error"]`** (was `int`). The API has always returned the string token; the 0.7.2 typed model annotated it as `int`, so every `bulk_create()` call raised `pydantic.ValidationError` at the deserialization step. The TS SDK had the same wrong shape (`number`); fixed in parallel in `@agledger/sdk` 0.7.2.

## [0.7.2] - 2026-05-02

Resolves cross-repo issue agledger-agents#62 (testbed F-524). Type-safety / parity gaps versus TS SDK 0.7.1 with no API change.

### Fixed
- **`agledger.verify.verify_export()` now accepts the typed `RecordAuditExport` model** returned by `client.records.get_audit_export()`. Previously raised `AttributeError` deep in the call stack — customers building the canonical fetch+verify flow had to manually `.model_dump(by_alias=True)` first. Both raw `dict` and Pydantic model inputs are supported.
- **`auth.get_me()` now returns the typed `AccountProfile`** (was raw `dict`). The model was already exported from the package — it just wasn't applied to the deserialization path.
- **`records.bulk_create()` now returns the typed `BulkCreateResult`** with nested `BulkCreateResultItem` and `BulkCreateSummary` (was raw `dict`).
- **`RecordAuditExport.export_metadata` is now a typed `AuditExportMetadata`** sub-model (was raw `dict`). Fields: `record_id`, `enterprise_id`, `type`, `operating_mode`, `export_date`, `total_entries`, `expected_entries`, `chain_integrity`, `chain_integrity_reason`, `export_format_version`, `canonicalization`, `signing_public_key`, `signing_public_keys`.
- **`agledger.verify` raises `ImportError` at import time** when `cryptography` is missing — was a deep `RuntimeError` six frames into `verify_export`. Install message unchanged: `pip install 'agledger[verify]'`.

### Added
- New typed models: `AuditExportMetadata`, `BulkCreateResult`, `BulkCreateResultItem`, `BulkCreateSummary`.

## [0.7.1] - 2026-04-30

Tracks AGLedger API v0.22.13. Adds 10 new routes mirroring the TS SDK 0.7.1: tenant string overrides admin (`AdminStringsResource`), `federation_admin.get_gateway_status()`, `agents.list()` peer directory, `compliance.list_vault_checkpoints()`, and `disputes.withdraw()`.

## [0.7.0] - 2026-04-27

Tracks AGLedger API v0.21.0 — the customer-facing vocabulary rewrite.
Mirrors the TypeScript SDK v0.7.0 release. No production customers; no
backwards-compatibility shims.

### Changed (BREAKING)
- **Mandate → Record rename throughout.** Every `/v1/mandates/*` route is now
  `/v1/records/*`. Resource is `client.records` (was `client.mandates`).
  Path params `{contractType}` are `{type}`. Vocabulary: Record (data model),
  Type (was Contract Type).
- **Type / model renames.**
  - `Mandate` → `RecordRow`
  - `MandateStatus` → `RecordStatus` (adds `RECORDED`)
  - `MandateTransitionAction` → `RecordTransitionAction`
    (`register | propose | activate | cancel`; no `MARK_INVALID` — internal-only)
  - `ContractType` → `RecordType`
- **Record-response fields:** `principal_type` removed; added `category`,
  `outcome`, `correlation_id`, `requested_by`, `vault_receipt`,
  `acceptance_status`, `acceptance_responded_at`,
  `parent_principal_enterprise_matches_performer`, `commission_amount`,
  `self_commitment`, `parent_record_id`, `root_record_id`, `child_record_ids`.
- **Webhook event types** — all `mandate.*` are now `record.*`
  (`record.created`, `record.fulfilled`, `record.delegated`, etc.).
- **Scope constants** `MANDATES_READ`/`MANDATES_WRITE` → `RECORDS_READ`/`RECORDS_WRITE`.
- **Compliance per-Record audit export** is now `client.records.get_audit_export()`
  (the duplicate `compliance.export_mandate()` was removed).
- **Field renames:** `parent_mandate_id` → `parent_record_id`,
  `mandate_id` → `record_id`, `record_id` (in compliance attestation context)
  remains the compliance-record id; clarified per resource.
- **Capabilities body field stays `contractTypes`** — the API kept the legacy
  field name on this endpoint despite the broader Type rename. Pythonic
  `contract_types` kwarg, camelCase to API.
- **Conformance** lives only on `client.discovery.get_conformance()`; the
  duplicate `client.health.conformance()` was removed.
- **Removed dead types:** `AuditChain`, `AccountType`, `MandateStatusSummary`,
  `DashboardSummary`, `DashboardAgent`, `DashboardAlert`, `Project`,
  `EnterpriseAgentRecord`, `ApprovalConfig`. `client.events.get_audit_chain()`
  removed (route does not exist).

### Added
- **`client.records.my_verdict_statistics()`** → `GET /v1/records/me/verdict-statistics`
- **`client.records.list_proposals()`** → `GET /v1/records/agent/proposals`
- **`client.records.batch_get([...])`** → `POST /v1/records/batch`
- **`client.records.bulk_create([...])`** → `POST /v1/records/bulk`
  (per-item idempotency_key supported)
- **`client.records.get_audit_export()`** — canonical per-Record audit export
- **`client.disputes.list(...)`** → `GET /v1/disputes` (tenant-wide)
- **`client.audit.tenant_reads_checkpoints.{list, get, cosign, proof}`** →
  `/v1/audit/tenant-reads/checkpoints/*` (new top-level resource)
- **`client.admin.records.{list, import_}`** →
  `GET /v1/admin/records`, `POST /v1/admin/records/import`
- **`client.admin.vault.{anchors{list, verify}, scan{run, status}, signing_keys{list, rotate}}`**
- **`client.schemas.meta_schema()`, `blank()`, `import_()`, `preview()`,
  `disable()`, `enable()`** → `/v1/schemas/{meta-schema, _blank, import, preview}`
  + disable/enable
- **Record lifecycle module** — `agledger.record_lifecycle` with
  `RECORD_TRANSITIONS`, `TERMINAL_STATUSES`, `can_transition_to()`,
  `get_valid_transitions()`, `is_terminal_status()`. Re-exported from
  `agledger`.
- **Errors** now surface `recovery_hint` and `refresh_url` extension fields
  (RFC 9457). Set on 422 INVALID_ACTION when the API can name a corrective
  step.
- **Top-level `missingScopes`** parsed from RFC 9457 problem+json bodies in
  addition to the legacy `details.missingScopes` location.

### Verify export
- `VerifyExportResult.mandate_id` → `record_id`. Doc strings updated to
  reference `/v1/records/{id}/audit-export`. Reads `recordId` from export
  metadata, falling back to legacy `mandateId` for older exports.

### Technical
- `User-Agent: agledger-python/0.7.0`.
- `keywords` updated `mandates` → `records` in `pyproject.toml`.

## [0.6.0] - 2026-04-23

Tracks AGLedger API v0.20.0 — the pre-launch principal-model rewrite.
Mirrors the TypeScript SDK v0.6.0 release. No production customers; no
migration shims.

### Changed (BREAKING)
- **API key role `enterprise` → `admin`.** `ApiKeyRole` type is now
  `Literal["admin", "agent", "platform"]`.
- **API key prefix `ach_(ent|age|pla)_*` → `agl_(adm|agt|plt)_*`.**
- **Scope profiles renamed and trimmed to 7.** New: `admin-standard`
  (default admin), `admin-observer`, `admin-iac`, `admin-schema`,
  `agent-full` (default agent), `agent-readonly`, `agent-performer-only`.
  Retired: `standard`, `restrictive`, `iac-pipeline`, `schema-manager`,
  `monitor`, `dashboard`, `sidecar`. `ScopeProfile` now exposes
  `allowed_roles`.
- **Scope constants `DASHBOARD_READ` and `AUDIT_ANALYZE` removed.**
  `ADMIN_TRUST` renamed to `ADMIN_BACKFILL`.
- **Principal model collapsed.** Every mandate has `principal_agent_id`
  (one named agent, required). Self-commitment valid. Agent keys default
  principal to themselves; admin keys must name the principal.
- **Unified `POST /v1/mandates`** for admin, agent, and platform callers.
- **Audit route rename `/v1/audit/stream` → `/v1/siem/stream`.**
- **Auth surface trimmed** to `GET /v1/auth/me` and `POST /v1/auth/keys/rotate`.

### Added
- **`AuthResource` / `AsyncAuthResource`** — `client.auth.get_me()` and
  `client.auth.rotate_key()`.
- **`DiscoveryResource` / `AsyncDiscoveryResource`** —
  `client.discovery.get_scope_profiles()`, `get_conformance()`,
  `get_lifecycle()`.
- `default_profile_for(role)` helper mirroring the API.
- `agent-performer-only` scope profile — performer that can deliver
  receipts and read mandates but cannot be a principal.

### Removed
- Resources: `dashboard`, `proxy` (governance sidecar sync), `notarize`
  (OpenClaw legacy), `projects`, `registration`, `enterprises`.
- Types: `DashboardSummary`, `DashboardAgent`, `DashboardAlert`,
  `EnterpriseAgentRecord`, `Project`, `ApprovalConfig`,
  `MandateStatusSummary`, trust-level types.
- Methods: `compliance.analyze()`, `mandates.get_summary()`, trust-level
  admin methods, `/v1/audit/enterprise-report*`.

### Parity test
- `test_parity.py` rewritten as a focused invariant set (critical routes
  present, retired routes absent, shape assertions on POST bodies).
- Shared `routes.json` regenerated from API v0.20.0 OpenAPI (188 routes).

## [0.1.0] - 2026-04-02

### Added
- `AgledgerClient` (sync) and `AsyncAgledgerClient` (async) with 23 resource sub-clients each
- Full error hierarchy: `APIError`, `AuthenticationError`, `PermissionDeniedError` (with `missing_scopes`), `NotFoundError`, `BadRequestError`, `ConflictError`, `UnprocessableError`, `RateLimitError`, `APIConnectionError`, `APITimeoutError`, `SignatureVerificationError`
- `doc_url` and `suggestion` on all API errors
- Auto-pagination via generators (`list_all()` methods)
- Retry with exponential backoff + jitter, respects `Retry-After`
- Auto-generated idempotency keys on mutations
- Webhook signature verification via `agledger.webhooks`
- Context manager support (`with AgledgerClient() as client:`)
- Environment variable fallback (`AGLEDGER_API_KEY`)
- Typed kwargs on core resources (mandates, receipts) with full IDE autocomplete
- 11 Pydantic v2 models: AgentProfile, VerificationStatus, WebhookTestResult, DashboardStats, DashboardAlert, DashboardAgent, Project, AgentCapabilities, ComplianceExport, AiImpactAssessment, EuAiActReport
- `py.typed` marker for PEP 561 compliance
- 101 tests (pytest + respx) with async coverage
- SECURITY.md with CVE disclosure policy

### Technical
- Python >=3.10
- Dependencies: httpx >=0.27.0, pydantic >=2.0.0
- Pydantic v2 models with `populate_by_name=True` and `extra="allow"` for forward compatibility
- Modern union syntax (`X | None`) throughout
