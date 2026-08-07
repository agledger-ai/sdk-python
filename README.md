# AGLedger Python SDK

The official Python SDK for [AGLedger](https://agledger.ai): change control for AI agents. A self-hosted notary that records every change an agent makes, signed and hash-chained, and gates the ones that matter.

**Learn more**

- [agledger.ai](https://agledger.ai): what AGLedger is and who needs it
- [How it works](https://agledger.ai/how-it-works) walks the lifecycle: Record, Completion, Verdict
- [Glossary](https://agledger.ai/glossary): canonical definitions of Record, Completion, SCITT Receipt, Verdict, Settlement Signal
- [Documentation](https://agledger.ai/docs): installation, integration guides, API reference

## Install

```bash
pip install agledger
```

## Quick Start

```python
import os
from agledger import AgledgerClient

client = AgledgerClient(
    api_key=os.environ["AGLEDGER_API_KEY"],
    base_url=os.environ["AGLEDGER_EXTERNAL_URL"],  # your AGLedger instance URL
)

# Create a Record. An agent key defaults the principal to itself; an admin
# key names the principal explicitly via principal_agent_id.
record = client.records.create(
    type="principal-gate-generic-v1",
    contract_version="1",
    platform="internal",
    performer_agent_id="agt-123",
    auto_activate=True,
    criteria={"summary": "Procure 100 widgets", "amount": 500, "currency": "USD"},
)

# Submit a completion
completion = client.completions.submit(
    record.id,
    evidence={"summary": "Delivered 95 widgets", "evidenceUrl": "/out.pdf"},
)

# Principal verdict
client.records.submit_verdict(record.id, completion_id=completion.id, verdict="accept")
```

## Configuration

```python
client = AgledgerClient(
    api_key="agl_agt_...",                              # or set AGLEDGER_API_KEY env var
    base_url="https://agledger.internal.example.com",   # your instance URL. Required.
    max_retries=3,                                      # default: 3
    timeout=30.0,                                       # default: 30s
    idempotency_key_prefix="my-app-",                   # default: ""
)
```

`base_url` is required: every AGLedger deployment is self-hosted, so there is no
default server to call. Omitting it raises `ConfigurationError` at construction,
where the mistake is, rather than failing every subsequent call against a host
you never named. `api_key` is the one option that falls back to an environment
variable (`AGLEDGER_API_KEY`).

## Async Support

```python
import os
from agledger import AsyncAgledgerClient

async with AsyncAgledgerClient(
    api_key=os.environ["AGLEDGER_API_KEY"],
    base_url=os.environ["AGLEDGER_EXTERNAL_URL"],
) as client:
    record = await client.records.get("rec-123")
```

## Resources

`records`, `completions`, `gate`, `disputes`,
`webhooks`, `reputation`, `events`, `schemas`, `compliance`, `health`, `admin`
(with `admin.records` + `admin.vault` sub-resources), `a2a`, `agents`, `audit`
(with `audit.org_reads_checkpoints` and `audit.vault_checkpoints`), `auth`,
`capabilities`, `discovery`, `references`, `federation`, `federation_admin`,
`verification_keys`, `scitt` (SCITT/SCRAPI entries + Transparency Service keys),
`predicates` (predicate schema discovery).

## Webhook Verification

Webhooks ship in two signing schemes, selected per subscription via `signing_alg`.

**HMAC** (`signing_alg="hmac"`, the default) is shared-secret HMAC-SHA256:

```python
from agledger.webhooks import verify_signature

is_valid = verify_signature(raw_body, request.headers["x-agledger-signature"], webhook_secret)
```

**Asymmetric** (`signing_alg="ed25519"` or `"ecdsa-p256-sha256"`) is RFC 9421
HTTP Message Signatures signed with the Server's vault key. The receiver holds
no secret and verifies against the Server's published public key, giving
non-repudiation for the Settlement Signal hop. Settlement-event subscriptions
default to this when the Server has a vault signing key. The wire `alg`
reflects the Server's active key; `verify_rfc9421` handles both.

```python
from agledger.webhooks import verify_rfc9421, SignatureAlgorithmUnavailableError

# Resolve the Server's published keys once (cache them); the delivery's
# keyid is matched against them automatically.
keys = client.verification_keys.list().data

try:
    is_valid = verify_rfc9421(
        request.headers,  # must include content-digest, signature-input, signature, x-agledger-idempotency-key
        raw_body,
        keys,             # or a single base64 public key string
    )
    if not is_valid:
        return Response(status=401)
except SignatureAlgorithmUnavailableError:
    # This host cannot compute the algorithm, so nothing was checked. Your
    # configuration, not the sender's: 401 would blame the wrong party.
    return Response(status=500)
```

`verify_rfc9421` recomputes the RFC 9530 Content-Digest, reconstructs the RFC 9421
signature base, verifies the signature under the algorithm the resolved key
commits to (Ed25519 or ES256), and enforces the `created` replay
window (default/max 300s). `construct_event_rfc9421` verifies and parses in one
step. This path needs the `cryptography` extra (`pip install 'agledger[verify]'`).

If the host runtime cannot compute the key's algorithm, both functions raise
`SignatureAlgorithmUnavailableError` instead of returning `False`. The usual
cause is an active OpenSSL FIPS provider, which carries no EdDSA. This is
deliberately not a verification failure: returning `False` would make the
standard `if not ok: return 401` reject every legitimate delivery as forged,
when the fault is in the receiver's configuration rather than the sender's
signature. Terminate the signature on an unrestricted host, or configure the
sender for `ecdsa-p256-sha256`, which FIPS does permit.

## Offline Audit Export Verification

Verify a Record's hash-chained, signed audit export without calling the API:

```python
from agledger.verify import verify_export

export_data = client.records.get_audit_export("rec-123")
result = verify_export(export_data.model_dump(by_alias=True))

if not result.valid:
    print(f"Broken at position {result.broken_at.position}: {result.broken_at.code}")
# VerifyExportResult(valid=True, verified_entries=12, total_entries=12, ...)
```

`broken_at.code` is a canonical SCREAMING_SNAKE `FailureCode` (e.g.
`CHAIN_HASH_MISMATCH`, `CHAIN_SIGNATURE_INVALID`) shared with the TypeScript
verification core, so both languages report identical verdicts over the shared
conformance corpus.

Requires `cbor2` (for COSE_Sign1 decoding) and `cryptography` (for signature
verification):

```bash
pip install 'agledger[verify]'
```

Decodes canonical COSE_Sign1 envelopes (RFC 9052), walks the hash chain, and
verifies each signature under the algorithm the verification key commits to
(Ed25519 or ES256). Format 2.0 (1.0 was JCS + detached Ed25519). Pass `public_keys={...}` to supply out-of-band keys (these override the
export's embedded keys), `require_key_id="key-id"` to reject exports signed by an
unexpected key, or `require_out_of_band_keys=True` for a high-assurance audit that
refuses the export's own embedded keys. `result.key_provenance` reports how many
signatures were checked against out-of-band vs embedded keys.

On a **FIPS-locked host** there is no EdDSA, so an Ed25519 chain cannot be
verified there (ES256 chains can). That is reported as
`CHAIN_UNSUPPORTED_ALGORITHM`, never as a signature failure: "I could not check
this" and "I checked this and it failed" lead to opposite conclusions, and only
one is grounds for a tamper investigation. The result still fails closed. To
verify an Ed25519 chain, re-run on a host without the restriction; verification
is entirely offline, so the export and keys are portable.

## Offline Full-Vault Dump Verification

For a whole-instance audit (not just one Record), verify a five-file NDJSON dump
produced by the API's dump-vault tool. This walks every per-record and per-org
schema-event chain, cross-checks the signed vault checkpoints against the live
chain, and verifies the `org_admin_reads` Merkle log + signed tree heads
(including fork detection):

```python
from agledger.verify import load_dump, verify_dump

report = verify_dump(load_dump("./vault-dump-dir"))
if not report.ok:
    for f in report.vault.failures + report.org_admin_reads.failures:
        print(f"[{f.code}] {f.message}")
```

### `agledger-verify` CLI (turnkey)

The `[verify]` extra installs an `agledger-verify` console script that
auto-detects its argument: a **directory** is a full-vault dump, a **file** is a
single `/audit-export` JSON document, so one command covers both verifiers, with
no network calls:

```bash
pip install 'agledger[verify]'

agledger-verify ./vault-dump-dir              # full-vault dump
agledger-verify audit-export.json             # single record export
agledger-verify ./vault-dump-dir -f json      # machine-readable report
agledger-verify ./vault-dump-dir --quiet      # exit code only
```

Exit codes: `0` clean, `1` verification failure, `2` usage/IO error (so a missing
file is never mistaken for tamper). Every failure carries an actionable next step
via `agledger.verify.suggestion(code)`. The dump verifier emits the same
canonical `FailureCode` taxonomy as the TypeScript `@agledger/verify` and is held
to the same shared conformance corpus, so the two agree verdict-for-verdict.

## SCITT / SCRAPI

Register Signed Statements with the Transparency Service and retrieve Transparent
Statements (Signed Statement + Receipt(s)):

```python
receipt = client.scitt.entries.register(signed_statement)
# COSE_Sign1 Merkle inclusion proof per draft-ietf-cose-merkle-tree-proofs-18

transparent = client.scitt.entries.get(entry_id)
# Transparent Statement: Signed Statement with one or more Receipts embedded

keys = client.scitt.keys.list()
# COSE_KeySet of the Transparency Service's signing keys
```

Wire format is binary `application/cose`. Errors surface as RFC 9290 CBOR
problem-details on `APIError.raw_body`.

## Predicate Schemas

Fetch the canonical JSON Schemas for each predicate kind (record-state,
settlement-signal, vault-checkpoint, schema-event, org-read,
counter-attestation, federation-projection):

```python
kinds = client.predicates.list()
schema = client.predicates.get("settlement-signal")
```

## Attestation Export

Pull a Record's chain as a tagged COSE_Sign1 stream or a sigstore-bundle v0.3.2
projection for Rekor / in-toto / sigstore-policy-controller ingest:

```python
cose_sequence = client.records.get_attestation(record_id)
# application/cose-sequence bytes (tagged COSE_Sign1 stream)

bundle = client.records.get_attestation_bundle(record_id)
# sigstore-bundle v0.3.2 projection
```

## Vault Checkpoints

Per-record signed Merkle anchors are emitted every 6 hours, letting an auditor
detect audit-vault TRUNCATE / DELETE tampering offline:

```python
checkpoints = client.audit.vault_checkpoints.list(record_id="rec-123")
```

## Licensing

The database is the license line. AGLedger is **free with its bundled PostgreSQL** (Docker Compose or Helm), in production, with every feature and every topology, federation included. Connecting to an external or managed database (Aurora, RDS, Cloud SQL, self-managed) requires a perpetual Enterprise license, priced per external database instance, plus an annual subscription for Enterprise-grade support. The license is perpetual: production never stops due to licensing.

Full details: [agledger.ai/pricing](https://agledger.ai/pricing) | [License Agreement](https://agledger.ai/license)

## SDK License

Proprietary. Copyright (c) 2026 AGLedger LLC. All rights reserved.
