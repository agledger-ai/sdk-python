# AGLedger Python SDK

The official Python SDK for [AGLedger](https://agledger.ai): change control for AI agents. Agent memory, approvals, audit trail, and notifications: one API, one signed ledger, self-hosted.

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
import time

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
    # Agent ids are uuids of agents you provisioned, so there is no id you can
    # invent here: read one from your config.
    performer_agent_id=os.environ["AGLEDGER_PERFORMER_AGENT_ID"],
    auto_activate=True,
    criteria={"summary": "Procure 100 widgets", "amount": 500, "currency": "USD"},
)

# Submit a completion
completion = client.completions.submit(
    record.id,
    evidence={"summary": "Delivered 95 widgets", "evidenceUrl": "https://files.example.com/out.pdf"},
)

# The worker validates the completion, then holds the Record at PROCESSING
# until the principal renders its verdict.
for _ in range(30):
    if client.records.get(record.id).status == "PROCESSING":
        break
    time.sleep(1)

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

Pass `bearer_token=` instead of `api_key=` to authenticate with a token your
identity provider issued. It takes a string, a function the client calls before
every request, or a credential object such as the OIDC cert credential below.
Pass one or the other: both at once raises `ConfigurationError`. The function
form caches nothing, so when the operator registers your issuer with
`jti_single_use=True` (each token accepted once), have the function mint a
fresh token on every call.

## OIDC workload identity

An agent can run with no AGLedger secret at rest. The operator registers your
identity provider as a trusted issuer; the agent then trades a short-lived token
from that provider for a certificate the Server signs, bound to a key pair the
SDK generates in memory. `oidc_cert_credential` does the exchange, renews the
certificate at half its lifetime (and once more if the Server refuses it), and
signs every request body with the bound key, so each chain entry the agent
writes carries the agent's signature as well as the Server's.

```bash
pip install 'agledger[oidc]'
```

```python
import os
from pathlib import Path

from agledger import AgledgerClient, oidc_cert_credential

def read_token() -> str:
    # Kubernetes rotates a projected service-account token on disk; read it on
    # every call rather than caching it.
    return Path(os.environ["AGLEDGER_OIDC_TOKEN_FILE"]).read_text().strip()

credential = oidc_cert_credential(get_oidc_token=read_token)
client = AgledgerClient(bearer_token=credential, base_url=os.environ["AGLEDGER_EXTERNAL_URL"])

me = client.auth.get_me()
print(me.auth_type, me.owner_id)  # ephemeral_cert <agent id>
```

The function is called once per exchange and must return a new token, with a
new `jti`, each time: the Server accepts a token id once and refuses it again
with 409. A projected token file changes only when the platform rotates it, so
if a scheduled renewal gets back the token already used, the credential keeps
its current certificate while it is still valid and tries again on a later
request. The same holds for any failed renewal (the provider down, a 5xx or
429 from the Server): the request goes out on the certificate still in hand.
Once the certificate has expired, an unchanged token raises
`OidcCertExchangeError` saying the token source must mint a new token. If your
platform rotates the file less often than the certificate lifetime, have the
function request a fresh token from your provider instead.
`agent_id=` binds the certificate to a named agent; without it the Server binds
from the token or, if the issuer allows it, creates the agent. A refused
exchange raises `OidcCertExchangeError` carrying the Server's `recovery_hint`,
with the token scrubbed out. `AsyncAgledgerClient` takes
`async_oidc_cert_credential`, whose token function may be a coroutine.

To verify an agent's own signatures offline later, keep `credential.public_key_jwk`
and pass it to `verify_export(..., agent_keys=[jwk])` (see below).

Work done for a person or another party rather than for the agent itself takes
`on_behalf_of=`: an RFC 8693 delegation token your provider issued, sent as the
`AGLedger-On-Behalf-Of` header on `records.create`, `records.transition`,
`records.submit_verdict`, `completions.submit` and `a2a.call`.

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
`webhooks`, `drift`, `events`, `schemas`, `compliance`, `health`, `admin`
(with `admin.records` + `admin.vault` sub-resources), `a2a`, `agents`, `audit`
(with `audit.org_reads_checkpoints` and `audit.vault_checkpoints`), `auth`,
`capabilities`, `discovery`, `references`, `federation`, `federation_admin`,
`verification_keys`, `scitt` (SCITT/SCRAPI entries + Transparency Service keys),
`predicates` (predicate schema discovery).

### When two publishers offer the same Type

Importing a peer's manifest (`schemas.import_()`) can leave your org with two registrations of one `type`: theirs and your local one. That is supported, and it means a bare `type` no longer names a schema. The API refuses to guess, because the guess would change the moment the other publisher shipped a higher version:

```python
from agledger import AgledgerClient, UnprocessableError

client = AgledgerClient(api_key="agl_agt_...", base_url="https://agledger.internal.example.com")

try:
    client.records.create(type="acme-po-v1", criteria={"poNumber": "PO-1"})
except UnprocessableError as err:
    if err.type == "/problems/ambiguous-publisher":
        # err.publishers is the candidate list, e.g. ["acme-corp", "local"].
        client.records.create(
            type="acme-po-v1",
            criteria={"poNumber": "PO-1"},
            publisher="acme-corp",
        )
```

Branch on `err.type`, not on the message. Schema reads take the same pin (`client.schemas.get("acme-po-v1", publisher="acme-corp")`), and `client.schemas.list()` returns one row per (publisher, type) so you can choose before reading.

Every Record reports the binding the engine used, whether or not you pinned it:

```python
record = client.records.get(record_id)
record.publisher   # "acme-corp", or None (see below)
record.schema_url  # "/v1/schemas/acme-po-v1?publisher=acme-corp". Follow it verbatim.
```

`publisher` is `None` on Records the engine never validated against a local registration: federation-received ones (the originator ran the gate against its own registration) and ones backfilled through admin import. Read that as "ask the originator", not as "the schema is missing here".

Single-publisher orgs, which is nearly every install, never pass `publisher` and read their one label (usually `local`) back.

### Disputes

`client.disputes` lists, files, resolves and withdraws disputes. Filing, withdrawing, reading and submitting evidence all take the **record** id. Resolving takes the **dispute** id, because the outcome is rendered on the dispute itself:

```python
page = client.disputes.list(status="PENDING_RESOLUTION")

filed = client.disputes.create(record.id, grounds="quality_issue")

# The dispute id, not the record id. `filed.id` is the one to pass.
resolved = client.disputes.resolve(
    filed.id,
    outcome="OVERTURNED",
    rationale="The completion met the tolerance band on re-read.",
)
```

`UPHELD` leaves the disputed verdict standing and returns the Record to the status it held before the dispute. `OVERTURNED` says the verdict does not stand: a Record that had failed settles at FULFILLED with the verdict re-rendered as `accept`, and a RELEASE Settlement Signal follows. The rendering is the caller's; AGLedger holds and serves the signed decision and never makes it.

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

Note that on such a host **no** delivery can be classified, valid or forged. The
check has to run before signature verification, so a genuine forgery raises too.
Treat the exception as "nothing is known about this delivery", never as evidence
it was legitimate.

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

Records written with the OIDC cert credential also carry the agent's own
signature over each request body. Pass the certificate's public key to check
those too; without it they are counted in `result.agent_signatures.present` and
left unchecked:

```python
from agledger.verify import verify_export

export_data = client.records.get_audit_export("rec-123")
result = verify_export(
    export_data.model_dump(by_alias=True),
    agent_keys=[credential.public_key_jwk],  # the JWK sent at cert exchange
)
print(result.agent_signature_check, result.agent_signatures)
# applied AgentSignatureCounts(present=1, verified=1)
```

A signature that does not verify fails as `CHAIN_AGENT_SIGNATURE_INVALID`. A key
is matched to an entry only through the certificate thumbprint the entry signed,
so a key for another certificate is simply never used.

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
agledger-verify ./vault-dump-dir --agent-keys agent-keys.json   # also re-check agent signatures
```

`--agent-keys` takes a JSON file of agent certificate keys: one JWK, a list, a
`{"keys": [...]}` JWK Set, or entries wrapping a key as `{"publicKeyJwk": ...}`
(what `credential.public_key_jwk` gives you). It works on a dump directory and
on an `/audit-export` file; in code, pass `agent_keys=` to `verify_dump` or
`verify_export`. Both reports say which input-gated checks ran
(`optional_checks`) and how many agent signatures were present and verified.

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

Running AGLedger in production requires a license. The Developer Edition license is free; see https://agledger.ai/license and https://agledger.ai/pricing.

## SDK License

Proprietary. Copyright (c) 2026 AGLedger LLC. All rights reserved.
