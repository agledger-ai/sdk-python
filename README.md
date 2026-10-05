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

A Record has two sides: the principal that asks for the work and renders the
verdict, and the performer that does it and submits the completion. Each is an
agent with its own key, so the walk-through below runs two clients.

```python
import os
import time

from agledger import AgledgerClient

base_url = os.environ["AGLEDGER_EXTERNAL_URL"]  # your AGLedger instance URL
principal = AgledgerClient(api_key=os.environ["AGLEDGER_API_KEY"], base_url=base_url)
performer = AgledgerClient(api_key=os.environ["AGLEDGER_PERFORMER_API_KEY"], base_url=base_url)

# Create a Record. An agent key defaults the principal to itself; an admin
# key names the principal explicitly via principal_agent_id.
record = principal.records.create(
    type="principal-gate-generic-v1",
    contract_version="1",
    platform="internal",
    # Agent ids are uuids of agents you provisioned, so there is no id you can
    # invent here: read one from your config.
    performer_agent_id=os.environ["AGLEDGER_PERFORMER_AGENT_ID"],
    auto_activate=True,
    criteria={"summary": "Procure 100 widgets", "amount": 500, "currency": "USD"},
)

# The performer submits the completion.
completion = performer.completions.submit(
    record.id,
    evidence={"summary": "Delivered 95 widgets", "evidenceUrl": "https://files.example.com/out.pdf"},
)

# The worker validates the completion, then holds the Record at PROCESSING
# until the principal renders its verdict.
for _ in range(30):
    if principal.records.get(record.id).status == "PROCESSING":
        break
    time.sleep(1)

# Principal verdict
verdict = principal.records.submit_verdict(record.id, completion_id=completion.id, verdict="accept")
print(verdict.record_status)  # FULFILLED
```

## Configuration

```python
client = AgledgerClient(
    api_key="agl_agt_...",                              # or set AGLEDGER_API_KEY env var
    base_url="https://agledger.internal.example.com",   # your instance URL. Required.
    max_retries=3,                                      # default: 3. A 429's retry-after is waited out in full
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
The token decides which agent the certificate binds to: the trusted issuer's
`claimMapping.agent_id`, or the agent carrying the token's `oidcIss`/`oidcSub`
(set with `client.agents.update(agent_id, oidc_iss=..., oidc_sub=...)` or in
provisioning), or, if the issuer allows it, a newly created agent. `agent_id=`
is only an assertion: when it names a different agent, or the token binds to
none, the exchange raises `OidcCertExchangeError` (403
`CERT_AGENT_BINDING_MISMATCH`). A refused exchange carries the Server's
`recovery_hint`, with the token scrubbed out. `AsyncAgledgerClient` takes
`async_oidc_cert_credential`, whose token function may be a coroutine.

To verify an agent's own signatures offline later, keep `credential.public_key_jwk`
and pass it to `verify_export(..., agent_keys=[jwk])` (see below).

Work done for a person or another party rather than for the agent itself takes
`on_behalf_of=`: an RFC 8693 delegation token your provider issued, sent as the
`AGLedger-On-Behalf-Of` header on `records.create`, `records.transition`,
`records.submit_verdict`, `completions.submit` and `a2a.call`.

## Async Support

```python
import asyncio
import os

from agledger import AsyncAgledgerClient


async def main() -> None:
    async with AsyncAgledgerClient(
        api_key=os.environ["AGLEDGER_API_KEY"],
        base_url=os.environ["AGLEDGER_EXTERNAL_URL"],
    ) as client:
        record = await client.records.create(
            type="notarize-generic-v1",
            criteria={"summary": "Async hello"},
        )
        fetched = await client.records.get(record.id)
        print(fetched.id, fetched.status)


asyncio.run(main())
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

Branch on `err.type`, not on `str(err)`, which is the body's human-readable `detail`. Schema reads take the same pin (`client.schemas.get("acme-po-v1", publisher="acme-corp")`), and `client.schemas.list()` returns one row per (publisher, type) so you can choose before reading.

Every Record reports the binding the engine used, whether or not you pinned it:

```python
record = client.records.get(record_id)
record.publisher   # "acme-corp", or None (see below)
record.schema_url  # "/v1/schemas/acme-po-v1?publisher=acme-corp". Follow it verbatim.
```

`publisher` is `None` on Records the engine never validated against a local registration: federation-received ones (the originator ran the gate against its own registration) and ones backfilled through admin import. Read that as "ask the originator", not as "the schema is missing here".

Single-publisher orgs, which is nearly every install, never pass `publisher` and read their one label (usually `local`) back.

### Disputes

`client.disputes` lists, files, resolves and withdraws disputes. Filing, withdrawing, reading and submitting evidence all take the **record** id. Resolving takes the **dispute** id, because the outcome is rendered on the dispute itself. Each call is made by the party the Server expects: here the principal has rejected the completion (the Quick Start with `verdict="reject"`), the performer disputes that verdict, the principal renders the outcome, and the org-wide listing takes an org admin key:

```python
admin = AgledgerClient(api_key=os.environ["AGLEDGER_ADMIN_API_KEY"], base_url=base_url)

filed = performer.disputes.create(record.id, grounds="quality_issue")

# The dispute id, not the record id. `filed.id` is the one to pass.
resolved = principal.disputes.resolve(
    filed.id,
    outcome="OVERTURNED",
    rationale="The completion met the tolerance band on re-read.",
)

page = admin.disputes.list(status="RESOLVED")
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

export_data = client.records.get_audit_export(record.id)
result = verify_export(export_data.model_dump(by_alias=True))

if result.verdict == "failed":
    print(f"Broken at position {result.broken_at.position}: {result.broken_at.code}")
print(result.verdict)  # "unanchored" here: pass trust_anchors for a trusted verdict
```

Read `result.verdict` (`"trusted"`, `"unanchored"` or `"failed"`) rather than
`result.valid` alone: a valid result with no `trust_anchors` is `"unanchored"`,
which is not a trusted verdict.

Records written with the OIDC cert credential also carry the agent's own
signature over each request body. Pass the certificate's public key to check
those too; without it they are counted in `result.agent_signatures.present` and
left unchecked:

```python
from agledger.verify import verify_export

export_data = client.records.get_audit_export(record.id)
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

### Anchoring keys

A vault key the Server publishes comes from its database, and anything with
write access to that database can add a key row and entries signed with it.
What it cannot add is a key statement: a COSE_Sign1 signed by a key the Server
already trusted (and, for a new key, by the new key too). Pass the SPKI digest
of a vault key you hold or took out of band as `trust_anchors`, and the
verifier walks the statements from it. The installer prints the digest of the
first vault key, and the Server's `signing-key-digest.js` derives one from any
key you hold. The export's own `exportMetadata.anchoredFrom` names the Server's
key and is reported against your anchors (`key_trust.anchored_from_pinned`),
but it is the export's word and never counts as an anchor.

```python
import json

from agledger.verify import verify_export

with open("audit-export.json") as fh:
    export_data = json.load(fh)

result = verify_export(
    export_data,
    trust_anchors=["sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e"],
    # The operator's VAULT_DISTRUSTED_KEYS, when a key leaked: what it signed
    # from the instant on (or, with none, from its retirement) counts for nothing.
    distrusted_keys=[],
)
trust = result.key_trust
print(result.verdict, trust.status, trust.anchored_key_ids, trust.unanchored_key_ids)
for finding in trust.findings:
    print(finding.code, finding.key_id, finding.detail)
```

An entry signed by a key the walk does not anchor fails
`CHAIN_SIGNING_KEY_UNANCHORED`, and each anchored key is held to the window its
statements sign. The statements walked are the export's own
(`exportMetadata.signingKeyStatements`) plus any `statements` on keys you pass
as `public_keys` (`client.verification_keys.list()` carries them; pass its
result, its `.data` list, or the `GET /v1/verification-keys` body as served). Findings about the statements themselves make the result invalid, at
position 0: `KEY_STATEMENT_INVALID` (a statement that does not verify, disagrees
with what it is filed under, touches no anchored key, was signed after a
closure or a second admission, or admits a trusted key under an endorser the
walk does not trust), `KEY_CLOSURE_INVALID` (a retired key with no closure that
counts for it, a closure that should not count, any counting closure of a
published key by a key the walk reaches but does not anchor, or a closure dated
after the time it was stored, as the engine's scan grades them), and
`CHAIN_KEY_WINDOW_DRIFT` (a listed window or status that differs from the
signed value).

A key the Server's `VAULT_DISTRUSTED_KEYS` names is listed with
`distrustedFrom`, the instant its entry gives (in an export's
`signingKeyWindows` and on `/v1/verification-keys`), and where that instant is
earlier than the retirement the key's closures sign, the listed `retiredAt` is
that instant. A walk not given the same entry still fails on that window, but
the finding names the entry the listing says the Server applied
(`distrustedKeys sha256:<hex>@<distrustedFrom>`, `--distrusted-key` in
`agledger-verify`) rather than reading as a rewritten column, and says so when
the entry it was given carries another instant; an entry at an earlier
instant, which fails nothing on the window, is said in `key_trust.notes`.
`distrustedFrom` is the source's unsigned word and only changes that wording:
it never ends, opens or widens a window and never clears a finding. Confirm
the instant with the Server's operator before giving that entry: off a dump an
entry also voids every admission the key signed, so a key it admitted that
nothing else reaches is no longer trusted and its window no longer graded.

A pinned key distrusted with no instant raises `TypeError`, as the Server
refuses to start with that pair. A pin beside a dated entry
(`sha256:<hex>@<instant>`) is taken: the pin vouches for what the key stored
before the instant, and the entry withdraws what it stored from then on. A
dump row repeating an earlier row's signed payload counts once, so a row
copied in the database under a new id and time says nothing new.

On a dump, a distrusted key that a key the walk trusts has retired (with force,
as the key-compromise runbook does) is bounded by that retirement, and what it
signed before then is accounted for rather than failed, as the engine's scan
lists it: a statement it signed is listed in `key_trust.accounted`, and a chain
entry whose signature verifies under it, outside what the key is trusted for,
is listed in `vault.accounted` as `CHAIN_SIGNED_BY_DISTRUSTED_KEY` (each an
`AccountedEntry` naming its chain, record or org, position and key). Neither
fails the dump, and `agledger-verify` prints both. What the key signed after
that retirement fails as before, and a distrusted key the dump's registry lists
that no trusted key has retired is `KEY_CLOSURE_INVALID`, naming the forced
retire call that bounds it. `verify_dump_dir(path, ...)` loads and verifies a
dump directory, refusing its key options before it reads anything.

`distrusted_keys` on an export is stricter than on a dump. A dump's
`vault_key_statements` rows date what a distrusted key stored before its cutoff,
as the engine does. An export's statements, and those on keys you pass, carry
an `id` and `createdAt` nothing signs, so a leaked key's holder can backdate
them at will: there a statement a distrusted key signed admits no key, whatever
time it carries. It still does everything that can only narrow trust (it dates
its subject's window, cuts that key's edge back as a later admission, and a
closure it signed still retires its subject). Where the document dates such a
statement before the cutoff, so the engine would have counted it, voiding it is
a note in `key_trust.notes`, never a finding, so an honest rotation away from a
key you later distrust still passes pinned on its successor.

Every instant is read as strict RFC 3339 (a `T`, a `Z` or numeric offset, a real
calendar date and time of day). A key window you pass in `public_keys` that is
not raises `TypeError` naming the key; one the export embeds in
`signingKeyWindows` fails the entries under that key `CHAIN_MALFORMED_ENTRY`
rather than skipping that edge.

Without `trust_anchors` the result still passes when nothing failed, flagged:
`result.key_trust.status` is `"no_anchor"` and
`result.optional_checks["key_anchoring"]` is `"skipped_no_input"`. That is not a
trusted verdict, because a key written into the Server's database alone would
pass too.

Statements are walked in the order the Server wrote them, never by an instant
a statement signs: a dump carries each row's `created_at`, and an API 2.0
export or `GET /v1/verification-keys` publishes each statement's row `id` and
`createdAt`, ordered by `createdAt` then `id` (`key_trust.order` is
`"written"`). Within such a document, a statement with no readable write time
is `KEY_STATEMENT_INVALID`, and so is one that is not strict RFC 3339 (a `T`,
a `Z` or numeric offset, a real calendar date). A document from a Server that published neither
field is walked in the order of the instants its statements sign
(`key_trust.order` is `"signed"`), which agrees with the write order for a
document the Server served but cannot hold a leaked key to when it actually
wrote a statement. A trusted key's document lists every admission it signed,
so the walk opens its window where the engine does; where it cannot (a later
succession whose endorser is not itself published, which the walk cannot
check), the key's listed window is reported as `CHAIN_KEY_WINDOW_DRIFT`. A dump
carries that endorser and agrees with the engine. The walk
is `agledger.verify.compute_key_trust`, with
`key_statements_from_verification_keys()` for a saved `GET
/v1/verification-keys` response.

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
(Ed25519 or ES256). Format 2.0 (1.0 was JCS + detached Ed25519). Pass `public_keys={...}` to supply keys yourself (these override the
export's embedded keys), `require_key_id="key-id"` to reject exports signed by an
unexpected key, or `require_supplied_keys=True` to refuse the export's own
embedded keys. `result.key_provenance` reports how many signatures were checked
against supplied vs embedded keys. That says where a key came from, not that it
is trusted: a key fetched from the Server comes from its database too, and
`trust_anchors` is what establishes trust.

On a **FIPS-locked host** there is no EdDSA, so an Ed25519 chain cannot be
verified there (ES256 chains can). That is reported as
`CHAIN_UNSUPPORTED_ALGORITHM`, never as a signature failure: "I could not check
this" and "I checked this and it failed" lead to opposite conclusions, and only
one is grounds for a tamper investigation. The result still fails closed. To
verify an Ed25519 chain, re-run on a host without the restriction; verification
is entirely offline, so the export and keys are portable.

## Offline Full-Vault Dump Verification

For a whole-instance audit (not just one Record), verify a six-file NDJSON dump
produced by the API's dump-vault tool. This walks the signed key statements
from your trust anchors, walks every per-record and per-org schema-event chain,
cross-checks the signed vault checkpoints against the live chain, and verifies
the `org_admin_reads` log: each leaf's RFC 9162 leaf hash, signed claim and
signature, and each signed tree head's RFC 9162 root, claim and signature
(including fork detection):

```python
from agledger.verify import load_dump, verify_dump

report = verify_dump(
    load_dump("./vault-dump-dir"),
    trust_anchors=["sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e"],
)
print(report.verdict)  # "trusted", "unanchored" (no trust_anchors) or "failed"
for finding in report.key_trust.findings:
    print(f"[{finding.code}] key {finding.key_id}: {finding.detail}")
for f in report.vault.failures + report.org_admin_reads.failures:
    print(f"[{f.code}] {f.message}")
```

A dump walks `vault_key_statements.ndjson` in write order. Entries, vault
checkpoints, read-log leaves and read-log tree heads signed by a key the walk
does not anchor fail `CHAIN_SIGNING_KEY_UNANCHORED`, `CHECKPOINT_KEY_UNANCHORED`,
`TENANT_READ_KEY_UNANCHORED` and `TENANT_CHECKPOINT_KEY_UNANCHORED`. The signed
claim inside each checkpoint, leaf and tree head is held to its row
(`CHECKPOINT_CLAIM_MISMATCH`, `TENANT_READ_CLAIM_MISMATCH`,
`TENANT_CHECKPOINT_CLAIM_MISMATCH`). `report.ok` is false only for the `failed`
verdict: an `unanchored` report passes, and is not a trusted verdict until you
give it a pin.

The org-read tree primitives are exported for checking an inclusion proof from
`GET /v1/audit/org-reads/checkpoints/{id}/proof`:

```python
from agledger.verify import org_read_leaf_hash, org_read_merkle_root, verify_org_read_inclusion

# leaf_hash = hex(sha256(0x00 || cose_sign1)); a checkpoint's root is the RFC 9162 root over them.
leaf = org_read_leaf_hash(b"cose-sign1-bytes")
root = org_read_merkle_root([leaf])
assert root is not None  # None only for a leaf hash that is not 64 lowercase hex characters
# A one-leaf tree has an empty path.
print(root == leaf, verify_org_read_inclusion(leaf, 0, 1, [], root))  # True True
```

### `agledger-verify` CLI (turnkey)

The `[verify]` extra installs an `agledger-verify` console script that
auto-detects its argument: a **directory** is a full-vault dump, a **file** is a
single `/audit-export` JSON document, so one command covers both verifiers, with
no network calls:

```bash
pip install 'agledger[verify]'

PIN=sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e
agledger-verify ./vault-dump-dir --trust-anchor "$PIN"      # full-vault dump
agledger-verify audit-export.json --trust-anchor "$PIN"     # single record export
agledger-verify ./vault-dump-dir -f json      # machine-readable report (unanchored)
agledger-verify ./vault-dump-dir --agent-keys agent-keys.json   # also re-check agent signatures
agledger-verify audit-export.json --keys verification-keys.json --require-supplied-keys
```

`--agent-keys` takes a JSON file of agent certificate keys: one JWK, a list, a
`{"keys": [...]}` JWK Set, or entries wrapping a key as `{"publicKeyJwk": ...}`
(what `credential.public_key_jwk` gives you). It works on a dump directory and
on an `/audit-export` file; in code, pass `agent_keys=` to `verify_dump` or
`verify_export`. Both reports say which input-gated checks ran
(`optional_checks`) and how many agent signatures were present and verified.
A dump not scoped to one org carries the certificate keys itself: each
`EPHEMERAL_CERT_ISSUED` entry on the platform-ops chain signs its
certificate's `publicKeyJwk` (engines from 1.8.0 on), and a key is used once
that chain has verified clean (`cert_keys_from_chain` counts them). An
org-scoped dump and an `/audit-export` carry none, so for those pass the keys.

A row with no signing key is reduced coverage only from before the install
began signing. An unsigned chain entry after a signed one, or any unsigned
entry, checkpoint or read-log row written at or after the earliest
`activatedAt` in the key set (retired keys included), fails
`CHAIN_ENTRY_UNSIGNED`, `CHECKPOINT_UNSIGNED`, `TENANT_READ_LEAF_UNSIGNED` or
`TENANT_CHECKPOINT_UNSIGNED`, as the engine grades it. Each read-log leaf's
signature is verified too.

`--trust-anchor` (repeat it once per key) pins the SPKI digest of a vault key
you hold, on a dump directory and on an `/audit-export` file alike, and
`--distrusted-key` (once per key: `sha256:<hex>`, optionally `@<RFC 3339
instant>`) passes the operator's `VAULT_DISTRUSTED_KEYS` entries. A pass
anchored to a pin is `[PASS]`. Without a pin the headline reads `[VERIFIED,
NOT ANCHORED]` and says plainly that the pass is not a trusted verdict: anyone
who re-signs the chain with a key of their own, and writes that key into the
registry, also passes. A pin that anchors no signature in the target (every
entry is unsigned history from before the install began signing) reads
`[VERIFIED, NOT ANCHORED]` too, saying so. A failure is `[FAIL]`.

The exit code is `0` for a pass, anchored or not, `1` for a failed
verification, `3` when the `[verify]` extra is not installed (the command prints
one line naming `pip install 'agledger[verify]'`), and `2` when no verdict was reached: an unknown flag, a flag
missing its value, a malformed pin or distrusted key, a key named twice,
`--distrusted-key` without `--trust-anchor`, a key given to both with no instant, a key-policy flag on a dump
directory, a target that does not exist, or a file that cannot be read or does
not parse. The flags, these refusals and their messages, `--help`, the
headlines and the exit codes are the same as `@agledger/verify`'s
`agledger-verify`. Where a message quotes
the JSON parser or the library's own `TypeError` about a key file, that part
is in Python's words, and the help leaves out `@agledger/verify`'s note on
streaming `audit_vault.ndjson`, which this verifier reads whole.

`--keys` supplies keys for an `/audit-export` file: save `GET
/v1/verification-keys` and pass it (the `{keyId: ...}` map, a `[{keyId,
publicKey}]` list, or the raw response envelope all work; the statements the
response carries are walked with the export's own). `--require-supplied-keys`
refuses the export's embedded keys outright and `--require-key-id <id>` pins
the key every entry must reference. The three key-policy flags apply to an
`/audit-export` file only; a dump directory carries its own key registry and
rejects them. In code they are the `public_keys`, `require_supplied_keys` and
`require_key_id` arguments to `verify_export`.

Every failure carries an actionable next step
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

Per-record signed Merkle anchors are written on a schedule (every 6 hours by
default), letting an auditor detect audit-vault TRUNCATE / DELETE tampering
offline. Listing them takes an org admin key:

```python
checkpoints = admin.audit.vault_checkpoints.list(record_id=record.id)
```

## Licensing

Running AGLedger in production requires a license. Get a [Developer Edition License Key](https://agledger.ai/register/), or read the terms at https://agledger.ai/license and the editions at https://agledger.ai/pricing.

## SDK License

Proprietary. Copyright (c) 2026 AGLedger LLC. All rights reserved.
