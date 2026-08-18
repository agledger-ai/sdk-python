"""API v1.3.4 client-facing deltas.

Both additions live in response bodies, which is the surface neither parity
snapshot pins: ``routes.json`` covers request fields and ``schema-fields.json``
covers the named ``components.schemas`` models. Response drift lands here.

Same style as test_response_contract.py: feed a real-server-shaped payload
(camelCase, exactly what the API emits) through a resource method and assert
the model parses and surfaces the new field.
"""

import httpx
import respx

from agledger import AgledgerClient

BASE = "https://agledger.example.com"


def _client() -> AgledgerClient:
    return AgledgerClient(api_key="test-key", base_url=BASE)


@respx.mock
def test_vault_checkpoint_carries_the_chain_discriminator():
    # Three chains are checkpointed. Only chain="record" is keyed by a
    # real record id; "schema" and "admin" carry a derived key that resolves to
    # no record, so a caller must read `chain` before dereferencing `recordId`.
    respx.get(f"{BASE}/v1/audit-vault/checkpoints").mock(
        return_value=httpx.Response(200, json={
            "data": [
                {
                    "id": "cp-1",
                    "recordId": "01900000-0000-7000-8000-000000000001",
                    "chain": "record",
                    "chainPosition": 4,
                    "payloadHash": "a" * 64,
                    "coseSign1": "0oRE...",
                    "signingKeyId": "key-1",
                    "createdAt": "2026-08-01T00:00:00.000Z",
                },
                {
                    "id": "cp-2",
                    "recordId": "00000000-0000-0000-0000-000000000000",
                    "chain": "admin",
                    "chainPosition": 9,
                    "payloadHash": "b" * 64,
                    "coseSign1": "0oRE...",
                    "signingKeyId": None,
                    "createdAt": "2026-08-01T00:00:00.000Z",
                },
            ],
            "pagination": {"nextCursor": None, "hasMore": False},
        })
    )
    page = _client().audit.vault_checkpoints.list(limit=2)
    record_cp, admin_cp = page["data"]
    assert record_cp.chain == "record"
    assert admin_cp.chain == "admin"
    assert admin_cp.signing_key_id is None


@respx.mock
def test_vault_checkpoint_parses_without_chain_on_an_older_server():
    # `chain` is additive in v1.3.4. A pre-1.3.4 server omits it, and that must
    # stay a None rather than a deserialization crash.
    respx.get(f"{BASE}/v1/audit-vault/checkpoints").mock(
        return_value=httpx.Response(200, json={
            "data": [{
                "id": "cp-1",
                "recordId": "01900000-0000-7000-8000-000000000001",
                "chainPosition": 1,
                "payloadHash": "c" * 64,
                "coseSign1": "0oRE...",
                "signingKeyId": None,
                "createdAt": "2026-08-01T00:00:00.000Z",
            }],
            "pagination": {"nextCursor": None, "hasMore": False},
        })
    )
    (checkpoint,) = _client().audit.vault_checkpoints.list()["data"]
    assert checkpoint.chain is None


@respx.mock
def test_compliance_export_surfaces_the_row_cap():
    # The export is capped at 10000 rows, newest first. Before this,
    # recordCount was the only signal and a truncated export was
    # indistinguishable from a complete one.
    respx.post(f"{BASE}/v1/compliance/export").mock(
        return_value=httpx.Response(200, json={
            "exportId": "exp-1",
            "status": "ready",
            "downloadUrl": f"{BASE}/v1/compliance/export/exp-1/download",
            "createdAt": "2026-08-01T00:00:00.000Z",
            "expiresAt": "2026-08-02T00:00:00.000Z",
            "recordCount": 10000,
            "truncated": True,
            "totalRecords": 41337,
        })
    )
    export = _client().compliance.export(format="json")
    assert export.truncated is True
    assert export.record_count == 10000
    assert export.total_records == 41337


@respx.mock
def test_compliance_export_untruncated_on_an_older_server():
    # Pre-1.3.4 servers omit both fields. None means unknown, which is
    # deliberately not the same as False.
    respx.post(f"{BASE}/v1/compliance/export").mock(
        return_value=httpx.Response(200, json={
            "exportId": "exp-2",
            "status": "ready",
            "recordCount": 12,
        })
    )
    export = _client().compliance.export(format="json")
    assert export.truncated is None
    assert export.total_records is None
