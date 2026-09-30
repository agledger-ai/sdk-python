"""API 2.0 client-facing deltas.

Same style as test_v1_8_0_contract.py: a real-server-shaped payload (camelCase,
exactly what the API emits) through a resource method, asserting the model
parses and surfaces the new field, or a request asserting the exact wire body.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient, EventPage

BASE = "https://agledger.example.com"
STATEMENT = {"kind": "genesis", "cose": ["0oRYJ6MB"]}


def _client() -> AgledgerClient:
    return AgledgerClient(api_key="test-key", base_url=BASE)


@respx.mock
def test_verification_keys_carry_the_signed_key_statements():
    respx.get(f"{BASE}/v1/verification-keys").mock(return_value=httpx.Response(200, json={
        "data": [{
            "keyId": "4b2f0b6374460c76", "algorithm": "Ed25519", "publicKey": "MCow",
            "status": "active", "activatedAt": "2026-09-18T06:29:52.325Z", "retiredAt": None,
            "statements": [STATEMENT],
        }],
        "anchoredFrom": "sha256:" + "a" * 64,
        "keyStatementFormat": "application/vnd.agledger.key-statement+cbor",
        "envelope": "COSE_Sign1", "payloadFormat": "application/vnd.in-toto+cbor",
        "canonicalization": "RFC8949-CDE", "coseAlgorithm": -8, "signatureAlgorithm": "Ed25519",
        "signatureInputTemplate": "Sig_structure = ...",
    }))
    keys = _client().verification_keys.list()
    assert keys.anchored_from == "sha256:" + "a" * 64
    assert keys.key_statement_format == "application/vnd.agledger.key-statement+cbor"
    statement = keys.data[0].statements[0]
    assert (statement.kind, statement.cose) == ("genesis", ["0oRYJ6MB"])


@respx.mock
def test_a_record_export_carries_the_key_statements_and_its_anchor():
    respx.get(f"{BASE}/v1/records/rec-1/audit-export").mock(return_value=httpx.Response(200, json={
        "exportMetadata": {
            "recordId": "rec-1", "type": "notarize-generic-v1", "exportDate": "2026-09-30T00:00:00Z",
            "totalEntries": 1, "chainIntegrity": False,
            "chainIntegrityReason": "signing_key_unanchored",
            "chainIntegrityDetail": {"brokenAtPosition": 1, "failure": "signing_key_unanchored"},
            "exportFormatVersion": "2.0", "canonicalization": "RFC8949-CDE",
            "signingKeyStatements": {"4b2f0b6374460c76": [STATEMENT]},
            "anchoredFrom": None,
        },
        "entries": [],
    }))
    export = _client().records.get_audit_export("rec-1")
    meta = export.export_metadata
    assert meta.chain_integrity_reason == "signing_key_unanchored"
    assert meta.signing_key_statements is not None
    assert meta.signing_key_statements["4b2f0b6374460c76"][0].kind == "genesis"
    assert meta.anchored_from is None


@respx.mock
def test_a_status_component_names_why_it_is_down():
    respx.get(f"{BASE}/status").mock(return_value=httpx.Response(200, json={
        "status": "degraded",
        "components": [
            {"name": "Database", "status": "operational", "latencyMs": 2},
            {"name": "Chain writes", "status": "degraded", "latencyMs": None,
             "reason": "chain_rewind_detected"},
        ],
        "uptime": 10, "timestamp": "2026-09-30T00:00:00Z",
    }))
    status = _client().health.status()
    assert [c.reason for c in status.components] == [None, "chain_rewind_detected"]


@respx.mock
def test_a_verdict_names_who_rendered_it():
    respx.post(f"{BASE}/v1/records/rec-1/verdict").mock(return_value=httpx.Response(200, json={
        "recordId": "rec-1", "completionId": "cmp-1", "verdict": "accept",
        "recommendation": "SETTLE", "recordStatus": "FULFILLED",
        "reporterType": "principal", "reporterRole": "org-admin",
        "reportedAt": "2026-09-30T00:00:00Z",
    }))
    result = _client().records.submit_verdict("rec-1", completion_id="cmp-1", verdict="accept")
    assert (result.reporter_type, result.reporter_role) == ("principal", "org-admin")


@respx.mock
def test_a_bulk_item_carries_the_bounds_it_broke():
    respx.post(f"{BASE}/v1/records/bulk").mock(return_value=httpx.Response(207, json={
        "results": [{
            "index": 0, "status": "error", "error": "Criteria too large",
            "constraintViolations": [
                {"field": "criteria", "parentValue": 65536, "childValue": 70000, "reason": "byte_cap"},
            ],
        }],
        "summary": {"total": 1, "succeeded": 0, "failed": 1},
    }))
    result = _client().records.bulk_create([{"type": "t", "criteria": {}}])
    violations = result.results[0].constraint_violations
    assert violations is not None
    assert violations[0]["field"] == "criteria"


@respx.mock
def test_the_events_page_carries_the_bound_the_walk_serves():
    respx.get(f"{BASE}/v1/events").mock(return_value=httpx.Response(200, json={
        "data": [], "hasMore": False, "nextCursor": None,
        "visibleBefore": "2026-09-30T00:00:00Z",
    }))
    page = _client().events.list(since="2026-09-29T00:00:00Z")
    assert isinstance(page, EventPage)
    assert page.visible_before == "2026-09-30T00:00:00Z"


@respx.mock
async def test_the_async_events_page_is_the_same_type():
    respx.get(f"{BASE}/v1/events").mock(return_value=httpx.Response(200, json={
        "data": [], "hasMore": False, "visibleBefore": "2026-09-30T00:00:00Z",
    }))
    async with AsyncAgledgerClient(api_key="test-key", base_url=BASE) as client:
        page = await client.events.list(since="2026-09-29T00:00:00Z")
    assert isinstance(page, EventPage)


@respx.mock
def test_a_completion_verdict_is_the_record_vocabulary():
    respx.post(f"{BASE}/v1/records/rec-1/completions").mock(return_value=httpx.Response(201, json={
        "id": "cmp-1", "recordId": "rec-1", "agentId": "agt-1", "evidence": {},
        "verdict": "accept", "createdAt": "2026-09-30T00:00:00Z",
    }))
    completion = _client().completions.submit("rec-1", evidence={})
    assert completion.verdict == "accept"


@respx.mock
def test_vault_anchors_list_sends_the_required_record_id():
    route = respx.get(f"{BASE}/v1/admin/vault/anchors").mock(
        return_value=httpx.Response(200, json={"data": [], "hasMore": False})
    )
    _client().admin.vault.anchors.list(record_id="rec-1")
    assert dict(route.calls.last.request.url.params) == {"recordId": "rec-1"}


def test_vault_anchors_list_requires_the_record_id():
    with pytest.raises(TypeError):
        _client().admin.vault.anchors.list()  # type: ignore[call-arg]
