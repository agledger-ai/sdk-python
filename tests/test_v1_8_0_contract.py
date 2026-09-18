"""API v1.8.0 client-facing deltas.

Same style as test_v1_7_0_contract.py: a real-server-shaped payload (camelCase,
exactly what the API emits) through a resource method, asserting the model
parses and surfaces the new field, or a request asserting the exact wire body.
"""

from __future__ import annotations

import json
import typing

import httpx
import pytest
import respx

from agledger import (
    AgledgerClient,
    AsyncAgledgerClient,
    AuditChainFailure,
    AuditChainIntegrityReason,
    ConflictError,
    UnprocessableError,
)

BASE = "https://agledger.example.com"
OBO = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwZXJzb24tMSIsImFjdCI6eyJzdWIiOiJhZ2VudC0xIn19.c2ln"


def _client() -> AgledgerClient:
    return AgledgerClient(api_key="test-key", base_url=BASE)


def _body(route: respx.Route) -> typing.Any:
    return json.loads(route.calls.last.request.content)


def _record(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "rec-1", "orgId": "org-1", "principalAgentId": "agt-1",
        "type": "notarize-generic-v1", "platform": "test", "status": "ACTIVE", "criteria": {},
        "submissionCount": 0, "version": 1,
        "createdAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-09-01T00:05:00Z",
    }
    row.update(overrides)
    return row


RECORD_READ = {"leafHash": "ab" * 32, "leafIndex": 41, "signedCheckpointRef": None}


# --- api keys ---


@respx.mock
def test_create_api_key_no_longer_sends_environment_and_takes_allowed_ips():
    route = respx.post(f"{BASE}/v1/admin/api-keys").mock(return_value=httpx.Response(201, json={}))
    _client().admin.create_api_key(
        role="agent", owner_id="agt-1", owner_type="agent", allowed_ips=["10.0.0.0/8"]
    )
    assert _body(route) == {
        "role": "agent", "ownerId": "agt-1", "ownerType": "agent", "allowedIps": ["10.0.0.0/8"],
    }


def test_create_api_key_refuses_environment_at_the_call_site():
    # The Server refuses the field (additionalProperties: false). The SDK no
    # longer offers it, so the mistake is a TypeError, not a 400.
    with pytest.raises(TypeError):
        _client().admin.create_api_key(  # type: ignore[call-arg]
            role="agent", owner_id="agt-1", owner_type="agent", environment="live"
        )


@respx.mock
def test_list_api_keys_sends_the_dormancy_filters():
    route = respx.get(f"{BASE}/v1/admin/api-keys").mock(
        return_value=httpx.Response(200, json={"data": [], "hasMore": False})
    )
    _client().admin.list_api_keys(last_used_before="2026-06-01T00:00:00Z", never_used=False)
    params = route.calls.last.request.url.params
    assert params["lastUsedBefore"] == "2026-06-01T00:00:00Z"
    assert params["neverUsed"] == "false"


@respx.mock
def test_list_api_keys_rows_carry_the_revocation_trail():
    respx.get(f"{BASE}/v1/admin/api-keys").mock(return_value=httpx.Response(200, json={
        "data": [{
            "keyId": "k-1", "role": "agent", "ownerId": "agt-1", "ownerType": "agent",
            "isActive": False, "revokedAt": "2026-09-01T00:00:00Z", "revokedByKeyId": "k-0",
            "revocationReason": "rotated", "rotatedFromKeyId": None,
        }],
        "hasMore": False,
    }))
    row = _client().admin.list_api_keys()["data"][0]
    assert row["revokedByKeyId"] == "k-0"
    assert "environment" not in row


@respx.mock
def test_bulk_revoke_takes_the_filters_as_well_as_ids():
    route = respx.post(f"{BASE}/v1/admin/api-keys/bulk-revoke").mock(
        return_value=httpx.Response(200, json={"revoked": 2})
    )
    client = _client()
    client.admin.bulk_revoke_api_keys(["k-1", "k-2"])
    assert _body(route) == {"keyIds": ["k-1", "k-2"]}
    client.admin.bulk_revoke_api_keys(
        never_used=True, created_before="2026-06-01T00:00:00Z", reason="dormant sweep"
    )
    assert _body(route) == {
        "neverUsed": True, "createdBefore": "2026-06-01T00:00:00Z", "reason": "dormant sweep",
    }
    client.admin.bulk_revoke_api_keys(last_used_before="2026-06-01T00:00:00Z", owner_id="agt-1", role="agent")
    assert _body(route) == {
        "lastUsedBefore": "2026-06-01T00:00:00Z", "ownerId": "agt-1", "role": "agent",
    }


@respx.mock
def test_update_api_key_sets_and_clears_allowed_ips():
    route = respx.patch(f"{BASE}/v1/admin/api-keys/k-1").mock(return_value=httpx.Response(200, json={}))
    client = _client()
    client.admin.update_api_key("k-1", allowed_ips=["203.0.113.7"])
    assert _body(route) == {"allowedIps": ["203.0.113.7"]}
    # null is how the route is told to remove the restriction, so it is sent.
    client.admin.update_api_key("k-1", allowed_ips=None)
    assert _body(route) == {"allowedIps": None}


@respx.mock
async def test_async_update_api_key_no_longer_maps_expires_at():
    # The async mapping sent expiresAt, which the PATCH route refuses. It now
    # matches the sync one.
    route = respx.patch(f"{BASE}/v1/admin/api-keys/k-1").mock(return_value=httpx.Response(200, json={}))
    async with AsyncAgledgerClient(api_key="k", base_url=BASE) as client:
        await client.admin.update_api_key("k-1", is_active=False, allowed_ips=[])
    assert _body(route) == {"isActive": False, "allowedIps": []}


# --- trusted issuers ---


@respx.mock
def test_trusted_issuer_create_and_update_take_jti_single_use_and_subject_allowlist():
    create = respx.post(f"{BASE}/v1/admin/trusted-issuers").mock(return_value=httpx.Response(201, json={}))
    update = respx.patch(f"{BASE}/v1/admin/trusted-issuers/ti-1").mock(return_value=httpx.Response(200, json={}))
    client = _client()
    client.admin.trusted_issuers.create(
        issuer_url="https://idp.example", expected_audience="agledger",
        jti_single_use=True, subject_allowlist=["svc-a", "svc-b"],
    )
    assert _body(create) == {
        "issuerUrl": "https://idp.example", "expectedAudience": "agledger",
        "jtiSingleUse": True, "subjectAllowlist": ["svc-a", "svc-b"],
    }
    client.admin.trusted_issuers.update("ti-1", jti_single_use=False)
    assert _body(update) == {"jtiSingleUse": False}


# --- recordRead on the reads that log an org-admin read ---


@respx.mock
def test_record_read_is_surfaced_on_every_read_that_carries_it():
    respx.get(f"{BASE}/v1/records/rec-1/gate-status").mock(return_value=httpx.Response(200, json={
        "recordId": "rec-1", "phase1Status": "passed", "phase2Status": "pending", "recordRead": RECORD_READ,
    }))
    respx.post(f"{BASE}/v1/records/rec-1/evaluate").mock(return_value=httpx.Response(200, json={
        "recordId": "rec-1", "completions": [], "overallStatus": "pending", "recordRead": RECORD_READ,
    }))
    completion = {
        "id": "c-1", "recordId": "rec-1", "agentId": "agt-1", "evidence": {},
        "createdAt": "2026-09-01T00:00:00Z", "recordRead": RECORD_READ,
    }
    respx.get(f"{BASE}/v1/records/rec-1/completions/c-1").mock(return_value=httpx.Response(200, json=completion))
    respx.get(f"{BASE}/v1/records/rec-1/completions").mock(
        return_value=httpx.Response(200, json={"data": [completion], "hasMore": False})
    )
    respx.get(f"{BASE}/v1/records/rec-1/dispute").mock(return_value=httpx.Response(200, json={
        "dispute": {
            "id": "d-1", "recordId": "rec-1", "initiatedByRole": "principal", "initiatedById": "agt-1",
            "grounds": "other", "status": "EVIDENCE_WINDOW", "createdAt": "2026-09-01T00:00:00Z",
        },
        "evidence": [],
        "recordRead": RECORD_READ,
    }))
    client = _client()
    reads = [
        client.gate.get_status("rec-1").record_read,
        client.gate.evaluate("rec-1").record_read,
        client.completions.get("rec-1", "c-1").record_read,
        client.completions.list("rec-1").data[0].record_read,
        client.disputes.get("rec-1").record_read,
    ]
    for read in reads:
        assert read is not None
        assert read.leaf_index == 41
        assert read.signed_checkpoint_ref is None


# --- webhooks ---


@respx.mock
def test_webhook_says_when_provisioning_manages_it_and_delete_is_a_conflict():
    respx.get(f"{BASE}/v1/webhooks/wh-1").mock(return_value=httpx.Response(200, json={
        "id": "wh-1", "url": "https://hooks.example", "isActive": True,
        "createdAt": "2026-09-01T00:00:00Z", "managedBy": "provisioning",
    }))
    respx.delete(f"{BASE}/v1/webhooks/wh-1").mock(return_value=httpx.Response(409, json={
        "message": "Provisioning-managed", "code": "CONFLICT",
        "recoveryHint": "Remove it from the provisioning config and reload.",
    }))
    client = _client()
    assert client.webhooks.get("wh-1").managed_by == "provisioning"
    with pytest.raises(ConflictError) as info:
        client.webhooks.delete("wh-1")
    assert info.value.recovery_hint is not None


@respx.mock
def test_rotate_key_422_is_an_unprocessable_error():
    respx.post(f"{BASE}/v1/auth/keys/rotate").mock(
        return_value=httpx.Response(422, json={"message": "cannot rotate", "code": "INVALID_STATE"})
    )
    with pytest.raises(UnprocessableError):
        _client().auth.rotate_key()


# --- license on conformance ---


@respx.mock
def test_conformance_reports_license_state():
    respx.get(f"{BASE}/v1/conformance").mock(return_value=httpx.Response(200, json={
        "capabilities": {}, "license": {"validity": "unlicensed", "notice": "unlicensed", "escalated": False},
    }))
    conformance = _client().discovery.get_conformance()
    assert conformance.license is not None
    assert conformance.license.validity == "unlicensed"
    assert conformance.license.notice == "unlicensed"
    assert conformance.license.escalated is False


# --- chain integrity reasons ---

# Every member the 1.8.0 spec declares at each site, minus null. Pinned here
# because the members are nullable on the wire and so cannot ride the shared
# enum snapshot (see test_enum_parity.py).
SPEC_1_8_0_CHAIN_INTEGRITY_REASON = {
    "agent_signature_invalid", "audit_vault_empty", "audit_vault_row_missing_for_checkpoint",
    "cert_actor_drift", "cert_expired", "cert_missing", "cert_window_drift", "chain_broken_at",
    "checkpoint_hash_mismatch", "oidc_actor_drift", "payload_drift", "signature_invalid",
    "signing_key_drift", "signing_key_unknown", "unsupported_algorithm",
}
SPEC_1_8_0_CHAIN_FAILURE = {
    "agent_signature_invalid", "audit_vault_truncated", "cert_actor_drift", "cert_expired",
    "cert_missing", "cert_window_drift", "checkpoint_anchor_mismatch", "oidc_actor_drift",
    "payload_drift", "payload_hash_mismatch", "previous_hash_mismatch", "signature_invalid",
    "signing_key_drift", "signing_key_unknown", "unsupported_algorithm",
}


def _members(alias: object) -> set[str]:
    return {
        value
        for arg in typing.get_args(alias)
        if typing.get_origin(arg) is typing.Literal
        for value in typing.get_args(arg)
    }


def test_chain_integrity_unions_match_the_spec():
    assert _members(AuditChainIntegrityReason) == SPEC_1_8_0_CHAIN_INTEGRITY_REASON
    assert _members(AuditChainFailure) == SPEC_1_8_0_CHAIN_FAILURE


def _export(reason: str, failure: str) -> dict[str, object]:
    return {
        "exportMetadata": {
            "recordId": "rec-1", "type": "notarize-generic-v1", "exportDate": "2026-09-01T00:00:00Z",
            "totalEntries": 1, "chainIntegrity": False, "chainIntegrityReason": reason,
            "chainIntegrityDetail": {"brokenAtPosition": 1, "failure": failure},
            "exportFormatVersion": "2.0", "canonicalization": "RFC8949-CDE",
        },
        "entries": [],
    }


@respx.mock
@pytest.mark.parametrize(
    ("reason", "failure"),
    [
        ("cert_window_drift", "cert_window_drift"),
        # A reason a newer Server adds must still parse. A closed Literal here
        # failed the whole export on the first value it did not list.
        ("some_future_reason", "some_future_failure"),
    ],
)
def test_an_export_carrying_a_new_reason_parses(reason: str, failure: str):
    respx.get(f"{BASE}/v1/records/rec-1/audit-export").mock(
        return_value=httpx.Response(200, json=_export(reason, failure))
    )
    export = _client().records.get_audit_export("rec-1")
    assert export.export_metadata.chain_integrity_reason == reason
    assert export.export_metadata.chain_integrity_detail is not None
    assert export.export_metadata.chain_integrity_detail.failure == failure


# --- AGLedger-On-Behalf-Of ---


@respx.mock
def test_on_behalf_of_rides_every_route_that_declares_it():
    create = respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(201, json=_record()))
    transition = respx.post(f"{BASE}/v1/records/rec-1/transition").mock(
        return_value=httpx.Response(200, json=_record())
    )
    verdict = respx.post(f"{BASE}/v1/records/rec-1/verdict").mock(return_value=httpx.Response(200, json={
        "recordId": "rec-1", "completionId": "c-1", "verdict": "accept", "recommendation": "SETTLE",
        "reporterType": "principal", "reportedAt": "2026-09-01T00:00:00Z",
    }))
    completion = respx.post(f"{BASE}/v1/records/rec-1/completions").mock(return_value=httpx.Response(201, json={
        "id": "c-1", "recordId": "rec-1", "agentId": "agt-1", "evidence": {},
        "createdAt": "2026-09-01T00:00:00Z",
    }))
    a2a = respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0"}))

    client = _client()
    client.records.create(type="notarize-generic-v1", criteria={}, on_behalf_of=OBO)
    client.records.transition("rec-1", "activate", on_behalf_of=OBO)
    client.records.submit_verdict("rec-1", completion_id="c-1", verdict="accept", on_behalf_of=OBO)
    client.completions.submit("rec-1", evidence={}, on_behalf_of=OBO)
    client.a2a.call("create_record", {"type": "notarize-generic-v1"}, on_behalf_of=OBO)

    for route in (create, transition, verdict, completion, a2a):
        assert route.calls.last.request.headers["agledger-on-behalf-of"] == OBO


@respx.mock
def test_on_behalf_of_is_absent_unless_given():
    create = respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(201, json=_record()))
    _client().records.create(type="notarize-generic-v1", criteria={})
    assert "agledger-on-behalf-of" not in create.calls.last.request.headers


@respx.mock
async def test_async_on_behalf_of():
    create = respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(201, json=_record()))
    async with AsyncAgledgerClient(api_key="k", base_url=BASE) as client:
        await client.records.create(type="notarize-generic-v1", criteria={}, on_behalf_of=OBO)
    assert create.calls.last.request.headers["agledger-on-behalf-of"] == OBO
