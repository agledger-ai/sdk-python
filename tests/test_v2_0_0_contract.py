"""API 2.0 client contract.

A real-server-shaped payload (camelCase, exactly what the 2.0 spec declares)
through a resource method, asserting the model parses and surfaces the field,
or a request asserting the exact wire body. Every route, field and enum member
named here is in the 2.0 spec.
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
    AuditChainFailureCode,
    AuditChainIntegrityReasonCode,
    ConflictError,
    EventPage,
    UnprocessableError,
)

BASE = "https://agledger.example.com"
OBO = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwZXJzb24tMSIsImFjdCI6eyJzdWIiOiJhZ2VudC0xIn19.c2ln"
STATEMENT = {
    "id": "01a0fd24-a41c-79ab-b3b2-51bab8e97597",
    "kind": "genesis",
    "createdAt": "2026-10-02T15:03:52.092689Z",
    "cose": ["0oRYJ6MB"],
}


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
        "detail": "Provisioning-managed", "error": "CONFLICT",
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
        return_value=httpx.Response(422, json={"detail": "cannot rotate", "error": "INVALID_STATE"})
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

# Every member the 2.0 spec declares for chainIntegrityReason and
# chainIntegrityDetail.failure, minus null. The shared enum snapshot pins these
# too. An unsigned entry after a signed one, or written once the install signs,
# is ``signature_missing``, and an unsigned checkpoint from then on is
# ``checkpoint_unsigned`` (a reason only; the detail's failure never carries a
# checkpoint class).
SPEC_CHAIN_INTEGRITY_REASON = {
    "agent_signature_invalid", "audit_vault_empty", "audit_vault_row_missing_for_checkpoint",
    "cert_actor_drift", "cert_expired", "cert_missing", "cert_window_drift", "chain_broken_at",
    "checkpoint_claim_mismatch", "checkpoint_hash_mismatch", "checkpoint_key_unknown",
    "checkpoint_signature_invalid", "checkpoint_unsigned", "key_expired", "key_not_yet_active",
    "oidc_actor_drift", "payload_drift", "signature_invalid", "signature_missing",
    "signing_key_drift", "signing_key_unknown", "signing_key_unpublished", "unsupported_algorithm",
    # A key no signed key statement anchors.
    "checkpoint_key_unanchored", "signing_key_unanchored",
}
SPEC_CHAIN_FAILURE = {
    "agent_signature_invalid", "audit_vault_truncated", "cert_actor_drift", "cert_expired",
    "cert_missing", "cert_window_drift", "checkpoint_anchor_mismatch", "key_expired",
    "key_not_yet_active", "oidc_actor_drift", "payload_drift", "payload_hash_mismatch",
    "previous_hash_mismatch", "signature_invalid", "signature_missing", "signing_key_drift",
    "signing_key_unknown", "signing_key_unpublished", "unsupported_algorithm",
    "signing_key_unanchored",
}


def _members(alias: object) -> set[str]:
    return {
        value
        for arg in typing.get_args(alias)
        if typing.get_origin(arg) is typing.Literal
        for value in typing.get_args(arg)
    }


def test_chain_integrity_unions_match_the_spec():
    assert _members(AuditChainIntegrityReasonCode) == SPEC_CHAIN_INTEGRITY_REASON
    assert _members(AuditChainFailureCode) == SPEC_CHAIN_FAILURE


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
        ("signature_missing", "signature_missing"),
        ("checkpoint_unsigned", "signature_missing"),
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


# --- fields and routes the Server never served ---


@respx.mock
def test_verification_keys_carry_the_envelope_the_verifier_floor_and_the_signed_key_statements():
    respx.get(f"{BASE}/v1/verification-keys").mock(return_value=httpx.Response(200, json={
        "data": [{
            "keyId": "4b2f0b6374460c76", "algorithm": "Ed25519", "publicKey": "MCow", "publicKeyRaw": "raw",
            "status": "active", "activatedAt": "2026-09-18T06:29:52.325Z", "retiredAt": None,
            "coseAlgorithm": -8, "minVerifierVersion": "1.0.0", "statements": [STATEMENT],
        }],
        "anchoredFrom": "sha256:" + "a" * 64,
        "keyStatementFormat": "application/vnd.agledger.key-statement+cbor",
        "envelope": "COSE_Sign1", "payloadFormat": "application/vnd.in-toto+cbor",
        "canonicalization": "RFC8949-CDE", "coseAlgorithm": -8, "signatureAlgorithm": "Ed25519",
        "signatureInputTemplate": "Sig_structure = ...",
    }))
    keys = _client().verification_keys.list()
    assert (keys.envelope, keys.payload_format, keys.cose_algorithm) == (
        "COSE_Sign1", "application/vnd.in-toto+cbor", -8,
    )
    assert keys.data[0].min_verifier_version == "1.0.0"
    assert keys.data[0].cose_algorithm == -8
    assert "hash_algorithm" not in type(keys).model_fields
    assert keys.anchored_from == "sha256:" + "a" * 64
    assert keys.key_statement_format == "application/vnd.agledger.key-statement+cbor"
    statement = keys.data[0].statements[0]
    assert (statement.id, statement.kind, statement.created_at, statement.cose) == (
        "01a0fd24-a41c-79ab-b3b2-51bab8e97597",
        "genesis",
        "2026-10-02T15:03:52.092689Z",
        ["0oRYJ6MB"],
    )


@respx.mock
def test_webhook_ping_reports_what_the_route_returns():
    respx.post(f"{BASE}/v1/webhooks/wh-1/ping").mock(return_value=httpx.Response(200, json={
        "statusCode": 502, "body": "bad gateway", "durationMs": 41, "success": False,
        "deliveryId": "d-1", "nextSteps": [],
    }))
    result = _client().webhooks.ping("wh-1")
    assert (result.status_code, result.duration_ms, result.body, result.delivery_id) == (502, 41, "bad gateway", "d-1")
    # API 2.0 dropped the httpStatus / latencyMs twins of statusCode / durationMs.
    for gone in ("response_time_ms", "http_status", "latency_ms"):
        assert gone not in type(result).model_fields


def test_models_no_longer_declare_fields_the_server_never_sent():
    from agledger import (
        AuditExportEntry,
        ComplianceExport,
        HealthResponse,
        StatusResponse,
    )

    assert not {"uptime", "database"} & set(HealthResponse.model_fields)
    assert "active_incidents" not in StatusResponse.model_fields
    # ``format`` came back: the create and the status read both carry it now.
    assert "id" not in ComplianceExport.model_fields
    assert not {"position", "timestamp", "actor"} & set(AuditExportEntry.model_fields)


@respx.mock
def test_rate_limit_exemptions_use_only_registered_routes():
    put = respx.put(f"{BASE}/v1/admin/rate-limit-exemptions/agt-1").mock(
        return_value=httpx.Response(200, json={"ownerId": "agt-1", "exempt": True, "nextSteps": []})
    )
    client = _client()
    assert client.admin.set_rate_limit_exemption("agt-1")["exempt"] is True
    assert put.calls.last.request.content == b""
    # GET /v1/admin/rate-limit-exemptions/{ownerId} was never registered.
    assert not hasattr(client.admin, "get_rate_limit_exemption")


@respx.mock
def test_predicates_get_uses_the_literal_v1_path():
    route = respx.get(f"{BASE}/predicates/record-state/v1").mock(
        return_value=httpx.Response(200, json={"$schema": "https://json-schema.org/draft/2019-09/schema"})
    )
    assert "$schema" in _client().predicates.get("record-state")
    assert route.called


@respx.mock
def test_reference_lookup_is_a_page_of_matches_and_walks_every_page():
    route = respx.get(f"{BASE}/v1/references").mock(side_effect=[
        httpx.Response(200, json={
            "data": [{"entityType": "record", "entityId": "rec-1", "reference": {"refId": "PO-1"}}],
            "hasMore": True, "nextCursor": "c2",
        }),
        httpx.Response(200, json={
            "data": [{"entityType": "agent", "entityId": "agt-1", "reference": {"refId": "PO-1"}}],
            "hasMore": False,
        }),
    ])
    matches = list(_client().references.lookup_all(system="erp", ref_type="po", ref_id="PO-1"))
    assert [m["entityId"] for m in matches] == ["rec-1", "agt-1"]
    assert route.calls[1].request.url.params["cursor"] == "c2"


@respx.mock
def test_a_compliance_export_carries_the_format_it_was_created_in():
    body = {"exportId": "exp-1", "status": "completed", "format": "csv", "downloadUrl": "/v1/compliance/export/exp-1/download"}
    respx.get(f"{BASE}/v1/compliance/export/exp-1").mock(return_value=httpx.Response(200, json=body))
    assert _client().compliance.get_export_status("exp-1").format == "csv"


# --- key statements, status, verdicts, bulk, events, vault anchors ---


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


# --- API main 63649593 ---


def test_create_api_key_pairs_each_role_with_its_owner_kind():
    # The Server refuses any other pair with a 400; the overloads say so to a type checker.
    hints = [typing.get_type_hints(o) for o in typing.get_overloads(AgledgerClient(api_key="k", base_url=BASE).admin.create_api_key.__func__)]  # type: ignore[attr-defined]
    pairs = {(typing.get_args(h["role"])[0], typing.get_args(h["owner_type"])[0]) for h in hints}
    assert pairs == {("admin", "org"), ("agent", "agent"), ("platform", "platform")}


@respx.mock
def test_a_rollup_synthesized_completion_has_no_agent():
    respx.get(f"{BASE}/v1/records/rec-1/completions/cmp-1").mock(return_value=httpx.Response(200, json={
        "id": "cmp-1", "recordId": "rec-1", "agentId": None, "rollupSynthesized": True,
        "evidence": {}, "createdAt": "2026-10-02T00:00:00Z",
    }))
    completion = _client().completions.get("rec-1", "cmp-1")
    assert (completion.agent_id, completion.rollup_synthesized) == (None, True)


@respx.mock
def test_deleting_a_webhook_returns_the_dead_letters_it_still_holds():
    body = {
        "webhookId": "wh-1", "isActive": False, "deadLetters": 2,
        "nextSteps": [{"action": "discard", "method": "DELETE", "href": "/v1/webhooks/wh-1/dlq/{dlqId}"}],
    }
    respx.delete(f"{BASE}/v1/webhooks/wh-1").mock(return_value=httpx.Response(200, json=body))
    assert _client().webhooks.delete("wh-1") == body


@respx.mock
def test_a_dead_letter_is_discarded_from_its_subscription_or_by_the_platform():
    body: dict[str, object] = {"discarded": True, "dlqId": "dlq-1", "webhookId": "wh-1", "nextSteps": []}
    own = respx.delete(f"{BASE}/v1/webhooks/wh-1/dlq/dlq-1").mock(return_value=httpx.Response(200, json=body))
    admin = respx.delete(f"{BASE}/v1/admin/webhook-dlq/dlq-1").mock(return_value=httpx.Response(200, json=body))
    assert _client().webhooks.discard_dlq("wh-1", "dlq-1") == body
    assert _client().admin.discard_dlq("dlq-1") == body
    assert own.called and admin.called


@respx.mock
async def test_async_discard_and_delete():
    body: dict[str, object] = {"discarded": True, "dlqId": "dlq-1", "webhookId": "wh-1", "nextSteps": []}
    respx.delete(f"{BASE}/v1/webhooks/wh-1/dlq/dlq-1").mock(return_value=httpx.Response(200, json=body))
    respx.delete(f"{BASE}/v1/admin/webhook-dlq/dlq-1").mock(return_value=httpx.Response(200, json=body))
    respx.delete(f"{BASE}/v1/webhooks/wh-1").mock(return_value=httpx.Response(200, json={
        "webhookId": "wh-1", "isActive": False, "deadLetters": 0, "nextSteps": [],
    }))
    async with AsyncAgledgerClient(api_key="test-key", base_url=BASE) as client:
        assert await client.webhooks.discard_dlq("wh-1", "dlq-1") == body
        assert await client.admin.discard_dlq("dlq-1") == body
        assert (await client.webhooks.delete("wh-1"))["deadLetters"] == 0


@respx.mock
def test_a_status_component_names_the_worker_and_signing_key_causes():
    reasons = ["database_unavailable", "signing_key_unusable", "no_worker_connected", "worker_not_consuming", "not_checked"]
    respx.get(f"{BASE}/status").mock(return_value=httpx.Response(200, json={
        "status": "outage",
        "components": [{"name": "Workers", "status": "degraded", "reason": r} for r in reasons],
        "uptime": 10, "timestamp": "2026-10-02T00:00:00Z",
    }))
    assert [c.reason for c in _client().health.status().components] == reasons
