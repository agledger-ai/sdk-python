"""Tests for AgledgerClient — resources, auth, context manager, typed kwargs."""

import json

import agledger
import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient, AuthenticationError, RecordRow


RECORD_JSON = {
    "id": "rec-123",
    "orgId": "ent-1",
    "agentId": None,
    "principalAgentId": "agt-principal",
    "type": "notarize-generic-v1",
    "contractVersion": "1",
    "platform": "test",
    "status": "CREATED",
    "criteria": {"item_spec": "widgets"},
    "submissionCount": 0,
    "maxSubmissions": None,
    "version": 1,
    "createdAt": "2026-04-27T00:00:00Z",
    "updatedAt": "2026-04-27T00:00:00Z",
}


@respx.mock
def test_records_create_typed_kwargs():
    respx.post("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    record = client.records.create(
        principal_agent_id="agt-principal",
        type="notarize-generic-v1",
        contract_version="1",
        platform="test",
        criteria={"item_spec": "widgets"},
        max_submissions=3,
    )
    assert isinstance(record, RecordRow)
    assert record.id == "rec-123"
    assert record.status == "CREATED"
    sent = json.loads(respx.calls[0].request.content)
    assert sent["principalAgentId"] == "agt-principal"
    assert sent["type"] == "notarize-generic-v1"
    assert sent["maxSubmissions"] == 3


@respx.mock
def test_records_get():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    record = client.records.get("rec-123")
    assert record.id == "rec-123"
    assert record.type == "notarize-generic-v1"


@respx.mock
def test_records_get_integrity():
    route = respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(
            200,
            json={
                **RECORD_JSON,
                "integrity": {
                    "verified": True,
                    "integrityLevel": "hash_chain_and_signatures",
                    "reason": None,
                    "entries": 3,
                    "projectionChecked": True,
                    "driftFields": [],
                },
            },
        )
    )
    client = AgledgerClient(api_key="test-key")
    record = client.records.get("rec-123", integrity=True)
    assert "integrity=true" in str(route.calls.last.request.url)
    assert record.integrity is not None
    assert record.integrity.verified is True
    assert record.integrity.integrity_level == "hash_chain_and_signatures"


@respx.mock
def test_records_list_actionable():
    route = respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_JSON], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    client.records.list(actionable=True)
    assert "actionable=true" in str(route.calls.last.request.url)


@respx.mock
def test_auth_rotate_key_grace_period():
    route = respx.post("https://agledger.example.com/v1/auth/keys/rotate").mock(
        return_value=httpx.Response(200, json={"apiKey": "agl_adm_new", "keyId": "key-1"})
    )
    client = AgledgerClient(api_key="test-key")
    client.auth.rotate_key(grace_period_seconds=300)
    assert json.loads(route.calls.last.request.content) == {"gracePeriodSeconds": 300}


@respx.mock
def test_records_list_with_status_filter():
    respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_JSON], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    page = client.records.list(org_id="ent-1", status="CREATED")
    assert len(page.data) == 1
    assert page.has_more is False
    assert isinstance(page.data[0], RecordRow)


@respx.mock
def test_records_transition():
    activated = {**RECORD_JSON, "status": "ACTIVE"}
    respx.post("https://agledger.example.com/v1/records/rec-123/transition").mock(
        return_value=httpx.Response(200, json=activated)
    )
    client = AgledgerClient(api_key="test-key")
    record = client.records.transition("rec-123", "activate")
    assert record.status == "ACTIVE"


@respx.mock
def test_records_request_revision():
    revised = {**RECORD_JSON, "status": "REVISION_REQUESTED"}
    respx.post("https://agledger.example.com/v1/records/rec-123/revision").mock(
        return_value=httpx.Response(200, json=revised)
    )
    client = AgledgerClient(api_key="test-key")
    record = client.records.request_revision("rec-123", "please fix X")
    assert record.status == "REVISION_REQUESTED"


@respx.mock
def test_records_my_verdict_statistics():
    respx.get("https://agledger.example.com/v1/records/me/verdict-statistics").mock(
        return_value=httpx.Response(200, json={
            "agentId": "agt-1",
            "asPrincipal": {"data": [
                {"performerAgentId": "agt-2", "verdictAcceptCount": 5, "verdictRejectCount": 1,
                 "cancelAfterCompletionCount": 0, "firstEventAt": "2026-05-01T00:00:00Z",
                 "lastEventAt": "2026-05-26T00:00:00Z"},
            ], "total": 1},
            "asPerformer": {"data": [], "total": 0},
        })
    )
    client = AgledgerClient(api_key="test-key")
    stats = client.records.my_verdict_statistics()
    assert stats.agent_id == "agt-1"
    assert stats.as_principal["total"] == 1
    assert stats.as_principal["data"][0]["verdictAcceptCount"] == 5


@respx.mock
def test_records_list_proposals():
    respx.get("https://agledger.example.com/v1/records/agent/proposals").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_JSON], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    page = client.records.list_proposals()
    assert len(page.data) == 1
    assert isinstance(page.data[0], RecordRow)


@respx.mock
def test_records_bulk_create():
    bulk_resp = {
        "results": [{"index": 0, "status": "created", "data": RECORD_JSON}],
        "summary": {"total": 1, "succeeded": 1, "failed": 0},
    }
    respx.post("https://agledger.example.com/v1/records/bulk").mock(
        return_value=httpx.Response(207, json=bulk_resp)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.records.bulk_create([{"type": "notarize-generic-v1", "criteria": {}, "idempotencyKey": "k-1"}])
    assert result.summary.succeeded == 1
    assert result.summary.total == 1
    assert result.results[0].status == "created"
    assert result.results[0].data is not None
    sent = json.loads(respx.calls[0].request.content)
    assert sent["records"][0]["idempotencyKey"] == "k-1"


@respx.mock
def test_records_get_audit_export():
    # F-713 regression: the entry MUST be populated with the real server shape
    # (humanReadableLabel, NOT description). An empty `entries: []` masked the
    # original crash — the model is only exercised when an entry is present.
    export_resp = {
        "exportMetadata": {
            "recordId": "rec-123",
            "orgId": "ent-1",
            "type": "notarize-generic-v1",
            "exportDate": "2026-04-27T00:00:00Z",
            "totalEntries": 1,
            "chainIntegrity": True,
            "exportFormatVersion": "2.0",
            "canonicalization": "RFC8949-CDE",
            "signingPublicKey": None,
        },
        "entries": [
            {
                "chainPosition": 1,
                "createdAt": "2026-04-27T00:00:00Z",
                "recordId": "rec-123",
                "actorId": "key-1",
                "actorRole": "agent",
                "actorOwnerId": "agt-1",
                "actorDisplayName": "Acme Agent",
                "actorOwnerType": "agent",
                "entryType": "RECORD_STATE_CHANGE",
                "humanReadableLabel": "Record state transitioned",
                "payload": {"state": "ACTIVE"},
                "integrity": {"payloadHash": "h", "previousHash": None, "coseSign1": "b64", "signingKeyId": "k", "valid": True},
            }
        ],
    }
    route = respx.get("https://agledger.example.com/v1/records/rec-123/audit-export").mock(
        return_value=httpx.Response(200, json=export_resp)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.records.get_audit_export("rec-123")
    assert result.export_metadata.record_id == "rec-123"
    assert result.export_metadata.canonicalization == "RFC8949-CDE"
    assert result.entries[0].human_readable_label == "Record state transitioned"
    assert result.entries[0].actor_display_name == "Acme Agent"
    assert "format=json" in str(route.calls[0].request.url)


@respx.mock
def test_completion_submit_typed_kwargs():
    completion_json = {
        "id": "rct-1", "recordId": "rec-123", "agentId": "agent-1",
        "evidence": {"delivered": True},
        "createdAt": "2026-04-27T00:00:00Z",
    }
    respx.post("https://agledger.example.com/v1/records/rec-123/completions").mock(
        return_value=httpx.Response(200, json=completion_json)
    )
    client = AgledgerClient(api_key="test-key")
    completion = client.completions.submit("rec-123", evidence={"delivered": True})
    assert completion.id == "rct-1"


@respx.mock
def test_auth_header():
    route = respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="agl_agt_test123")
    client.records.get("rec-123")
    assert route.calls[0].request.headers["authorization"] == "Bearer agl_agt_test123"


@respx.mock
def test_user_agent_header():
    route = respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    client.records.get("rec-123")
    ua = route.calls[0].request.headers["user-agent"]
    assert ua == f"agledger-python/{agledger.__version__}"


@respx.mock
def test_idempotency_key_on_post():
    route = respx.post("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    client.records.create(type="notarize-generic-v1", criteria={})
    assert "idempotency-key" in route.calls[0].request.headers


@respx.mock
def test_no_idempotency_key_on_get():
    route = respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    client.records.get("rec-123")
    assert "idempotency-key" not in route.calls[0].request.headers


@respx.mock
def test_no_content_type_on_get():
    route = respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    client.records.get("rec-123")
    assert "content-type" not in route.calls[0].request.headers


@respx.mock
def test_context_manager():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    with AgledgerClient(api_key="test-key") as client:
        record = client.records.get("rec-123")
        assert record.id == "rec-123"


def test_env_var_fallback(monkeypatch):
    monkeypatch.setenv("AGLEDGER_API_KEY", "agl_agt_from_env")
    client = AgledgerClient()
    assert client._http._api_key == "agl_agt_from_env"


def test_no_api_key_raises(monkeypatch):
    monkeypatch.delenv("AGLEDGER_API_KEY", raising=False)
    with pytest.raises(AuthenticationError, match="No API key"):
        AgledgerClient()


def test_populate_by_name():
    """Verify Pydantic models can be constructed with snake_case names."""
    r = RecordRow(
        id="rec-1",
        org_id="ent-1",
        principal_agent_id="agt-1",
        type="notarize-generic-v1",
        contract_version="1",
        platform="test",
        status="CREATED",
        criteria={},
        submission_count=0,
        max_submissions=None,
        version=1,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    assert r.org_id == "ent-1"
    assert r.type == "notarize-generic-v1"
    assert r.submission_count == 0


def test_has_all_resources():
    """Verify the client wires every resource (sync + async)."""
    client = AgledgerClient(api_key="test-key")
    resources = [
        "a2a", "admin", "agents", "audit", "auth", "capabilities", "compliance",
        "discovery", "disputes", "events", "federation", "federation_admin",
        "health", "completions", "records", "references", "reputation",
        "schemas", "gate", "verification_keys", "webhooks",
    ]
    for r in resources:
        assert hasattr(client, r), f"Missing resource: {r}"


def test_admin_has_subresources():
    client = AgledgerClient(api_key="test-key")
    assert hasattr(client.admin, "records")
    assert hasattr(client.admin, "vault")
    assert hasattr(client.admin.vault, "anchors")
    assert hasattr(client.admin.vault, "scan")
    assert hasattr(client.admin.vault, "signing_keys")


def test_audit_has_org_reads_checkpoints():
    client = AgledgerClient(api_key="test-key")
    assert hasattr(client.audit, "org_reads_checkpoints")


# --- Admin provisioning tests ---

@respx.mock
def test_admin_create_org():
    response_json = {"id": "org-1", "name": "Acme Corp"}
    respx.post("https://agledger.example.com/v1/admin/orgs").mock(
        return_value=httpx.Response(200, json=response_json)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.create_org(name="Acme Corp", display_name="Acme")
    assert result["id"] == "org-1"
    sent = json.loads(respx.calls[0].request.content)
    assert sent["name"] == "Acme Corp"
    assert sent["displayName"] == "Acme"


@respx.mock
def test_admin_create_agent():
    response_json = {"id": "agt-1", "name": "My Agent", "orgId": "org-1"}
    respx.post("https://agledger.example.com/v1/admin/agents").mock(
        return_value=httpx.Response(200, json=response_json)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.create_agent(name="My Agent", org_id="org-1")
    assert result["id"] == "agt-1"
    sent = json.loads(respx.calls[0].request.content)
    assert sent["orgId"] == "org-1"


@respx.mock
def test_admin_update_org_config():
    config = {"enforcement": {"agentApprovalRequired": True}}
    respx.patch("https://agledger.example.com/v1/admin/orgs/org-1/config").mock(
        return_value=httpx.Response(200, json=config)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.update_org_config("org-1", config)
    assert result["enforcement"]["agentApprovalRequired"] is True


@respx.mock
def test_admin_set_capabilities_uses_contract_types_field():
    respx.put("https://agledger.example.com/v1/admin/agents/agt-1/capabilities").mock(
        return_value=httpx.Response(200, json={"agentId": "agt-1", "capabilities": ["notarize-generic-v1"]})
    )
    client = AgledgerClient(api_key="test-key")
    client.admin.set_capabilities("agt-1", contract_types=["notarize-generic-v1"])
    sent = json.loads(respx.calls[0].request.content)
    assert "contractTypes" in sent
    assert sent["contractTypes"] == ["notarize-generic-v1"]


@respx.mock
def test_admin_records_list():
    respx.get("https://agledger.example.com/v1/admin/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_JSON], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.records.list()
    assert result["data"][0]["id"] == "rec-123"


@respx.mock
def test_admin_records_import():
    respx.post("https://agledger.example.com/v1/admin/records/import").mock(
        return_value=httpx.Response(200, json={"imported": 1, "recordIds": ["rec-imp-1"], "source": "legacy"})
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.records.import_(
        org_id="ent-1", source="legacy",
        records=[{"principalAgentId": "agt-1", "type": "notarize-generic-v1", "platform": "x", "criteria": {}, "terminalStatus": "FULFILLED", "createdAt": "2026-01-01T00:00:00Z"}],
    )
    assert result["imported"] == 1
    assert result["recordIds"] == ["rec-imp-1"]


@respx.mock
def test_admin_vault_anchors_list():
    respx.get("https://agledger.example.com/v1/admin/vault/anchors").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    client = AgledgerClient(api_key="test-key")
    client.admin.vault.anchors.list(record_id="rec-1")
    assert "recordId=rec-1" in str(respx.calls[0].request.url)


@respx.mock
def test_admin_vault_scan_run():
    respx.post("https://agledger.example.com/v1/admin/vault/scan").mock(
        return_value=httpx.Response(200, json={"jobId": "job-1", "status": "pending", "startedAt": "2026-04-27T00:00:00Z"})
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.vault.scan.run(record_ids=["rec-1", "rec-2"])
    assert result["jobId"] == "job-1"


@respx.mock
def test_admin_vault_signing_keys_rotate():
    respx.post("https://agledger.example.com/v1/admin/vault/signing-keys/rotate").mock(
        return_value=httpx.Response(200, json={"id": "key-2", "status": "active", "createdAt": "2026-04-27T00:00:00Z"})
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.vault.signing_keys.rotate()
    assert result["id"] == "key-2"


@respx.mock
def test_audit_org_reads_checkpoint_get():
    respx.get("https://agledger.example.com/v1/audit/org-reads/checkpoints/cp-1").mock(
        return_value=httpx.Response(200, json={
            "id": "cp-1", "orgId": "ent-1", "treeSize": 100,
            "rootHash": "abc", "checkpointAt": "2026-04-27T00:00:00Z", "logId": "log-1",
            "coseSign1Base64": "b64", "signingKeyId": None,
            "witnessSignature": None, "witnessKeyId": None, "witnessCosignedAt": None,
        })
    )
    client = AgledgerClient(api_key="test-key")
    cp = client.audit.org_reads_checkpoints.get("cp-1")
    assert cp.id == "cp-1"
    assert cp.tree_size == 100


@respx.mock
def test_audit_org_reads_checkpoint_cosign():
    respx.post("https://agledger.example.com/v1/audit/org-reads/checkpoints/cp-1/cosign").mock(
        return_value=httpx.Response(200, json={
            "id": "cp-1", "orgId": "ent-1", "treeSize": 100,
            "rootHash": "abc", "checkpointAt": "2026-04-27T00:00:00Z", "logId": "log-1",
            "coseSign1Base64": "b64", "signingKeyId": None,
            "witnessSignature": None, "witnessKeyId": None, "witnessCosignedAt": None,
        })
    )
    client = AgledgerClient(api_key="test-key")
    client.audit.org_reads_checkpoints.cosign(
        "cp-1", witness_key_id="witness-1", witness_signature="sig-bytes",
    )
    sent = json.loads(respx.calls[0].request.content)
    assert sent["witnessKeyId"] == "witness-1"
    assert sent["witnessSignature"] == "sig-bytes"


@respx.mock
def test_disputes_list():
    respx.get("https://agledger.example.com/v1/disputes").mock(
        return_value=httpx.Response(200, json={"data": [], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    page = client.disputes.list(status="OPENED")
    assert page.data == []
    assert "status=OPENED" in str(respx.calls[0].request.url)


@respx.mock
def test_webhooks_list_url_filter():
    respx.get("https://agledger.example.com/v1/webhooks").mock(
        return_value=httpx.Response(200, json={"data": [], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    page = client.webhooks.list(url="https://example.com/hook")
    assert page.data == []
    request_url = str(respx.calls[0].request.url)
    assert "url=https" in request_url


# --- Async tests ---

@respx.mock
@pytest.mark.asyncio
async def test_async_records_get():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    async with AsyncAgledgerClient(api_key="test-key") as client:
        record = await client.records.get("rec-123")
        assert record.id == "rec-123"
        assert isinstance(record, RecordRow)


@respx.mock
@pytest.mark.asyncio
async def test_async_context_manager():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(200, json=RECORD_JSON)
    )
    async with AsyncAgledgerClient(api_key="test-key") as client:
        record = await client.records.get("rec-123")
        assert record.id == "rec-123"


# --- Admin API key tests ---

@respx.mock
def test_admin_toggle_api_key():
    response_json = {"id": "key-1", "isActive": True}
    respx.patch("https://agledger.example.com/v1/admin/api-keys/key-1").mock(
        return_value=httpx.Response(200, json=response_json)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.toggle_api_key("key-1", is_active=True)
    assert result["isActive"] is True
    sent = json.loads(respx.calls[0].request.content)
    assert sent["isActive"] is True


@respx.mock
def test_admin_get_webhook_health():
    respx.get("https://agledger.example.com/v1/admin/webhooks/health").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "wh-1", "circuitState": "closed"}], "total": 1})
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.get_webhook_health()
    assert result["data"][0]["circuitState"] == "closed"


@respx.mock
def test_admin_update_circuit_breaker():
    respx.patch("https://agledger.example.com/v1/admin/webhooks/wh-1/circuit-breaker").mock(
        return_value=httpx.Response(200, json={"id": "wh-1", "circuitState": "open", "consecutiveFailures": 5})
    )
    client = AgledgerClient(api_key="test-key")
    result = client.admin.update_circuit_breaker("wh-1", state="open")
    assert result["circuitState"] == "open"
    sent = json.loads(respx.calls[0].request.content)
    assert sent["state"] == "open"


# --- Webhook get / pause ---

@respx.mock
def test_webhooks_get():
    webhook_json = {
        "id": "wh-1", "url": "https://example.com/hook",
        "eventTypes": ["record.created"],
        "isActive": True, "createdAt": "2026-01-01T00:00:00Z",
    }
    respx.get("https://agledger.example.com/v1/webhooks/wh-1").mock(
        return_value=httpx.Response(200, json=webhook_json)
    )
    client = AgledgerClient(api_key="test-key")
    webhook = client.webhooks.get("wh-1")
    assert webhook.id == "wh-1"
    assert webhook.url == "https://example.com/hook"


@respx.mock
def test_webhooks_pause():
    webhook_json = {
        "id": "wh-1", "url": "https://example.com/hook",
        "eventTypes": ["record.created"],
        "isActive": False, "isPaused": True, "createdAt": "2026-01-01T00:00:00Z",
    }
    respx.post("https://agledger.example.com/v1/webhooks/wh-1/pause").mock(
        return_value=httpx.Response(200, json=webhook_json)
    )
    client = AgledgerClient(api_key="test-key")
    webhook = client.webhooks.pause("wh-1")
    assert webhook.id == "wh-1"
    assert webhook.is_paused is True


# --- Record counter_propose and batch_get ---

@respx.mock
def test_records_counter_propose():
    counter_json = {**RECORD_JSON, "status": "PROPOSED", "acceptanceStatus": "COUNTER_PROPOSED"}
    respx.post("https://agledger.example.com/v1/records/rec-123/counter-propose").mock(
        return_value=httpx.Response(200, json=counter_json)
    )
    client = AgledgerClient(api_key="test-key")
    record = client.records.counter_propose("rec-123", counter_deadline="2026-06-01T00:00:00Z")
    assert isinstance(record, RecordRow)
    assert record.acceptance_status == "COUNTER_PROPOSED"
    sent = json.loads(respx.calls[0].request.content)
    assert sent["counterDeadline"] == "2026-06-01T00:00:00Z"


@respx.mock
def test_compliance_create_assessment_maps_snake_to_camel():
    # F-740: create_assessment must accept idiomatic snake_case kwargs and emit
    # the camelCase wire shape (the route has additionalProperties:false).
    assessment_json = {
        "id": "aia-1",
        "recordId": "rec-123",
        "riskLevel": "high",
        "domain": "employment",
        "humanOversight": {"overseer": "alice"},
        "testingResults": {"passed": True},
        "createdAt": "2026-06-02T00:00:00Z",
    }
    respx.post(
        "https://agledger.example.com/v1/records/rec-123/ai-impact-assessment"
    ).mock(return_value=httpx.Response(201, json=assessment_json))
    client = AgledgerClient(api_key="test-key")
    result = client.compliance.create_assessment(
        "rec-123",
        risk_level="high",
        domain="employment",
        human_oversight={"overseer": "alice"},
        testing_results={"passed": True},
    )
    assert result.id == "aia-1"
    assert result.risk_level == "high"
    sent = json.loads(respx.calls[0].request.content)
    assert sent == {
        "riskLevel": "high",
        "domain": "employment",
        "humanOversight": {"overseer": "alice"},
        "testingResults": {"passed": True},
    }


@respx.mock
def test_compliance_create_assessment_omits_optional_fields():
    assessment_json = {
        "id": "aia-2",
        "recordId": "rec-123",
        "riskLevel": "minimal",
        "domain": "education",
        "createdAt": "2026-06-02T00:00:00Z",
    }
    respx.post(
        "https://agledger.example.com/v1/records/rec-123/ai-impact-assessment"
    ).mock(return_value=httpx.Response(201, json=assessment_json))
    client = AgledgerClient(api_key="test-key")
    client.compliance.create_assessment("rec-123", risk_level="minimal", domain="education")
    sent = json.loads(respx.calls[0].request.content)
    assert sent == {"riskLevel": "minimal", "domain": "education"}


@respx.mock
def test_records_batch_get():
    batch_response = {"data": [RECORD_JSON, {**RECORD_JSON, "id": "rec-456"}]}
    respx.post("https://agledger.example.com/v1/records/batch").mock(
        return_value=httpx.Response(200, json=batch_response)
    )
    client = AgledgerClient(api_key="test-key")
    result = client.records.batch_get(["rec-123", "rec-456"])
    assert len(result["data"]) == 2
    sent = json.loads(respx.calls[0].request.content)
    assert sent["ids"] == ["rec-123", "rec-456"]


def test_records_batch_get_validates_ids():
    client = AgledgerClient(api_key="test-key")
    with pytest.raises(ValueError, match="1-100"):
        client.records.batch_get([])


# RateLimitInfo getter parity with TS SDK (audit gap fixed 2026-05-28).

_RECORD_JSON = {
    "id": "rec-1", "orgId": "org-1", "performerAgentId": None,
    "principalAgentId": "agt-1", "type": "notarize-generic-v1",
    "contractVersion": "1", "platform": "test", "status": "CREATED",
    "criteria": {}, "submissionCount": 0, "maxSubmissions": None,
    "version": 1, "createdAt": "2026-04-27T00:00:00Z",
    "updatedAt": "2026-04-27T00:00:00Z",
}


@respx.mock
def test_rate_limit_info_populated_from_headers():
    from agledger import RateLimitInfo

    respx.get("https://agledger.example.com/v1/records/rec-1").mock(
        return_value=httpx.Response(
            200,
            json=_RECORD_JSON,
            headers={
                "x-ratelimit-limit": "1000",
                "x-ratelimit-remaining": "987",
                "x-ratelimit-reset": "1735689600",
            },
        )
    )
    client = AgledgerClient(api_key="test-key")
    client.records.get("rec-1")
    info = client.rate_limit_info
    assert info is not None
    assert isinstance(info, RateLimitInfo)
    assert info.limit == 1000
    assert info.remaining == 987
    assert info.reset == 1735689600


@respx.mock
def test_rate_limit_info_none_when_headers_absent():
    respx.get("https://agledger.example.com/v1/records/rec-1").mock(
        return_value=httpx.Response(200, json=_RECORD_JSON)
    )
    client = AgledgerClient(api_key="test-key")
    client.records.get("rec-1")
    assert client.rate_limit_info is None
