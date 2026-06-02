"""Federation resource tests (v0.24.0 surface)."""

import httpx
import respx

from agledger import AgledgerClient


BASE = "https://agledger.example.com"


class TestFederationResource:
    @respx.mock
    def test_peer_handshake(self):
        respx.post(f"{BASE}/federation/v1/peer").mock(
            return_value=httpx.Response(201, json={"established": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            result = client.federation.peer_handshake(
                hubId="hub-x",
                signingPublicKey="ed25519-pk",
                encryptionPublicKey="x25519-pk",
                peeringToken="tok-abc",
                agentDirectory=[],
            )
        assert result["established"] is True

    @respx.mock
    def test_sync_agent_directory(self):
        route = respx.post(f"{BASE}/federation/v1/peer/agent-sync").mock(
            return_value=httpx.Response(200, json={"synced": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation.sync_agent_directory(
                hubId="hub-x", agents=[], directoryHash="sha256-abc"
            )
        assert route.called

    @respx.mock
    def test_submit_state_transition(self):
        route = respx.post(f"{BASE}/federation/v1/state-transitions").mock(
            return_value=httpx.Response(200, json={"accepted": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation.submit_state_transition(
                record_id="rec-1",
                state="FULFILLED",
                type="terminal-outcome-v1",
                idempotency_key="idem-1",
                performer_agent_id="agt-perf",
                co_sign_required=True,
                schema_ref={
                    "publisher": "local", "type": "terminal-outcome-v1", "version": "1",
                    "manifestDigest": "sha256:" + "0" * 64,
                },
                parent_record_id="rec-parent",
                root_record_id="rec-root",
                chain_depth=2,
            )
        assert route.called
        import json
        sent = json.loads(route.calls[0].request.content)
        # Only the API-accepted fields ride the wire (additionalProperties: false).
        assert sent == {
            "recordId": "rec-1", "state": "FULFILLED", "type": "terminal-outcome-v1",
            "idempotencyKey": "idem-1", "performerAgentId": "agt-perf",
            "coSignRequired": True,
            "schemaRef": {
                "publisher": "local", "type": "terminal-outcome-v1", "version": "1",
                "manifestDigest": "sha256:" + "0" * 64,
            },
            "parentRecordId": "rec-parent", "rootRecordId": "rec-root",
            "chainDepth": 2,
        }

    @respx.mock
    def test_relay_signal(self):
        route = respx.post(f"{BASE}/federation/v1/signals").mock(
            return_value=httpx.Response(200, json={"relayed": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation.relay_signal(
                record_id="rec-1",
                recommendation="HOLD",
                outcome_hash="sha256-o",
                valid_until="2026-05-22T00:00:00Z",
                idempotency_key="idem-2",
                outcome="reject",
                reason_code="PRINCIPAL_REJECT",
                failing_rule_ids=["amount.max", "deadline"],
                reason="over budget",
            )
        assert route.called
        import json
        sent = json.loads(route.calls[0].request.content)
        assert sent == {
            "recordId": "rec-1", "recommendation": "HOLD", "outcomeHash": "sha256-o",
            "validUntil": "2026-05-22T00:00:00Z", "idempotencyKey": "idem-2",
            "outcome": "reject", "reasonCode": "PRINCIPAL_REJECT",
            "failingRuleIds": ["amount.max", "deadline"], "reason": "over budget",
        }

    @respx.mock
    def test_submit_co_sign_request(self):
        route = respx.post(f"{BASE}/federation/v1/co-sign-requests").mock(
            return_value=httpx.Response(200, json={"queued": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation.submit_co_sign_request(recordId="rec-1", payload="cbor:...")
        assert route.called

    @respx.mock
    def test_submit_dispute_protocol(self):
        route = respx.post(f"{BASE}/federation/v1/disputes").mock(
            return_value=httpx.Response(200, json={"received": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation.submit_dispute_protocol(recordId="rec-1", reason="mismatch")
        assert route.called

    @respx.mock
    def test_contribute_reputation(self):
        route = respx.post(f"{BASE}/federation/v1/reputation/contribute").mock(
            return_value=httpx.Response(200, json={"contributed": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation.contribute_reputation(
                agentId="a-1", type="notarize-generic-v1", period="2026-Q2",
                totalRecords=10, totalVerified=9, totalPassed=9,
            )
        assert route.called

    @respx.mock
    def test_get_agent_reputation(self):
        respx.get(f"{BASE}/federation/v1/agents/a-1/reputation").mock(
            return_value=httpx.Response(200, json={"agentId": "a-1", "score": 95})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            result = client.federation.get_agent_reputation("a-1")
        assert result["score"] == 95


class TestFederationAdminResource:
    @respx.mock
    def test_create_peering_token(self):
        route = respx.post(f"{BASE}/federation/v1/admin/peering-tokens").mock(
            return_value=httpx.Response(201, json={"token": "tok-xyz", "label": "partner-x"})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            result = client.federation_admin.create_peering_token(label="partner-x")
        assert result["token"] == "tok-xyz"
        assert route.called

    @respx.mock
    def test_list_peers(self):
        respx.get(f"{BASE}/federation/v1/admin/peers").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            result = client.federation_admin.list_peers(status="active")
        assert "data" in result

    @respx.mock
    def test_revoke_peer(self):
        route = respx.post(f"{BASE}/federation/v1/admin/peers/hub-x/revoke").mock(
            return_value=httpx.Response(200, json={"revoked": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation_admin.revoke_peer("hub-x", reason="compromise")
        assert route.called

    @respx.mock
    def test_delete_peer(self):
        route = respx.delete(f"{BASE}/federation/v1/admin/peers/hub-x").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation_admin.delete_peer("hub-x")
        assert route.called

    @respx.mock
    def test_list_dlq(self):
        respx.get(f"{BASE}/federation/v1/admin/dlq").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            result = client.federation_admin.list_dlq(limit=50)
        assert "data" in result

    @respx.mock
    def test_recover_dlq(self):
        route = respx.post(f"{BASE}/federation/v1/admin/dlq/recover").mock(
            return_value=httpx.Response(200, json={"recovered": 0})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            client.federation_admin.recover_dlq()
        assert route.called

    @respx.mock
    def test_get_instance(self):
        respx.get(f"{BASE}/federation/v1/admin/instance").mock(
            return_value=httpx.Response(200, json={"hubId": "h-001"})
        )
        with AgledgerClient(api_key="agl_adm_test") as client:
            result = client.federation_admin.get_instance()
        assert result["hubId"] == "h-001"
