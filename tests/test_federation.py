"""Federation resource tests (v0.24.0 surface)."""

import json

import httpx
import respx

from agledger import AgledgerClient

BASE = "https://agledger.example.com"


class TestFederationResource:
    @respx.mock
    def test_peer_handshake_sends_exactly_the_five_body_fields(self):
        """The route is additionalProperties: false, so an extra key is a 400 and
        a missing one is a 400. The body is the whole contract here."""
        route = respx.post(f"{BASE}/federation/v1/peer").mock(
            return_value=httpx.Response(
                201,
                json={
                    "peered": True,
                    "peerId": "11111111-1111-4111-8111-111111111111",
                    "peerHubId": "hub-x",
                    "status": "active",
                    "serverSigningPublicKey": "ed25519-pk",
                },
            )
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            result = client.federation.peer_handshake(
                peer_hub_id="33333333-3333-4333-8333-333333333333",
                peer_url="https://peer.example.com",
                signing_public_key="ed25519-pk",
                peering_token="tok-abcdefghijklmno",
                bound_org_id="44444444-4444-4444-8444-444444444444",
            )
        assert json.loads(route.calls[0].request.content) == {
            "peerHubId": "33333333-3333-4333-8333-333333333333",
            "peerUrl": "https://peer.example.com",
            "signingPublicKey": "ed25519-pk",
            "peeringToken": "tok-abcdefghijklmno",
            "boundOrgId": "44444444-4444-4444-8444-444444444444",
        }
        assert result.peered is True
        # peer_hub_id is the identifier the admin peer paths take; peer_id is
        # the receiver-local row id and resolves nowhere.
        assert result.peer_hub_id == "hub-x"
        assert result.peer_id == "11111111-1111-4111-8111-111111111111"
        assert result.status == "active"
        assert result.server_signing_public_key == "ed25519-pk"
        assert result.next_steps is None

    @respx.mock
    def test_submit_state_transition(self):
        route = respx.post(f"{BASE}/federation/v1/state-transitions").mock(
            return_value=httpx.Response(200, json={"accepted": True})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
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
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
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
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            client.federation.submit_co_sign_request(recordId="rec-1", payload="cbor:...")
        assert route.called

    @respx.mock
    def test_submit_dispute_protocol(self):
        route = respx.post(f"{BASE}/federation/v1/disputes").mock(
            return_value=httpx.Response(200, json={"received": True})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            client.federation.submit_dispute_protocol(recordId="rec-1", reason="mismatch")
        assert route.called


class TestFederationAdminResource:
    @respx.mock
    def test_create_peering_token(self):
        route = respx.post(f"{BASE}/federation/v1/admin/peering-tokens").mock(
            return_value=httpx.Response(201, json={"token": "tok-xyz", "label": "partner-x"})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            result = client.federation_admin.create_peering_token(label="partner-x")
        assert result["token"] == "tok-xyz"
        assert route.called

    @respx.mock
    def test_list_peers(self):
        respx.get(f"{BASE}/federation/v1/admin/peers").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "peerId": "22222222-2222-4222-8222-222222222222",
                            "peerHubId": "hub-x",
                            "peerUrl": "https://peer.example.com",
                            "status": "active",
                            "createdAt": "2026-03-01T00:00:00Z",
                            "agentDirectoryHash": None,
                            "consecutiveDeliveryFailures": 0,
                            "lastDeliveryAt": None,
                            "lastDeliveryError": None,
                            "lastSyncAt": None,
                        }
                    ],
                    "hasMore": False,
                    "nextCursor": None,
                    "total": 1,
                },
            )
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            result = client.federation_admin.list_peers(status="active")
        peer = result.data[0]
        assert peer.peer_hub_id == "hub-x"
        assert peer.peer_url == "https://peer.example.com"
        assert peer.status == "active"
        assert peer.consecutive_delivery_failures == 0
        assert result.has_more is False

    @respx.mock
    def test_get_peer(self):
        respx.get(f"{BASE}/federation/v1/admin/peers/hub-x").mock(
            return_value=httpx.Response(
                200,
                json={
                    "peerId": "22222222-2222-4222-8222-222222222222",
                    "peerHubId": "hub-x",
                    "peerUrl": "https://peer.example.com",
                    "status": "revoked",
                    "createdAt": "2026-03-01T00:00:00Z",
                    "lastDeliveryAt": "2026-03-02T00:00:00Z",
                    "lastDeliveryError": "503 from peer",
                    "consecutiveDeliveryFailures": 3,
                },
            )
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            peer = client.federation_admin.get_peer(peer_hub_id="hub-x")
        assert peer.status == "revoked"
        # Reachability is lastDeliveryAt. There is no lastSyncAt any more: the
        # directory push it tracked is gone, so a caller reaching for it now gets
        # an AttributeError rather than a permanently null field.
        assert peer.last_delivery_at == "2026-03-02T00:00:00Z"
        assert not hasattr(peer, "last_sync_at")
        assert peer.consecutive_delivery_failures == 3

    @respx.mock
    def test_revoke_peer(self):
        route = respx.post(f"{BASE}/federation/v1/admin/peers/hub-x/revoke").mock(
            return_value=httpx.Response(200, json={"revoked": True})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            client.federation_admin.revoke_peer("hub-x", reason="compromise")
        assert route.called

    @respx.mock
    def test_delete_peer(self):
        route = respx.delete(f"{BASE}/federation/v1/admin/peers/hub-x").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            client.federation_admin.delete_peer("hub-x")
        assert route.called

    @respx.mock
    def test_list_dlq(self):
        respx.get(f"{BASE}/federation/v1/admin/dlq").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            result = client.federation_admin.list_dlq(limit=50)
        assert "data" in result

    @respx.mock
    def test_recover_dlq(self):
        route = respx.post(f"{BASE}/federation/v1/admin/dlq/recover").mock(
            return_value=httpx.Response(200, json={"recovered": 0})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            client.federation_admin.recover_dlq()
        assert route.called

    @respx.mock
    def test_get_instance(self):
        respx.get(f"{BASE}/federation/v1/admin/instance").mock(
            return_value=httpx.Response(200, json={"hubId": "h-001"})
        )
        with AgledgerClient(base_url="https://agledger.example.com", api_key="agl_adm_test") as client:
            result = client.federation_admin.get_instance()
        assert result["hubId"] == "h-001"
