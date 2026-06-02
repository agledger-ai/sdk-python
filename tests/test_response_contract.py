"""Response-contract regression tests.

These guard the F-713/F-710/F-706 bug class: SDK Pydantic models requiring a
field the server renamed/dropped, which crashes deserialization. Each test
feeds a *real-server-shaped* payload (camelCase, exactly what the API emits)
through a resource method and asserts the model parses. The reported crashes
all slipped through because the existing tests either used empty list bodies or
never round-tripped a populated response.
"""

import httpx
import respx

from agledger import AgledgerClient

BASE = "https://agledger.example.com"


def _client() -> AgledgerClient:
    return AgledgerClient(api_key="test-key", base_url=BASE)


@respx.mock
def test_agents_get_parses_display_name_shape():
    # F-713 class: server emits displayName (no name/slug/updatedAt).
    respx.get(f"{BASE}/v1/agents/agt-1").mock(
        return_value=httpx.Response(200, json={
            "id": "agt-1", "orgId": "org-1", "displayName": "Acme Bot",
            "agentClass": "system", "agentCardUrl": None, "ownerRef": None,
            "orgUnit": None, "description": None, "references": [],
            "createdAt": "2026-04-27T00:00:00Z",
        })
    )
    agent = _client().agents.get("agt-1")
    assert agent.display_name == "Acme Bot"
    assert agent.agent_class == "system"


@respx.mock
def test_agents_list_parses_directory_shape():
    respx.get(f"{BASE}/v1/agents").mock(
        return_value=httpx.Response(200, json={
            "data": [{
                "id": "agt-1", "orgId": "org-1", "displayName": "Acme Bot",
                "agentCardUrl": None, "agentClass": "system", "orgUnit": None,
                "description": None, "createdAt": "2026-04-27T00:00:00Z",
            }],
            "hasMore": False,
        })
    )
    page = _client().agents.list()
    assert page.data[0].display_name == "Acme Bot"


@respx.mock
def test_events_list_parses_type_and_data():
    # F-713 class: server emits `type` + `data`, not `eventType` + `payload`.
    respx.get(f"{BASE}/v1/events").mock(
        return_value=httpx.Response(200, json={
            "data": [{
                "id": "evt-1", "type": "record.created",
                "recordId": "rec-1", "agentId": "agt-1",
                "data": {"state": "CREATED"}, "createdAt": "2026-04-27T00:00:00Z",
            }],
            "hasMore": False,
        })
    )
    page = _client().events.list(since="2026-04-01T00:00:00Z")
    assert page.data[0].type == "record.created"
    assert page.data[0].data == {"state": "CREATED"}


@respx.mock
def test_reputation_get_by_type_tolerates_null_scores():
    # A freshly-provisioned agent has null scores; confidenceLevel/formulaVersion
    # are numbers, not strings. The old non-nullable str model crashed here.
    respx.get(f"{BASE}/v1/agents/agt-1/reputation/notarize-generic-v1").mock(
        return_value=httpx.Response(200, json={
            "agentId": "agt-1", "type": "notarize-generic-v1",
            "reliabilityScore": None, "accuracyScore": None,
            "efficiencyScore": None, "compositeScore": None, "confidenceLevel": None,
            "lifetimeRecords": 0, "lifetimeVerdicts": 0, "lifetimeAccepted": 0,
            "lifetimeCompletions": 0, "reversals": 0,
            "lastUpdatedAt": "2026-04-27T00:00:00Z", "formulaVersion": 3,
        })
    )
    score = _client().reputation.get_by_type("agt-1", "notarize-generic-v1")
    assert score.reliability_score is None
    assert score.confidence_level is None
    assert score.formula_version == 3
    assert score.lifetime_records == 0


@respx.mock
def test_completions_submit_omits_unknown_root_keys():
    # F-710 class: only evidence/evidenceHash/idempotencyKey are accepted root
    # keys. `notes` is gone; `evidence_hash` maps to evidenceHash.
    import json
    route = respx.post(f"{BASE}/v1/records/rec-1/completions").mock(
        return_value=httpx.Response(201, json={
            "id": "cmp-1", "recordId": "rec-1", "agentId": "agt-1",
            "evidence": {"qty": 5}, "createdAt": "2026-04-27T00:00:00Z",
        })
    )
    _client().completions.submit("rec-1", evidence={"qty": 5}, evidence_hash="a" * 64)
    assert route.called
    sent = json.loads(route.calls[0].request.content)
    assert sent == {"evidence": {"qty": 5}, "evidenceHash": "a" * 64}


@respx.mock
def test_get_chain_unwraps_paginated_envelope():
    # F-730 class: /chain returns a paginated envelope, not a bare array.
    # The old code iterated the dict's keys and crashed on the string "data".
    def _row(rid: str, status: str) -> dict:
        return {
            "id": rid, "orgId": "org-1", "agentId": "agt-1",
            "principalAgentId": "agt-1", "type": "delegated-workflow-v1", "contractVersion": "1",
            "platform": "test", "status": status, "criteria": {},
            "submissionCount": 0, "maxSubmissions": None, "version": 1,
            "createdAt": "2026-04-27T00:00:00Z", "updatedAt": "2026-04-27T00:00:00Z",
        }

    respx.get(f"{BASE}/v1/records/rec-1/chain").mock(
        return_value=httpx.Response(200, json={
            "data": [_row("rec-1", "ACTIVE"), _row("rec-2", "FULFILLED")],
            "total": 2, "nextCursor": None, "hasMore": False,
        })
    )
    chain = _client().records.get_chain("rec-1")
    assert isinstance(chain, list)
    assert [r.id for r in chain] == ["rec-1", "rec-2"]


@respx.mock
def test_record_reject_sends_message_not_reason():
    # F-710 class: the reject route accepts only `message`.
    import json
    route = respx.post(f"{BASE}/v1/records/rec-1/reject").mock(
        return_value=httpx.Response(200, json={
            "id": "rec-1", "orgId": "org-1", "agentId": None,
            "principalAgentId": "agt-1", "type": "notarize-generic-v1", "contractVersion": "1",
            "platform": "test", "status": "REJECTED", "criteria": {},
            "submissionCount": 0, "maxSubmissions": None, "version": 1,
            "createdAt": "2026-04-27T00:00:00Z", "updatedAt": "2026-04-27T00:00:00Z",
        })
    )
    _client().records.reject("rec-1", message="out of scope")
    assert route.called
    sent = json.loads(route.calls[0].request.content)
    assert sent == {"message": "out of scope"}
