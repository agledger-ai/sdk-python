"""Response-contract regression tests.

These guard a bug class: SDK Pydantic models requiring a
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
    # server emits displayName (no name/slug/updatedAt).
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
    # server emits `type` + `data`, not `eventType` + `payload`.
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
def test_drift_get_agent_tolerates_null_rates():
    # A window that holds no verdict and no completion nulls acceptanceRate and
    # medianCompletionMs on the bucket AND on the change, which is null wherever
    # either side is. A non-nullable model would crash on a quiet week.
    def bucket(records, completions, verdicts, accepted, rejected, rate, median):
        return {
            "from": "2026-09-01T00:00:00Z", "to": "2026-09-08T00:00:00Z",
            "records": records, "completions": completions, "verdicts": verdicts,
            "accepted": accepted, "rejected": rejected, "overturned": 0,
            "acceptanceRate": rate, "medianCompletionMs": median,
        }

    respx.get(f"{BASE}/v1/agents/agt-1/drift").mock(
        return_value=httpx.Response(200, json={
            "agentId": "agt-1",
            "window": {
                "days": 7,
                "currentFrom": "2026-09-01T00:00:00Z", "currentTo": "2026-09-08T00:00:00Z",
                "baselineFrom": "2026-08-25T00:00:00Z", "baselineTo": "2026-09-01T00:00:00Z",
            },
            "overall": {
                "current": bucket(4, 0, 0, 0, 0, None, None),
                "baseline": bucket(2, 2, 2, 2, 0, 1.0, 4200),
                "change": {
                    "records": 2, "completions": -2, "verdicts": -2, "overturned": 0,
                    "acceptanceRate": None, "medianCompletionMs": None,
                },
            },
            "byType": [{
                "type": "notarize-generic-v1",
                "current": bucket(4, 0, 0, 0, 0, None, None),
                "baseline": bucket(2, 2, 2, 2, 0, 1.0, 4200),
                "change": {
                    "records": 2, "completions": -2, "verdicts": -2, "overturned": 0,
                    "acceptanceRate": None, "medianCompletionMs": None,
                },
            }],
        })
    )
    drift = _client().drift.get_agent("agt-1")
    assert drift.agent_id == "agt-1"
    assert drift.window.days == 7
    assert drift.window.baseline_from == "2026-08-25T00:00:00Z"
    # `from` is a keyword, so the bucket edge reads back as from_.
    assert drift.overall.current.from_ == "2026-09-01T00:00:00Z"
    assert drift.overall.current.acceptance_rate is None
    assert drift.overall.current.median_completion_ms is None
    assert drift.overall.baseline.acceptance_rate == 1.0
    # The change fields are reachable, including the two nulled ones.
    assert drift.overall.change.records == 2
    assert drift.overall.change.completions == -2
    assert drift.overall.change.acceptance_rate is None
    assert drift.overall.change.median_completion_ms is None
    assert drift.by_type[0].type == "notarize-generic-v1"
    assert drift.by_type[0].change.verdicts == -2


@respx.mock
def test_completions_submit_omits_unknown_root_keys():
    # only evidence/evidenceHash/idempotencyKey are accepted root
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
    # /chain returns a paginated envelope, not a bare array.
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
    # the reject route accepts only `message`.
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
