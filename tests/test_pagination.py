"""Tests for auto-pagination."""

import httpx
import respx

from agledger import AgledgerClient, RecordRow


RECORD_1 = {
    "id": "rec-1", "orgId": "org-1", "performerAgentId": None, "principalAgentId": "agt-1",
    "type": "notarize-generic-v1", "contractVersion": "1", "platform": "test",
    "status": "ACTIVE", "criteria": {}, "submissionCount": 0, "maxSubmissions": None,
    "version": 1, "createdAt": "2026-04-27T00:00:00Z", "updatedAt": "2026-04-27T00:00:00Z",
}
RECORD_2 = {**RECORD_1, "id": "rec-2"}
RECORD_3 = {**RECORD_1, "id": "rec-3"}


@respx.mock
def test_list_all_multi_page():
    route = respx.get("https://agledger.example.com/v1/records")
    route.side_effect = [
        httpx.Response(200, json={"data": [RECORD_1, RECORD_2], "hasMore": True, "nextCursor": "cur-2"}),
        httpx.Response(200, json={"data": [RECORD_3], "hasMore": False}),
    ]
    client = AgledgerClient(api_key="test-key")
    records = list(client.records.list_all(org_id="ent-1"))
    assert len(records) == 3
    assert all(isinstance(m, RecordRow) for m in records)
    assert [m.id for m in records] == ["rec-1", "rec-2", "rec-3"]
    assert len(route.calls) == 2


@respx.mock
def test_list_all_empty():
    respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    records = list(client.records.list_all(org_id="ent-1"))
    assert records == []


@respx.mock
def test_list_all_single_page():
    respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": False})
    )
    client = AgledgerClient(api_key="test-key")
    records = list(client.records.list_all(org_id="ent-1"))
    assert len(records) == 1
