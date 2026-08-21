"""Tests for auto-pagination."""

import httpx
import pytest
import respx

from agledger import AgledgerClient, PaginationLimitError, RecordRow

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
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
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
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    records = list(client.records.list_all(org_id="ent-1"))
    assert records == []


@respx.mock
def test_list_all_single_page():
    respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": False})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    records = list(client.records.list_all(org_id="ent-1"))
    assert len(records) == 1


@respx.mock
def test_list_all_api_keys_replays_owner_with_cursor():
    """A cursor minted under ``ownerId`` carries that owner, and the API rejects
    a replay that drops it rather than serving the install-wide listing at the
    same offset. So the iterator has to resend the filters, not just the cursor.
    """
    route = respx.get("https://agledger.example.com/v1/admin/api-keys")
    route.side_effect = [
        httpx.Response(200, json={"data": [{"id": "key-1"}], "hasMore": True, "nextCursor": "b2Zmc2V0OjE="}),
        httpx.Response(200, json={"data": [{"id": "key-2"}], "hasMore": False, "nextCursor": None}),
    ]
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    keys = list(client.admin.list_all_api_keys(owner_id="org-1"))

    assert [k["id"] for k in keys] == ["key-1", "key-2"]
    assert len(route.calls) == 2
    second = route.calls[1].request.url
    assert second.params["ownerId"] == "org-1"
    assert second.params["cursor"] == "b2Zmc2V0OjE="


@respx.mock
def test_get_chain_walks_every_page():
    """A chain page caps at 1000 rows. Returning page one dropped the rest of a
    longer chain with nothing on the result saying it was partial."""
    route = respx.get("https://agledger.example.com/v1/records/rec-1/chain")
    route.side_effect = [
        httpx.Response(200, json={"data": [RECORD_1], "total": 2, "hasMore": True, "nextCursor": "cur-2"}),
        httpx.Response(200, json={"data": [RECORD_2], "total": 2, "hasMore": False}),
    ]
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    chain = client.records.get_chain("rec-1")
    assert [m.id for m in chain] == ["rec-1", "rec-2"]
    assert len(route.calls) == 2
    assert "cursor=cur-2" in str(route.calls[1].request.url)


@respx.mock
def test_get_sub_records_spends_the_cursor():
    route = respx.get("https://agledger.example.com/v1/records/rec-1/sub-records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_2], "hasMore": False})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    page = client.records.get_sub_records("rec-1", cursor="cur-9", limit=25)
    assert [m.id for m in page.data] == ["rec-2"]
    url = str(route.calls[0].request.url)
    assert "cursor=cur-9" in url
    assert "limit=25" in url


@respx.mock
def test_default_ceiling_raises_rather_than_returning_a_prefix():
    """The 100-page guard is a runaway guard, not a result. A walk that stops
    there has yielded a prefix, and returning it silently is indistinguishable
    from having read the whole listing."""
    respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": True, "nextCursor": "cur-n"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    seen = 0
    with pytest.raises(PaginationLimitError) as excinfo:
        for _record in client.records.list_all(org_id="ent-1"):
            seen += 1

    # The rows it did yield are valid: the error says they are not all of them.
    assert seen == 100
    err = excinfo.value
    assert err.path == "/v1/records"
    assert err.pages_read == 100
    assert err.items_yielded == 100
    assert err.max_pages == 100


@respx.mock
def test_explicit_max_pages_stops_quietly():
    """A bound the caller set is an intentional stop, so it does not raise."""
    respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": True, "nextCursor": "cur-n"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    records = list(client.records.list_all(org_id="ent-1", max_pages=3))
    assert len(records) == 3


@respx.mock
def test_list_all_sends_the_page_size():
    """`limit` was unreachable from list_all, so the only way to walk a large
    listing was 100 pages of whatever the server chose."""
    route = respx.get("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": False})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    list(client.records.list_all(org_id="ent-1", limit=250))
    assert "limit=250" in str(route.calls[0].request.url)


@respx.mock
def test_get_chain_raises_on_a_chain_longer_than_the_guard():
    respx.get("https://agledger.example.com/v1/records/rec-1/chain").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": True, "nextCursor": "cur-n"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    with pytest.raises(PaginationLimitError):
        client.records.get_chain("rec-1")


@respx.mock
def test_get_chain_honours_an_explicit_bound():
    respx.get("https://agledger.example.com/v1/records/rec-1/chain").mock(
        return_value=httpx.Response(200, json={"data": [RECORD_1], "hasMore": True, "nextCursor": "cur-n"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    assert len(client.records.get_chain("rec-1", max_pages=2)) == 2
