"""Agent drift resource: request shape and response parsing.

The drift routes replaced the reputation routes, which scored agents. What
matters at this layer is that the window and the filters actually reach the
wire under their documented names: ``window`` is bound into the fleet cursor, so
a walk that drops it is refused rather than answered, and ``from_`` has to
arrive as ``from`` because Python cannot spell the parameter the API declares.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient
from agledger.types import FleetDriftPage

BASE = "https://agledger.example.com"

WINDOW = {
    "days": 30,
    "currentFrom": "2026-08-09T00:00:00Z",
    "currentTo": "2026-09-08T00:00:00Z",
    "baselineFrom": "2026-07-10T00:00:00Z",
    "baselineTo": "2026-08-09T00:00:00Z",
}


def _bucket(records: int = 3, rate: float | None = 0.75) -> dict[str, object]:
    return {
        "from": "2026-08-09T00:00:00Z",
        "to": "2026-09-08T00:00:00Z",
        "records": records,
        "completions": records,
        "verdicts": records,
        "accepted": records,
        "rejected": 0,
        "overturned": 0,
        "acceptanceRate": rate,
        "medianCompletionMs": 1200,
    }


def _change() -> dict[str, object]:
    return {
        "records": 1,
        "completions": 1,
        "verdicts": 1,
        "overturned": 0,
        "acceptanceRate": 0.05,
        "medianCompletionMs": -300,
    }


def _series() -> dict[str, object]:
    return {"current": _bucket(), "baseline": _bucket(2, 0.7), "change": _change()}


def _fleet_page(agent_id: str, *, next_cursor: str | None, has_more: bool) -> dict[str, object]:
    row = {"agentId": agent_id, "displayName": f"Bot {agent_id}", **_series()}
    return {
        "window": WINDOW,
        "data": [row],
        "total": 2,
        "nextCursor": next_cursor,
        "hasMore": has_more,
    }


def _client() -> AgledgerClient:
    return AgledgerClient(base_url=BASE, api_key="test-key")


@respx.mock
def test_get_agent_sends_window_and_type():
    route = respx.get(f"{BASE}/v1/agents/agt-1/drift").mock(
        return_value=httpx.Response(200, json={
            "agentId": "agt-1", "window": WINDOW, "overall": _series(),
            "byType": [{"type": "notarize-generic-v1", **_series()}],
        })
    )
    drift = _client().drift.get_agent("agt-1", window=30, type="notarize-generic-v1")

    assert route.calls.last.request.url.path == "/v1/agents/agt-1/drift"
    assert dict(route.calls.last.request.url.params) == {
        "window": "30",
        "type": "notarize-generic-v1",
    }
    assert drift.window.days == 30
    assert drift.overall.change.records == 1
    assert drift.by_type[0].type == "notarize-generic-v1"


@respx.mock
def test_get_agent_omits_unset_params():
    route = respx.get(f"{BASE}/v1/agents/agt-1/drift").mock(
        return_value=httpx.Response(200, json={
            "agentId": "agt-1", "window": WINDOW, "overall": _series(), "byType": [],
        })
    )
    _client().drift.get_agent("agt-1")
    assert dict(route.calls.last.request.url.params) == {}


@respx.mock
def test_list_fleet_keeps_the_window_beside_the_rows():
    """The window is computed once per page and rides on the envelope, not on
    each row. A page model that only carried ``data`` would drop it, leaving the
    caller unable to say what the counts are counts of."""
    route = respx.get(f"{BASE}/v1/agents/drift").mock(
        return_value=httpx.Response(200, json=_fleet_page("agt-1", next_cursor=None, has_more=False))
    )
    page = _client().drift.list_fleet(window=30, limit=20, cursor="cur-0")

    assert route.calls.last.request.url.path == "/v1/agents/drift"
    assert dict(route.calls.last.request.url.params) == {
        "window": "30",
        "limit": "20",
        "cursor": "cur-0",
    }
    assert isinstance(page, FleetDriftPage)
    assert page.window.days == 30
    assert page.window.baseline_from == "2026-07-10T00:00:00Z"
    assert page.data[0].agent_id == "agt-1"
    assert page.data[0].display_name == "Bot agt-1"
    assert page.data[0].current.records == 3
    assert page.has_more is False


@respx.mock
def test_list_all_fleet_resends_the_window_with_the_cursor():
    """The query parameters are bound into the cursor, so a second page fetched
    without ``window`` is refused rather than answered from a stale offset."""
    pages = [
        httpx.Response(200, json=_fleet_page("agt-1", next_cursor="cur-1", has_more=True)),
        httpx.Response(200, json=_fleet_page("agt-2", next_cursor=None, has_more=False)),
    ]
    route = respx.get(f"{BASE}/v1/agents/drift").mock(side_effect=pages)

    rows = list(_client().drift.list_all_fleet(window=30))

    assert [r.agent_id for r in rows] == ["agt-1", "agt-2"]
    assert dict(route.calls[0].request.url.params) == {"window": "30"}
    assert dict(route.calls[1].request.url.params) == {"window": "30", "cursor": "cur-1"}


@respx.mock
def test_get_agent_history_maps_from_to_the_wire_name():
    route = respx.get(f"{BASE}/v1/agents/agt-1/history").mock(
        return_value=httpx.Response(200, json={
            "data": [{
                "recordId": "rec-1", "type": "notarize-generic-v1",
                "status": "FULFILLED", "role": "both", "outcome": "accept",
                "createdAt": "2026-09-01T00:00:00Z",
                "completedAt": "2026-09-01T00:05:00Z",
            }],
            "total": 1, "nextCursor": None, "hasMore": False,
        })
    )
    page = _client().drift.get_agent_history(
        "agt-1",
        limit=50,
        offset=0,
        cursor="cur-0",
        type="notarize-generic-v1",
        outcome="accept",
        from_="2026-09-01T00:00:00Z",
        to="2026-09-08T00:00:00Z",
    )

    assert route.calls.last.request.url.path == "/v1/agents/agt-1/history"
    assert dict(route.calls.last.request.url.params) == {
        "limit": "50",
        "offset": "0",
        "cursor": "cur-0",
        "type": "notarize-generic-v1",
        "outcome": "accept",
        "from": "2026-09-01T00:00:00Z",
        "to": "2026-09-08T00:00:00Z",
    }
    assert page.data[0].record_id == "rec-1"
    assert page.data[0].completed_at == "2026-09-01T00:05:00Z"


@respx.mock
def test_get_agent_history_tolerates_a_pending_record():
    respx.get(f"{BASE}/v1/agents/agt-1/history").mock(
        return_value=httpx.Response(200, json={
            "data": [{
                "recordId": "rec-2", "type": "principal-gate-generic-v1",
                "status": "PROCESSING", "role": "performer", "outcome": "PENDING",
                "createdAt": "2026-09-07T00:00:00Z", "completedAt": None,
            }],
            "total": 1, "nextCursor": None, "hasMore": False,
        })
    )
    page = _client().drift.get_agent_history("agt-1")
    assert page.data[0].outcome == "PENDING"
    assert page.data[0].completed_at is None


@pytest.mark.asyncio
@respx.mock
async def test_async_drift_mirrors_the_sync_surface():
    respx.get(f"{BASE}/v1/agents/agt-1/drift").mock(
        return_value=httpx.Response(200, json={
            "agentId": "agt-1", "window": WINDOW, "overall": _series(), "byType": [],
        })
    )
    route = respx.get(f"{BASE}/v1/agents/drift").mock(
        side_effect=[
            httpx.Response(200, json=_fleet_page("agt-1", next_cursor="cur-1", has_more=True)),
            httpx.Response(200, json=_fleet_page("agt-2", next_cursor=None, has_more=False)),
        ]
    )
    async with AsyncAgledgerClient(base_url=BASE, api_key="test-key") as client:
        drift = await client.drift.get_agent("agt-1", window=30)
        assert drift.agent_id == "agt-1"

        rows = [row async for row in client.drift.list_all_fleet(window=30)]

    assert [r.agent_id for r in rows] == ["agt-1", "agt-2"]
    assert dict(route.calls[1].request.url.params) == {"window": "30", "cursor": "cur-1"}
