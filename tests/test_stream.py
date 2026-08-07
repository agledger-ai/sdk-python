"""Tests for compliance.stream() and stream_all() — SIEM audit streaming."""

import json

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient, AuditStreamResult


EVENTS = [
    {"type": "record.created", "timestamp": "2026-01-01T00:00:00Z", "id": "evt-1"},
    {"type": "record.fulfilled", "timestamp": "2026-01-01T01:00:00Z", "id": "evt-2"},
]
NDJSON = "\n".join(json.dumps(e) for e in EVENTS) + "\n"


@respx.mock
def test_stream_returns_events_and_cursor():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(
            200,
            text=NDJSON,
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-cursor": "2026-01-01T01:00:00Z_evt-2",
            },
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    result = client.compliance.stream(since="2026-01-01T00:00:00Z")

    assert isinstance(result, AuditStreamResult)
    assert len(result.events) == 2
    assert result.events[0]["type"] == "record.created"
    assert result.cursor == "2026-01-01T01:00:00Z_evt-2"
    assert result.has_more is False


@respx.mock
def test_stream_has_more_when_at_limit():
    events = [{"type": "record.created", "timestamp": f"2026-01-01T0{i}:00:00Z", "id": f"evt-{i}"} for i in range(3)]
    ndjson = "\n".join(json.dumps(e) for e in events) + "\n"
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(
            200,
            text=ndjson,
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-cursor": "2026-01-01T02:00:00Z_evt-2",
            },
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    result = client.compliance.stream(since="2026-01-01T00:00:00Z", limit=3)

    assert result.has_more is True
    assert len(result.events) == 3


@respx.mock
def test_stream_sends_correct_params():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    client.compliance.stream(since="2026-01-01T00:00:00Z", limit=500, format="raw")

    req = respx.calls[0].request
    assert req.headers["accept"] == "application/x-ndjson"
    assert "since=2026-01-01" in str(req.url)
    assert "limit=500" in str(req.url)
    assert "format=raw" in str(req.url)


@respx.mock
def test_stream_empty_response():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    result = client.compliance.stream(since="2026-01-01T00:00:00Z")

    assert result.events == []
    assert result.cursor is None
    assert result.has_more is False


@respx.mock
def test_stream_all_iterates_pages():
    page1 = [
        {"type": "record.created", "timestamp": "2026-01-01T00:00:00Z", "id": "evt-1"},
        {"type": "record.fulfilled", "timestamp": "2026-01-01T01:00:00Z", "id": "evt-2"},
    ]
    page2 = [
        {"type": "record.expired", "timestamp": "2026-01-01T02:00:00Z", "id": "evt-3"},
    ]
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(
                200,
                text="\n".join(json.dumps(e) for e in page1) + "\n",
                headers={
                    "content-type": "application/x-ndjson",
                    "x-agledger-stream-cursor": "2026-01-01T01:00:00Z_evt-2",
                },
            )
        return httpx.Response(
            200,
            text="\n".join(json.dumps(e) for e in page2) + "\n",
            headers={"content-type": "application/x-ndjson"},
        )

    respx.get("https://agledger.example.com/v1/siem/stream").mock(side_effect=side_effect)
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    all_events = list(client.compliance.stream_all(since="2026-01-01T00:00:00Z", limit=2))
    assert len(all_events) == 3
    assert all_events[2]["type"] == "record.expired"
    assert call_count == 2


@respx.mock
@pytest.mark.anyio
async def test_async_stream():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(
            200,
            text=NDJSON,
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-cursor": "2026-01-01T01:00:00Z_evt-2",
            },
        )
    )
    async with AsyncAgledgerClient(base_url="https://agledger.example.com", api_key="test-key") as client:
        result = await client.compliance.stream(since="2026-01-01T00:00:00Z")
        assert len(result.events) == 2
        assert result.cursor == "2026-01-01T01:00:00Z_evt-2"
