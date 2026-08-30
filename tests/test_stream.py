"""Tests for compliance.stream() and stream_all(): SIEM audit streaming."""

import json

import httpx
import pytest
import respx

from agledger import (
    AgledgerClient,
    AsyncAgledgerClient,
    AuditStreamResult,
    PaginationLimitError,
)

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
    assert result.has_more is True


@respx.mock
def test_stream_has_more_tracks_rows_not_page_size():
    """A short page is not the end of the stream.

    The Server holds rows back while a transaction that stamped them is still
    open, so a page below ``limit`` says nothing about whether more is coming.
    ``has_more`` reports whether this page produced rows, which is the only
    honest local signal on a cursor walk.
    """
    events = [{"type": "record.created", "timestamp": "2026-01-01T00:00:00Z", "id": "evt-0"}]
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(
            200,
            text=json.dumps(events[0]) + "\n",
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-cursor": "2026-01-01T00:00:00Z_evt-0",
                "x-agledger-stream-holdback-seconds": "42",
            },
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    result = client.compliance.stream(since="2026-01-01T00:00:00Z", limit=100)

    assert len(result.events) == 1
    assert result.has_more is True
    assert result.holdback_seconds == 42


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
    assert result.holdback_seconds is None


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
        if call_count == 2:
            return httpx.Response(
                200,
                text="\n".join(json.dumps(e) for e in page2) + "\n",
                headers={
                    "content-type": "application/x-ndjson",
                    "x-agledger-stream-cursor": "2026-01-01T02:00:00Z_evt-3",
                },
            )
        return httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})

    respx.get("https://agledger.example.com/v1/siem/stream").mock(side_effect=side_effect)
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    all_events = list(client.compliance.stream_all(since="2026-01-01T00:00:00Z", limit=2))
    assert len(all_events) == 3
    assert all_events[2]["type"] == "record.expired"
    assert call_count == 3


# --- The transaction-group regression --------------------------------------
#
# Audit rows written in one transaction all carry the same created_at. Paging by
# advancing `since` to the newest instant on the page therefore cannot address a
# position inside that group: the Server compares strictly after, so every other
# row stamped at that instant is skipped and never appears on any later page.
# The three rows below are one such group.

SHARED_INSTANT = "2026-03-04T12:00:00.123456Z"
GROUP = [
    {"type": "record.created", "timestamp": SHARED_INSTANT, "id": "row-a"},
    {"type": "record.activated", "timestamp": SHARED_INSTANT, "id": "row-b"},
    {"type": "record.fulfilled", "timestamp": SHARED_INSTANT, "id": "row-c"},
]
CURSOR_AFTER_B = f"{SHARED_INSTANT}_row-b"
CURSOR_AFTER_C = f"{SHARED_INSTANT}_row-c"


def _ndjson(events):
    return "".join(json.dumps(e) + "\n" for e in events)


def _transaction_group_server(request):
    """Answers the way the Server does, including the skip the old walk caused."""
    params = request.url.params
    if params.get("cursor") == CURSOR_AFTER_B:
        return httpx.Response(
            200,
            text=_ndjson(GROUP[2:]),
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-cursor": CURSOR_AFTER_C,
                "x-agledger-stream-holdback-seconds": "0",
            },
        )
    if params.get("cursor") == CURSOR_AFTER_C:
        return httpx.Response(
            200,
            text="",
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-holdback-seconds": "0",
            },
        )
    if params.get("since") == SHARED_INSTANT:
        # What the old rfind("_") derivation asked for: strictly after the
        # instant, which is past the whole group. row-c is lost here.
        return httpx.Response(
            200,
            text="",
            headers={
                "content-type": "application/x-ndjson",
                "x-agledger-stream-holdback-seconds": "0",
            },
        )
    return httpx.Response(
        200,
        text=_ndjson(GROUP[:2]),
        headers={
            "content-type": "application/x-ndjson",
            "x-agledger-stream-cursor": CURSOR_AFTER_B,
            "x-agledger-stream-holdback-seconds": "0",
        },
    )


@respx.mock
def test_stream_all_keeps_rows_that_share_one_created_at():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        side_effect=_transaction_group_server
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    ids = [e["id"] for e in client.compliance.stream_all(since="2026-03-04T00:00:00Z", limit=2)]

    assert ids == ["row-a", "row-b", "row-c"]


@respx.mock
def test_stream_all_sends_the_cursor_verbatim_and_drops_since():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        side_effect=_transaction_group_server
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    list(client.compliance.stream_all(since="2026-03-04T00:00:00Z", limit=2))

    second = respx.calls[1].request.url.params
    assert second.get("cursor") == CURSOR_AFTER_B
    assert "since" not in second


@respx.mock
def test_stream_all_starts_from_a_cursor():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        side_effect=_transaction_group_server
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    ids = [e["id"] for e in client.compliance.stream_all(cursor=CURSOR_AFTER_B)]

    assert ids == ["row-c"]
    assert respx.calls[0].request.url.params.get("cursor") == CURSOR_AFTER_B


@respx.mock
def test_stream_all_raises_when_a_page_has_rows_but_no_cursor():
    """An unrequested truncation raises; only a caller-set bound stops quietly."""
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(
            200,
            text=_ndjson(GROUP[:1]),
            headers={"content-type": "application/x-ndjson"},
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    with pytest.raises(PaginationLimitError, match="cannot resume"):
        list(client.compliance.stream_all(since="2026-03-04T00:00:00Z"))


@respx.mock
def test_stream_rejects_since_and_cursor_together():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    with pytest.raises(ValueError, match="not both"):
        client.compliance.stream(since="2026-03-04T00:00:00Z", cursor=CURSOR_AFTER_B)
    assert not respx.calls


@respx.mock
def test_stream_rejects_neither_since_nor_cursor():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")

    with pytest.raises(ValueError, match="requires 'since' or 'cursor'"):
        client.compliance.stream()
    assert not respx.calls


@respx.mock
@pytest.mark.anyio
async def test_async_stream_all_keeps_rows_that_share_one_created_at():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        side_effect=_transaction_group_server
    )
    async with AsyncAgledgerClient(
        base_url="https://agledger.example.com", api_key="test-key"
    ) as client:
        ids = [
            e["id"]
            async for e in client.compliance.stream_all(since="2026-03-04T00:00:00Z", limit=2)
        ]

    assert ids == ["row-a", "row-b", "row-c"]
    second = respx.calls[1].request.url.params
    assert second.get("cursor") == CURSOR_AFTER_B
    assert "since" not in second


@respx.mock
@pytest.mark.anyio
async def test_async_stream_all_raises_when_a_page_has_rows_but_no_cursor():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(
            200,
            text=_ndjson(GROUP[:1]),
            headers={"content-type": "application/x-ndjson"},
        )
    )
    async with AsyncAgledgerClient(
        base_url="https://agledger.example.com", api_key="test-key"
    ) as client:
        with pytest.raises(PaginationLimitError, match="cannot resume"):
            [e async for e in client.compliance.stream_all(since="2026-03-04T00:00:00Z")]


@respx.mock
@pytest.mark.anyio
async def test_async_stream_rejects_since_and_cursor_together():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})
    )
    async with AsyncAgledgerClient(
        base_url="https://agledger.example.com", api_key="test-key"
    ) as client:
        with pytest.raises(ValueError, match="not both"):
            await client.compliance.stream(
                since="2026-03-04T00:00:00Z", cursor=CURSOR_AFTER_B
            )
    assert not respx.calls


@respx.mock
@pytest.mark.anyio
async def test_async_stream_rejects_neither_since_nor_cursor():
    respx.get("https://agledger.example.com/v1/siem/stream").mock(
        return_value=httpx.Response(200, text="", headers={"content-type": "application/x-ndjson"})
    )
    async with AsyncAgledgerClient(
        base_url="https://agledger.example.com", api_key="test-key"
    ) as client:
        with pytest.raises(ValueError, match="requires 'since' or 'cursor'"):
            await client.compliance.stream()
    assert not respx.calls


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
