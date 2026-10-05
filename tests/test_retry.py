"""Tests for retry logic, backoff, and connection errors."""

import httpx
import pytest
import respx

from agledger import AgledgerClient
from agledger._errors import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    RateLimitError,
)

RECORD_JSON = {
    "id": "rec-123", "orgId": "org-1", "performerAgentId": None, "principalAgentId": "agt-1",
    "type": "notarize-generic-v1", "contractVersion": "1", "platform": "test",
    "status": "CREATED", "criteria": {}, "submissionCount": 0, "maxSubmissions": None,
    "version": 1, "createdAt": "2026-04-27T00:00:00Z", "updatedAt": "2026-04-27T00:00:00Z",
}


@respx.mock
def test_retries_on_429():
    route = respx.get("https://agledger.example.com/v1/records/rec-123")
    route.side_effect = [
        httpx.Response(429, json={"detail": "Rate limited"}, headers={"retry-after": "0"}),
        httpx.Response(200, json=RECORD_JSON),
    ]
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=1)
    record = client.records.get("rec-123")
    assert record.id == "rec-123"
    assert len(route.calls) == 2


@respx.mock
def test_retries_on_500():
    route = respx.get("https://agledger.example.com/v1/records/rec-123")
    route.side_effect = [
        httpx.Response(500, json={"detail": "Server error"}),
        httpx.Response(200, json=RECORD_JSON),
    ]
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=1)
    record = client.records.get("rec-123")
    assert record.id == "rec-123"
    assert len(route.calls) == 2


@respx.mock
def test_no_retry_on_400():
    route = respx.post("https://agledger.example.com/v1/records")
    route.mock(return_value=httpx.Response(400, json={"detail": "Bad request"}))
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=2)
    with pytest.raises(APIError):
        client.records.create(type="notarize-generic-v1", criteria={})
    assert len(route.calls) == 1  # No retries


@respx.mock
def test_no_retry_on_404():
    route = respx.get("https://agledger.example.com/v1/records/x")
    route.mock(return_value=httpx.Response(404, json={"detail": "Not found"}))
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=2)
    with pytest.raises(APIError):
        client.records.get("x")
    assert len(route.calls) == 1


@respx.mock
def test_max_retries_exhausted():
    route = respx.get("https://agledger.example.com/v1/records/rec-123")
    route.side_effect = [
        httpx.Response(500, json={"detail": "fail"}),
        httpx.Response(500, json={"detail": "fail"}),
        httpx.Response(500, json={"detail": "fail"}),
    ]
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=2)
    with pytest.raises(APIError):
        client.records.get("rec-123")
    assert len(route.calls) == 3  # 1 initial + 2 retries


@respx.mock
def test_zero_retries():
    route = respx.get("https://agledger.example.com/v1/records/rec-123")
    route.mock(return_value=httpx.Response(500, json={"detail": "fail"}))
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=0)
    with pytest.raises(APIError):
        client.records.get("rec-123")
    assert len(route.calls) == 1


@respx.mock
def test_connection_error():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=0)
    with pytest.raises(APIConnectionError):
        client.records.get("rec-123")


@respx.mock
def test_timeout_error():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        side_effect=httpx.ReadTimeout("Read timed out")
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=0)
    with pytest.raises(APITimeoutError):
        client.records.get("rec-123")


@respx.mock
def test_204_returns_none():
    respx.delete("https://agledger.example.com/v1/webhooks/wh-1").mock(
        return_value=httpx.Response(204)
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key")
    client.webhooks.delete("wh-1")  # Should not raise


# Regression for the retry-set realignment with TS (2026-05-28): drop 409 from
# the retry set so an IDEMPOTENCY_CONFLICT surfaces immediately. Auto-retrying
# 409s was masking real client errors: same idempotency key + different body.

@respx.mock
def test_no_retry_on_409_conflict():
    """A 409 is structural (idempotency conflict). Must NOT auto-retry;
    retrying would mask the client error and waste API budget."""
    route = respx.post("https://agledger.example.com/v1/records")
    route.mock(return_value=httpx.Response(409, json={"detail": "Idempotency conflict", "error": "IDEMPOTENCY_CONFLICT"}))
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=3)
    with pytest.raises(APIError):
        client.records.create(type="notarize-generic-v1", criteria={})
    assert len(route.calls) == 1


@respx.mock
def test_no_retry_on_408():
    """408 is excluded from retry set (the API never emits it)."""
    route = respx.get("https://agledger.example.com/v1/records/rec-123")
    route.mock(return_value=httpx.Response(408, json={"detail": "Request timeout"}))
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=3)
    with pytest.raises(APIError):
        client.records.get("rec-123")
    assert len(route.calls) == 1


def test_default_retry_aligns_with_ts_sdk():
    """Defaults match TS SDK: 3 retries, 30s ceiling."""
    from agledger._http import _RETRYABLE_STATUSES, DEFAULT_MAX_RETRIES, MAX_BACKOFF

    assert DEFAULT_MAX_RETRIES == 3
    assert MAX_BACKOFF == 30.0
    assert _RETRYABLE_STATUSES == {429, 500, 502, 503, 504}


@respx.mock
def test_retry_after_falls_back_to_the_429_body():
    """A 429 body carries `retryAfterSeconds`. Reading only the header left
    retry_after None behind a proxy that strips it, with the answer in the body."""
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(429, json={"detail": "Rate limited", "retryAfterSeconds": 7})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=0)
    with pytest.raises(RateLimitError) as excinfo:
        client.records.get("rec-123")
    assert excinfo.value.retry_after == 7.0


@respx.mock
def test_retry_after_header_wins_over_the_body():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        return_value=httpx.Response(
            429,
            json={"detail": "Rate limited", "retryAfterSeconds": 7},
            headers={"retry-after": "3"},
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=0)
    with pytest.raises(RateLimitError) as excinfo:
        client.records.get("rec-123")
    assert excinfo.value.retry_after == 3.0


def test_backoff_waits_out_a_retry_after_longer_than_the_cap():
    """retry-after 60 was clamped to MAX_BACKOFF (30 s), so the retry drew another
    429. The wait is the larger of the step and retry-after, plus up to 25% jitter."""
    from agledger._http import MAX_BACKOFF, _backoff

    for _ in range(50):
        assert 60.0 <= _backoff(0, 60.0) <= 75.0
    for _ in range(50):
        assert MAX_BACKOFF <= _backoff(10, 5.0) <= MAX_BACKOFF * 1.25  # step wins when larger


@respx.mock
def test_retry_sleeps_for_the_full_retry_after(monkeypatch: pytest.MonkeyPatch):
    sleeps: list[float] = []
    monkeypatch.setattr("agledger._http.time.sleep", sleeps.append)
    route = respx.get("https://agledger.example.com/v1/records/rec-123")
    route.side_effect = [
        httpx.Response(429, json={"detail": "Rate limited"}, headers={"retry-after": "60"}),
        httpx.Response(200, json=RECORD_JSON),
    ]
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=1)
    client.records.get("rec-123")
    assert len(sleeps) == 1 and 60.0 <= sleeps[0] <= 75.0


@respx.mock
def test_timeout_error_carries_the_idempotency_key_every_attempt_sent():
    route = respx.post("https://agledger.example.com/v1/records").mock(
        side_effect=httpx.ReadTimeout("Read timed out")
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=1)
    with pytest.raises(APITimeoutError) as excinfo:
        client.records.create(type="notarize-generic-v1", criteria={})
    sent = {call.request.headers["idempotency-key"] for call in route.calls}
    assert len(route.calls) == 2 and len(sent) == 1
    assert excinfo.value.idempotency_key == sent.pop()


@respx.mock
def test_connection_error_on_a_read_carries_no_key():
    respx.get("https://agledger.example.com/v1/records/rec-123").mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test-key", max_retries=0)
    with pytest.raises(APIConnectionError) as excinfo:
        client.records.get("rec-123")
    assert excinfo.value.idempotency_key is None
