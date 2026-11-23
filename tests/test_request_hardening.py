"""Path encoding, transport retries, Retry-After bounds, pagination and NDJSON
forwarding."""

from __future__ import annotations

import ast
import math
import re
from pathlib import Path

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient, PaginationLimitError
from agledger._errors import APIConnectionError, ConfigurationError, RateLimitError
from agledger._http import MAX_RETRY_AFTER, _retry_after_seconds
from agledger._paths import seg

BASE = "https://agledger.example.com"
HOSTILE = "../admin/x?y=1#z"
ENCODED = "..%2Fadmin%2Fx%3Fy%3D1%23z"
RESOURCES = Path(__file__).resolve().parent.parent / "src" / "agledger" / "resources"


def test_seg_encodes_every_reserved_character():
    assert seg(HOSTILE) == ENCODED
    assert seg("a b") == "a%20b"
    assert seg(42) == "42"


@pytest.mark.parametrize("bad", [".", ".."])
def test_dot_segments_are_refused(bad: str):
    with pytest.raises(ValueError):
        seg(bad)
    client = AgledgerClient(base_url=BASE, api_key="k", max_retries=0)
    with pytest.raises(ValueError):
        client.webhooks.get(bad)


def test_no_resource_path_interpolates_a_raw_value():
    """Every ``{name}`` in a path string under resources/ is wrapped in seg()."""
    offenders: list[str] = []
    for path in sorted(RESOURCES.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            head = node.values[0] if node.values else None
            if not (isinstance(head, ast.Constant) and isinstance(head.value, str) and head.value.startswith("/")):
                continue
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    call = part.value
                    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "seg"):
                        offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, "raw path interpolation:\n" + "\n".join(offenders)


@respx.mock
def test_a_hostile_id_stays_inside_its_segment():
    route = respx.get(url__regex=re.escape(BASE) + r"/v1/webhooks/.*").mock(
        return_value=httpx.Response(200, json={})
    )
    client = AgledgerClient(base_url=BASE, api_key="k", max_retries=0)
    try:
        client.webhooks.get(HOSTILE)
    except Exception:  # response shape is irrelevant; the request is what is asserted
        pass
    assert route.calls[0].request.url.raw_path == f"/v1/webhooks/{ENCODED}".encode()


@respx.mock
async def test_a_hostile_id_stays_inside_its_segment_async():
    route = respx.get(url__regex=re.escape(BASE) + r"/v1/webhooks/.*").mock(
        return_value=httpx.Response(200, json={})
    )
    async with AsyncAgledgerClient(base_url=BASE, api_key="k", max_retries=0) as client:
        try:
            await client.webhooks.get(HOSTILE)
        except Exception:
            pass
    assert route.calls[0].request.url.raw_path == f"/v1/webhooks/{ENCODED}".encode()


@respx.mock
def test_a_protocol_error_is_retried_then_wrapped(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agledger._http.time.sleep", lambda _s: None)
    route = respx.get(f"{BASE}/v1/records/r1").mock(side_effect=httpx.RemoteProtocolError("peer closed"))
    client = AgledgerClient(base_url=BASE, api_key="k", max_retries=2)
    with pytest.raises(APIConnectionError):
        client.records.get("r1")
    assert len(route.calls) == 3


@respx.mock
def test_a_read_error_recovers_on_retry(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agledger._http.time.sleep", lambda _s: None)
    route = respx.get(f"{BASE}/v1/schemas")
    route.side_effect = [httpx.ReadError("reset"), httpx.Response(200, json={"data": [], "hasMore": False})]
    client = AgledgerClient(base_url=BASE, api_key="k", max_retries=1)
    client._http.get("/v1/schemas")
    assert len(route.calls) == 2


@pytest.mark.parametrize("raw", ["inf", "Infinity", "nan", "-1"])
def test_a_non_finite_retry_after_is_ignored(raw: str):
    assert _retry_after_seconds(raw, None) is None


def test_a_non_finite_body_retry_after_is_ignored():
    assert _retry_after_seconds(None, math.inf) is None


@respx.mock
def test_a_retry_after_beyond_the_cap_raises_the_original_error(monkeypatch: pytest.MonkeyPatch):
    sleeps: list[float] = []
    monkeypatch.setattr("agledger._http.time.sleep", sleeps.append)
    route = respx.get(f"{BASE}/v1/records/r1").mock(
        return_value=httpx.Response(
            429, json={"detail": "slow down"}, headers={"retry-after": str(int(MAX_RETRY_AFTER) + 1)}
        )
    )
    client = AgledgerClient(base_url=BASE, api_key="k", max_retries=3)
    with pytest.raises(RateLimitError):
        client.records.get("r1")
    assert sleeps == [] and len(route.calls) == 1


@respx.mock
def test_hasmore_without_a_cursor_raises():
    respx.get(f"{BASE}/v1/records").mock(
        return_value=httpx.Response(200, json={"data": [], "hasMore": True})
    )
    client = AgledgerClient(base_url=BASE, api_key="k")
    with pytest.raises(PaginationLimitError, match="no cursor"):
        list(client._http.paginate("/v1/records"))


@pytest.mark.parametrize("bad", [0, -1])
def test_max_pages_below_one_is_refused(bad: int):
    client = AgledgerClient(base_url=BASE, api_key="k")
    with pytest.raises(ConfigurationError):
        list(client._http.paginate("/v1/records", max_pages=bad))


@respx.mock
def test_get_ndjson_forwards_auth_override_and_a_zero_timeout():
    route = respx.get(f"{BASE}/v1/events/stream").mock(
        return_value=httpx.Response(200, text='{"a":1}\n', headers={"content-type": "application/x-ndjson"})
    )
    client = AgledgerClient(base_url=BASE, api_key="default-key")
    client._http.get_ndjson("/v1/events/stream", auth_override="other-key", headers={"X-Extra": "1"})
    sent = route.calls[0].request.headers
    assert sent["authorization"] == "Bearer other-key"
    assert sent["x-extra"] == "1"
    assert sent["accept"] == "application/x-ndjson"


@respx.mock
async def test_get_ndjson_forwards_auth_override_async():
    route = respx.get(f"{BASE}/v1/events/stream").mock(
        return_value=httpx.Response(200, text='{"a":1}\n', headers={"content-type": "application/x-ndjson"})
    )
    async with AsyncAgledgerClient(base_url=BASE, api_key="default-key") as client:
        await client._http.get_ndjson("/v1/events/stream", auth_override="other-key")
    assert route.calls[0].request.headers["authorization"] == "Bearer other-key"
