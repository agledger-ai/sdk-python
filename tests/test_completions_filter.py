"""The completions listing's structuralValidation filter reaches the wire on
every listing call, sync and async."""

from __future__ import annotations

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient

BASE = "https://agledger.example.com"
PAGE = {"data": [], "hasMore": False}


@respx.mock
def test_sync_list_and_list_all_send_the_filter() -> None:
    route = respx.get(f"{BASE}/v1/records/rec-1/completions").mock(return_value=httpx.Response(200, json=PAGE))
    client = AgledgerClient(api_key="test-key", base_url=BASE)
    client.completions.list("rec-1", structural_validation="INVALID")
    list(client.completions.list_all("rec-1", structural_validation="ACCEPTED"))
    client.completions.list("rec-1")
    sent = [call.request.url.params.get("structuralValidation") for call in route.calls]
    assert sent == ["INVALID", "ACCEPTED", None]


@pytest.mark.asyncio
@respx.mock
async def test_async_list_and_list_all_send_the_filter() -> None:
    route = respx.get(f"{BASE}/v1/records/rec-1/completions").mock(return_value=httpx.Response(200, json=PAGE))
    client = AsyncAgledgerClient(api_key="test-key", base_url=BASE)
    await client.completions.list("rec-1", structural_validation="INVALID")
    async for _ in client.completions.list_all("rec-1", structural_validation="ACCEPTED"):
        pass
    sent = [call.request.url.params.get("structuralValidation") for call in route.calls]
    assert sent == ["INVALID", "ACCEPTED"]
