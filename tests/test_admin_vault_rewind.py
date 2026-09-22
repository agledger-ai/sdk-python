"""The four admin vault routes the engine added during the 1.8.0 line: signing
key retirement, anchor-bucket reconciliation, and the chain-rewind pair.

Each is checked for the path it calls and for the body it sends, because an
optional argument that is always sent is a different request from one that is
sent only when asked: the retire quiet period and the reconcile walk bounds are
both engine defaults that a stray `null` would override.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient

_BASE = "https://agledger.example.com"


def _client() -> AgledgerClient:
    return AgledgerClient(base_url=_BASE, api_key="test-key")


def _body(index: int = 0) -> object:
    return json.loads(respx.calls[index].request.content)


@respx.mock
def test_retire_puts_the_key_id_in_the_path() -> None:
    respx.post(f"{_BASE}/v1/admin/vault/signing-keys/a1b2c3d4e5f60718/retire").mock(
        return_value=httpx.Response(
            200,
            json={
                "retiredKeyId": "a1b2c3d4e5f60718",
                "retiredAt": "2026-09-22T00:00:00Z",
                "lastSignedAt": None,
                "activeKeys": [],
            },
        )
    )
    result = _client().admin.vault.signing_keys.retire("a1b2c3d4e5f60718")
    assert result["retiredKeyId"] == "a1b2c3d4e5f60718"


@respx.mock
def test_retire_sends_force_only_when_asked() -> None:
    """An always-sent ``force: false`` would read as an explicit refusal of the
    quiet period rather than as the default."""
    route = respx.post(
        url__regex=rf"{_BASE}/v1/admin/vault/signing-keys/k/retire"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "retiredKeyId": "k",
                "retiredAt": "2026-09-22T00:00:00Z",
                "lastSignedAt": None,
                "activeKeys": [],
            },
        )
    )
    client = _client()
    client.admin.vault.signing_keys.retire("k")
    assert _body(0) == {}
    client.admin.vault.signing_keys.retire("k", force=True)
    assert _body(1) == {"force": True}
    assert route.call_count == 2


@respx.mock
def test_reconcile_maps_the_walk_bounds_to_camel_case() -> None:
    respx.post(f"{_BASE}/v1/admin/vault/anchors/reconcile").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "ok",
                "scannedKeys": 12,
                "recordsInBucket": 12,
                "rewound": 0,
                "missingLocally": 0,
                "unverified": 0,
                "findings": [],
                "truncated": False,
                "truncatedReason": None,
                "keyLimit": 50,
                "deadlineMs": 1000,
                "posture": {
                    "conditionalWrites": "supported",
                    "versioning": "supported",
                    "objectLock": "enabled",
                    "note": "",
                },
            },
        )
    )
    result = _client().admin.vault.anchors.reconcile(max_keys=50, deadline_ms=1000)
    assert _body() == {"maxKeys": 50, "deadlineMs": 1000}
    assert result["status"] == "ok"


@respx.mock
def test_reconcile_sends_an_empty_body_by_default() -> None:
    """Both bounds default on the engine side and it reports the ones it used."""
    respx.post(f"{_BASE}/v1/admin/vault/anchors/reconcile").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "disabled",
                "scannedKeys": 0,
                "recordsInBucket": 0,
                "rewound": 0,
                "missingLocally": 0,
                "unverified": 0,
                "findings": [],
                "truncated": False,
                "truncatedReason": None,
                "keyLimit": 1000,
                "deadlineMs": 30000,
                "posture": {
                    "conditionalWrites": "unknown",
                    "versioning": "unknown",
                    "objectLock": "unknown",
                    "note": "",
                },
            },
        )
    )
    _client().admin.vault.anchors.reconcile()
    assert _body() == {}


@respx.mock
def test_rewind_get_reads_the_blocked_flag() -> None:
    respx.get(f"{_BASE}/v1/admin/vault/rewind").mock(
        return_value=httpx.Response(
            200,
            json={
                "blocked": True,
                "state": {
                    "detectedAt": "2026-09-22T00:00:00Z",
                    "source": "anchor_reconcile",
                    "evidence": {"rewound": 3},
                    "acknowledgedAt": None,
                    "acknowledgedBy": None,
                },
                "posture": {
                    "conditionalWrites": "supported",
                    "versioning": "supported",
                    "objectLock": "enabled",
                    "note": "",
                },
            },
        )
    )
    result = _client().admin.vault.rewind.get()
    assert result["blocked"] is True
    assert result["state"]["acknowledgedAt"] is None


@respx.mock
def test_rewind_acknowledge_carries_the_note() -> None:
    respx.post(f"{_BASE}/v1/admin/vault/rewind/acknowledge").mock(
        return_value=httpx.Response(
            200,
            json={
                "acknowledged": True,
                "epochEntryId": "11111111-1111-1111-1111-111111111111",
                "state": None,
                "nextSteps": [],
            },
        )
    )
    result = _client().admin.vault.rewind.acknowledge(
        note="restored from the 06:00 base backup"
    )
    assert _body() == {"note": "restored from the 06:00 base backup"}
    assert result["acknowledged"] is True


@respx.mock
def test_rewind_acknowledge_omits_an_unset_note() -> None:
    respx.post(f"{_BASE}/v1/admin/vault/rewind/acknowledge").mock(
        return_value=httpx.Response(
            200, json={"acknowledged": False, "epochEntryId": None, "state": None}
        )
    )
    _client().admin.vault.rewind.acknowledge()
    assert _body() == {}


@pytest.mark.asyncio
@respx.mock
async def test_the_async_client_exposes_the_same_four() -> None:
    respx.get(f"{_BASE}/v1/admin/vault/rewind").mock(
        return_value=httpx.Response(
            200,
            json={
                "blocked": False,
                "state": None,
                "posture": {
                    "conditionalWrites": "unknown",
                    "versioning": "unknown",
                    "objectLock": "unknown",
                    "note": "",
                },
            },
        )
    )
    client = AsyncAgledgerClient(base_url=_BASE, api_key="test-key")
    assert (await client.admin.vault.rewind.get())["blocked"] is False
    assert hasattr(client.admin.vault.signing_keys, "retire")
    assert hasattr(client.admin.vault.anchors, "reconcile")
    assert hasattr(client.admin.vault.rewind, "acknowledge")
    await client.close()
