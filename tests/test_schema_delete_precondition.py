"""Why a schema delete was refused, and the credential fields ``/v1/auth/me`` sends.

The delete precondition is the same trap ``publishers`` was: the engine sends a
recovery hint saying the type is still referenced, and the counts that make the
hint actionable arrive as top-level extension fields. The error mapper copies a
fixed set of keys and drops the rest, so a field it does not name is not merely
untyped, it is unreachable. A caller could read "still referenced" and had no
way to learn whether the reference was fixable.

The two counts mean different things. ``pinned_records`` names Records written
against the exact registration being deleted, so deleting the other publisher's
registration instead is a real remedy. ``unattributable_records`` names Records
carrying no registration pin at all, which block the delete under every label,
so a non-zero value there cannot be worked around by re-pinning.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient
from agledger._errors import APIError
from agledger.types import AccountProfile

BASE = "https://agledger.example.com"

REFUSED = {
    "type": "/problems/schema-in-use",
    "title": "Type still referenced",
    "error": "RECORDS_REFERENCE_TYPE",
    "message": "Records still reference ruleskew-v1",
    "publisher": "peerco",
    "pinnedRecords": 3,
    "unattributableRecords": 0,
    "recoveryHint": "Delete or terminalize the referencing Records first.",
}


def client() -> AgledgerClient:
    return AgledgerClient(api_key="agl_adm_test", base_url=BASE, max_retries=0)


@respx.mock
def test_delete_refusal_carries_both_counts() -> None:
    respx.delete(f"{BASE}/v1/schemas/ruleskew-v1").mock(
        return_value=httpx.Response(409, json=REFUSED)
    )

    with pytest.raises(APIError) as excinfo:
        client().schemas.delete("ruleskew-v1", publisher="peerco")

    err = excinfo.value
    assert err.pinned_records == 3
    assert err.unattributable_records == 0
    # Branch on the problem URI, not on message prose.
    assert err.type == "/problems/schema-in-use"


@respx.mock
def test_unattributable_records_block_under_every_label() -> None:
    body = dict(REFUSED, pinnedRecords=0, unattributableRecords=2)
    respx.delete(f"{BASE}/v1/schemas/ruleskew-v1").mock(
        return_value=httpx.Response(409, json=body)
    )

    with pytest.raises(APIError) as excinfo:
        client().schemas.delete("ruleskew-v1", publisher="peerco")

    # Zero pinned Records and the delete still fails: re-pinning to the other
    # publisher would not help, which is exactly what the pair discloses.
    assert excinfo.value.pinned_records == 0
    assert excinfo.value.unattributable_records == 2


@respx.mock
def test_counts_are_none_when_the_engine_does_not_send_them() -> None:
    respx.delete(f"{BASE}/v1/schemas/other-v1").mock(
        return_value=httpx.Response(409, json={"error": "CONFLICT", "message": "nope"})
    )

    with pytest.raises(APIError) as excinfo:
        client().schemas.delete("other-v1")

    # The SDK does not invent content: absent stays None rather than 0.
    assert excinfo.value.pinned_records is None
    assert excinfo.value.unattributable_records is None


@respx.mock
def test_export_pins_a_publisher() -> None:
    route = respx.post(f"{BASE}/v1/schemas/ruleskew-v1/export").mock(
        return_value=httpx.Response(200, json={"type": "ruleskew-v1", "publisher": "peerco"})
    )

    client().schemas.export_schema("ruleskew-v1", publisher="peerco")

    assert route.calls.last.request.url.params["publisher"] == "peerco"


@pytest.mark.asyncio
@respx.mock
async def test_async_export_pins_a_publisher() -> None:
    route = respx.post(f"{BASE}/v1/schemas/ruleskew-v1/export").mock(
        return_value=httpx.Response(200, json={"type": "ruleskew-v1", "publisher": "peerco"})
    )

    async with AsyncAgledgerClient(api_key="agl_adm_test", base_url=BASE, max_retries=0) as ac:
        await ac.schemas.export_schema("ruleskew-v1", publisher="peerco")

    assert route.calls.last.request.url.params["publisher"] == "peerco"


@respx.mock
def test_account_profile_types_credential_expiry_and_ip_allowlist() -> None:
    respx.get(f"{BASE}/v1/auth/me").mock(
        return_value=httpx.Response(
            200,
            json={
                "apiKeyId": "019fe300-0000-7000-8000-00000000000a",
                "role": "agent",
                "ownerId": "019fe300-0000-7000-8000-00000000000b",
                "ownerType": "agent",
                "scopes": None,
                "expiresAt": "2026-12-31T00:00:00.000Z",
                "allowedIps": ["203.0.113.7"],
            },
        )
    )

    me: AccountProfile = client().auth.get_me()

    assert me.expires_at == "2026-12-31T00:00:00.000Z"
    assert me.allowed_ips == ["203.0.113.7"]
