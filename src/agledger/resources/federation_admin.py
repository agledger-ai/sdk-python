"""Federation admin resource: operator-side management of peer servers + DLQ."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient


class FederationAdminResource:
    """Federation admin operations (API key auth, admin:system scope)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create_peering_token(self, *, label: str) -> dict[str, Any]:
        """Create a single-use peering token for hub-to-hub federation setup."""
        return self._http.post("/federation/v1/admin/peering-tokens", json={"label": label})

    def list_peers(self, **params: Any) -> dict[str, Any]:
        """List all peer servers known to this instance."""
        return self._http.get_page("/federation/v1/admin/peers", params=params)

    def get_peer(self, hub_id: str) -> dict[str, Any]:
        """Get details for a specific peer server."""
        return self._http.get(f"/federation/v1/admin/peers/{hub_id}")

    def revoke_peer(self, hub_id: str, *, reason: str) -> dict[str, Any]:
        """Revoke a peer server (irreversible)."""
        return self._http.post(f"/federation/v1/admin/peers/{hub_id}/revoke", json={"reason": reason})

    def resync_peer(self, hub_id: str) -> dict[str, Any]:
        """Trigger a full resync with a peer server."""
        return self._http.post(f"/federation/v1/admin/peers/{hub_id}/resync", json={})

    def delete_peer(self, hub_id: str) -> dict[str, Any]:
        """Permanently remove a revoked peer's record."""
        return self._http.delete(f"/federation/v1/admin/peers/{hub_id}")

    def list_dlq(self, **params: Any) -> dict[str, Any]:
        """List failed outbound federation messages in the dead-letter queue."""
        return self._http.get_page("/federation/v1/admin/dlq", params=params)

    def recover_dlq(self, **params: Any) -> dict[str, Any]:
        """Recover stuck or failed outbound federation jobs."""
        return self._http.post("/federation/v1/admin/dlq/recover", json=params)

    def get_instance(self) -> dict[str, Any]:
        """This instance's federation identity (hubId, public keys, endpoint URL)."""
        return self._http.get("/federation/v1/admin/instance")


class AsyncFederationAdminResource:
    """Async federation admin operations."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def create_peering_token(self, *, label: str) -> dict[str, Any]:
        return await self._http.post("/federation/v1/admin/peering-tokens", json={"label": label})

    async def list_peers(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/federation/v1/admin/peers", params=params)

    async def get_peer(self, hub_id: str) -> dict[str, Any]:
        return await self._http.get(f"/federation/v1/admin/peers/{hub_id}")

    async def revoke_peer(self, hub_id: str, *, reason: str) -> dict[str, Any]:
        return await self._http.post(f"/federation/v1/admin/peers/{hub_id}/revoke", json={"reason": reason})

    async def resync_peer(self, hub_id: str) -> dict[str, Any]:
        return await self._http.post(f"/federation/v1/admin/peers/{hub_id}/resync", json={})

    async def delete_peer(self, hub_id: str) -> dict[str, Any]:
        return await self._http.delete(f"/federation/v1/admin/peers/{hub_id}")

    async def list_dlq(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/federation/v1/admin/dlq", params=params)

    async def recover_dlq(self, **params: Any) -> dict[str, Any]:
        return await self._http.post("/federation/v1/admin/dlq/recover", json=params)

    async def get_instance(self) -> dict[str, Any]:
        return await self._http.get("/federation/v1/admin/instance")
