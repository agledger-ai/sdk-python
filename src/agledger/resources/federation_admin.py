"""Federation admin resource: operator-side management of peer servers + DLQ."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import FederationPeer, Page


class FederationAdminResource:
    """Federation admin operations (API key auth, admin:system scope)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create_peering_token(self, *, label: str) -> dict[str, Any]:
        """Create a single-use peering token, to be shared out of band with the
        operator of the peer Server that will use it in the handshake."""
        return self._http.post("/federation/v1/admin/peering-tokens", json={"label": label})

    def list_peers(self, **params: Any) -> Page[FederationPeer]:
        """List all peer Servers known to this instance.

        Filters: ``status`` (``active`` / ``suspended`` / ``revoked``),
        ``limit``, ``offset``, ``cursor``."""
        return Page[FederationPeer].model_validate(
            self._http.get_page("/federation/v1/admin/peers", params=params)
        )

    def get_peer(self, peer_hub_id: str) -> FederationPeer:
        """Get details for a specific peer Server.

        Takes the ``peer_hub_id`` served on every listing row, not ``peer_id``,
        which is the receiver-local row id and resolves nowhere."""
        return FederationPeer.model_validate(
            self._http.get(f"/federation/v1/admin/peers/{peer_hub_id}")
        )

    def revoke_peer(self, peer_hub_id: str, *, reason: str) -> dict[str, Any]:
        """Revoke a peer Server (irreversible)."""
        return self._http.post(f"/federation/v1/admin/peers/{peer_hub_id}/revoke", json={"reason": reason})

    def resync_peer(self, peer_hub_id: str) -> dict[str, Any]:
        """Trigger a full resync with a peer Server."""
        return self._http.post(f"/federation/v1/admin/peers/{peer_hub_id}/resync", json={})

    def delete_peer(self, peer_hub_id: str) -> dict[str, Any]:
        """Permanently remove a revoked peer's record."""
        return self._http.delete(f"/federation/v1/admin/peers/{peer_hub_id}")

    def list_dlq(self, **params: Any) -> dict[str, Any]:
        """List failed outbound federation messages in the dead-letter queue."""
        return self._http.get_page("/federation/v1/admin/dlq", params=params)

    def recover_dlq(self, **params: Any) -> dict[str, Any]:
        """Recover stuck or failed outbound federation jobs."""
        return self._http.post("/federation/v1/admin/dlq/recover", json=params)

    def get_instance(self) -> dict[str, Any]:
        """This instance's federation identity: ``instanceId`` (paste verbatim as
        a peer's ``peerHubId``), ``signingPublicKey``, ``encryptionPublicKey``,
        and ``configured``, which is true only when a handshake can complete."""
        return self._http.get("/federation/v1/admin/instance")


class AsyncFederationAdminResource:
    """Async federation admin operations."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def create_peering_token(self, *, label: str) -> dict[str, Any]:
        return await self._http.post("/federation/v1/admin/peering-tokens", json={"label": label})

    async def list_peers(self, **params: Any) -> Page[FederationPeer]:
        return Page[FederationPeer].model_validate(
            await self._http.get_page("/federation/v1/admin/peers", params=params)
        )

    async def get_peer(self, peer_hub_id: str) -> FederationPeer:
        return FederationPeer.model_validate(
            await self._http.get(f"/federation/v1/admin/peers/{peer_hub_id}")
        )

    async def revoke_peer(self, peer_hub_id: str, *, reason: str) -> dict[str, Any]:
        return await self._http.post(f"/federation/v1/admin/peers/{peer_hub_id}/revoke", json={"reason": reason})

    async def resync_peer(self, peer_hub_id: str) -> dict[str, Any]:
        return await self._http.post(f"/federation/v1/admin/peers/{peer_hub_id}/resync", json={})

    async def delete_peer(self, peer_hub_id: str) -> dict[str, Any]:
        return await self._http.delete(f"/federation/v1/admin/peers/{peer_hub_id}")

    async def list_dlq(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/federation/v1/admin/dlq", params=params)

    async def recover_dlq(self, **params: Any) -> dict[str, Any]:
        return await self._http.post("/federation/v1/admin/dlq/recover", json=params)

    async def get_instance(self) -> dict[str, Any]:
        return await self._http.get("/federation/v1/admin/instance")
