"""Agents resource — agent identity and references."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import AgentDirectoryEntry, AgentProfile, Page

_UPDATE_FIELDS = {"agent_class": "agentClass", "owner_ref": "ownerRef", "org_unit": "orgUnit", "description": "description"}


class AgentsResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[AgentDirectoryEntry]:
        """List agents in the caller's org (peer directory).

        Returns the lightweight directory shape — for full agent identity
        use ``get(agent_id)``.
        """
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = self._http.get_page("/v1/agents", params=params)
        raw["data"] = [AgentDirectoryEntry.model_validate(d) for d in raw.get("data", [])]
        return Page[AgentDirectoryEntry].model_validate(raw)

    def get(self, agent_id: str) -> AgentProfile:
        """Get an agent profile."""
        return AgentProfile.model_validate(self._http.get(f"/v1/agents/{agent_id}"))

    def update(self, agent_id: str, **params: Any) -> dict[str, Any]:
        """Update agent identity fields (agentClass, ownerRef, orgUnit, description)."""
        body = {api_key: params[key] for key, api_key in _UPDATE_FIELDS.items() if key in params}
        return self._http.patch(f"/v1/agents/{agent_id}", json=body)

    def add_references(self, agent_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        """Add references to an agent."""
        return self._http.post(f"/v1/agents/{agent_id}/references", json={"references": references})

    def get_references(self, agent_id: str) -> dict[str, Any]:
        """Get agent references."""
        return self._http.get(f"/v1/agents/{agent_id}/references")

    def list_peers(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        peer_hub_id: str | None = None,
    ) -> dict[str, Any]:
        """List federated agents synced into the local directory from peers.

        This is an audited read — the response carries a ``recordRead``
        checkpoint reference alongside the agent page.
        """
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        if peer_hub_id is not None: params["peerHubId"] = peer_hub_id
        return self._http.get("/v1/peer-agents", params=params)


class AsyncAgentsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[AgentDirectoryEntry]:
        """List agents in the caller's org (peer directory)."""
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = await self._http.get_page("/v1/agents", params=params)
        raw["data"] = [AgentDirectoryEntry.model_validate(d) for d in raw.get("data", [])]
        return Page[AgentDirectoryEntry].model_validate(raw)

    async def get(self, agent_id: str) -> AgentProfile:
        """Get an agent profile."""
        return AgentProfile.model_validate(await self._http.get(f"/v1/agents/{agent_id}"))

    async def update(self, agent_id: str, **params: Any) -> dict[str, Any]:
        """Update agent identity fields (agentClass, ownerRef, orgUnit, description)."""
        body = {api_key: params[key] for key, api_key in _UPDATE_FIELDS.items() if key in params}
        return await self._http.patch(f"/v1/agents/{agent_id}", json=body)

    async def add_references(self, agent_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        """Add references to an agent."""
        return await self._http.post(f"/v1/agents/{agent_id}/references", json={"references": references})

    async def get_references(self, agent_id: str) -> dict[str, Any]:
        """Get agent references."""
        return await self._http.get(f"/v1/agents/{agent_id}/references")

    async def list_peers(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        peer_hub_id: str | None = None,
    ) -> dict[str, Any]:
        """List federated agents synced into the local directory from peers.

        This is an audited read — the response carries a ``recordRead``
        checkpoint reference alongside the agent page.
        """
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        if peer_hub_id is not None: params["peerHubId"] = peer_hub_id
        return await self._http.get("/v1/peer-agents", params=params)
