"""Reputation resource."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Page, ReputationScore


class ReputationResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get_agent(self, agent_id: str, **params: Any) -> Page[dict[str, Any]]:
        """Get paginated per-Type reputation scores for an agent."""
        return Page[dict[str, Any]].model_validate(self._http.get_page(f"/v1/agents/{agent_id}/reputation", params=params))

    def get_by_type(self, agent_id: str, type: str) -> ReputationScore:
        """Get reputation score for an agent on a specific Type."""
        return ReputationScore.model_validate(self._http.get(f"/v1/agents/{agent_id}/reputation/{type}"))

    def get_history(self, agent_id: str, **params: Any) -> Page[dict[str, Any]]:
        """Get transaction history for an agent."""
        return Page[dict[str, Any]].model_validate(self._http.get_page(f"/v1/agents/{agent_id}/history", params=params))


class AsyncReputationResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get_agent(self, agent_id: str, **params: Any) -> Page[dict[str, Any]]:
        return Page[dict[str, Any]].model_validate(await self._http.get_page(f"/v1/agents/{agent_id}/reputation", params=params))

    async def get_by_type(self, agent_id: str, type: str) -> ReputationScore:
        return ReputationScore.model_validate(await self._http.get(f"/v1/agents/{agent_id}/reputation/{type}"))

    async def get_history(self, agent_id: str, **params: Any) -> Page[dict[str, Any]]:
        return Page[dict[str, Any]].model_validate(await self._http.get_page(f"/v1/agents/{agent_id}/history", params=params))
