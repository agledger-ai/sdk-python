"""Capabilities resource."""

from __future__ import annotations

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import AgentCapabilities


class CapabilitiesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, agent_id: str) -> AgentCapabilities:
        """Get an agent's declared capabilities."""
        return AgentCapabilities.model_validate(self._http.get(f"/v1/agents/{agent_id}/capabilities"))

    def set(self, agent_id: str, *, contract_types: list[str]) -> AgentCapabilities:
        """Set the authenticated agent's own capabilities (replaces all).

        Body field is ``contractTypes`` on the wire: pass Python ``contract_types``.
        """
        return AgentCapabilities.model_validate(
            self._http.put(f"/v1/agents/{agent_id}/capabilities", json={"contractTypes": contract_types})
        )


class AsyncCapabilitiesResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get(self, agent_id: str) -> AgentCapabilities:
        return AgentCapabilities.model_validate(await self._http.get(f"/v1/agents/{agent_id}/capabilities"))

    async def set(self, agent_id: str, *, contract_types: list[str]) -> AgentCapabilities:
        return AgentCapabilities.model_validate(
            await self._http.put(f"/v1/agents/{agent_id}/capabilities", json={"contractTypes": contract_types})
        )
