"""A2A (Agent-to-Agent) protocol resource."""

from __future__ import annotations

import uuid
from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import AgentCard


class A2AResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get_agent_card(self) -> AgentCard:
        """Fetch the platform's AgentCard for A2A discovery."""
        return AgentCard.model_validate(self._http.get("/.well-known/agent-card.json"))

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a JSON-RPC 2.0 request to the A2A endpoint."""
        return self._http.post("/a2a", json=request)

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Convenience: call a named A2A method with params. Auto-generates JSON-RPC envelope."""
        return self.dispatch({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": str(uuid.uuid4()),
        })


class AsyncA2AResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get_agent_card(self) -> AgentCard:
        """Fetch the platform's AgentCard for A2A discovery."""
        return AgentCard.model_validate(await self._http.get("/.well-known/agent-card.json"))

    async def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a JSON-RPC 2.0 request to the A2A endpoint."""
        return await self._http.post("/a2a", json=request)

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Convenience: call a named A2A method with params. Auto-generates JSON-RPC envelope."""
        return await self.dispatch({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": str(uuid.uuid4()),
        })

