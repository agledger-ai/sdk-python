"""References resource — reverse lookup by external ID."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient


class ReferencesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def lookup(self, *, system: str, ref_type: str, ref_id: str) -> dict[str, Any]:
        """Reverse lookup Records/agents by external reference."""
        return self._http.get("/v1/references", params={"system": system, "refType": ref_type, "refId": ref_id})

    def add_record_references(self, record_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        """Add external references to a Record."""
        return self._http.post(f"/v1/records/{record_id}/references", json={"references": references})

    def get_record_references(self, record_id: str) -> dict[str, Any]:
        """Get a Record's external references."""
        return self._http.get(f"/v1/records/{record_id}/references")

    def add_agent_references(self, agent_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        """Add external references to an agent."""
        return self._http.post(f"/v1/agents/{agent_id}/references", json={"references": references})

    def get_agent_references(self, agent_id: str) -> dict[str, Any]:
        """Get an agent's external references."""
        return self._http.get(f"/v1/agents/{agent_id}/references")


class AsyncReferencesResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def lookup(self, *, system: str, ref_type: str, ref_id: str) -> dict[str, Any]:
        return await self._http.get("/v1/references", params={"system": system, "refType": ref_type, "refId": ref_id})

    async def add_record_references(self, record_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._http.post(f"/v1/records/{record_id}/references", json={"references": references})

    async def get_record_references(self, record_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/records/{record_id}/references")

    async def add_agent_references(self, agent_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._http.post(f"/v1/agents/{agent_id}/references", json={"references": references})

    async def get_agent_references(self, agent_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/agents/{agent_id}/references")
