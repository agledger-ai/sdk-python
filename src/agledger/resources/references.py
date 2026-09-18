"""References resource: reverse lookup by external ID."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

from agledger._http import AsyncHttpClient, HttpClient


def _lookup_params(system: str, ref_type: str, ref_id: str, limit: int | None, cursor: str | None) -> dict[str, Any]:
    params: dict[str, Any] = {"system": system, "refType": ref_type, "refId": ref_id}
    if limit is not None: params["limit"] = limit
    if cursor is not None: params["cursor"] = cursor
    return params


class ReferencesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def lookup(
        self,
        *,
        system: str,
        ref_type: str,
        ref_id: str,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Find the Records and agents that carry an external reference.

        One reference can sit on several entities, so this is a page of
        matches (``{"data": [{"entityType", "entityId", "reference"}],
        "hasMore", "nextCursor"}``). Use :meth:`lookup_all` to walk every page."""
        return self._http.get_page(
            "/v1/references", params=_lookup_params(system, ref_type, ref_id, limit, cursor)
        )

    def lookup_all(
        self, *, system: str, ref_type: str, ref_id: str, max_pages: int | None = None
    ) -> Iterator[dict[str, Any]]:
        """Every match for an external reference, across all pages."""
        yield from self._http.paginate(
            "/v1/references",
            params=_lookup_params(system, ref_type, ref_id, None, None),
            max_pages=max_pages,
        )

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

    async def lookup(
        self,
        *,
        system: str,
        ref_type: str,
        ref_id: str,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Find the Records and agents that carry an external reference (a page
        of matches). See the sync counterpart."""
        return await self._http.get_page(
            "/v1/references", params=_lookup_params(system, ref_type, ref_id, limit, cursor)
        )

    async def lookup_all(
        self, *, system: str, ref_type: str, ref_id: str, max_pages: int | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Every match for an external reference, across all pages."""
        async for item in self._http.paginate(
            "/v1/references",
            params=_lookup_params(system, ref_type, ref_id, None, None),
            max_pages=max_pages,
        ):
            yield item

    async def add_record_references(self, record_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._http.post(f"/v1/records/{record_id}/references", json={"references": references})

    async def get_record_references(self, record_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/records/{record_id}/references")

    async def add_agent_references(self, agent_id: str, references: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._http.post(f"/v1/agents/{agent_id}/references", json={"references": references})

    async def get_agent_references(self, agent_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/agents/{agent_id}/references")
