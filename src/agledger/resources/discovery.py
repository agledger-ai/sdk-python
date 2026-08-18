"""
Discovery resource — unauthenticated (or lightly authenticated) public
metadata endpoints. Useful for agent onboarding and capability probing.
"""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import ConformanceResponse


class DiscoveryResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get_scope_profiles(self) -> dict[str, Any]:
        """List all available scope profiles. Public discovery endpoint.

        Returns the page envelope the API sends: ``{"data": [...], "total",
        "hasMore", "nextCursor"}``. Previously annotated ``list[...]``, which
        made ``for p in client.discovery.get_scope_profiles()`` typecheck and
        then iterate the envelope's KEYS.
        """
        return self._http.get("/v1/scope-profiles")

    def get_conformance(self) -> ConformanceResponse:
        """Return conformance metadata (version, capabilities, contract types, limits).

        Returns the parsed model, matching this SDK's convention everywhere else
        and the TypeScript SDK's ``getConformance()``. ``ConformanceResponse``
        was exported publicly but returned by nothing, so ``limits`` and
        ``capabilities`` had no typed reader. The model allows extra fields, so
        anything the Server adds still arrives; call ``.model_dump()`` for the
        raw mapping.
        """
        return ConformanceResponse.model_validate(self._http.get("/v1/conformance"))

    def get_lifecycle(self) -> dict[str, Any]:
        """Return the Record lifecycle definition (states + transitions)."""
        return self._http.get("/lifecycle")


class AsyncDiscoveryResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get_scope_profiles(self) -> dict[str, Any]:
        """List all available scope profiles. Returns the page envelope."""
        return await self._http.get("/v1/scope-profiles")

    async def get_conformance(self) -> ConformanceResponse:
        """Return conformance metadata (version, capabilities, contract types, limits)."""
        return ConformanceResponse.model_validate(await self._http.get("/v1/conformance"))

    async def get_lifecycle(self) -> dict[str, Any]:
        """Return the Record lifecycle definition."""
        return await self._http.get("/lifecycle")
