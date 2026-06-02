"""Predicate schema discovery.

Each AGLedger chain entry is an in-toto v1 Statement; the ``predicate`` body
is shaped per entry type. These endpoints publish the canonical predicate
JSON Schemas so customers can validate the predicate they decode from a
COSE_Sign1 envelope.

Known kinds: ``record-state``, ``settlement-signal``, ``vault-checkpoint``,
``schema-event``, ``org-read``, ``counter-attestation``,
``federation-projection``.
"""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient


class PredicatesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self) -> dict[str, Any]:
        """List available predicate kinds."""
        return self._http.get("/predicates")

    def get(self, kind: str, version: str = "v1") -> dict[str, Any]:
        """Fetch the JSON Schema for a specific predicate kind + version."""
        return self._http.get(f"/predicates/{kind}/{version}")


class AsyncPredicatesResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self) -> dict[str, Any]:
        return await self._http.get("/predicates")

    async def get(self, kind: str, version: str = "v1") -> dict[str, Any]:
        return await self._http.get(f"/predicates/{kind}/{version}")
