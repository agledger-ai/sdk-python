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

from typing import Any, Literal

from agledger._http import AsyncHttpClient, HttpClient


class PredicatesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self) -> dict[str, Any]:
        """List the predicate kinds: ``{"data": [{"kind", "predicateType",
        "schemaUrl"}]}``."""
        return self._http.get("/predicates")

    def get(self, kind: str, version: Literal["v1"] = "v1") -> dict[str, Any]:
        """Fetch the JSON Schema (draft 2019-09) for a predicate kind, returned as
        the schema document itself. ``v1`` is the only version the Server
        publishes; the path segment is literal, so any other value 404s."""
        del version
        return self._http.get(f"/predicates/{kind}/v1")


class AsyncPredicatesResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self) -> dict[str, Any]:
        return await self._http.get("/predicates")

    async def get(self, kind: str, version: Literal["v1"] = "v1") -> dict[str, Any]:
        del version
        return await self._http.get(f"/predicates/{kind}/v1")
