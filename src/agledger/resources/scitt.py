"""SCITT Transparency Service surface (draft-ietf-scitt-scrapi-09).

Customers register Signed Statements (COSE_Sign1) and receive Receipts
(COSE_Sign1 carrying RFC 9162 Merkle inclusion proofs per
draft-ietf-cose-merkle-tree-proofs-18). Reads return Transparent Statements
(Signed Statement + Receipt(s) composed at unprotected label 394). The
Transparency Service's COSE_KeySet is available at ``/.well-known/scitt-keys``
for offline Receipt verification.

Wire types are ``application/cose`` for entries and ``application/cose-key-set``
for keys. 4xx / 5xx return ``application/concise-problem-details+cbor`` (RFC 9290)
NOT JSON. The error body is captured on the raised exception's ``raw_body``
attribute for the caller to decode.
"""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient


class ScittEntriesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def register(self, signed_statement: bytes) -> bytes:
        """Register a customer-prepared Signed Statement.

        :param signed_statement: Tagged COSE_Sign1 bytes.
        :returns: The Receipt as tagged COSE_Sign1 bytes. Per SCITT spec, posting
            the same bytes twice creates two distinct entries.
        """
        return self._http.post_bytes(
            "/v1/scitt/entries",
            body=signed_statement,
            content_type="application/cose",
            accept="application/cose",
        )

    def get(self, entry_id: str) -> bytes:
        """Read a Transparent Statement (Signed Statement + Receipt(s)) by entry id."""
        return self._http.get_bytes(f"/v1/scitt/entries/{entry_id}", accept="application/cose")


class ScittKeysResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self) -> bytes:
        """Fetch the Transparency Service's COSE_KeySet (unauthenticated).

        Returned as CBOR bytes: an array of COSE_Key maps.
        """
        return self._http.get_bytes(
            "/.well-known/scitt-keys", accept="application/cose-key-set", auth_override="none"
        )

    def get(self, kid: str) -> bytes:
        """Fetch a single COSE_Key by kid (unauthenticated)."""
        return self._http.get_bytes(
            f"/.well-known/scitt-keys/{kid}", accept="application/cose-key", auth_override="none"
        )


class ScittResource:
    """SCITT/SCRAPI transparency surface: signed-statement entries and keys."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self.entries: ScittEntriesResource = ScittEntriesResource(http)
        self.keys: ScittKeysResource = ScittKeysResource(http)

    def get_configuration(self) -> dict[str, Any]:
        """Fetch the SCRAPI discovery document (``/.well-known/scitt-configuration``,
        unauthenticated): registration/resolution/checkpoint endpoints plus
        supported signature algorithms and registration policies. Returns JSON."""
        return self._http.get("/.well-known/scitt-configuration", auth_override="none")

    def get_checkpoint(self) -> dict[str, Any]:
        """Fetch the org's signed SCITT log checkpoint (tree head). The signature
        covers a canonical input prefixed by ``logId``. Returns JSON."""
        return self._http.get("/v1/scitt/checkpoint")


class AsyncScittEntriesResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def register(self, signed_statement: bytes) -> bytes:
        return await self._http.post_bytes(
            "/v1/scitt/entries",
            body=signed_statement,
            content_type="application/cose",
            accept="application/cose",
        )

    async def get(self, entry_id: str) -> bytes:
        return await self._http.get_bytes(f"/v1/scitt/entries/{entry_id}", accept="application/cose")


class AsyncScittKeysResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self) -> bytes:
        return await self._http.get_bytes(
            "/.well-known/scitt-keys", accept="application/cose-key-set", auth_override="none"
        )

    async def get(self, kid: str) -> bytes:
        return await self._http.get_bytes(
            f"/.well-known/scitt-keys/{kid}", accept="application/cose-key", auth_override="none"
        )


class AsyncScittResource:
    """SCITT/SCRAPI transparency surface: signed-statement entries and keys."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http
        self.entries: AsyncScittEntriesResource = AsyncScittEntriesResource(http)
        self.keys: AsyncScittKeysResource = AsyncScittKeysResource(http)

    async def get_configuration(self) -> dict[str, Any]:
        """Fetch the SCRAPI discovery document (``/.well-known/scitt-configuration``,
        unauthenticated): registration/resolution/checkpoint endpoints plus
        supported signature algorithms and registration policies. Returns JSON."""
        return await self._http.get("/.well-known/scitt-configuration", auth_override="none")

    async def get_checkpoint(self) -> dict[str, Any]:
        """Fetch the org's signed SCITT log checkpoint (tree head). The signature
        covers a canonical input prefixed by ``logId``. Returns JSON."""
        return await self._http.get("/v1/scitt/checkpoint")
