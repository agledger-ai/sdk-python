"""Verification keys resource: public, unauthenticated endpoint."""

from __future__ import annotations
from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import VerificationKeysResponse


class VerificationKeysResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self) -> VerificationKeysResponse:
        """List all vault signing public keys (GET /v1/verification-keys). No auth required."""
        return VerificationKeysResponse.model_validate(
            self._http.get("/v1/verification-keys", auth_override="none")
        )


class AsyncVerificationKeysResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self) -> VerificationKeysResponse:
        """List all vault signing public keys (GET /v1/verification-keys). No auth required."""
        return VerificationKeysResponse.model_validate(
            await self._http.get("/v1/verification-keys", auth_override="none")
        )
