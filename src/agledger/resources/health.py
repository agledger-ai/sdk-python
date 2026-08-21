"""Health resource."""

from __future__ import annotations

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import HealthResponse, StatusResponse


class HealthResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def check(self) -> HealthResponse:
        """Quick health check (GET /health)."""
        return HealthResponse.model_validate(self._http.get("/health"))

    def status(self) -> StatusResponse:
        """Get detailed system status with component health (GET /status)."""
        return StatusResponse.model_validate(self._http.get("/status"))


class AsyncHealthResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def check(self) -> HealthResponse:
        return HealthResponse.model_validate(await self._http.get("/health"))

    async def status(self) -> StatusResponse:
        return StatusResponse.model_validate(await self._http.get("/status"))
