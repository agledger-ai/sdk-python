"""Gate resource."""

from __future__ import annotations
from typing import Any
from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import GateEvaluationResult, GateStatus


class GateResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def evaluate(self, record_id: str, completion_ids: list[str] | None = None) -> GateEvaluationResult:
        """Trigger an on-demand gate evaluation for a Record (advisory in principal mode)."""
        body: dict[str, Any] = {}
        if completion_ids:
            body["completionIds"] = completion_ids
        data = self._http.post(f"/v1/records/{record_id}/evaluate", json=body)
        return GateEvaluationResult.model_validate(data)

    def get_status(self, record_id: str) -> GateStatus:
        """Get the gate status (Phase 1 structural + Phase 2 evaluation) for a Record."""
        return GateStatus.model_validate(self._http.get(f"/v1/records/{record_id}/gate-status"))


class AsyncGateResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def evaluate(self, record_id: str, completion_ids: list[str] | None = None) -> GateEvaluationResult:
        """Trigger an on-demand gate evaluation for a Record (advisory in principal mode)."""
        body: dict[str, Any] = {}
        if completion_ids:
            body["completionIds"] = completion_ids
        data = await self._http.post(f"/v1/records/{record_id}/evaluate", json=body)
        return GateEvaluationResult.model_validate(data)

    async def get_status(self, record_id: str) -> GateStatus:
        """Get the gate status (Phase 1 structural + Phase 2 evaluation) for a Record."""
        return GateStatus.model_validate(await self._http.get(f"/v1/records/{record_id}/gate-status"))
