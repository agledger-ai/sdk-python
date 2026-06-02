"""Disputes resource."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Dispute, DisputeResponse, Page


class DisputesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(
        self,
        *,
        status: str | None = None,
        record_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Dispute]:
        """List disputes across the org. Filter by status or record_id.

        Backed by ``GET /v1/disputes``.
        """
        params: dict[str, Any] = {}
        if status is not None: params["status"] = status
        if record_id is not None: params["recordId"] = record_id
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = self._http.get_page("/v1/disputes", params=params)
        raw["data"] = [Dispute.model_validate(d) for d in raw.get("data", [])]
        return Page[Dispute].model_validate(raw)

    def create(self, record_id: str, *, grounds: str, context: str | None = None) -> Dispute:
        """Initiate a dispute on a Record. Returns the dispute object (from the create envelope)."""
        body: dict[str, Any] = {"grounds": grounds}
        if context is not None:
            body["context"] = context
        response = self._http.post(f"/v1/records/{record_id}/dispute", json=body)
        # API may return { dispute, tier1Result } envelope on create
        if isinstance(response, dict) and "dispute" in response:
            return Dispute.model_validate(response["dispute"])
        return Dispute.model_validate(response)

    def get(self, record_id: str) -> DisputeResponse:
        """Get the dispute for a Record, including submitted evidence."""
        return DisputeResponse.model_validate(self._http.get(f"/v1/records/{record_id}/dispute"))

    def escalate(self, record_id: str, reason: str | None = None) -> Dispute:
        """Escalate a dispute to the next review tier."""
        body = {"reason": reason} if reason else {}
        return Dispute.model_validate(self._http.post(f"/v1/records/{record_id}/dispute/escalate", json=body))

    def withdraw(self, record_id: str, reason: str | None = None) -> Dispute:
        """Withdraw an open dispute. Optional ``reason`` is recorded in the audit trail."""
        body = {"reason": reason} if reason else {}
        return Dispute.model_validate(self._http.post(f"/v1/records/{record_id}/dispute/withdraw", json=body))

    def submit_evidence(
        self,
        record_id: str,
        *,
        evidence_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit additional evidence for a dispute."""
        return self._http.post(
            f"/v1/records/{record_id}/dispute/evidence",
            json={"evidenceType": evidence_type, "payload": payload},
        )


class AsyncDisputesResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(
        self,
        *,
        status: str | None = None,
        record_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Dispute]:
        params: dict[str, Any] = {}
        if status is not None: params["status"] = status
        if record_id is not None: params["recordId"] = record_id
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = await self._http.get_page("/v1/disputes", params=params)
        raw["data"] = [Dispute.model_validate(d) for d in raw.get("data", [])]
        return Page[Dispute].model_validate(raw)

    async def create(self, record_id: str, *, grounds: str, context: str | None = None) -> Dispute:
        body: dict[str, Any] = {"grounds": grounds}
        if context is not None:
            body["context"] = context
        response = await self._http.post(f"/v1/records/{record_id}/dispute", json=body)
        if isinstance(response, dict) and "dispute" in response:
            return Dispute.model_validate(response["dispute"])
        return Dispute.model_validate(response)

    async def get(self, record_id: str) -> DisputeResponse:
        return DisputeResponse.model_validate(await self._http.get(f"/v1/records/{record_id}/dispute"))

    async def escalate(self, record_id: str, reason: str | None = None) -> Dispute:
        body = {"reason": reason} if reason else {}
        return Dispute.model_validate(await self._http.post(f"/v1/records/{record_id}/dispute/escalate", json=body))

    async def withdraw(self, record_id: str, reason: str | None = None) -> Dispute:
        """Withdraw an open dispute. Optional ``reason`` is recorded in the audit trail."""
        body = {"reason": reason} if reason else {}
        return Dispute.model_validate(await self._http.post(f"/v1/records/{record_id}/dispute/withdraw", json=body))

    async def submit_evidence(
        self,
        record_id: str,
        *,
        evidence_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._http.post(
            f"/v1/records/{record_id}/dispute/evidence",
            json={"evidenceType": evidence_type, "payload": payload},
        )
