"""Disputes resource."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Dispute, DisputeOutcome, DisputeResponse, DisputeStatus, Page


class DisputesResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(
        self,
        *,
        status: DisputeStatus | str | None = None,
        record_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Dispute]:
        """List disputes across the org. Filter by status or record_id.

        ``status`` takes a :data:`~agledger.types.DisputeStatus`; the route
        declares a strict enum, so anything else is a 400.

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
        # The create 201 is a { dispute, autoReadjudication } envelope. Read the
        # envelope through ``client.request()`` when you need the
        # auto-readjudication result alongside the dispute.
        if isinstance(response, dict) and "dispute" in response:
            return Dispute.model_validate(response["dispute"])
        return Dispute.model_validate(response)

    def get(self, record_id: str) -> DisputeResponse:
        """Get the dispute for a Record, including submitted evidence."""
        return DisputeResponse.model_validate(self._http.get(f"/v1/records/{record_id}/dispute"))

    def resolve(
        self,
        dispute_id: str,
        *,
        outcome: DisputeOutcome,
        rationale: str | None = None,
    ) -> Dispute:
        """Render the outcome on a dispute. The dispute id goes in the path, not
        the record id.

        ``OVERTURNED`` says the disputed verdict does not stand: a record whose
        pre-dispute status was FAILED settles at FULFILLED with the verdict
        re-rendered as ``accept``, one already FULFILLED or REMEDIATED is
        restored to that terminal, and a RELEASE Settlement Signal follows
        carrying reason code ``DISPUTE_OVERTURNED``. ``UPHELD`` returns the
        record to exactly the status it held before the dispute and emits no
        signal.

        Accepted while the dispute is at ``EVIDENCE_WINDOW`` or
        ``PENDING_RESOLUTION``. One already ``RESOLVED`` or ``WITHDRAWN`` raises
        :class:`~agledger.UnprocessableError` carrying ``currentState`` and
        ``allowedActions``.

        The rendering is the caller's: AGLedger holds and serves the signed
        decision and never makes it. Authorized for the principal of the
        disputed record, or an org admin.
        """
        body: dict[str, Any] = {"outcome": outcome}
        if rationale is not None:
            body["rationale"] = rationale
        return Dispute.model_validate(self._http.post(f"/v1/disputes/{dispute_id}/resolve", json=body))

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
        status: DisputeStatus | str | None = None,
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
        # The create 201 is a { dispute, autoReadjudication } envelope.
        if isinstance(response, dict) and "dispute" in response:
            return Dispute.model_validate(response["dispute"])
        return Dispute.model_validate(response)

    async def get(self, record_id: str) -> DisputeResponse:
        return DisputeResponse.model_validate(await self._http.get(f"/v1/records/{record_id}/dispute"))

    async def resolve(
        self,
        dispute_id: str,
        *,
        outcome: DisputeOutcome,
        rationale: str | None = None,
    ) -> Dispute:
        """Render the outcome on a dispute. The dispute id goes in the path, not
        the record id."""
        body: dict[str, Any] = {"outcome": outcome}
        if rationale is not None:
            body["rationale"] = rationale
        return Dispute.model_validate(
            await self._http.post(f"/v1/disputes/{dispute_id}/resolve", json=body)
        )

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
