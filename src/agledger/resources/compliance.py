"""Compliance, audit, and EU AI Act reporting surface.

The ``stream`` method is backed by the SIEM NDJSON endpoint at ``/v1/siem/stream``.
Per-Record audit export lives on ``client.records.get_audit_export()``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

from agledger._errors import PaginationLimitError
from agledger._http import DEFAULT_MAX_PAGES, AsyncHttpClient, HttpClient
from agledger.types import (
    AiImpactAssessment,
    AuditStreamResult,
    ComplianceExport,
    ComplianceRecord,
    EuAiActDomain,
    EuAiActRiskTier,
    Page,
)

_NO_CURSOR_MESSAGE = (
    "The SIEM stream returned events but no X-AGLedger-Stream-Cursor, so the walk "
    "cannot resume and stopped after {yielded} event(s) with the feed still open. "
    "Returning here would read as the end of the audit trail. A page with rows "
    "always carries a resume position, so retry the same request; if the header "
    "stays absent, bound the walk with 'max_pages' to take a prefix on purpose."
)


class ComplianceResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def export(self, **params: Any) -> ComplianceExport:
        """Start a compliance data export."""
        return ComplianceExport.model_validate(self._http.post("/v1/compliance/export", json=params))

    def get_export_status(self, export_id: str) -> ComplianceExport:
        """Check the status of a compliance export."""
        return ComplianceExport.model_validate(self._http.get(f"/v1/compliance/export/{export_id}"))

    def download_export(self, export_id: str) -> dict[str, Any]:
        """Download a completed compliance export."""
        return self._http.get(f"/v1/compliance/export/{export_id}/download")

    def wait_for_export(
        self,
        export_id: str,
        *,
        poll_interval_s: float = 2.0,
        timeout_s: float = 120.0,
    ) -> ComplianceExport:
        """Poll until a compliance export is ready or timeout. Raises if it times out."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            result = self.get_export_status(export_id)
            if result.status == "ready":
                return result
            time.sleep(poll_interval_s)
        raise TimeoutError(f"Export {export_id} did not complete within {timeout_s}s")

    def create_assessment(
        self,
        record_id: str,
        *,
        risk_level: EuAiActRiskTier | str,
        domain: EuAiActDomain | str,
        human_oversight: dict[str, Any] | None = None,
        testing_results: dict[str, Any] | None = None,
    ) -> AiImpactAssessment:
        """Create an AI impact assessment for a Record (EU AI Act)."""
        body: dict[str, Any] = {"riskLevel": risk_level, "domain": domain}
        if human_oversight is not None:
            body["humanOversight"] = human_oversight
        if testing_results is not None:
            body["testingResults"] = testing_results
        return AiImpactAssessment.model_validate(
            self._http.post(f"/v1/records/{record_id}/ai-impact-assessment", json=body)
        )

    def get_assessment(self, record_id: str) -> AiImpactAssessment:
        """Get the AI impact assessment for a Record."""
        return AiImpactAssessment.model_validate(
            self._http.get(f"/v1/records/{record_id}/ai-impact-assessment")
        )

    def create_record(
        self,
        record_id: str,
        *,
        record_type: str,
        attestation: dict[str, Any],
        attested_by: str,
        attested_at: str | None = None,
    ) -> ComplianceRecord:
        """Create a compliance record (attestation) for a Record."""
        body: dict[str, Any] = {
            "recordType": record_type,
            "attestation": attestation,
            "attestedBy": attested_by,
        }
        if attested_at is not None:
            body["attestedAt"] = attested_at
        return ComplianceRecord.model_validate(
            self._http.post(f"/v1/records/{record_id}/compliance-records", json=body)
        )

    def list_records(self, record_id: str, **params: Any) -> Page[dict[str, Any]]:
        """List compliance records for a Record."""
        return Page[dict[str, Any]].model_validate(
            self._http.get_page(f"/v1/records/{record_id}/compliance-records", params=params)
        )

    def get_record(self, record_id: str, compliance_record_id: str) -> ComplianceRecord:
        """Get a specific compliance record."""
        return ComplianceRecord.model_validate(
            self._http.get(f"/v1/records/{record_id}/compliance-records/{compliance_record_id}")
        )

    def export_audit_vault(self, **params: Any) -> dict[str, Any]:
        """Export the entire audit vault (platform-wide; admin-only)."""
        return self._http.get("/v1/audit-vault/export", params=params)

    def list_vault_checkpoints(
        self,
        *,
        record_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """List vault checkpoints for offline integrity verification.

        Filter by ``record_id`` to scope to a single record, or omit to walk
        the global chain.
        """
        params: dict[str, Any] = {}
        if record_id is not None: params["recordId"] = record_id
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        return self._http.get_page("/v1/audit-vault/checkpoints", params=params)

    def stream(
        self,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        format: str = "ocsf",
    ) -> AuditStreamResult:
        """Pull audit events as NDJSON for SIEM ingestion. Requires audit:read scope.

        Route mounted at ``/v1/siem/stream``.

        ``since`` starts a walk and ``cursor`` continues one, and they are
        mutually exclusive: pass one or the other, never both. ``cursor`` is the
        previous page's :attr:`AuditStreamResult.cursor`, sent back verbatim.

        Do not poll by advancing ``since`` to the newest event time ingested.
        Rows written in one transaction all carry the same ``created_at``, so a
        time-only boundary cannot address a position inside that group and every
        row sharing the newest instant is skipped. The cursor carries the row id
        alongside the instant and steps through them.
        """
        if since is not None and cursor is not None:
            raise ValueError(
                "stream() takes 'since' or 'cursor', not both: 'since' starts a walk and "
                "'cursor' continues one. Pass the previous page's cursor verbatim to "
                "resume, and drop 'since'."
            )
        if since is None and cursor is None:
            raise ValueError(
                "stream() requires 'since' or 'cursor': 'since' starts a walk and 'cursor' "
                "continues one. Pass 'since' to start a new walk, or the previous page's "
                "cursor verbatim to resume one."
            )
        params: dict[str, Any] = {"format": format}
        if since is not None:
            params["since"] = since
        if cursor is not None:
            params["cursor"] = cursor
        if limit is not None:
            params["limit"] = limit
        result = self._http.get_ndjson("/v1/siem/stream", params=params)
        return AuditStreamResult.model_validate({
            "events": result["data"],
            "cursor": result.get("cursor"),
            "hasMore": len(result["data"]) > 0,
            "holdbackSeconds": result.get("holdbackSeconds"),
        })

    def stream_all(
        self,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        format: str = "ocsf",
        max_pages: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Auto-paginating iterator for SIEM streaming.

        Every page after the first resumes from the previous page's cursor,
        verbatim. Nothing is ever derived from it: splitting a cursor to
        reconstruct a ``since`` drops every row that shares the newest
        ``created_at``, which is every other row written in the same
        transaction.

        Unbounded, hitting the runaway guard raises
        :class:`PaginationLimitError`: a SIEM feed that stops early and says
        nothing reads as a quiet window with no events in it. Pass ``max_pages``
        to take a bounded slice on purpose. A page that carries events but no
        cursor raises for the same reason: the walk cannot advance, and that is
        a truncation the caller did not ask for.
        """
        ceiling = DEFAULT_MAX_PAGES if max_pages is None else max_pages
        next_since = since
        next_cursor = cursor
        pages_read = 0
        yielded = 0
        for _ in range(ceiling):
            result = self.stream(
                since=next_since, cursor=next_cursor, limit=limit, format=format
            )
            pages_read += 1
            yield from result.events
            yielded += len(result.events)
            if not result.events:
                return
            if not result.cursor:
                raise PaginationLimitError(
                    "/v1/siem/stream", pages_read, yielded, ceiling,
                    message=_NO_CURSOR_MESSAGE.format(yielded=yielded),
                )
            next_since = None
            next_cursor = result.cursor
        if max_pages is None:
            raise PaginationLimitError("/v1/siem/stream", pages_read, yielded, ceiling)


class AsyncComplianceResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def export(self, **params: Any) -> ComplianceExport:
        return ComplianceExport.model_validate(await self._http.post("/v1/compliance/export", json=params))

    async def get_export_status(self, export_id: str) -> ComplianceExport:
        return ComplianceExport.model_validate(await self._http.get(f"/v1/compliance/export/{export_id}"))

    async def download_export(self, export_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/compliance/export/{export_id}/download")

    async def wait_for_export(
        self,
        export_id: str,
        *,
        poll_interval_s: float = 2.0,
        timeout_s: float = 120.0,
    ) -> ComplianceExport:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            result = await self.get_export_status(export_id)
            if result.status == "ready":
                return result
            await asyncio.sleep(poll_interval_s)
        raise TimeoutError(f"Export {export_id} did not complete within {timeout_s}s")

    async def create_assessment(
        self,
        record_id: str,
        *,
        risk_level: EuAiActRiskTier | str,
        domain: EuAiActDomain | str,
        human_oversight: dict[str, Any] | None = None,
        testing_results: dict[str, Any] | None = None,
    ) -> AiImpactAssessment:
        body: dict[str, Any] = {"riskLevel": risk_level, "domain": domain}
        if human_oversight is not None:
            body["humanOversight"] = human_oversight
        if testing_results is not None:
            body["testingResults"] = testing_results
        return AiImpactAssessment.model_validate(
            await self._http.post(f"/v1/records/{record_id}/ai-impact-assessment", json=body)
        )

    async def get_assessment(self, record_id: str) -> AiImpactAssessment:
        return AiImpactAssessment.model_validate(
            await self._http.get(f"/v1/records/{record_id}/ai-impact-assessment")
        )

    async def create_record(
        self,
        record_id: str,
        *,
        record_type: str,
        attestation: dict[str, Any],
        attested_by: str,
        attested_at: str | None = None,
    ) -> ComplianceRecord:
        body: dict[str, Any] = {
            "recordType": record_type,
            "attestation": attestation,
            "attestedBy": attested_by,
        }
        if attested_at is not None:
            body["attestedAt"] = attested_at
        return ComplianceRecord.model_validate(
            await self._http.post(f"/v1/records/{record_id}/compliance-records", json=body)
        )

    async def list_records(self, record_id: str, **params: Any) -> Page[dict[str, Any]]:
        return Page[dict[str, Any]].model_validate(
            await self._http.get_page(f"/v1/records/{record_id}/compliance-records", params=params)
        )

    async def get_record(self, record_id: str, compliance_record_id: str) -> ComplianceRecord:
        return ComplianceRecord.model_validate(
            await self._http.get(f"/v1/records/{record_id}/compliance-records/{compliance_record_id}")
        )

    async def export_audit_vault(self, **params: Any) -> dict[str, Any]:
        return await self._http.get("/v1/audit-vault/export", params=params)

    async def list_vault_checkpoints(
        self,
        *,
        record_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """List vault checkpoints for offline integrity verification."""
        params: dict[str, Any] = {}
        if record_id is not None: params["recordId"] = record_id
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        return await self._http.get_page("/v1/audit-vault/checkpoints", params=params)

    async def stream(
        self,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        format: str = "ocsf",
    ) -> AuditStreamResult:
        """See the sync counterpart: ``since`` and ``cursor`` are mutually exclusive,
        and one of them is required."""
        if since is not None and cursor is not None:
            raise ValueError(
                "stream() takes 'since' or 'cursor', not both: 'since' starts a walk and "
                "'cursor' continues one. Pass the previous page's cursor verbatim to "
                "resume, and drop 'since'."
            )
        if since is None and cursor is None:
            raise ValueError(
                "stream() requires 'since' or 'cursor': 'since' starts a walk and 'cursor' "
                "continues one. Pass 'since' to start a new walk, or the previous page's "
                "cursor verbatim to resume one."
            )
        params: dict[str, Any] = {"format": format}
        if since is not None:
            params["since"] = since
        if cursor is not None:
            params["cursor"] = cursor
        if limit is not None:
            params["limit"] = limit
        result = await self._http.get_ndjson("/v1/siem/stream", params=params)
        return AuditStreamResult.model_validate({
            "events": result["data"],
            "cursor": result.get("cursor"),
            "hasMore": len(result["data"]) > 0,
            "holdbackSeconds": result.get("holdbackSeconds"),
        })

    async def stream_all(
        self,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        format: str = "ocsf",
        max_pages: int | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """See the sync counterpart for why the cursor is sent back verbatim and
        why the runaway guard raises."""
        ceiling = DEFAULT_MAX_PAGES if max_pages is None else max_pages
        next_since = since
        next_cursor = cursor
        pages_read = 0
        yielded = 0
        for _ in range(ceiling):
            result = await self.stream(
                since=next_since, cursor=next_cursor, limit=limit, format=format
            )
            pages_read += 1
            for event in result.events:
                yield event
            yielded += len(result.events)
            if not result.events:
                return
            if not result.cursor:
                raise PaginationLimitError(
                    "/v1/siem/stream", pages_read, yielded, ceiling,
                    message=_NO_CURSOR_MESSAGE.format(yielded=yielded),
                )
            next_since = None
            next_cursor = result.cursor
        if max_pages is None:
            raise PaginationLimitError("/v1/siem/stream", pages_read, yielded, ceiling)
