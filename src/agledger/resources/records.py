"""Records resource — CRUD, lifecycle transitions, delegation, rework loops, audit export."""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator

from agledger._http import AsyncHttpClient, HttpClient
from agledger.record_lifecycle import get_valid_transitions
from agledger.types import (
    BulkCreateResult,
    Page,
    RecordAuditExport,
    RecordRow,
    VerdictResult,
    VerdictStatistics,
)


def _build_list_params(
    org_id: str | None, status: str | None, type: str | None,
    performer_agent_id: str | None, role: str | None, from_: str | None,
    to: str | None, has_dispute: bool | None, dispute_status: str | None,
    imported: bool | None, source: str | None, actionable: bool | None,
    limit: int | None, cursor: str | None,
) -> dict[str, Any]:
    """Assemble the query params for GET /v1/records, mapping snake_case to the wire names."""
    params: dict[str, Any] = {}
    for key, value in (
        ("orgId", org_id),
        ("status", status),
        ("type", type),
        ("performerAgentId", performer_agent_id),
        ("role", role),
        ("from", from_),
        ("to", to),
        ("hasDispute", has_dispute),
        ("disputeStatus", dispute_status),
        ("imported", imported),
        ("source", source),
        ("actionable", actionable),
        ("limit", limit),
        ("cursor", cursor),
    ):
        if value is not None:
            params[key] = value
    return params


class RecordsResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(
        self,
        *,
        type: str,
        criteria: dict[str, Any],
        publisher: str | None = None,
        principal_agent_id: str | None = None,
        performer_agent_id: str | None = None,
        org_id: str | None = None,
        contract_version: str | None = None,
        platform: str | None = None,
        platform_ref: str | None = None,
        tolerance: dict[str, Any] | None = None,
        deadline: str | None = None,
        commission_pct: float | None = None,
        max_submissions: int | None = None,
        operating_mode: str | None = None,
        gate_mode: str | None = None,
        risk_classification: str | None = None,
        eu_ai_act_domain: str | None = None,
        human_oversight: dict[str, Any] | None = None,
        parent_record_id: str | None = None,
        supersedes_record_id: str | None = None,
        references: list[dict[str, Any]] | None = None,
        share: bool | None = None,
        external_task_id: str | None = None,
        project_ref: str | None = None,
        depends_on: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        outcome: str | None = None,
        correlation_id: str | None = None,
        requested_by: str | None = None,
        auto_activate: bool | None = None,
        constraint_inheritance: str | None = None,
        enforcement_overrides: dict[str, Any] | None = None,
    ) -> RecordRow:
        """Create a Record. Admin keys pass ``principal_agent_id``; agent keys default
        it to the authenticated agent.

        ``publisher`` pins WHICH registration of ``type`` the Record binds to, and
        is only needed when two publishers offer the same type in the org (an
        imported peer manifest alongside a local registration). That case raises
        ``UnprocessableError`` with ``type == "/problems/ambiguous-publisher"``
        and the candidates on ``.publishers``, rather than the engine picking one.
        Re-send pinned to one of those labels.
        """
        body: dict[str, Any] = {"type": type, "criteria": criteria}
        if publisher is not None: body["publisher"] = publisher
        if principal_agent_id is not None: body["principalAgentId"] = principal_agent_id
        if performer_agent_id is not None: body["performerAgentId"] = performer_agent_id
        if org_id is not None: body["orgId"] = org_id
        if contract_version is not None: body["contractVersion"] = contract_version
        if platform is not None: body["platform"] = platform
        if platform_ref is not None: body["platformRef"] = platform_ref
        if tolerance is not None: body["tolerance"] = tolerance
        if deadline is not None: body["deadline"] = deadline
        if commission_pct is not None: body["commissionPct"] = commission_pct
        if max_submissions is not None: body["maxSubmissions"] = max_submissions
        if operating_mode is not None: body["operatingMode"] = operating_mode
        if gate_mode is not None: body["gateMode"] = gate_mode
        if risk_classification is not None: body["riskClassification"] = risk_classification
        if eu_ai_act_domain is not None: body["euAiActDomain"] = eu_ai_act_domain
        if human_oversight is not None: body["humanOversight"] = human_oversight
        if parent_record_id is not None: body["parentRecordId"] = parent_record_id
        if supersedes_record_id is not None: body["supersedesRecordId"] = supersedes_record_id
        if references is not None: body["references"] = references
        if share is not None: body["share"] = share
        if external_task_id is not None: body["externalTaskId"] = external_task_id
        if project_ref is not None: body["projectRef"] = project_ref
        if depends_on is not None: body["dependsOn"] = depends_on
        if metadata is not None: body["metadata"] = metadata
        if outcome is not None: body["outcome"] = outcome
        if correlation_id is not None: body["correlationId"] = correlation_id
        if requested_by is not None: body["requestedBy"] = requested_by
        if auto_activate is not None: body["autoActivate"] = auto_activate
        if constraint_inheritance is not None: body["constraintInheritance"] = constraint_inheritance
        if enforcement_overrides is not None: body["enforcementOverrides"] = enforcement_overrides
        return RecordRow.model_validate(self._http.post("/v1/records", json=body))

    def get(self, record_id: str, *, integrity: bool | None = None) -> RecordRow:
        """Get a Record by ID.

        Pass ``integrity=True`` to re-verify the audit chain and cross-check the
        served row against it (API #732); the result is on ``RecordRow.integrity``.
        """
        params = {"integrity": integrity} if integrity is not None else None
        return RecordRow.model_validate(self._http.get(f"/v1/records/{record_id}", params=params))

    def list(
        self,
        *,
        org_id: str | None = None,
        status: str | None = None,
        type: str | None = None,
        performer_agent_id: str | None = None,
        role: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        has_dispute: bool | None = None,
        dispute_status: str | None = None,
        imported: bool | None = None,
        source: str | None = None,
        actionable: bool | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[RecordRow]:
        """List Records with optional filters.

        ``actionable=True`` returns the agent-recovery set: every Record whose next
        action awaits the caller's structural side (API #731). Agent keys only.
        """
        params = _build_list_params(
            org_id, status, type, performer_agent_id, role, from_, to,
            has_dispute, dispute_status, imported, source, actionable, limit, cursor,
        )
        raw = self._http.get_page("/v1/records", params=params)
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    def list_all(
        self,
        *,
        org_id: str | None = None,
        status: str | None = None,
        type: str | None = None,
        performer_agent_id: str | None = None,
        role: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        has_dispute: bool | None = None,
        dispute_status: str | None = None,
        imported: bool | None = None,
        source: str | None = None,
        actionable: bool | None = None,
    ) -> Iterator[RecordRow]:
        """Auto-paginate through all Records."""
        params = _build_list_params(
            org_id, status, type, performer_agent_id, role, from_, to,
            has_dispute, dispute_status, imported, source, actionable, None, None,
        )
        for item in self._http.paginate("/v1/records", params=params):
            yield RecordRow.model_validate(item)

    def search(
        self,
        *,
        org_id: str | None = None,
        status: str | None = None,
        type: str | None = None,
        role: str | None = None,
        performer_agent_id: str | None = None,
        category: str | None = None,
        project_ref: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        sort: str | None = None,
        order: str | None = None,
        external_task_id: str | None = None,
        parent_record_id: str | None = None,
        correlation_id: str | None = None,
        updated_after: str | None = None,
        updated_before: str | None = None,
        gate_mode: str | None = None,
        operating_mode: str | None = None,
        superseded: bool | None = None,
        supersedes_record_id: str | None = None,
        criteria: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        has_dispute: bool | None = None,
        dispute_status: str | None = None,
        imported: bool | None = None,
        source: str | None = None,
        ref_system: str | None = None,
        ref_type: str | None = None,
        ref_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        cursor: str | None = None,
    ) -> Page[RecordRow]:
        """Search Records with advanced filters."""
        params: dict[str, Any] = {}
        if org_id is not None: params["orgId"] = org_id
        if status is not None: params["status"] = status
        if type is not None: params["type"] = type
        if role is not None: params["role"] = role
        if performer_agent_id is not None: params["performerAgentId"] = performer_agent_id
        if category is not None: params["category"] = category
        if project_ref is not None: params["projectRef"] = project_ref
        if from_date is not None: params["from"] = from_date
        if to_date is not None: params["to"] = to_date
        if sort is not None: params["sort"] = sort
        if order is not None: params["order"] = order
        if external_task_id is not None: params["externalTaskId"] = external_task_id
        if parent_record_id is not None: params["parentRecordId"] = parent_record_id
        if correlation_id is not None: params["correlationId"] = correlation_id
        if updated_after is not None: params["updatedAfter"] = updated_after
        if updated_before is not None: params["updatedBefore"] = updated_before
        if gate_mode is not None: params["gateMode"] = gate_mode
        if operating_mode is not None: params["operatingMode"] = operating_mode
        if superseded is not None: params["superseded"] = superseded
        if supersedes_record_id is not None: params["supersedesRecordId"] = supersedes_record_id
        if criteria is not None: params["criteria"] = criteria
        if metadata is not None: params["metadata"] = metadata
        if has_dispute is not None: params["hasDispute"] = has_dispute
        if dispute_status is not None: params["disputeStatus"] = dispute_status
        if imported is not None: params["imported"] = imported
        if source is not None: params["source"] = source
        if ref_system is not None: params["ref.system"] = ref_system
        if ref_type is not None: params["ref.type"] = ref_type
        if ref_id is not None: params["ref.id"] = ref_id
        if limit is not None: params["limit"] = limit
        if offset is not None: params["offset"] = offset
        if cursor is not None: params["cursor"] = cursor
        raw = self._http.get_page("/v1/records/search", params=params)
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    def update(self, record_id: str, **params: Any) -> RecordRow:
        """Update a Record's mutable fields."""
        return RecordRow.model_validate(self._http.patch(f"/v1/records/{record_id}", json=params))

    def transition(self, record_id: str, action: str, reason: str | None = None) -> RecordRow:
        """Transition a Record to a new state. Read ``next_actions`` on the Record
        response for the exact set valid right now."""
        body: dict[str, Any] = {"action": action}
        if reason:
            body["reason"] = reason
        return RecordRow.model_validate(self._http.post(f"/v1/records/{record_id}/transition", json=body))

    def cancel(self, record_id: str, reason: str | None = None) -> RecordRow:
        """Cancel a Record."""
        body = {"reason": reason} if reason else {}
        return RecordRow.model_validate(self._http.post(f"/v1/records/{record_id}/cancel", json=body))

    def accept(self, record_id: str, message: str | None = None) -> RecordRow:
        """Accept a PROPOSED Record (as performer). The optional ``message``
        explains the acceptance (max 2000 chars; the API also accepts
        ``reason``/``notes`` as wire-level aliases of the same field, #780)."""
        body = {"message": message} if message else {}
        return RecordRow.model_validate(self._http.post(f"/v1/records/{record_id}/accept", json=body))

    def reject(self, record_id: str, message: str | None = None) -> RecordRow:
        """Reject a PROPOSED Record (as performer). The optional ``message``
        explains the rejection (``reason``/``notes`` are wire-level aliases, #780)."""
        body = {"message": message} if message else {}
        return RecordRow.model_validate(self._http.post(f"/v1/records/{record_id}/reject", json=body))

    def request_revision(self, record_id: str, reason: str | None = None) -> RecordRow:
        """Request revision after principal rejection (rework loop)."""
        body = {"reason": reason} if reason else {}
        return RecordRow.model_validate(self._http.post(f"/v1/records/{record_id}/revision", json=body))

    def get_chain(self, record_id: str) -> list[RecordRow]:
        """Get the full delegation chain for a Record."""
        raw = self._http.get_page(f"/v1/records/{record_id}/chain")
        return [RecordRow.model_validate(m) for m in raw.get("data", [])]

    def get_graph(self, record_id: str) -> dict[str, Any]:
        """Get the delegation graph for a Record."""
        return self._http.get(f"/v1/records/{record_id}/graph")

    def counter_propose(
        self,
        record_id: str,
        *,
        counter_criteria: dict[str, Any] | None = None,
        counter_tolerance: dict[str, Any] | None = None,
        counter_deadline: str | None = None,
        counter_commission_pct: float | None = None,
        message: str | None = None,
    ) -> RecordRow:
        """Counter-propose modified terms on a PROPOSED Record. Sets
        acceptanceStatus to COUNTER_PROPOSED."""
        body: dict[str, Any] = {}
        if counter_criteria is not None: body["counterCriteria"] = counter_criteria
        if counter_tolerance is not None: body["counterTolerance"] = counter_tolerance
        if counter_deadline is not None: body["counterDeadline"] = counter_deadline
        if counter_commission_pct is not None: body["counterCommissionPct"] = counter_commission_pct
        if message is not None: body["message"] = message
        return RecordRow.model_validate(
            self._http.post(f"/v1/records/{record_id}/counter-propose", json=body)
        )

    def accept_counter(self, record_id: str) -> RecordRow:
        """Accept a counter-proposal on a Record."""
        return RecordRow.model_validate(
            self._http.post(f"/v1/records/{record_id}/accept-counter", json={})
        )

    def get_sub_records(self, record_id: str) -> Page[RecordRow]:
        """Get direct sub-Records of a Record."""
        raw = self._http.get_page(f"/v1/records/{record_id}/sub-records")
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    def delegate(self, record_id: str, **kwargs: Any) -> RecordRow:
        """Delegate a Record by creating a child Record. Uses the unified
        ``POST /v1/records`` endpoint with ``parent_record_id`` set."""
        kwargs["parent_record_id"] = record_id
        return self.create(**kwargs)

    def bulk_create(self, records: list[dict[str, Any]]) -> BulkCreateResult:
        """Create multiple Records in a single request. Each item may carry an
        ``idempotencyKey`` for replay-safe high-volume ingest."""
        return BulkCreateResult.model_validate(
            self._http.post("/v1/records/bulk", json={"records": records})
        )

    def batch_get(self, ids: list[str]) -> dict[str, Any]:
        """Fetch up to 100 Records by ID in a single request."""
        if not ids or len(ids) > 100:
            raise ValueError(f"batch_get requires 1-100 IDs, got {len(ids)}")
        return self._http.post("/v1/records/batch", json={"ids": ids})

    def list_proposals(self, **kwargs: Any) -> Page[RecordRow]:
        """List Records proposed to the authenticated agent (pending acceptance)."""
        raw = self._http.get_page("/v1/records/agent/proposals", params=kwargs or None)
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    def submit_verdict(
        self,
        record_id: str,
        *,
        completion_id: str,
        verdict: str,
        checks: dict[str, Any] | None = None,
        notes: str | None = None,
        reason: str | None = None,
    ) -> VerdictResult:
        """Submit the principal verdict (accept or reject) on a Completion."""
        body: dict[str, Any] = {"completionId": completion_id, "verdict": verdict}
        if checks is not None:
            body["checks"] = checks
        if notes is not None:
            body["notes"] = notes
        if reason is not None:
            body["reason"] = reason
        return VerdictResult.model_validate(
            self._http.post(f"/v1/records/{record_id}/verdict", json=body)
        )

    def my_verdict_statistics(self) -> VerdictStatistics:
        """Verdict statistics for the authenticated agent — per (principal, performer)
        pair counters of accept / reject / cancel-after-completion, decomposed into
        asPrincipal and asPerformer. Agent role only."""
        return VerdictStatistics.model_validate(
            self._http.get("/v1/records/me/verdict-statistics")
        )

    def get_audit_export(
        self,
        record_id: str,
        *,
        format: str = "json",
        receipts: bool | None = None,
        evidence: bool | None = None,
    ) -> RecordAuditExport:
        """Export the per-Record, hash-chained audit trail.

        Vault entries carry an ``_actor`` envelope (key id, role, owner id) folded
        into the canonical payload; the hash chain covers it. Set ``receipts=True``
        to opt the SCITT Receipts (Merkle inclusion proofs) into the export — only
        emitted when the engine has a ``VAULT_SIGNING_KEY``. Set ``evidence=True`` to
        inline the completion evidence body at each COMPLETION_SUBMITTED entry (API
        #870) — an UNSIGNED projection the chain binds by hash via
        ``payload.evidenceHash``. JSON/NDJSON only.
        """
        params: dict[str, Any] = {"format": format}
        if receipts is not None:
            params["receipts"] = "true" if receipts else "false"
        if evidence is not None:
            params["evidence"] = "true" if evidence else "false"
        return RecordAuditExport.model_validate(
            self._http.get(f"/v1/records/{record_id}/audit-export", params=params)
        )

    def get_attestation(self, record_id: str) -> bytes:
        """Fetch the canonical COSE_Sign1 envelope stream for a Record's chain.

        Returns ``application/cose-sequence`` bytes — a concatenation of tagged
        COSE_Sign1 messages. Pair with ``agledger.verify`` for cryptographic
        verification.
        """
        return self._http.get_bytes(
            f"/v1/records/{record_id}/attestation",
            accept="application/cose-sequence",
        )

    def get_attestation_bundle(self, record_id: str) -> dict[str, Any]:
        """Fetch the sigstore-bundle v0.3.2 projection of a Record's chain.

        One bundle per chain entry, for Rekor / in-toto / sigstore-policy-controller
        ingest. NOT cryptographically verifiable end-to-end (the DSSE inner signature
        is byte-incompatible with the canonical COSE_Sign1 signature); use
        ``get_attestation()`` for cryptographic verification.
        """
        return self._http.get(f"/v1/records/{record_id}/attestation.bundle")

    def create_and_activate(self, **params: Any) -> RecordRow:
        """Create, register, and activate a Record. Three API calls — if a step fails,
        the Record exists in the intermediate state."""
        record = self.create(**params)
        self.transition(record.id, "register")
        return self.transition(record.id, "activate")

    def get_valid_transitions(self, record: RecordRow) -> tuple[str, ...]:
        """Get valid transitions for a Record's current status. Client-side lookup, no API call."""
        return get_valid_transitions(record.status)


class AsyncRecordsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def create(
        self,
        *,
        type: str,
        criteria: dict[str, Any],
        publisher: str | None = None,
        principal_agent_id: str | None = None,
        performer_agent_id: str | None = None,
        org_id: str | None = None,
        contract_version: str | None = None,
        platform: str | None = None,
        platform_ref: str | None = None,
        tolerance: dict[str, Any] | None = None,
        deadline: str | None = None,
        commission_pct: float | None = None,
        max_submissions: int | None = None,
        operating_mode: str | None = None,
        gate_mode: str | None = None,
        risk_classification: str | None = None,
        eu_ai_act_domain: str | None = None,
        human_oversight: dict[str, Any] | None = None,
        parent_record_id: str | None = None,
        supersedes_record_id: str | None = None,
        references: list[dict[str, Any]] | None = None,
        share: bool | None = None,
        external_task_id: str | None = None,
        project_ref: str | None = None,
        depends_on: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        outcome: str | None = None,
        correlation_id: str | None = None,
        requested_by: str | None = None,
        auto_activate: bool | None = None,
        constraint_inheritance: str | None = None,
        enforcement_overrides: dict[str, Any] | None = None,
    ) -> RecordRow:
        """Create a Record."""
        body: dict[str, Any] = {"type": type, "criteria": criteria}
        if publisher is not None: body["publisher"] = publisher
        if principal_agent_id is not None: body["principalAgentId"] = principal_agent_id
        if performer_agent_id is not None: body["performerAgentId"] = performer_agent_id
        if org_id is not None: body["orgId"] = org_id
        if contract_version is not None: body["contractVersion"] = contract_version
        if platform is not None: body["platform"] = platform
        if platform_ref is not None: body["platformRef"] = platform_ref
        if tolerance is not None: body["tolerance"] = tolerance
        if deadline is not None: body["deadline"] = deadline
        if commission_pct is not None: body["commissionPct"] = commission_pct
        if max_submissions is not None: body["maxSubmissions"] = max_submissions
        if operating_mode is not None: body["operatingMode"] = operating_mode
        if gate_mode is not None: body["gateMode"] = gate_mode
        if risk_classification is not None: body["riskClassification"] = risk_classification
        if eu_ai_act_domain is not None: body["euAiActDomain"] = eu_ai_act_domain
        if human_oversight is not None: body["humanOversight"] = human_oversight
        if parent_record_id is not None: body["parentRecordId"] = parent_record_id
        if supersedes_record_id is not None: body["supersedesRecordId"] = supersedes_record_id
        if references is not None: body["references"] = references
        if share is not None: body["share"] = share
        if external_task_id is not None: body["externalTaskId"] = external_task_id
        if project_ref is not None: body["projectRef"] = project_ref
        if depends_on is not None: body["dependsOn"] = depends_on
        if metadata is not None: body["metadata"] = metadata
        if outcome is not None: body["outcome"] = outcome
        if correlation_id is not None: body["correlationId"] = correlation_id
        if requested_by is not None: body["requestedBy"] = requested_by
        if auto_activate is not None: body["autoActivate"] = auto_activate
        if constraint_inheritance is not None: body["constraintInheritance"] = constraint_inheritance
        if enforcement_overrides is not None: body["enforcementOverrides"] = enforcement_overrides
        return RecordRow.model_validate(await self._http.post("/v1/records", json=body))

    async def get(self, record_id: str, *, integrity: bool | None = None) -> RecordRow:
        """Get a Record by ID. Pass ``integrity=True`` to re-verify the chain (API #732)."""
        params = {"integrity": integrity} if integrity is not None else None
        return RecordRow.model_validate(
            await self._http.get(f"/v1/records/{record_id}", params=params)
        )

    async def list(
        self,
        *,
        org_id: str | None = None,
        status: str | None = None,
        type: str | None = None,
        performer_agent_id: str | None = None,
        role: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        has_dispute: bool | None = None,
        dispute_status: str | None = None,
        imported: bool | None = None,
        source: str | None = None,
        actionable: bool | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[RecordRow]:
        """List Records with optional filters.

        ``actionable=True`` returns the agent-recovery set: every Record whose next
        action awaits the caller's structural side (API #731). Agent keys only.
        """
        params = _build_list_params(
            org_id, status, type, performer_agent_id, role, from_, to,
            has_dispute, dispute_status, imported, source, actionable, limit, cursor,
        )
        raw = await self._http.get_page("/v1/records", params=params)
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    async def list_all(
        self,
        *,
        org_id: str | None = None,
        status: str | None = None,
        type: str | None = None,
        performer_agent_id: str | None = None,
        role: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        has_dispute: bool | None = None,
        dispute_status: str | None = None,
        imported: bool | None = None,
        source: str | None = None,
        actionable: bool | None = None,
    ) -> AsyncIterator[RecordRow]:
        """Auto-paginate through all Records."""
        params = _build_list_params(
            org_id, status, type, performer_agent_id, role, from_, to,
            has_dispute, dispute_status, imported, source, actionable, None, None,
        )
        async for item in self._http.paginate("/v1/records", params=params):
            yield RecordRow.model_validate(item)

    async def search(
        self,
        *,
        org_id: str | None = None,
        status: str | None = None,
        type: str | None = None,
        role: str | None = None,
        performer_agent_id: str | None = None,
        category: str | None = None,
        project_ref: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        sort: str | None = None,
        order: str | None = None,
        external_task_id: str | None = None,
        parent_record_id: str | None = None,
        correlation_id: str | None = None,
        updated_after: str | None = None,
        updated_before: str | None = None,
        gate_mode: str | None = None,
        operating_mode: str | None = None,
        superseded: bool | None = None,
        supersedes_record_id: str | None = None,
        criteria: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        has_dispute: bool | None = None,
        dispute_status: str | None = None,
        imported: bool | None = None,
        source: str | None = None,
        ref_system: str | None = None,
        ref_type: str | None = None,
        ref_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        cursor: str | None = None,
    ) -> Page[RecordRow]:
        """Search Records with advanced filters."""
        params: dict[str, Any] = {}
        if org_id is not None: params["orgId"] = org_id
        if status is not None: params["status"] = status
        if type is not None: params["type"] = type
        if role is not None: params["role"] = role
        if performer_agent_id is not None: params["performerAgentId"] = performer_agent_id
        if category is not None: params["category"] = category
        if project_ref is not None: params["projectRef"] = project_ref
        if from_date is not None: params["from"] = from_date
        if to_date is not None: params["to"] = to_date
        if sort is not None: params["sort"] = sort
        if order is not None: params["order"] = order
        if external_task_id is not None: params["externalTaskId"] = external_task_id
        if parent_record_id is not None: params["parentRecordId"] = parent_record_id
        if correlation_id is not None: params["correlationId"] = correlation_id
        if updated_after is not None: params["updatedAfter"] = updated_after
        if updated_before is not None: params["updatedBefore"] = updated_before
        if gate_mode is not None: params["gateMode"] = gate_mode
        if operating_mode is not None: params["operatingMode"] = operating_mode
        if superseded is not None: params["superseded"] = superseded
        if supersedes_record_id is not None: params["supersedesRecordId"] = supersedes_record_id
        if criteria is not None: params["criteria"] = criteria
        if metadata is not None: params["metadata"] = metadata
        if has_dispute is not None: params["hasDispute"] = has_dispute
        if dispute_status is not None: params["disputeStatus"] = dispute_status
        if imported is not None: params["imported"] = imported
        if source is not None: params["source"] = source
        if ref_system is not None: params["ref.system"] = ref_system
        if ref_type is not None: params["ref.type"] = ref_type
        if ref_id is not None: params["ref.id"] = ref_id
        if limit is not None: params["limit"] = limit
        if offset is not None: params["offset"] = offset
        if cursor is not None: params["cursor"] = cursor
        raw = await self._http.get_page("/v1/records/search", params=params)
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    async def update(self, record_id: str, **params: Any) -> RecordRow:
        return RecordRow.model_validate(await self._http.patch(f"/v1/records/{record_id}", json=params))

    async def transition(self, record_id: str, action: str, reason: str | None = None) -> RecordRow:
        body: dict[str, Any] = {"action": action}
        if reason: body["reason"] = reason
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/transition", json=body)
        )

    async def cancel(self, record_id: str, reason: str | None = None) -> RecordRow:
        body = {"reason": reason} if reason else {}
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/cancel", json=body)
        )

    async def accept(self, record_id: str, message: str | None = None) -> RecordRow:
        """Accept a PROPOSED Record (as performer). The optional ``message``
        explains the acceptance (``reason``/``notes`` are wire-level aliases, #780)."""
        body = {"message": message} if message else {}
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/accept", json=body)
        )

    async def reject(self, record_id: str, message: str | None = None) -> RecordRow:
        """Reject a PROPOSED Record (as performer). The optional ``message``
        explains the rejection (``reason``/``notes`` are wire-level aliases, #780)."""
        body = {"message": message} if message else {}
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/reject", json=body)
        )

    async def request_revision(self, record_id: str, reason: str | None = None) -> RecordRow:
        body = {"reason": reason} if reason else {}
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/revision", json=body)
        )

    async def get_chain(self, record_id: str) -> list[RecordRow]:
        raw = await self._http.get_page(f"/v1/records/{record_id}/chain")
        return [RecordRow.model_validate(m) for m in raw.get("data", [])]

    async def get_graph(self, record_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/records/{record_id}/graph")

    async def counter_propose(
        self,
        record_id: str,
        *,
        counter_criteria: dict[str, Any] | None = None,
        counter_tolerance: dict[str, Any] | None = None,
        counter_deadline: str | None = None,
        counter_commission_pct: float | None = None,
        message: str | None = None,
    ) -> RecordRow:
        body: dict[str, Any] = {}
        if counter_criteria is not None: body["counterCriteria"] = counter_criteria
        if counter_tolerance is not None: body["counterTolerance"] = counter_tolerance
        if counter_deadline is not None: body["counterDeadline"] = counter_deadline
        if counter_commission_pct is not None: body["counterCommissionPct"] = counter_commission_pct
        if message is not None: body["message"] = message
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/counter-propose", json=body)
        )

    async def accept_counter(self, record_id: str) -> RecordRow:
        return RecordRow.model_validate(
            await self._http.post(f"/v1/records/{record_id}/accept-counter", json={})
        )

    async def get_sub_records(self, record_id: str) -> Page[RecordRow]:
        raw = await self._http.get_page(f"/v1/records/{record_id}/sub-records")
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    async def delegate(self, record_id: str, **kwargs: Any) -> RecordRow:
        kwargs["parent_record_id"] = record_id
        return await self.create(**kwargs)

    async def bulk_create(self, records: list[dict[str, Any]]) -> BulkCreateResult:
        return BulkCreateResult.model_validate(
            await self._http.post("/v1/records/bulk", json={"records": records})
        )

    async def batch_get(self, ids: list[str]) -> dict[str, Any]:
        if not ids or len(ids) > 100:
            raise ValueError(f"batch_get requires 1-100 IDs, got {len(ids)}")
        return await self._http.post("/v1/records/batch", json={"ids": ids})

    async def list_proposals(self, **kwargs: Any) -> Page[RecordRow]:
        raw = await self._http.get_page("/v1/records/agent/proposals", params=kwargs or None)
        raw["data"] = [RecordRow.model_validate(m) for m in raw.get("data", [])]
        return Page[RecordRow].model_validate(raw)

    async def submit_verdict(
        self,
        record_id: str,
        *,
        completion_id: str,
        verdict: str,
        checks: dict[str, Any] | None = None,
        notes: str | None = None,
        reason: str | None = None,
    ) -> VerdictResult:
        """Submit the principal verdict (accept or reject) on a Completion."""
        body: dict[str, Any] = {"completionId": completion_id, "verdict": verdict}
        if checks is not None:
            body["checks"] = checks
        if notes is not None:
            body["notes"] = notes
        if reason is not None:
            body["reason"] = reason
        return VerdictResult.model_validate(
            await self._http.post(f"/v1/records/{record_id}/verdict", json=body)
        )

    async def my_verdict_statistics(self) -> VerdictStatistics:
        return VerdictStatistics.model_validate(
            await self._http.get("/v1/records/me/verdict-statistics")
        )

    async def get_audit_export(
        self,
        record_id: str,
        *,
        format: str = "json",
        receipts: bool | None = None,
        evidence: bool | None = None,
    ) -> RecordAuditExport:
        params: dict[str, Any] = {"format": format}
        if receipts is not None:
            params["receipts"] = "true" if receipts else "false"
        if evidence is not None:
            params["evidence"] = "true" if evidence else "false"
        return RecordAuditExport.model_validate(
            await self._http.get(f"/v1/records/{record_id}/audit-export", params=params)
        )

    async def get_attestation(self, record_id: str) -> bytes:
        return await self._http.get_bytes(
            f"/v1/records/{record_id}/attestation",
            accept="application/cose-sequence",
        )

    async def get_attestation_bundle(self, record_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/records/{record_id}/attestation.bundle")

    async def create_and_activate(self, **params: Any) -> RecordRow:
        record = await self.create(**params)
        await self.transition(record.id, "register")
        return await self.transition(record.id, "activate")

    def get_valid_transitions(self, record: RecordRow) -> tuple[str, ...]:
        return get_valid_transitions(record.status)
