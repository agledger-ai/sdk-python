"""Federation peer-facing surface: used by federated AGLedger instances over the wire."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import PeerHandshakeResult


def _state_transition_body(
    record_id: str, state: str, type: str, idempotency_key: str,
    schema_ref: dict[str, Any] | None, principal_agent_id: str | None,
    performer_agent_id: str | None, co_sign_required: bool | None,
    correlation_id: str | None, project_ref: str | None,
    external_task_id: str | None, operating_mode: str | None,
    parent_record_id: str | None, root_record_id: str | None,
    chain_depth: int | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "recordId": record_id,
        "state": state,
        "type": type,
        "idempotencyKey": idempotency_key,
    }
    if schema_ref is not None: body["schemaRef"] = schema_ref
    if principal_agent_id is not None: body["principalAgentId"] = principal_agent_id
    if performer_agent_id is not None: body["performerAgentId"] = performer_agent_id
    if co_sign_required is not None: body["coSignRequired"] = co_sign_required
    if correlation_id is not None: body["correlationId"] = correlation_id
    if project_ref is not None: body["projectRef"] = project_ref
    if external_task_id is not None: body["externalTaskId"] = external_task_id
    if operating_mode is not None: body["operatingMode"] = operating_mode
    if parent_record_id is not None: body["parentRecordId"] = parent_record_id
    if root_record_id is not None: body["rootRecordId"] = root_record_id
    if chain_depth is not None: body["chainDepth"] = chain_depth
    return body


def _signal_body(
    record_id: str, recommendation: str, outcome_hash: str, valid_until: str,
    idempotency_key: str, outcome: str | None, counter_signature: str | None,
    schema_ref: dict[str, Any] | None, reason_code: str | None,
    failing_rule_ids: list[str] | None, reason: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "recordId": record_id,
        "recommendation": recommendation,
        "outcomeHash": outcome_hash,
        "validUntil": valid_until,
        "idempotencyKey": idempotency_key,
    }
    if outcome is not None: body["outcome"] = outcome
    if counter_signature is not None: body["counterSignature"] = counter_signature
    if schema_ref is not None: body["schemaRef"] = schema_ref
    if reason_code is not None: body["reasonCode"] = reason_code
    if failing_rule_ids is not None: body["failingRuleIds"] = failing_rule_ids
    if reason is not None: body["reason"] = reason
    return body


class FederationResource:
    """Federation peer-facing operations (bearer-token auth)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def peer_handshake(self, **params: Any) -> PeerHandshakeResult:
        """Establish a peer relationship via single-use peering token.

        The ``peer_hub_id`` on the result is the identifier every
        ``/federation/v1/admin/peers/{peerHubId}`` path takes; ``peer_id`` is
        the receiver-local row id and resolves nowhere."""
        return PeerHandshakeResult.model_validate(
            self._http.post("/federation/v1/peer", json=params)
        )

    def sync_agent_directory(self, **params: Any) -> dict[str, Any]:
        """Synchronize agent directory with a peer."""
        return self._http.post("/federation/v1/peer/agent-sync", json=params)

    def submit_state_transition(
        self,
        *,
        record_id: str,
        state: str,
        type: str,
        idempotency_key: str,
        schema_ref: dict[str, Any] | None = None,
        principal_agent_id: str | None = None,
        performer_agent_id: str | None = None,
        co_sign_required: bool | None = None,
        correlation_id: str | None = None,
        project_ref: str | None = None,
        external_task_id: str | None = None,
        operating_mode: str | None = None,
        parent_record_id: str | None = None,
        root_record_id: str | None = None,
        chain_depth: int | None = None,
    ) -> dict[str, Any]:
        """Submit a cross-boundary state transition to a peer."""
        body = _state_transition_body(
            record_id, state, type, idempotency_key, schema_ref, principal_agent_id,
            performer_agent_id, co_sign_required, correlation_id, project_ref,
            external_task_id, operating_mode, parent_record_id, root_record_id,
            chain_depth,
        )
        return self._http.post("/federation/v1/state-transitions", json=body)

    def relay_signal(
        self,
        *,
        record_id: str,
        recommendation: str,
        outcome_hash: str,
        valid_until: str,
        idempotency_key: str,
        outcome: str | None = None,
        counter_signature: str | None = None,
        schema_ref: dict[str, Any] | None = None,
        reason_code: str | None = None,
        failing_rule_ids: list[str] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Relay a Settlement Signal (SETTLE / HOLD / RELEASE) to a counterparty peer."""
        body = _signal_body(
            record_id, recommendation, outcome_hash, valid_until, idempotency_key,
            outcome, counter_signature, schema_ref, reason_code, failing_rule_ids,
            reason,
        )
        return self._http.post("/federation/v1/signals", json=body)

    def submit_co_sign_request(self, **params: Any) -> dict[str, Any]:
        """Request a co-signature on a federated artifact."""
        return self._http.post("/federation/v1/co-sign-requests", json=params)

    def submit_dispute_protocol(self, **params: Any) -> dict[str, Any]:
        """Submit a dispute-protocol message to a federated counterparty."""
        return self._http.post("/federation/v1/disputes", json=params)

    def contribute_reputation(self, **params: Any) -> dict[str, Any]:
        """Contribute reputation data for an agent to the federation."""
        return self._http.post("/federation/v1/reputation/contribute", json=params)

    def get_agent_reputation(self, agent_id: str) -> dict[str, Any]:
        """Get an agent's federated reputation score."""
        return self._http.get(f"/federation/v1/agents/{agent_id}/reputation")


class AsyncFederationResource:
    """Async federation peer-facing operations."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def peer_handshake(self, **params: Any) -> PeerHandshakeResult:
        return PeerHandshakeResult.model_validate(
            await self._http.post("/federation/v1/peer", json=params)
        )

    async def sync_agent_directory(self, **params: Any) -> dict[str, Any]:
        return await self._http.post("/federation/v1/peer/agent-sync", json=params)

    async def submit_state_transition(
        self,
        *,
        record_id: str,
        state: str,
        type: str,
        idempotency_key: str,
        schema_ref: dict[str, Any] | None = None,
        principal_agent_id: str | None = None,
        performer_agent_id: str | None = None,
        co_sign_required: bool | None = None,
        correlation_id: str | None = None,
        project_ref: str | None = None,
        external_task_id: str | None = None,
        operating_mode: str | None = None,
        parent_record_id: str | None = None,
        root_record_id: str | None = None,
        chain_depth: int | None = None,
    ) -> dict[str, Any]:
        body = _state_transition_body(
            record_id, state, type, idempotency_key, schema_ref, principal_agent_id,
            performer_agent_id, co_sign_required, correlation_id, project_ref,
            external_task_id, operating_mode, parent_record_id, root_record_id,
            chain_depth,
        )
        return await self._http.post("/federation/v1/state-transitions", json=body)

    async def relay_signal(
        self,
        *,
        record_id: str,
        recommendation: str,
        outcome_hash: str,
        valid_until: str,
        idempotency_key: str,
        outcome: str | None = None,
        counter_signature: str | None = None,
        schema_ref: dict[str, Any] | None = None,
        reason_code: str | None = None,
        failing_rule_ids: list[str] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        body = _signal_body(
            record_id, recommendation, outcome_hash, valid_until, idempotency_key,
            outcome, counter_signature, schema_ref, reason_code, failing_rule_ids,
            reason,
        )
        return await self._http.post("/federation/v1/signals", json=body)

    async def submit_co_sign_request(self, **params: Any) -> dict[str, Any]:
        return await self._http.post("/federation/v1/co-sign-requests", json=params)

    async def submit_dispute_protocol(self, **params: Any) -> dict[str, Any]:
        return await self._http.post("/federation/v1/disputes", json=params)

    async def contribute_reputation(self, **params: Any) -> dict[str, Any]:
        return await self._http.post("/federation/v1/reputation/contribute", json=params)

    async def get_agent_reputation(self, agent_id: str) -> dict[str, Any]:
        return await self._http.get(f"/federation/v1/agents/{agent_id}/reputation")
