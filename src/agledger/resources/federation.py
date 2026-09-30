"""Federation peer-facing surface: used by federated AGLedger instances over the wire."""

from __future__ import annotations

from typing import Any, Literal

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import (
    DisputeGrounds,
    DisputeProtocolAction,
    EuAiActDomain,
    FederationSettlementSignal,
    FederationVerdict,
    OperatingMode,
    PeerHandshakeResult,
    RiskClassification,
)


def _handshake_body(
    peer_hub_id: str, peer_url: str, signing_public_key: str, peering_token: str,
) -> dict[str, Any]:
    """The whole ``POST /federation/v1/peer`` body. All four are required and the
    route takes nothing else: the token names the local org the peering binds
    to, so the body names none."""
    return {
        "peerHubId": peer_hub_id,
        "peerUrl": peer_url,
        "signingPublicKey": signing_public_key,
        "peeringToken": peering_token,
    }


def _state_transition_body(
    record_id: str, state: str, type: str, idempotency_key: str,
    schema_ref: dict[str, Any], principal_agent_id: str,
    performer_agent_id: str, operating_mode: OperatingMode,
    co_sign_required: bool | None,
    correlation_id: str | None, project_ref: str | None,
    external_task_id: str | None, platform_ref: str | None,
    risk_classification: RiskClassification | None,
    eu_ai_act_domain: EuAiActDomain | None,
    parent_record_id: str | None, root_record_id: str | None,
    chain_depth: int | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "recordId": record_id,
        "state": state,
        "type": type,
        "idempotencyKey": idempotency_key,
        "schemaRef": schema_ref,
        "principalAgentId": principal_agent_id,
        "performerAgentId": performer_agent_id,
        "operatingMode": operating_mode,
    }
    if co_sign_required is not None: body["coSignRequired"] = co_sign_required
    if correlation_id is not None: body["correlationId"] = correlation_id
    if project_ref is not None: body["projectRef"] = project_ref
    if external_task_id is not None: body["externalTaskId"] = external_task_id
    if platform_ref is not None: body["platformRef"] = platform_ref
    if risk_classification is not None: body["riskClassification"] = risk_classification
    if eu_ai_act_domain is not None: body["euAiActDomain"] = eu_ai_act_domain
    if parent_record_id is not None: body["parentRecordId"] = parent_record_id
    if root_record_id is not None: body["rootRecordId"] = root_record_id
    if chain_depth is not None: body["chainDepth"] = chain_depth
    return body


def _signal_body(
    record_id: str, recommendation: FederationSettlementSignal, outcome_hash: str,
    valid_until: str, idempotency_key: str, outcome: FederationVerdict | None,
    schema_ref: dict[str, Any], reason_code: str | None,
    failing_rule_ids: list[str] | None, counter_signature: str | None,
) -> dict[str, Any]:
    """``outcome``, ``reasonCode`` and ``failingRuleIds`` are required and
    nullable, so they go out as JSON null rather than being left off."""
    body: dict[str, Any] = {
        "recordId": record_id,
        "recommendation": recommendation,
        "outcome": outcome,
        "outcomeHash": outcome_hash,
        "validUntil": valid_until,
        "idempotencyKey": idempotency_key,
        "schemaRef": schema_ref,
        "reasonCode": reason_code,
        "failingRuleIds": failing_rule_ids,
    }
    if counter_signature is not None: body["counterSignature"] = counter_signature
    return body


def _co_sign_body(
    record_id: str, recommendation: FederationSettlementSignal, outcome_hash: str,
    state: str, performer_hub_id: str, valid_until: str, idempotency_key: str,
    schema_ref: dict[str, Any], outcome: FederationVerdict | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "recordId": record_id,
        "recommendation": recommendation,
        "outcomeHash": outcome_hash,
        "state": state,
        "performerHubId": performer_hub_id,
        "validUntil": valid_until,
        "idempotencyKey": idempotency_key,
        "schemaRef": schema_ref,
    }
    if outcome is not None: body["outcome"] = outcome
    return body


def _dispute_body(
    record_id: str, action: DisputeProtocolAction, dispute_id: str,
    dispute_status: str, idempotency_key: str, schema_ref: dict[str, Any],
    grounds: DisputeGrounds | None, outcome: str | None,
    initiated_by_role: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "recordId": record_id,
        "action": action,
        "disputeId": dispute_id,
        "disputeStatus": dispute_status,
        "idempotencyKey": idempotency_key,
        "schemaRef": schema_ref,
    }
    if grounds is not None: body["grounds"] = grounds
    if outcome is not None: body["outcome"] = outcome
    if initiated_by_role is not None: body["initiatedByRole"] = initiated_by_role
    return body


class FederationResource:
    """Federation peer-facing operations (bearer-token auth)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def peer_handshake(
        self,
        *,
        peer_hub_id: str,
        peer_url: str,
        signing_public_key: str,
        peering_token: str,
    ) -> PeerHandshakeResult:
        """Establish a peer relationship with another Server.

        The four fields are the whole body: the route is
        ``additionalProperties: false``, so anything else is a 400. It is
        unauthenticated and admits on ``peering_token`` alone, a single-use
        secret the RECEIVING Server's operator mints at
        ``federation_admin.create_peering_token()`` and shares out of band. Send
        it over the peer's real URL and nothing else: this is the one federation
        call that carries no signature to fall back on.

        The token is checked first: an unknown, consumed or expired one is a
        401 before anything else about the request is looked at. The token was
        minted for one hub id and one local org; ``peer_hub_id`` must be that
        hub id (your own ``instanceId``), else 422 with the token left
        unconsumed. The org comes from the token.

        ``signing_public_key`` is your own Ed25519 signing key, SPKI-DER
        base64, which this Server will verify your later messages against. Your
        own is served at ``federation_admin.get_instance()``.

        The ``peer_hub_id`` on the result is the identifier every
        ``/federation/v1/admin/peers/{peerHubId}`` path takes; ``peer_id`` is
        the receiver-local row id and resolves nowhere.
        """
        return PeerHandshakeResult.model_validate(
            self._http.post("/federation/v1/peer", json=_handshake_body(
                peer_hub_id, peer_url, signing_public_key, peering_token,
            ))
        )

    def submit_state_transition(
        self,
        *,
        record_id: str,
        state: str,
        type: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        principal_agent_id: str,
        performer_agent_id: str,
        operating_mode: OperatingMode,
        co_sign_required: bool | None = None,
        correlation_id: str | None = None,
        project_ref: str | None = None,
        external_task_id: str | None = None,
        platform_ref: str | None = None,
        risk_classification: RiskClassification | None = None,
        eu_ai_act_domain: EuAiActDomain | None = None,
        parent_record_id: str | None = None,
        root_record_id: str | None = None,
        chain_depth: int | None = None,
    ) -> dict[str, Any]:
        """Submit a cross-boundary state transition to a peer.

        ``schema_ref`` (``{"publisher", "type", "version", "manifestDigest"}``),
        both agent ids and ``operating_mode`` are required: a record with no
        separate performer sends the principal as ``performer_agent_id``. The
        body is ``additionalProperties: false``."""
        body = _state_transition_body(
            record_id, state, type, idempotency_key, schema_ref, principal_agent_id,
            performer_agent_id, operating_mode, co_sign_required, correlation_id,
            project_ref, external_task_id, platform_ref, risk_classification,
            eu_ai_act_domain, parent_record_id, root_record_id, chain_depth,
        )
        return self._http.post("/federation/v1/state-transitions", json=body)

    def relay_signal(
        self,
        *,
        record_id: str,
        recommendation: FederationSettlementSignal,
        outcome: FederationVerdict | None,
        outcome_hash: str,
        valid_until: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        reason_code: str | None,
        failing_rule_ids: list[str] | None,
        counter_signature: str | None = None,
    ) -> dict[str, Any]:
        """Relay a Settlement Signal (SETTLE / HOLD / RELEASE) to a counterparty peer.

        A receiver that registered the record's type with
        ``coSignRequired: true`` refuses a signal without ``counter_signature``
        with 422, ``retryable: false``, reason ``co_sign_required``.

        ``outcome``, ``reason_code`` and ``failing_rule_ids`` are required and
        nullable: pass None for a RELEASE that binds no verdict, a signal with
        no classifiable cause, or a terminal no rule failed, and each goes out
        as JSON null. Free text does not cross the federation wire, so the body
        takes no ``reason``: ``reason_code`` and ``failing_rule_ids`` carry the
        cause."""
        body = _signal_body(
            record_id, recommendation, outcome_hash, valid_until, idempotency_key,
            outcome, schema_ref, reason_code, failing_rule_ids, counter_signature,
        )
        return self._http.post("/federation/v1/signals", json=body)

    def submit_co_sign_request(
        self,
        *,
        record_id: str,
        recommendation: FederationSettlementSignal,
        outcome_hash: str,
        state: str,
        performer_hub_id: str,
        valid_until: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        outcome: FederationVerdict | None = None,
    ) -> dict[str, Any]:
        """Ask a counterparty Server to counter-sign a Settlement Signal over its
        canonical co-sign payload. ``state`` is the terminal RecordStatus the
        firing Server asserts, which the receiver checks its own record sits at.
        ``schema_ref`` is required."""
        return self._http.post(
            "/federation/v1/co-sign-requests",
            json=_co_sign_body(
                record_id, recommendation, outcome_hash, state, performer_hub_id,
                valid_until, idempotency_key, schema_ref, outcome,
            ),
        )

    def submit_dispute_protocol(
        self,
        *,
        record_id: str,
        action: DisputeProtocolAction,
        dispute_id: str,
        dispute_status: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        grounds: DisputeGrounds | None = None,
        outcome: Literal["OVERTURNED", "UPHELD", "SPLIT"] | None = None,
        initiated_by_role: str | None = None,
    ) -> dict[str, Any]:
        """Send a dispute-protocol message to a federated counterparty.

        ``action`` is ``opened``, ``resolved`` or ``withdrawn``, and
        ``dispute_status`` the status after it (``EVIDENCE_WINDOW`` on opened,
        ``RESOLVED`` on resolved, ``WITHDRAWN`` on withdrawn). ``schema_ref`` is
        required. There is no tier: the body is ``additionalProperties: false``,
        so a ``tier`` is a 400."""
        return self._http.post(
            "/federation/v1/disputes",
            json=_dispute_body(
                record_id, action, dispute_id, dispute_status, idempotency_key,
                schema_ref, grounds, outcome, initiated_by_role,
            ),
        )


class AsyncFederationResource:
    """Async federation peer-facing operations."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def peer_handshake(
        self,
        *,
        peer_hub_id: str,
        peer_url: str,
        signing_public_key: str,
        peering_token: str,
    ) -> PeerHandshakeResult:
        """Establish a peer relationship with another Server. The four fields are
        the whole body, and the route admits on ``peering_token`` alone: a bad
        token is a 401, a ``peer_hub_id`` other than the one it was minted for a
        422. See :meth:`FederationResource.peer_handshake`."""
        return PeerHandshakeResult.model_validate(
            await self._http.post("/federation/v1/peer", json=_handshake_body(
                peer_hub_id, peer_url, signing_public_key, peering_token,
            ))
        )

    async def submit_state_transition(
        self,
        *,
        record_id: str,
        state: str,
        type: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        principal_agent_id: str,
        performer_agent_id: str,
        operating_mode: OperatingMode,
        co_sign_required: bool | None = None,
        correlation_id: str | None = None,
        project_ref: str | None = None,
        external_task_id: str | None = None,
        platform_ref: str | None = None,
        risk_classification: RiskClassification | None = None,
        eu_ai_act_domain: EuAiActDomain | None = None,
        parent_record_id: str | None = None,
        root_record_id: str | None = None,
        chain_depth: int | None = None,
    ) -> dict[str, Any]:
        body = _state_transition_body(
            record_id, state, type, idempotency_key, schema_ref, principal_agent_id,
            performer_agent_id, operating_mode, co_sign_required, correlation_id,
            project_ref, external_task_id, platform_ref, risk_classification,
            eu_ai_act_domain, parent_record_id, root_record_id, chain_depth,
        )
        return await self._http.post("/federation/v1/state-transitions", json=body)

    async def relay_signal(
        self,
        *,
        record_id: str,
        recommendation: FederationSettlementSignal,
        outcome: FederationVerdict | None,
        outcome_hash: str,
        valid_until: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        reason_code: str | None,
        failing_rule_ids: list[str] | None,
        counter_signature: str | None = None,
    ) -> dict[str, Any]:
        body = _signal_body(
            record_id, recommendation, outcome_hash, valid_until, idempotency_key,
            outcome, schema_ref, reason_code, failing_rule_ids, counter_signature,
        )
        return await self._http.post("/federation/v1/signals", json=body)

    async def submit_co_sign_request(
        self,
        *,
        record_id: str,
        recommendation: FederationSettlementSignal,
        outcome_hash: str,
        state: str,
        performer_hub_id: str,
        valid_until: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        outcome: FederationVerdict | None = None,
    ) -> dict[str, Any]:
        """See :meth:`FederationResource.submit_co_sign_request`."""
        return await self._http.post(
            "/federation/v1/co-sign-requests",
            json=_co_sign_body(
                record_id, recommendation, outcome_hash, state, performer_hub_id,
                valid_until, idempotency_key, schema_ref, outcome,
            ),
        )

    async def submit_dispute_protocol(
        self,
        *,
        record_id: str,
        action: DisputeProtocolAction,
        dispute_id: str,
        dispute_status: str,
        idempotency_key: str,
        schema_ref: dict[str, Any],
        grounds: DisputeGrounds | None = None,
        outcome: Literal["OVERTURNED", "UPHELD", "SPLIT"] | None = None,
        initiated_by_role: str | None = None,
    ) -> dict[str, Any]:
        """See :meth:`FederationResource.submit_dispute_protocol`."""
        return await self._http.post(
            "/federation/v1/disputes",
            json=_dispute_body(
                record_id, action, dispute_id, dispute_status, idempotency_key,
                schema_ref, grounds, outcome, initiated_by_role,
            ),
        )
