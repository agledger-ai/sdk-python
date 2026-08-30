"""
AGLedger SDK: Type definitions.
Mirrors the TypeScript SDK types. All models are Pydantic v2.
"""

from __future__ import annotations

from typing import Any, ClassVar, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class NextStep(BaseModel):
    """A suggested next API call: guides agents through the lifecycle."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    action: str
    """What to do next."""
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    """HTTP method."""
    href: str
    """Relative URL template (substitute {id} placeholders)."""
    description: str
    """Why this step matters."""
    after_this: str | None = Field(None, alias="afterThis")
    """Action name expected to follow this one, or None at a terminal step."""
    workflow_label: str | None = Field(None, alias="workflowLabel")
    """Human-readable label for the workflow this step belongs to."""
    workflow_step: int | None = Field(None, alias="workflowStep")
    """1-indexed position of this step within its workflow."""
    workflow_total: int | None = Field(None, alias="workflowTotal")
    """Total number of steps in this step's workflow."""


RecordType = (
    Literal[
        "notarize-generic-v1",
        "principal-gate-generic-v1",
        "terminal-outcome-v1",
        "delegated-workflow-v1",
    ]
    | str
)
"""Record Type identifier. The API ships NO built-in contract types: your org
owns its entire type namespace and you register your own via POST /v1/schemas.
Every new org is auto-seeded with the four example contracts named above (use,
edit, rename, or delete them); listed only as a discovery hint. Typed as an open
``Literal | str`` since types are arbitrary and an org may have deleted the
samples. The canonical set for an org is GET /v1/schemas."""


RecordStatus = Literal[
    "CREATED",
    "PROPOSED",
    "ACTIVE",
    "PROCESSING",
    "REVISION_REQUESTED",
    "DISPUTED",
    "FULFILLED",
    "FAILED",
    "REMEDIATED",
    "EXPIRED",
    "PENDING_ARBITRATION",
    "CANCELLED",
    "REJECTED",
    "RECORDED",
]

RecordTransitionAction = Literal["register", "propose", "activate", "cancel"]

OperatingMode = Literal["cleartext", "encrypted"]
GateMode = Literal["auto", "principal"]
VaultCheckpointChain = Literal["record", "schema", "admin"] | str
"""Which chain a vault checkpoint anchors (API v1.3.4). All three are the
same signed-checkpoint construction over a different chain; only ``record`` is
keyed by a real record id. Typed as the open ``Literal | str`` union so a
server-added chain kind is not a break."""
Verdict = Literal["accept", "reject"] | str
"""The principal verdict. Known values: ``accept``, ``reject``. Typed as the
open ``Literal | str`` union for forward compatibility: new API versions
may add verdicts; code generic over ``Verdict`` then composes through
``submit_verdict`` without an extra narrowing step."""
EuAiActRiskTier = Literal["unacceptable", "high", "limited", "minimal"]
"""EU AI Act risk tier (Article 5 prohibited -> Annex III high -> Article 50
limited -> minimal). An AI impact assessment always asserts one of these."""
RiskClassification = Literal["unacceptable", "high", "limited", "minimal", "unclassified"]
"""Record-column risk classification: the canonical tiers plus the notary
sentinel ``unclassified`` (the create-time default, nothing asserted yet)."""
EuAiActDomain = Literal[
    "biometrics",
    "critical_infrastructure",
    "education",
    "employment",
    "essential_services",
    "law_enforcement",
    "migration",
    "justice",
]
"""EU AI Act Annex III high-risk domains. Shared by a Record's ``euAiActDomain``
and an AI impact assessment's ``domain`` so the two surfaces speak one taxonomy."""
ConstraintInheritanceMode = Literal["none", "advisory", "enforced"]

AcceptanceStatus = Literal["PROPOSED", "ACCEPTED", "REJECTED", "COUNTER_PROPOSED"]


class SignedStatement(BaseModel):
    """Inline tamper-evident head of a Record's audit chain (the Signed Statement at chainPosition)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    chain_position: int = Field(alias="chainPosition")
    """Per-Record monotonic chain position of the head Signed Statement (1-indexed)."""
    leaf_hash: str = Field(alias="leafHash")
    """Hex sha256 over the canonical COSE_Sign1 envelope bytes."""
    previous_hash: str | None = Field(None, alias="previousHash")
    """leafHash of the prior entry (null only on chainPosition === 1)."""
    signing_key_id: str | None = Field(None, alias="signingKeyId")
    """Vault signing key id: resolves to a public key at GET /v1/verification-keys."""
    signed_at: str | None = Field(None, alias="signedAt")
    """Signed instant of the head Signed Statement: the CWT ``iat`` claim (second
    precision) sealed in the COSE_Sign1 protected header. THE authoritative
    timestamp for time-anchored contracts (wait windows, notice clocks); the Record's
    ``created_at`` is a millisecond DB clock that only approximates it. Null if the
    envelope fails to decode."""
    signed_checkpoint_ref: str | None = Field(None, alias="signedCheckpointRef")
    """Most recent signed checkpoint covering this position, or null."""
    url: str
    """Relative URL to the COSE_Sign1 attestation stream for this Record."""


class RecordReadCompletion(BaseModel):
    """SCITT-style inclusion-proof completion record for org-admin cross-party reads."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    leaf_index: int = Field(alias="leafIndex")
    leaf_hash: str = Field(alias="leafHash")
    signed_checkpoint_ref: str | None = Field(None, alias="signedCheckpointRef")


class EntityReference(BaseModel):
    """An external entity reference attached to a Record."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    system: str
    ref_type: str = Field(alias="refType")
    ref_id: str = Field(alias="refId")
    display_name: str | None = Field(None, alias="displayName")
    uri: str | None = None
    attributes: dict[str, Any] | None = None
    created_at: str = Field(alias="createdAt")
    created_by: str = Field(alias="createdBy")


class SettlementSignalSummary(BaseModel):
    """Settlement Signal projected onto a Record: the SETTLE/HOLD/RELEASE
    recommendation bound to the terminal verdict, plus federation delivery state."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    recommendation: Literal["SETTLE", "HOLD", "RELEASE"]
    """The settlement recommendation bound to the terminal verdict."""
    outcome: Literal["accept", "reject"] | None = None
    """Verdict the recommendation binds to (accept ~ SETTLE, reject ~ HOLD), or None."""
    reason_code: str | None = Field(None, alias="reasonCode")
    """Optional machine-readable reason code, or None."""
    failing_rule_ids: list[str] | None = Field(None, alias="failingRuleIds")
    """Rule IDs that failed and drove the recommendation, or None."""
    reason: str | None = None
    """Optional human-readable reason, or None."""
    delivered_to_peers: list[str] = Field(alias="deliveredToPeers")
    """Peer Servers the signal was successfully delivered to."""
    pending_to_peers: list[str] = Field(alias="pendingToPeers")
    """Peer Servers the signal is still pending delivery to."""
    failed_to_peers: list[str] = Field(alias="failedToPeers")
    """Peer Servers the signal failed to deliver to."""
    idempotency_key: str | None = Field(alias="idempotencyKey")
    """Idempotency key for the signal, or None."""
    co_sign_status: Literal["not_required", "pending", "succeeded", "failed"] | None = Field(
        None, alias="coSignStatus"
    )
    """Co-signature state of the signal, or None."""
    counter_signature: str | None = Field(None, alias="counterSignature")
    """Hex Ed25519 counter-signature on the signal, or None."""
    valid_until: str | None = Field(None, alias="validUntil")
    """ISO 8601 expiry of the signal, or None."""
    outcome_hash: str | None = Field(None, alias="outcomeHash")
    """Hex sha256 binding the signal to the terminal outcome, or None."""
    source: Literal["outbound", "inbound", "local"] | None = None
    """Origin of the signal relative to this Server."""
    received_from: dict[str, Any] | None = Field(None, alias="receivedFrom")
    """Peer the signal was received from (inbound only), or None."""


class RecordIntegrity(BaseModel):
    """Tamper-evidence result attached to a Record read with ``integrity=True``."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    verified: bool
    """True iff the audit chain re-verifies AND the served row matches what the chain asserts.

    False ⇒ this body may not match the signed evidence; read the audit-export as the source of truth.
    """
    integrity_level: Literal[
        "hash_chain_only", "hash_chain_partial_signatures", "hash_chain_and_signatures", "invalid"
    ] = Field(alias="integrityLevel")
    """Strength of the chain verification: whether every entry was signed or only hash-linked."""
    reason: str | None = None
    """Failure class when ``verified`` is False (e.g. ``record_projection_drift``); None when verified."""
    entries: int
    """Number of audit-chain entries verified."""
    projection_checked: bool = Field(alias="projectionChecked")
    """True when the row-vs-chain projection cross-check ran."""
    drift_fields: list[str] = Field(default_factory=list, alias="driftFields")
    """Record fields that diverged from the chain when ``reason`` is ``record_projection_drift``."""


class RecordRow(BaseModel):
    """A Record: a registered commitment between a principal and a performer."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    """Unique Record ID (UUID)."""
    org_id: str = Field(alias="orgId")
    """Org that owns this Record."""
    performer_agent_id: str | None = Field(None, alias="performerAgentId")
    """Agent assigned as performer, or null if unassigned."""
    principal_agent_id: str | None = Field(None, alias="principalAgentId")
    """Agent ID of the principal."""
    created_by_key_id: str | None = Field(None, alias="createdByKeyId")
    """API key that created this Record."""
    type: str
    """Record Type: a contract type registered for the org (GET /v1/schemas)."""
    contract_version: str | None = Field(None, alias="contractVersion")
    """Type schema version."""
    platform: str
    """Platform where this Record operates."""
    platform_ref: str | None = Field(None, alias="platformRef")
    """External reference ID on the platform."""
    status: RecordStatus | str
    """Current lifecycle status."""
    criteria: dict[str, Any]
    """Acceptance criteria: what the performer must deliver."""
    tolerance: dict[str, Any] | None = None
    """Tolerance bands for numeric criteria."""
    deadline: str | None = None
    """ISO 8601 deadline for completion."""
    commission_pct: float | None = Field(None, alias="commissionPct")
    """Commission percentage for the performing agent."""
    commission_amount: float | None = Field(None, alias="commissionAmount")
    """Computed commission amount."""
    operating_mode: OperatingMode | str | None = Field(None, alias="operatingMode")
    """Operating mode: cleartext (default) or encrypted."""
    gate_mode: GateMode | str | None = Field(None, alias="gateMode")
    """Gate mode: auto (auto-settles against the principal's pre-configured predicates) or principal (engine advisory pass, then the principal renders accept/reject). Either way the verdict is the principal's; AGLedger holds the signed decision and never renders it."""
    risk_classification: RiskClassification | str | None = Field(None, alias="riskClassification")
    """EU AI Act risk classification."""
    eu_ai_act_domain: str | None = Field(None, alias="euAiActDomain")
    """EU AI Act domain."""
    human_oversight: dict[str, Any] | None = Field(None, alias="humanOversight")
    """Human oversight configuration for EU AI Act compliance."""
    acceptance_status: AcceptanceStatus | str | None = Field(None, alias="acceptanceStatus")
    """Performer's response to a proposed Record."""
    acceptance_responded_at: str | None = Field(None, alias="acceptanceRespondedAt")
    """ISO 8601 timestamp when performer responded to proposal."""
    project_ref: str | None = Field(None, alias="projectRef")
    """Project grouping reference for related Records."""
    parent_record_id: str | None = Field(None, alias="parentRecordId")
    """Parent Record ID in a delegation chain."""
    root_record_id: str | None = Field(None, alias="rootRecordId")
    """Root Record ID at the top of the delegation chain."""
    chain_depth: int | None = Field(None, alias="chainDepth")
    """Depth in the delegation chain (0 = root)."""
    child_record_ids: list[str] | None = Field(None, alias="childRecordIds")
    """IDs of child Records in the delegation chain, OLDEST first by creation
    time. Do not read ``[0]`` as the latest child: for the newest child of a
    type, use ``records.search(parent_record_id=..., type=...)``, which returns
    newest first."""
    supersedes_record_id: str | None = Field(None, alias="supersedesRecordId")
    """The earlier Record this one replaces, asserted by the writer at create and
    immutable thereafter. Orthogonal to delegation: ``parent_record_id`` says
    what this Record is part of, this says which earlier Record it makes stale.
    It sits inside the create-time signature, so an offline verifier
    reconstructs the same lineage the API reports."""
    superseded_by_count: int | None = Field(None, alias="supersededByCount")
    """How many later Records name this one as their ``supersedesRecordId``. 0
    means this Record is current. Greater than 1 is a FORK: two writers
    superseded the same Record independently, so there are that many current
    heads and no single answer."""
    parent_principal_org_matches_performer: bool | None = Field(
        None, alias="parentPrincipalOrgMatchesPerformer"
    )
    """Delegation-shell indicator. Informational only."""
    last_transition_reason: str | None = Field(None, alias="lastTransitionReason")
    """Reason provided for the last state transition."""
    last_transition_by: str | None = Field(None, alias="lastTransitionBy")
    """Actor who triggered the last state transition."""
    last_verdict_reason: str | None = Field(None, alias="lastVerdictReason")
    """Reason from the most recent verdict or revision request."""
    last_verdict_at: str | None = Field(None, alias="lastVerdictAt")
    """ISO 8601 timestamp of the most recent verdict."""
    submission_count: int = Field(alias="submissionCount")
    """Number of completion submissions so far."""
    max_submissions: int | None = Field(None, alias="maxSubmissions")
    """Maximum allowed submissions, or None for unlimited."""
    revision_count: int | None = Field(None, alias="revisionCount")
    """Number of revisions consumed."""
    max_revisions: int | None = Field(None, alias="maxRevisions")
    """Maximum revisions allowed."""
    dispute_count: int | None = Field(None, alias="disputeCount")
    """Number of disputes opened against this Record."""
    max_disputes: int | None = Field(None, alias="maxDisputes")
    """Maximum disputes allowed."""
    past_deadline: bool | None = Field(None, alias="pastDeadline")
    """True iff a deadline is set AND has passed."""
    version: int
    """Optimistic concurrency version."""
    created_at: str = Field(alias="createdAt")
    """ISO 8601 creation timestamp."""
    updated_at: str = Field(alias="updatedAt")
    """ISO 8601 last update timestamp."""
    activated_at: str | None = Field(None, alias="activatedAt")
    """ISO 8601 timestamp when activated."""
    fulfilled_at: str | None = Field(None, alias="fulfilledAt")
    """ISO 8601 timestamp when fulfilled."""
    next_actions: list[str] | None = Field(None, alias="nextActions")
    """Valid next actions from current state."""
    valid_transitions: list[str] | None = Field(None, alias="validTransitions")
    """Valid target statuses from current state."""
    completion_hint: dict[str, Any] | None = Field(None, alias="completionHint")
    """Hint for completion evidence fields."""
    advisory_warnings: list[dict[str, Any]] | None = Field(None, alias="advisoryWarnings")
    """Advisory enforcement warnings."""
    publisher: str | None = None
    """Publisher label of the registration this Record binds to. With ``type`` and
    ``contract_version`` it names exactly which schema the Record was judged
    against, which ``type`` alone cannot once two publishers offer the same type.
    Present whether or not ``publisher`` was pinned on create, so a
    single-publisher org reads its one label (usually ``local``).

    ``None`` means the engine never validated this Record against a local
    registration, which leaves exactly one case: federation-received Records,
    where the originator ran the gate against its own registration. Read
    ``None`` as "ask the originator", not as "the schema is missing here".

    Records backfilled through the admin import route are NOT ``None``. Import
    binds the registration it validated against, so a backfilled Record reads
    its publisher label and a ``schema_url`` scoped to it."""
    schema_url: str | None = Field(None, alias="schemaUrl")
    """URL to the Type schema definition. Carries ``?publisher=`` whenever
    ``publisher`` is known, so the link resolves even for a type two publishers
    offer. Follow it verbatim; do not rebuild it from ``type``."""
    verdict_checks: dict[str, Any] | None = Field(None, alias="verdictChecks")
    """Detailed per-rule gate-evaluation results with tolerance bands, or None if the gate has not run."""
    verdict: str | None = Field(None, alias="verdict")
    """Phase 2 gate verdict: accept, reject, or None until the gate evaluation completes."""
    self_principal: bool | None = Field(None, alias="selfPrincipal")
    """True when principal and performer are the same agent (self-principal Record)."""
    constraint_inheritance: ConstraintInheritanceMode | str | None = Field(
        None, alias="constraintInheritance"
    )
    """Constraint inheritance mode from parent."""
    external_task_id: str | None = Field(None, alias="externalTaskId")
    """External task ID from the caller's system."""
    depends_on: list[str] | None = Field(None, alias="dependsOn")
    """Record IDs this Record depends on."""
    enforcement_overrides: dict[str, Any] | None = Field(None, alias="enforcementOverrides")
    """Per-field enforcement overrides."""
    metadata: dict[str, Any] | None = None
    """Arbitrary metadata attached to the Record."""
    category: str | None = None
    """Free-form taxonomy of what kind of artifact this Record represents."""
    outcome: str | None = None
    """Optional free-form outcome (success/failure/denied/partial)."""
    correlation_id: str | None = Field(None, alias="correlationId")
    """Optional grouping ID for related Records."""
    requested_by: str | None = Field(None, alias="requestedBy")
    """Free-form identifier of the human or upstream system that asked for the work."""
    references: list[EntityReference] | None = None
    """External references attached to this Record (present on single-Record fetch only)."""
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    """Suggested next API calls after Record mutations."""
    signed_statement: SignedStatement | None = Field(None, alias="signedStatement")
    """Inline tamper-evident head of this Record's audit chain (the Signed Statement at chainPosition)."""
    record_read: RecordReadCompletion | None = Field(None, alias="recordRead")
    """SCITT-style inclusion-proof completion record for cross-party reads."""
    has_children: bool | None = Field(None, alias="hasChildren")
    """True when this Record has child (delegated) Records."""
    latest_completion_id: str | None = Field(None, alias="latestCompletionId")
    """ID of the most recent Completion submitted against this Record, or None."""
    awaiting_actor: Literal["principal", "performer", "system", "arbitration"] | None = Field(
        None, alias="awaitingActor"
    )
    """Which role the Record is currently awaiting, or None when not blocked."""
    terminal_reason: str | None = Field(None, alias="terminalReason")
    """Terminal-state reason string, or None while non-terminal."""
    expired_at: str | None = Field(None, alias="expiredAt")
    """ISO 8601 timestamp when the Record expired, or None."""
    imported: bool | None = None
    """True iff the Record was imported from an external system."""
    source: str | None = None
    """Free-form identifier of the originating system, or None."""
    has_dispute: bool | None = Field(None, alias="hasDispute")
    """True when an open dispute exists against this Record."""
    dispute_id: str | None = Field(None, alias="disputeId")
    """ID of the open/most-recent dispute, or None."""
    dispute_status: DisputeStatus | str | None = Field(None, alias="disputeStatus")
    """Lifecycle status of the dispute, or None when none."""
    co_sign_required: bool | None = Field(None, alias="coSignRequired")
    """Whether a co-signature is required before settlement, or None when not configured."""
    co_sign_status: Literal["not_required", "pending", "succeeded", "failed"] | None = Field(
        None, alias="coSignStatus"
    )
    """Co-signature state, or None when co-sign is not configured."""
    counter_signature: str | None = Field(None, alias="counterSignature")
    """Hex Ed25519 counter-signature from the most recent successful co-sign, or None."""
    settlement_signal: SettlementSignalSummary | None = Field(None, alias="settlementSignal")
    """Settlement Signal projected onto the Record, or None until a terminal verdict produces one."""
    federation_status: Literal["pending", "delivered", "partial", "failed"] | None = Field(
        None, alias="federationStatus"
    )
    """Federation delivery status for this Record's outbound state, or None when not federated."""
    shared_to_peers: list[str] | None = Field(None, alias="sharedToPeers")
    """Peer Server IDs this Record has been shared to via federation."""
    share: bool | None = None
    """Whether this Record participates in revenue share, or None when not configured."""
    integrity: RecordIntegrity | None = None
    """Tamper-evidence result, present only when read with ``integrity=True``."""


class BulkCreateResultItem(BaseModel):
    """One per-record outcome from POST /v1/records/bulk."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    index: int
    status: Literal["created", "replayed", "error"]
    data: RecordRow | None = None
    error: str | None = None
    problem_type: str | None = Field(None, alias="problemType")
    """RFC 9457 problem URI when the failure carries a narrower one than its
    class, e.g. ``/problems/ambiguous-publisher``. Branch on this rather than on
    the ``error`` prose."""
    context: dict[str, Any] | None = None
    """Structured extras from the failure, matching the singleton error body.
    For ``/problems/ambiguous-publisher`` this carries ``publishers`` (the
    candidate labels) and ``recordType``."""
    recovery_hint: str | None = Field(None, alias="recoveryHint")
    """What to do next about this item, when the failure carries a pointer.
    Mirrors the ``recoveryHint`` a singleton caller gets in the RFC 9457 body.
    For ``/problems/idempotency-key-reuse`` the fix is a fresh
    ``idempotencyKey``: resending the same item unchanged fails identically
    until the key expires."""


class BulkCreateSummary(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    total: int
    succeeded: int
    failed: int


class BulkCreateResult(BaseModel):
    """Response envelope from POST /v1/records/bulk."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    results: list[BulkCreateResultItem] = Field(default_factory=list[BulkCreateResultItem])
    summary: BulkCreateSummary


class CompletionSettlementSignal(BaseModel):
    """The auto-gate's inline settlement decision on a Completion. A
    leaner projection than ``SettlementSignalSummary`` (no federation delivery
    state), carrying just the gate outcome the caller needs at completion time."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    recommendation: Literal["SETTLE", "HOLD", "RELEASE"]
    """The gate decision in GET /v1/records vocabulary: SETTLE, HOLD, or RELEASE."""
    outcome: Literal["accept", "reject"]
    """Engine verdict that drove the recommendation."""
    reason_code: str | None = Field(None, alias="reasonCode")
    """Discriminator code (same as the settlement webhook), e.g. ``AUTO_SETTLE``, or
    ``AUTO_SETTLE_WITHIN_TOLERANCE`` when the gate cleared only via a
    non-zero tolerance band rather than the base criteria threshold. None when not classifiable."""


class Completion(BaseModel):
    """A Completion: structured evidence submitted by a performer."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    """Unique completion ID."""
    record_id: str = Field(alias="recordId")
    """Record this completion is for."""
    agent_id: str = Field(alias="agentId")
    """Agent that submitted the completion."""
    evidence: dict[str, Any]
    """Evidence of completion."""
    evidence_hash: str | None = Field(None, alias="evidenceHash")
    """SHA-256 hash of the evidence payload."""
    structural_validation: str | None = Field(None, alias="structuralValidation")
    """Structural validation result: ACCEPTED, INVALID, or WARNING."""
    warnings: list[Any] | None = None
    """Validation warnings."""
    record_status: RecordStatus | str | None = Field(None, alias="recordStatus")
    """Record status after completion submission."""
    verdict: Verdict | None = None
    """Denormalized gate verdict on the parent Record: ``accept``, ``reject``, or None until the gate evaluates."""
    last_verdict_reason: str | None = Field(None, alias="lastVerdictReason")
    """Reason attached to the most recent verdict, or None."""
    settlement_signal: CompletionSettlementSignal | None = Field(
        None, alias="settlementSignal"
    )
    """The auto-gate's settle/hold/reject decision, surfaced inline so the caller learns the
    outcome at completion time without a follow-up GET. ``structural_validation ==
    'ACCEPTED'`` means only the body parsed; this field carries the gate's decision. None when
    the gate did not render inline (encrypted Records, principal-mode held at PENDING_VERDICT,
    or the inline run was skipped); read ``record_status`` and ``records.get(id)`` in that case."""
    validation_errors: list[Any] | None = Field(None, alias="validationErrors")
    """Schema validation errors, if any."""
    idempotency_key: str | None = Field(None, alias="idempotencyKey")
    """Client-supplied idempotency key."""
    created_at: str = Field(alias="createdAt")
    """ISO 8601 creation timestamp."""
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    """Suggested next API calls after completion submission."""


class GateEvaluationResult(BaseModel):
    """Result of an on-demand gate evaluation (POST /v1/records/{id}/evaluate)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    record_id: str = Field(alias="recordId")
    completions: list[dict[str, Any]] = Field(default_factory=list[dict[str, Any]])
    overall_status: str = Field(alias="overallStatus")
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    """Suggested next API calls after evaluation."""


DisputeStatus = Literal[
    "EVIDENCE_WINDOW", "TIER_2_REVIEW", "ESCALATED",
    "TIER_3_ARBITRATION", "RESOLVED", "WITHDRAWN",
]
"""Lifecycle status of a dispute.

This is the full set the Server serves, and the set every dispute-status filter
validates against. ``OPENED`` and ``TIER_1_REVIEW`` were listed here and exist
nowhere in the API: the three query params that take this type declare a strict
enum, so either value is a guaranteed 400.

Models widen this to ``DisputeStatus | str`` where the value is read off a
response, so a status added by a newer Server parses rather than raising.
"""


class Dispute(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    record_id: str = Field(alias="recordId")
    initiated_by_role: str = Field(alias="initiatedByRole")
    initiated_by_id: str = Field(alias="initiatedById")
    grounds: str
    context: str | None = None
    status: DisputeStatus | str
    current_tier: int = Field(alias="currentTier")
    outcome: str | None = None
    resolution_rationale: str | None = Field(None, alias="resolutionRationale")
    fee_charged_to: str | None = Field(None, alias="feeChargedTo")
    fee_amount: float | None = Field(None, alias="feeAmount")
    fee_currency: str | None = Field(None, alias="feeCurrency")
    evidence_window_closes_at: str | None = Field(None, alias="evidenceWindowClosesAt")
    created_at: str = Field(alias="createdAt")
    resolved_at: str | None = Field(None, alias="resolvedAt")
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    """Suggested next API calls after dispute operations."""


class DisputeEvidence(BaseModel):
    """A single piece of evidence submitted on a dispute."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    dispute_id: str = Field(alias="disputeId")
    evidence_type: str = Field(alias="evidenceType")
    payload: dict[str, Any]
    payload_hash: str = Field(alias="payloadHash")
    """Hex sha256 over the canonical evidence payload."""
    submitted_by_id: str = Field(alias="submittedById")
    submitted_by_role: str = Field(alias="submittedByRole")
    created_at: str = Field(alias="createdAt")


class DisputeResponse(BaseModel):
    """Response envelope from GET /v1/records/{id}/dispute: includes both dispute and evidence."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    dispute: Dispute
    evidence: list[DisputeEvidence] = Field(default_factory=list[DisputeEvidence])


WebhookEventType = (
    Literal[
        # Wildcard: subscribe to every event type
        "*",
        # Record lifecycle
        "record.created",
        "record.recorded",
        "record.registered",
        "record.activated",
        "record.completion_submitted",
        "record.completion_invalid",
        "record.gate_complete",
        # Principal-mode record held at PROCESSING awaiting the principal verdict;
        # payload carries the completionId to verdict against plus the engine/rollup
        # advisory result.
        "record.gate_held",
        "record.fulfilled",
        "record.failed",
        "record.expired",
        "record.cancelled",
        # Agent-to-agent
        "record.proposed",
        "record.proposal_accepted",
        "record.proposal_rejected",
        "record.proposal_counter_proposed",
        "record.delegated",
        "record.revision_requested",
        # Cascading gate
        "cascading.gate.complete",
        # EU AI Act compliance filings
        "record.ai_impact_assessment_filed",
        "record.compliance_attestation_filed",
        # Settlement & disputes
        "signal.emitted",
        "signal.received",
        "record.settled",
        "record.released",
        "dispute.opened",
        "dispute.escalated",
        "dispute.evidence_window_closed",
        "dispute.resolved",
        "dispute.withdrawn",
        # Federation
        "federation.record.state_changed",
        "federation.settlement.signal",
        "federation.dispute",
        # Federation-projected lifecycle (thin federation payload shape, distinct
        # from the local-shape "record.<state>" events)
        "record.federation_activated",
        "record.federation_fulfilled",
        "record.federation_failed",
        "record.federation_remediated",
        "record.federation_recorded",
        "record.federation_cancelled",
        "record.federation_expired",
        "record.federation_proposal_rejected",
        # Entity references
        "record.reference_added",
        "agent.reference_added",
    ]
    | str
)


class Webhook(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    url: str
    event_types: list[str] | None = Field(None, alias="eventTypes")
    record_types: list[str] | None = Field(None, alias="recordTypes")
    """Record-type filter for record-scoped events. ``["*"]`` means all
    record types (wildcard sentinel); any other list means record events are
    delivered ONLY for the listed types (fail-closed). ``None`` = no filter."""
    is_active: bool = Field(alias="isActive")
    is_paused: bool | None = Field(None, alias="isPaused")
    format: str = "standard"
    signing_alg: str | None = Field(None, alias="signingAlg")
    """Delivery signing scheme: ``hmac`` (shared secret) or ``ed25519`` (RFC 9421, vault-key signed).

    Verify ``ed25519`` deliveries with ``verify_rfc9421`` from ``agledger.webhooks``.
    """
    secret: str | None = None
    """Only present on creation/rotation of an ``hmac`` subscription (one-time). Absent for ``ed25519``."""
    secret_grace_active: bool | None = Field(None, alias="secretGraceActive")
    """Whether a secret grace period is active after rotation."""
    secret_grace_expires_at: str | None = Field(None, alias="secretGraceExpiresAt")
    """When the secret grace period expires (ISO 8601), or None."""
    circuit_state: Literal["closed", "open", "half_open"] | None = Field(None, alias="circuitState")
    """Circuit breaker state: closed (healthy), open (stopped), half_open (testing)."""
    consecutive_failures: int | None = Field(None, alias="consecutiveFailures")
    """Number of consecutive delivery failures."""
    last_successful_at: str | None = Field(None, alias="lastSuccessfulAt")
    """Last successful delivery timestamp (ISO 8601), or None."""
    last_failure_at: str | None = Field(None, alias="lastFailureAt")
    """Last failed delivery timestamp (ISO 8601), or None."""
    created_at: str = Field(alias="createdAt")
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    """Suggested next API calls after webhook creation."""


class VerdictResult(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    record_id: str = Field(alias="recordId")
    completion_id: str = Field(alias="completionId")
    verdict: str
    recommendation: str
    record_status: RecordStatus | str | None = Field(None, alias="recordStatus")
    """Record status after the verdict settled: FULFILLED (accept) or FAILED (reject),
    same vocabulary as the Record GET. Surfaced inline so the caller learns
    where the Record landed without a follow-up fetch."""
    reporter_type: str = Field(alias="reporterType")
    reported_at: str = Field(alias="reportedAt")
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    """Suggested next API calls after submitting the verdict."""


class VerdictStatistics(BaseModel):
    """Own verdict-distribution counters from /v1/records/me/verdict-statistics, decomposed by the
    calling agent's structural role on each counterparty pair (asPrincipal / asPerformer)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    agent_id: str = Field(alias="agentId")
    as_principal: dict[str, Any] = Field(default_factory=dict, alias="asPrincipal")
    as_performer: dict[str, Any] = Field(default_factory=dict, alias="asPerformer")


class ComplianceRecord(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    record_id: str = Field(alias="recordId")
    org_id: str = Field(alias="orgId")
    record_type: str = Field(alias="recordType")
    attestation: dict[str, Any]
    attested_by: str = Field(alias="attestedBy")
    attested_at: str = Field(alias="attestedAt")
    created_at: str = Field(alias="createdAt")


class AuditActor(BaseModel):
    """Actor envelope embedded in canonical audit payloads."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    actor_key_id: str | None = None
    actor_role: str | None = None
    actor_owner_id: str | None = None


class AuditExportEntry(BaseModel):
    """Per-record audit-vault entry as it lands on the wire.

    The engine emits ``chainPosition`` + ``createdAt`` (v0.25.x and later);
    ``position`` + ``timestamp`` are the pre-v0.25 names, kept for backward
    compatibility with old exports. Either side may be absent on a given wire,
    so both are typed optional: consumers should prefer the canonical names
    and fall back to the legacy ones."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    chain_position: int | None = Field(None, alias="chainPosition")
    """Per-record monotonic chain position (1-indexed). Canonical field on current exports."""
    position: int | None = None
    """Pre-v0.25 alias for ``chain_position``: kept so old exports still parse."""
    created_at: str | None = Field(None, alias="createdAt")
    """Canonical entry timestamp (engine v0.25+)."""
    timestamp: str | None = None
    """Pre-v0.25 alias for ``created_at``."""
    record_id: str | None = Field(None, alias="recordId")
    actor_id: str | None = Field(None, alias="actorId")
    actor_role: str | None = Field(None, alias="actorRole")
    actor_owner_id: str | None = Field(None, alias="actorOwnerId")
    """Owner id of the API key: org id (admin), agent id (agent), or platform sentinel."""
    actor_display_name: str | None = Field(None, alias="actorDisplayName")
    """Human-readable label for the actor owner. Display PROJECTION: NOT signature-covered."""
    actor_owner_type: str | None = Field(None, alias="actorOwnerType")
    """Owner table discriminator (``agent`` / ``org`` / ``platform``); pairs with ``actor_owner_id``."""
    actor_oidc_iss: str | None = Field(None, alias="actorOidcIss")
    actor_oidc_sub: str | None = Field(None, alias="actorOidcSub")
    actor_oidc_synthesized: bool | None = Field(None, alias="actorOidcSynthesized")
    entry_type: str = Field(alias="entryType")
    human_readable_label: str | None = Field(None, alias="humanReadableLabel")
    """Auditor-readable label for ``entry_type`` (e.g. RECORD_STATE_CHANGE → "Record state
    transitioned"). Display PROJECTION: NOT signature-covered; the canonical machine-readable name
    stays in ``entry_type``. Replaced the pre-launch ``description`` placeholder (engine v0.26.x+)."""
    payload: dict[str, Any]
    actor: AuditActor | None = None
    """Optional ``_actor`` envelope surfaced from the canonical payload."""
    evidence: dict[str, Any] | None = None
    """Completion evidence body, present only when the export was fetched with
    ``evidence=True`` AND this is a COMPLETION_SUBMITTED entry. UNSIGNED
    projection: the chain binds it by hash only: recompute SHA-256 over the RFC 8785
    (JCS) canonicalization of this object and compare against ``payload.evidenceHash``.
    Encrypted-mode records inline the stored ciphertext envelope."""
    integrity: dict[str, Any]


class AuditChainIntegrityDetail(BaseModel):
    """Localizes a chain-integrity failure. Null on a clean chain."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    broken_at_position: int | None = Field(None, alias="brokenAtPosition")
    broken_at_entry_id: str | None = Field(None, alias="brokenAtEntryId")
    expected_previous_hash: str | None = Field(None, alias="expectedPreviousHash")
    actual_previous_hash: str | None = Field(None, alias="actualPreviousHash")
    expected_payload_hash: str | None = Field(None, alias="expectedPayloadHash")
    actual_payload_hash: str | None = Field(None, alias="actualPayloadHash")
    failure: (
        Literal[
            "previous_hash_mismatch",
            "payload_hash_mismatch",
            "checkpoint_anchor_mismatch",
            "audit_vault_truncated",
            "payload_drift",
            "oidc_actor_drift",
            "cert_actor_drift",
            "cert_expired",
            "cert_missing",
            "agent_signature_invalid",
            # Per-entry signature failures. These reached this field with the
            # v1.3.2 fail-closed verification work and were only ever added to
            # chain_integrity_reason, so a real export carrying one of them
            # failed to parse here rather than typing loosely.
            "signature_invalid",
            "signing_key_unknown",
            "signing_key_drift",
            # Signed under a COSE algorithm this engine build cannot verify.
            # Not a tamper signal: check minVerifierVersion on the key.
            "unsupported_algorithm",
        ]
        | None
    ) = None


class AuditSignatureCoverage(BaseModel):
    """Per-entry signature coverage on the export envelope."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    signed: int
    unsigned: int
    total: int


class AuditExportMetadata(BaseModel):
    """Metadata envelope on a record audit export: mirrors TS RecordAuditExport.exportMetadata."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    record_id: str = Field(alias="recordId")
    org_id: str | None = Field(None, alias="orgId")
    type: str
    """Record Type identifier: a contract type registered for the org."""
    operating_mode: Literal["cleartext", "encrypted"] | None = Field(None, alias="operatingMode")
    export_date: str = Field(alias="exportDate")
    total_entries: int = Field(alias="totalEntries")
    expected_entries: int | None = Field(None, alias="expectedEntries")
    chain_integrity: bool = Field(alias="chainIntegrity")
    chain_integrity_reason: (
        Literal[
            "chain_broken_at",
            "audit_vault_row_missing_for_checkpoint",
            "checkpoint_hash_mismatch",
            "payload_drift",
            "oidc_actor_drift",
            "cert_actor_drift",
            "cert_expired",
            "cert_missing",
            "agent_signature_invalid",
            # API v1.3.2: vault fails closed on per-entry signature
            # verification: signature did not verify / signing key unresolvable /
            # denormalized signing_key_id column drifted from the signed kid.
            "signature_invalid",
            "signing_key_unknown",
            "signing_key_drift",
            # Signed under a COSE algorithm this engine build cannot verify.
            # Not a tamper signal: check minVerifierVersion on the key.
            "unsupported_algorithm",
        ]
        | None
    ) = Field(None, alias="chainIntegrityReason")
    chain_integrity_detail: AuditChainIntegrityDetail | None = Field(None, alias="chainIntegrityDetail")
    signature_coverage: AuditSignatureCoverage | None = Field(None, alias="signatureCoverage")
    integrity_level: (
        Literal[
            "hash_chain_only",
            "hash_chain_partial_signatures",
            "hash_chain_and_signatures",
            "invalid",
        ]
        | None
    ) = Field(None, alias="integrityLevel")
    export_format_version: str = Field(alias="exportFormatVersion")
    """`2.0` since the COSE_Sign1 cutover."""
    canonicalization: str
    """`RFC8949-CDE` since 2.0: deterministic CBOR per RFC 8949 §4.2.1."""
    signing_public_key: str | None = Field(None, alias="signingPublicKey")
    signing_public_keys: dict[str, str] | None = Field(None, alias="signingPublicKeys")


class VaultCheckpoint(BaseModel):
    """A row from GET /v1/audit-vault/checkpoints: signed Merkle anchor."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    #: The uuid this checkpoint is keyed to. Read ``chain`` before treating it
    #: as a record id: only ``chain == "record"`` rows point at a real record.
    #: On ``"schema"`` and ``"admin"`` it is a derived key that resolves to no
    #: record, and fetching it returns 404 by design.
    record_id: str = Field(alias="recordId")
    #: Which chain this row anchors (API v1.3.4). ``record`` is the
    #: per-record chain, ``schema`` an org's schema-registration chain
    #: (record-less), ``admin`` the platform-ops chain. All three are the same
    #: signed-checkpoint construction. None on a pre-1.3.4 server.
    chain: VaultCheckpointChain | None = None
    chain_position: int = Field(alias="chainPosition")
    payload_hash: str = Field(alias="payloadHash")
    cose_sign1: str = Field(alias="coseSign1")
    signing_key_id: str | None = Field(None, alias="signingKeyId")
    created_at: str = Field(alias="createdAt")


class RecordAuditExport(BaseModel):
    """Audit export envelope returned by GET /v1/records/{id}/audit-export."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    export_metadata: AuditExportMetadata = Field(alias="exportMetadata")
    entries: list[AuditExportEntry] = Field(default_factory=list[AuditExportEntry])


class AuditStreamResult(BaseModel):
    """One page of ``GET /v1/siem/stream``."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    events: list[dict[str, Any]] = Field(default_factory=list[dict[str, Any]])
    cursor: str | None = None
    """Resume position after the last row on this page, from the
    ``X-AGLedger-Stream-Cursor`` header, as ``<RFC 3339 instant>_<uuid>``. Send
    it back verbatim as ``cursor=`` to get the next page. ``None`` when the page
    is empty. Never split it: the row id half is what addresses a position
    inside a group of rows sharing one ``created_at``, and feeding the instant
    half back as ``since`` skips every other row in that group."""
    has_more: bool = Field(False, alias="hasMore")
    """Whether this page produced rows. On a cursor walk that is the only honest
    local signal: a short page is not the end of the stream (the Server holds
    rows back while a transaction that stamped them is still open), so page size
    says nothing. A zero-row page means this poll is exhausted; read
    ``holdback_seconds`` before concluding nothing has happened."""
    holdback_seconds: int | None = Field(None, alias="holdbackSeconds")
    """Whole seconds by which this page stops short of now, from the
    ``X-AGLedger-Stream-Holdback-Seconds`` header. ``0`` means the page runs up
    to the present. A large value means an empty page is not evidence that
    nothing has happened: keep the same cursor and keep polling. ``None`` when
    the header is absent."""


class OrgReadsCheckpoint(BaseModel):
    """Org-admin reads checkpoint (SCITT-style signed tree head).

    Wire fields per ``GET /v1/audit/org-reads/checkpoints``: the timestamp
    is ``checkpointAt`` (not ``createdAt``) and the signed envelope is
    ``coseSign1Base64`` (not ``sthBytes``/``signature``)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    org_id: str = Field(alias="orgId")
    tree_size: int = Field(alias="treeSize")
    root_hash: str = Field(alias="rootHash")
    checkpoint_at: str = Field(alias="checkpointAt")
    log_id: str | None = Field(None, alias="logId")
    cose_sign1_base64: str | None = Field(None, alias="coseSign1Base64")
    """Base64 of the canonical COSE_Sign1 (RFC 9052) envelope over the STH."""
    signing_key_id: str | None = Field(None, alias="signingKeyId")
    witness_signature: str | None = Field(None, alias="witnessSignature")
    witness_key_id: str | None = Field(None, alias="witnessKeyId")
    witness_cosigned_at: str | None = Field(None, alias="witnessCosignedAt")


class OrgReadsInclusionProof(BaseModel):
    """Inclusion-proof response for a leaf within an org-reads checkpoint.

    Wire fields: the audit path array is ``path`` (not ``proof``); there is no
    ``checkpointId`` on the response."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    leaf_index: int = Field(alias="leafIndex")
    leaf_hash: str = Field(alias="leafHash")
    tree_size: int | None = Field(None, alias="treeSize")
    root_hash: str = Field(alias="rootHash")
    path: list[str]


class OrgAdminRead(BaseModel):
    """One leaf of the org read-transparency log, from
    ``GET /v1/audit/org-reads``.

    These rows are what the signed checkpoints cover, and listing them is how an
    empty checkpoint list is told apart from "no qualifying reads have happened
    yet": no rows here means nothing was logged, whereas rows here with no
    checkpoint mean the sweep has not run over them yet."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    org_id: str = Field(alias="orgId")
    record_id: str = Field(alias="recordId")
    caller_key_id: str = Field(alias="callerKeyId")
    """API key that performed the read."""
    read_at: str = Field(alias="readAt")
    read_context: str = Field(alias="readContext")
    """``interactive``, ``scheduled-job``, or ``export-batch:<uuid>``."""
    filter_applied: str = Field(alias="filterApplied")
    export_batch_id: str | None = Field(alias="exportBatchId")
    leaf_hash: str = Field(alias="leafHash")
    """sha256 hex of the row's COSE_Sign1 bytes: the Merkle leaf the checkpoints
    cover. Verify it with
    ``org_reads_checkpoints.proof(checkpoint_id, str(leaf_index))``."""
    leaf_index: int = Field(alias="leafIndex")


class OrgReadsCheckpointing(BaseModel):
    """Checkpoint sweep posture, served alongside the checkpoint listing.

    Read it before reporting missing checkpoints: the sweep is time-driven, so a
    fresh install returns an empty listing however many qualifying reads it has
    logged.

    Distinct from :class:`VaultCheckpoint`'s vault-anchoring schedule, which
    carries an ``anchoringEnabled`` flag this object does not have."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    cron: str
    """Cron the sweep runs on (UTC). Fixed cadence; there is no env knob."""
    interval_minutes: int | None = Field(alias="intervalMinutes")
    last_checkpoint_at: str | None = Field(alias="lastCheckpointAt")
    """Newest checkpoint in the caller's org; ``None`` until the first sweep
    lands one."""
    next_run_at: str | None = Field(alias="nextRunAt")
    source: Literal["worker", "config"] | str
    """``worker`` when read from the schedule the worker registered; ``config``
    when the API process fell back to its own defaults."""


class ReputationScore(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    agent_id: str = Field(alias="agentId")
    type: str
    reliability_score: float | None = Field(None, alias="reliabilityScore")
    accuracy_score: float | None = Field(None, alias="accuracyScore")
    efficiency_score: float | None = Field(None, alias="efficiencyScore")
    composite_score: float | None = Field(None, alias="compositeScore")
    confidence_level: float | None = Field(None, alias="confidenceLevel")
    """Statistical confidence (0-1): a number, not a label. Null until the agent has history."""
    lifetime_records: int = Field(0, alias="lifetimeRecords")
    lifetime_verdicts: int = Field(0, alias="lifetimeVerdicts")
    lifetime_accepted: int = Field(0, alias="lifetimeAccepted")
    lifetime_completions: int = Field(0, alias="lifetimeCompletions")
    reversals: int = Field(0, alias="reversals")
    last_updated_at: str | None = Field(None, alias="lastUpdatedAt")
    formula_version: int | None = Field(None, alias="formulaVersion")


class Event(BaseModel):
    """A platform event (from /v1/events)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    type: str
    """Event type (e.g. ``record.created``). Wire field is ``type``, not ``eventType``."""
    record_id: str | None = Field(None, alias="recordId")
    agent_id: str | None = Field(None, alias="agentId")
    data: dict[str, Any] | None = None
    """Event-specific payload. Wire field is ``data``, not ``payload``."""
    created_at: str | None = Field(None, alias="createdAt")


ApiKeyRole = Literal["admin", "agent", "platform"]


class AccountProfile(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    api_key_id: str = Field(alias="apiKeyId")
    role: ApiKeyRole | str
    owner_id: str = Field(alias="ownerId")
    """Owner of the key. When ``owner_type == "agent"`` this IS the agent id; when it is ``"org"`` this is the org id. There is no separate ``agentId`` field: one was declared here through 1.7.0 and ``/v1/auth/me`` has never returned it, so reading it always yielded ``None``."""
    owner_type: str = Field(alias="ownerType")
    scopes: list[str] | None = None
    org_id: str | None = Field(None, alias="orgId")
    name: str | None = None
    created_at: str | None = Field(None, alias="createdAt")
    expires_at: str | None = Field(None, alias="expiresAt")
    """Expiry of this credential, or ``None`` when it does not expire."""
    allowed_ips: list[str] | None = Field(None, alias="allowedIps")
    """IP allowlist enforced on this key, or ``None`` when the key is unrestricted."""
    auth_type: str | None = Field(None, alias="authType")
    """Credential class: ``api_key`` (long-lived ``agl_`` key), ``ephemeral_cert`` (OIDC-bound short-lived signing cert, Mode 2), or ``oidc`` (direct OIDC bearer, Mode 1)."""
    cert: dict[str, Any] | None = None
    """Present (non-null) only for ``ephemeral_cert`` sessions: the bound short-lived signing cert (``id``, ``thumbprint``, ``expiresAt``)."""
    oidc: dict[str, Any] | None = None
    """Present (non-null) for OIDC-bound sessions: the upstream IdP identity (``iss``, ``sub``)."""


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Unified page type for all list endpoints."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    data: list[T]  # type: ignore[type-var]
    has_more: bool = Field(alias="hasMore")
    next_cursor: str | None = Field(None, alias="nextCursor")
    total: int | None = None
    # The two siblings the list envelope names alongside the rows. They arrived
    # as untyped extras before the Server gave the envelope a name.
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
    record_read: RecordReadCompletion | None = Field(None, alias="recordRead")


class OrgReadsCheckpointPage(Page[OrgReadsCheckpoint]):
    """``GET /v1/audit/org-reads/checkpoints``: a page of checkpoints plus the
    sweep posture that explains an empty one."""

    checkpointing: OrgReadsCheckpointing


class HealthResponse(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    status: str
    version: str | None = None
    #: Deprecated. ``GET /health`` declares only ``status``, ``version`` and
    #: ``timestamp``, and the Server strips what its response schema does not
    #: declare, so these two never arrive. Kept so callers keep working.
    #: Process uptime and database state are on ``admin.get_system_health()``,
    #: where ``database`` is an object, not a string.
    uptime: float | None = None
    database: str | None = None
    timestamp: str


class StatusComponent(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    status: str
    latency_ms: float | None = Field(None, alias="latencyMs")


class StatusResponse(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    status: str
    components: list[StatusComponent] = []
    active_incidents: list[dict[str, Any]] = Field(default=[], alias="activeIncidents")
    uptime: float
    timestamp: str


class ConformanceResponse(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    capabilities: dict[str, Any] | None = None
    """Feature capability flags: which features are wired on this install (e.g.
    ``recordLifecycle``, ``twoPhaseGate``, ``euAiActCompliance``,
    ``oidcWorkloadIdentity``). Open-ended; read defensively.

    Values are NOT all booleans. ``signingAlgorithms`` is a list of the COSE
    algorithms this build can sign with, e.g. ``["Ed25519"]``. This was typed
    ``dict[str, bool]``, which rejects every real response, and nothing caught it
    because no method returned this model."""
    contract_types: int | None = Field(None, alias="contractTypes")
    """Number of registered contract types in this org."""
    schemas_url: str | None = Field(None, alias="schemasUrl")
    """URL to list all type schemas (criteria + evidence structure)."""
    settlement_signals: list[str] | None = Field(None, alias="settlementSignals")
    """Supported settlement signal types (e.g. SETTLE, HOLD, RELEASE)."""
    limits: dict[str, int] | None = None
    """The numeric caps this install enforces, keyed by name:
    ``criteriaMaxBytesDefault``, ``referencesMaxPerRequest``,
    ``referencesMaxPerRecordDefault``, ``referenceAttributesMaxKeys``,
    ``metadataMaxProperties``, ``recordBodyMaxBytes``,
    ``delegationMaxDepthDefault``, ``delegationMaxDepthCeiling``,
    ``cursorMaxLength``, ``paginationLimitMax``, ``searchCursorMaxLength``.
    Several are org-configurable, so read these rather than hardcoding: the
    value here is what THIS Server will accept. The three pagination caps bound
    what a paging client must handle: round-trip ``nextCursor`` verbatim, keep
    ``?limit=`` at or under ``paginationLimitMax`` for portability, and size
    cursor storage to ``searchCursorMaxLength``, the widest token any route
    mints."""
    version: str | None = None
    """AGLedger API version."""


class AgentCard(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    description: str | None = None
    url: str
    capabilities: dict[str, Any] | None = None
    skills: list[dict[str, Any]] | None = None


class AgentProfile(BaseModel):
    """Agent identity returned by ``GET /v1/agents/{id}``.

    Wire field is ``displayName`` (not ``name``); there is no ``slug`` or
    ``updatedAt`` on the agent surface. Earlier models required those three and
    crashed every ``agents.get()`` call."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    org_id: str | None = Field(None, alias="orgId")
    display_name: str | None = Field(None, alias="displayName")
    agent_class: str | None = Field(None, alias="agentClass")
    agent_card_url: str | None = Field(None, alias="agentCardUrl")
    owner_ref: str | None = Field(None, alias="ownerRef")
    org_unit: str | None = Field(None, alias="orgUnit")
    description: str | None = None
    references: list[dict[str, Any]] | None = None
    created_at: str | None = Field(None, alias="createdAt")


class AgentDirectoryEntry(BaseModel):
    """A row in the org agent directory returned by ``GET /v1/agents``.

    Use this for peer discovery; for full agent identity use ``agents.get(id)``.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    org_id: str | None = Field(None, alias="orgId")
    display_name: str | None = Field(None, alias="displayName")
    agent_card_url: str | None = Field(None, alias="agentCardUrl")
    agent_class: str | None = Field(None, alias="agentClass")
    org_unit: str | None = Field(None, alias="orgUnit")
    description: str | None = None
    created_at: str | None = Field(None, alias="createdAt")


class GateStatus(BaseModel):
    """Gate status for a Record (GET /v1/records/{id}/gate-status)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    record_id: str = Field(alias="recordId")
    phase1_status: str = Field(alias="phase1Status")
    phase2_status: str = Field(alias="phase2Status")
    last_evaluated_at: str | None = Field(None, alias="lastEvaluatedAt")
    pending_rules: list[str] | None = Field(None, alias="pendingRules")


class WebhookTestResult(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    success: bool
    status_code: int | None = Field(None, alias="statusCode")
    response_time_ms: int | None = Field(None, alias="responseTimeMs")


class AgentCapabilities(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    agent_id: str = Field(alias="agentId")
    capabilities: list[str] = []


class ComplianceExport(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str | None = None
    export_id: str | None = Field(None, alias="exportId")
    status: str
    format: str | None = None
    created_at: str | None = Field(None, alias="createdAt")
    expires_at: str | None = Field(None, alias="expiresAt")
    download_url: str | None = Field(None, alias="downloadUrl")
    #: Rows in the export. Capped at 10000, newest first. Read ``truncated``
    #: before treating this as the size of the match set.
    record_count: int | None = Field(None, alias="recordCount")
    #: True when the filters matched more than the 10000-row export cap, so the
    #: export holds only the newest 10000 rows (API v1.3.4). Window
    #: with ``filters.from`` / ``filters.to`` to cover the rest. On a download
    #: the same answer rides the ``X-AGLedger-Export-Truncated`` response
    #: header, the only carrier for a ``csv`` download (the body is raw rows,
    #: and a notice line would corrupt the parse). None on a pre-1.3.4 server.
    truncated: bool | None = None
    #: Total rows the filters matched at creation time, before the cap. Equals
    #: ``record_count`` unless ``truncated``. Header twin on a download:
    #: ``X-AGLedger-Export-Total-Records``.
    total_records: int | None = Field(None, alias="totalRecords")


class AiImpactAssessment(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    id: str | None = None
    record_id: str = Field(alias="recordId")
    risk_level: EuAiActRiskTier | str = Field(alias="riskLevel")
    domain: EuAiActDomain | str
    overseer_name: str | None = Field(None, alias="overseerName")
    human_oversight: dict[str, Any] | None = Field(None, alias="humanOversight")
    testing_results: dict[str, Any] | None = Field(None, alias="testingResults")
    created_at: str = Field(alias="createdAt")


class VerificationKey(BaseModel):
    """A vault signing public key for independent audit chain verification."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    key_id: str = Field(alias="keyId")
    algorithm: str
    public_key: str = Field(alias="publicKey")
    """Base64-encoded SPKI DER public key."""
    public_key_raw: str | None = Field(None, alias="publicKeyRaw")
    """Base64 of the raw 32-byte Ed25519 key: for raw-key verifiers (RFC 9421 / Standard-Webhooks-style). Same key as ``public_key``, different encoding."""
    status: str
    activated_at: str | None = Field(None, alias="activatedAt")
    """May be a full ISO timestamp (engine ≥ v0.26.x) or a bare date string
    (older builds). Optional so the model parses either way."""
    retired_at: str | None = Field(None, alias="retiredAt")


class VerificationKeysResponse(BaseModel):
    """Response from GET /v1/verification-keys."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    data: list[VerificationKey]
    canonicalization: str
    hash_algorithm: str | None = Field(None, alias="hashAlgorithm")
    """Optional: not emitted by every server build. Engines that
    emit it set ``"SHA-256"``; absent means the implicit COSE/Ed25519 default."""
    signature_algorithm: str | None = Field(None, alias="signatureAlgorithm")
    signature_input_template: str | None = Field(None, alias="signatureInputTemplate")
    """Template for the canonical signature-input string (v0.25.x)."""


class FederationPeer(BaseModel):
    """A peered Server, as served by ``GET /federation/v1/admin/peers`` and
    ``GET /federation/v1/admin/peers/{peerHubId}``.

    Federation is peer to peer: there is no hub, and ``peerHubId`` is only the
    name the identity field kept."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    peer_id: str = Field(alias="peerId")
    """Receiver-local row id of the registration. No admin path takes it."""
    peer_hub_id: str = Field(alias="peerHubId")
    """The peer identity every ``/federation/v1/admin/peers/{peerHubId}`` path
    takes, in canonical lowercase. Not ``peer_id``, which resolves nowhere."""
    peer_url: str = Field(alias="peerUrl")
    status: Literal["active", "suspended", "revoked"] | str
    created_at: str = Field(alias="createdAt")
    agent_directory_hash: str | None = Field(None, alias="agentDirectoryHash")
    """Digest of the agent directory this peer last pushed. ``None`` until the
    peer has pushed one."""
    consecutive_delivery_failures: int | None = Field(None, alias="consecutiveDeliveryFailures")
    """Failed delivery attempts since the last success, reset to 0 on a 2xx. Not
    purely a reachability count: a peer that answers and rejects the payload
    counts here too, because the message did not get through either way.
    ``last_delivery_error`` says which."""
    last_delivery_at: str | None = Field(None, alias="lastDeliveryAt")
    """When an outbound message last reached this peer with a 2xx. ``None``
    means nothing has been delivered yet, not that the peer is unreachable."""
    last_delivery_error: str | None = Field(None, alias="lastDeliveryError")
    """Why the most recent delivery attempt failed, cleared on the next
    success."""
    last_sync_at: str | None = Field(None, alias="lastSyncAt")
    """When this peer last pushed its agent directory. Directory-sync state, NOT
    reachability: V1 federation has no pull protocol, so a peer taking delivery
    after delivery never moves it. Read ``last_delivery_at`` instead."""


class PeerHandshakeResult(BaseModel):
    """201 from ``POST /federation/v1/peer``: the registration this Server filed
    for the caller, and the keys the caller verifies it with."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", populate_by_name=True)

    peered: Literal[True]
    """Always true; a refusal is a thrown 4xx, never a ``False`` here."""
    peer_id: str = Field(alias="peerId")
    """Receiver-local row id of the registration. No admin path takes it."""
    peer_hub_id: str = Field(alias="peerHubId")
    """The identity the registration is filed under, in canonical lowercase, and
    the one every ``/federation/v1/admin/peers/{peerHubId}`` path takes."""
    status: str
    """Peer status as created (``active``)."""
    server_signing_public_key: str = Field(alias="serverSigningPublicKey")
    server_encryption_public_key: str = Field(alias="serverEncryptionPublicKey")
    next_steps: list[NextStep] | None = Field(None, alias="nextSteps")
