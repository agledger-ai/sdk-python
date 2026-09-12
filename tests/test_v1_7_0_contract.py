"""API v1.7.0 client-facing deltas.

The wave that carried the 1.7.0 client sync was prepared against an untagged API
commit, and the tag landed sixteen commits later. Everything here is a delta
between those two specs, so none of it was covered by the round that validated
the wave.

Same style as test_response_contract.py: feed a real-server-shaped payload
(camelCase, exactly what the API emits) through a resource method and assert the
model parses and surfaces the new field.
"""

from __future__ import annotations

import typing

import httpx
import pytest
import respx

from agledger import (
    AgledgerClient,
    CoSignPeerLeg,
    CoSignStatus,
    DisputeStatusFilter,
    FederationPeerStatus,
    FederationPeerStatusFilter,
    RecordStatusFilter,
)

BASE = "https://agledger.example.com"


def _client() -> AgledgerClient:
    return AgledgerClient(api_key="test-key", base_url=BASE)


def _record(**overrides: object) -> dict:
    row = {
        "id": "rec-1", "orgId": "org-1", "agentId": "agt-1",
        "principalAgentId": "agt-1", "type": "notarize-generic-v1", "contractVersion": "1",
        "platform": "test", "status": "FULFILLED", "criteria": {},
        "submissionCount": 0, "maxSubmissions": None, "version": 1,
        "createdAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-09-01T00:05:00Z",
    }
    row.update(overrides)
    return row


@respx.mock
def test_integrity_says_which_fields_it_compared():
    # `verified` is only as strong as the field list behind it: criteria and
    # verdict are compared only where the chain asserts them, so a clean
    # `verified` on a dispute-overturned record is silent about the verdict.
    respx.get(f"{BASE}/v1/records/rec-1").mock(
        return_value=httpx.Response(200, json=_record(integrity={
            "verified": True,
            "integrityLevel": "hash_chain_and_signatures",
            "reason": None,
            "entries": 7,
            "projectionChecked": True,
            "driftFields": [],
            "comparedFields": ["status", "type", "criteria"],
        }))
    )
    row = _client().records.get("rec-1", integrity=True)
    assert row.integrity is not None
    assert row.integrity.compared_fields == ["status", "type", "criteria"]
    assert row.integrity.drift_fields == []


@respx.mock
def test_a_settlement_signal_answers_which_peer_did_what():
    # The rollup is one word over the whole fan-out. Only the per-peer legs say
    # which peer counter-signed, which matters most for a waived leg: it sits
    # outside the count on every rollup value.
    respx.get(f"{BASE}/v1/records/rec-1").mock(
        return_value=httpx.Response(200, json=_record(settlementSignal={
            "recommendation": "SETTLE",
            "outcome": "accept",
            "deliveredToPeers": ["peer-a"],
            "pendingToPeers": [],
            "failedToPeers": [],
            "idempotencyKey": "idem-1",
            "coSignStatus": "succeeded",
            "source": "outbound",
            "coSignPeers": [
                {"peerHubId": "peer-a", "status": "succeeded", "counterSignature": "ab" * 32},
                {"peerHubId": "peer-b", "status": "not_required", "counterSignature": None},
            ],
        }))
    )
    signal = _client().records.get("rec-1").settlement_signal
    assert signal is not None
    assert signal.co_sign_peers is not None
    waived = signal.co_sign_peers[1]
    assert isinstance(waived, CoSignPeerLeg)
    assert waived.peer_hub_id == "peer-b"
    assert waived.status == "not_required"
    assert waived.counter_signature is None
    # A peer that counter-signed is not the same as a peer that was delivered to.
    assert signal.co_sign_peers[0].status == "succeeded"
    assert signal.delivered_to_peers == ["peer-a"]


def test_a_leg_status_is_narrower_than_the_rollup():
    # `partial` is a fan-out outcome no single peer can hold.
    rollup = set(typing.get_args(CoSignStatus))
    leg = set(typing.get_args(CoSignPeerLeg.model_fields["status"].annotation))
    assert "partial" in rollup
    assert "partial" not in leg
    assert leg < rollup


@respx.mock
def test_gate_status_carries_the_decision_not_just_the_phases():
    # A dispute resolved OVERTURNED re-renders the verdict and writes no
    # evaluation row of its own, so the failing gate row stays on the record
    # with `verdict: accept` and `recommendation: RELEASE` beside it.
    respx.get(f"{BASE}/v1/records/rec-1/gate-status").mock(
        return_value=httpx.Response(200, json={
            "recordId": "rec-1",
            "phase1Status": "passed",
            "phase2Status": "superseded",
            "lastEvaluatedAt": "2026-09-01T00:04:00Z",
            "pendingRules": [],
            "verdict": "accept",
            "recommendation": "RELEASE",
            "gateMode": "principal",
            "reporterType": "principal",
        })
    )
    status = _client().gate.get_status("rec-1")
    assert status.phase2_status == "superseded"
    assert status.verdict == "accept"
    assert status.recommendation == "RELEASE"
    assert status.gate_mode == "principal"
    assert status.reporter_type == "principal"


@respx.mock
def test_gate_status_parses_a_record_that_never_gets_a_completion():
    # A notarize-only type terminalizes at RECORDED on create: no completion is
    # coming, and both phases say so rather than sitting at "pending" forever.
    respx.get(f"{BASE}/v1/records/rec-2/gate-status").mock(
        return_value=httpx.Response(200, json={
            "recordId": "rec-2",
            "phase1Status": "not_applicable",
            "phase2Status": "not_applicable",
            "lastEvaluatedAt": None,
            "verdict": None,
            "recommendation": None,
        })
    )
    status = _client().gate.get_status("rec-2")
    assert status.phase1_status == "not_applicable"
    assert status.recommendation is None


@respx.mock
def test_agent_history_says_which_side_the_agent_was_on():
    respx.get(f"{BASE}/v1/agents/agt-1/history").mock(
        return_value=httpx.Response(200, json={
            "data": [
                {
                    "recordId": "rec-1", "type": "notarize-generic-v1",
                    "status": "RECORDED", "role": "both", "outcome": "PENDING",
                    "createdAt": "2026-09-01T00:00:00Z", "completedAt": None,
                },
                {
                    "recordId": "rec-2", "type": "principal-gate-generic-v1",
                    "status": "FULFILLED", "role": "performer", "outcome": "accept",
                    "createdAt": "2026-09-02T00:00:00Z",
                    "completedAt": "2026-09-02T00:05:00Z",
                },
            ],
            "total": 2, "nextCursor": None, "hasMore": False,
        })
    )
    page = _client().drift.get_agent_history("agt-1")
    # An agent-created notarize record defaults its performer to its principal,
    # so `both` is the ordinary case rather than an edge one.
    assert [row.role for row in page.data] == ["both", "performer"]


@pytest.mark.parametrize(
    ("alias", "removed"),
    [
        (RecordStatusFilter, "PENDING_ARBITRATION"),
        (DisputeStatusFilter, "TIER_2_REVIEW"),
        (FederationPeerStatusFilter, "suspended"),
    ],
)
def test_a_status_filter_names_no_value_the_engine_removed(alias: object, removed: str) -> None:
    """The filters are strict enums server-side: a stale value is a 400.

    This SDK closes the record and dispute response unions too, so the filter
    aliases match them. The peer status is the one that stays open on the
    response, and closed on the filter.
    """
    assert removed not in set(typing.get_args(alias))


def test_the_peer_status_response_union_stays_open():
    # A status a newer Server adds still parses on a response; it just cannot be
    # sent as a filter.
    assert str in typing.get_args(FederationPeerStatus)
    assert str not in typing.get_args(FederationPeerStatusFilter)
