"""AGLedger Server 3.0.0 surface: producedBy, trace and origin search, numeric
bounds, record counts, federation fields, verdict signatures and the HTML export."""

from __future__ import annotations

import json
from urllib.parse import unquote

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient

BASE = "https://agledger.example.com"
PAGE = {"data": [], "hasMore": False}
RECORD = {
    "id": "rec-1", "orgId": "org-1", "type": "notarize-generic-v1", "platform": "test",
    "status": "CREATED", "criteria": {}, "submissionCount": 0, "version": 1,
    "createdAt": "2026-11-20T00:00:00Z", "updatedAt": "2026-11-20T00:00:00Z",
}
PRODUCED_BY = {"modelProvider": "anthropic", "modelId": "m-1", "promptDigest": "sha256:ab"}
TRACE = "0af7651916cd43dd8448eb211c80319c"


def _client() -> AgledgerClient:
    return AgledgerClient(base_url=BASE, api_key="test-key")


@respx.mock
def test_create_sends_produced_by_on_the_wire_keys():
    route = respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(201, json=RECORD))
    _client().records.create(type="notarize-generic-v1", criteria={}, produced_by=PRODUCED_BY)
    assert json.loads(route.calls.last.request.content)["producedBy"] == PRODUCED_BY


@respx.mock
def test_create_without_produced_by_sends_no_key():
    route = respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(201, json=RECORD))
    _client().records.create(type="notarize-generic-v1", criteria={})
    assert "producedBy" not in json.loads(route.calls.last.request.content)


@respx.mock
def test_completion_submit_sends_produced_by():
    route = respx.post(f"{BASE}/v1/records/rec-1/completions").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "c-1", "recordId": "rec-1", "agentId": "a", "evidence": {},
                "createdAt": "2026-11-20T00:00:00Z", "producedBy": PRODUCED_BY,
            },
        )
    )
    completion = _client().completions.submit("rec-1", evidence={}, produced_by=PRODUCED_BY)
    assert json.loads(route.calls.last.request.content)["producedBy"] == PRODUCED_BY
    assert completion.produced_by is not None
    assert completion.produced_by.model_id == "m-1"
    assert completion.produced_by.prompt_digest == "sha256:ab"


def test_record_models_read_the_new_fields():
    from agledger.types import RecordRow

    row = RecordRow.model_validate(
        {
            **RECORD,
            "traceId": TRACE,
            "producedBy": PRODUCED_BY,
            "federationOrigin": {"peerHubId": "hub-2", "recordId": "orig-1"},
            "federationLegs": [
                {
                    "peerHubId": "hub-2", "kind": "signal", "status": "pending", "state": None,
                    "attempts": 3, "deliveredAt": None, "lastAttemptedAt": "2026-11-20T00:01:00Z",
                    "lastError": "timeout", "lastErrorReason": "transport_error",
                }
            ],
            "settlementSignal": {
                "recommendation": "SETTLE", "deliveredToPeers": [], "pendingToPeers": [], "failedToPeers": [],
                "idempotencyKey": "k",
                "coSignPeers": [
                    {
                        "peerHubId": "hub-2", "status": "failed", "attempts": 2,
                        "lastAttemptedAt": "2026-11-20T00:02:00Z", "lastError": "no",
                        "lastErrorReason": "co_sign_rejected",
                    }
                ],
            },
        }
    )
    assert row.trace_id == TRACE
    assert row.produced_by is not None and row.produced_by.model_provider == "anthropic"
    assert row.federation_origin is not None
    assert (row.federation_origin.peer_hub_id, row.federation_origin.record_id) == ("hub-2", "orig-1")
    assert row.federation_legs is not None
    leg = row.federation_legs[0]
    assert (leg.kind, leg.status, leg.attempts, leg.last_error_reason) == ("signal", "pending", 3, "transport_error")
    assert row.settlement_signal is not None and row.settlement_signal.co_sign_peers is not None
    peer = row.settlement_signal.co_sign_peers[0]
    assert (peer.attempts, peer.last_error_reason) == (2, "co_sign_rejected")


def test_local_record_has_no_origin_or_trace():
    from agledger.types import RecordRow

    row = RecordRow.model_validate({**RECORD, "federationOrigin": None, "traceId": None, "producedBy": None})
    assert row.federation_origin is None and row.trace_id is None and row.produced_by is None


@respx.mock
def test_search_serializes_trace_origin_produced_by_and_bounds():
    route = respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=PAGE))
    _client().records.search(
        trace_id=TRACE,
        origin_record_id="9f1c6a6e-0000-4000-8000-000000000000",
        produced_by={"modelId": "m-1", "agentSoftware": "agent-x"},
        criteria_gte={"amount": 500},
        criteria_lt={"amount": 1500.75},
        metadata_gt={"score": "-12"},
        metadata_lte={"big": 1e22},
    )
    url = unquote(str(route.calls.last.request.url))
    for expected in (
        f"traceId={TRACE}",
        "originRecordId=9f1c6a6e-0000-4000-8000-000000000000",
        "producedBy[modelId]=m-1",
        "producedBy[agentSoftware]=agent-x",
        "criteriaGte[amount]=500",
        "criteriaLt[amount]=1500.75",
        "metadataGt[score]=-12",
        "metadataLte[big]=10000000000000000000000",
    ):
        assert expected in url, expected
    assert "{" not in url and "e+" not in url


def test_a_boolean_or_non_finite_bound_is_refused_before_sending():
    with pytest.raises(ValueError):
        _client().records.search(criteria_gte={"flag": True})
    with pytest.raises(ValueError):
        _client().records.search(criteria_gte={"x": float("nan")})


COUNTS = {
    "data": [
        {"type": "a-v1", "status": "FULFILLED", "count": 5},
        {"type": "a-v1", "status": "FAILED", "count": 2},
    ],
    "groupBy": ["type", "status"],
    "total": 7,
    "groupCount": 2,
    "truncated": False,
}


@respx.mock
def test_counts_sends_filters_and_comma_joined_group_by():
    route = respx.get(f"{BASE}/v1/records/counts").mock(return_value=httpx.Response(200, json=COUNTS))
    result = _client().records.counts(
        type="a-v1", from_date="2026-10-01T00:00:00Z", criteria_gte={"amount": 500},
        group_by=["type", "status"], limit=50,
    )
    url = unquote(str(route.calls.last.request.url))
    assert url.startswith(f"{BASE}/v1/records/counts?")
    for expected in ("type=a-v1", "from=2026-10-01T00:00:00Z", "criteriaGte[amount]=500", "groupBy=type,status", "limit=50"):
        assert expected in url, expected
    assert result.total == 7 and result.group_count == 2 and result.truncated is False
    assert result.group_by == ["type", "status"]
    assert [(g.type, g.status, g.count) for g in result.data] == [("a-v1", "FULFILLED", 5), ("a-v1", "FAILED", 2)]


@respx.mock
def test_counts_takes_one_dimension_as_a_string_and_reads_camel_dimensions():
    route = respx.get(f"{BASE}/v1/records/counts").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [{"performerAgentId": None, "createdDay": "2026-11-01", "count": 1}],
                "groupBy": ["createdDay"], "total": 1, "groupCount": 1, "truncated": False,
            },
        )
    )
    result = _client().records.counts(group_by="createdDay")
    assert "groupBy=createdDay" in str(route.calls.last.request.url)
    assert result.data[0].created_day == "2026-11-01"


def test_counts_refuses_more_than_two_dimensions():
    with pytest.raises(ValueError):
        _client().records.counts(group_by=["type", "status", "category"])


@respx.mock
@pytest.mark.asyncio
async def test_async_counts():
    route = respx.get(f"{BASE}/v1/records/counts").mock(return_value=httpx.Response(200, json=COUNTS))
    async with AsyncAgledgerClient(base_url=BASE, api_key="test-key") as client:
        result = await client.records.counts(group_by="status", metadata_gt={"n": 1})
    url = unquote(str(route.calls.last.request.url))
    assert "groupBy=status" in url and "metadataGt[n]=1" in url
    assert result.total == 7


VERDICT = {
    "recordId": "rec-1", "completionId": "c-1", "verdict": "accept", "recommendation": "SETTLE",
    "reporterType": "principal", "reportedAt": "2026-11-20T00:00:00Z",
}
SIGNATURE = {
    "meaning": "approval", "signerName": "Ada Lovelace", "signerIss": "https://idp.example",
    "signerSub": "u-1", "signedAt": "2026-11-20T00:00:00Z",
}


@respx.mock
def test_verdict_sends_signature_meaning_and_reads_signature():
    route = respx.post(f"{BASE}/v1/records/rec-1/verdict").mock(
        return_value=httpx.Response(200, json={**VERDICT, "signature": SIGNATURE})
    )
    result = _client().records.submit_verdict(
        "rec-1", completion_id="c-1", verdict="accept", signature_meaning="approval"
    )
    assert json.loads(route.calls.last.request.content)["signatureMeaning"] == "approval"
    assert result.signature is not None
    assert (result.signature.meaning, result.signature.signer_name, result.signature.signer_iss) == (
        "approval", "Ada Lovelace", "https://idp.example",
    )
    assert result.signature.signer_sub == "u-1" and result.signature.signed_at == SIGNATURE["signedAt"]


@respx.mock
def test_verdict_without_meaning_sends_none_and_reads_null_signature():
    route = respx.post(f"{BASE}/v1/records/rec-1/verdict").mock(
        return_value=httpx.Response(200, json={**VERDICT, "signature": None})
    )
    result = _client().records.submit_verdict("rec-1", completion_id="c-1", verdict="accept")
    assert "signatureMeaning" not in json.loads(route.calls.last.request.content)
    assert result.signature is None


@respx.mock
@pytest.mark.parametrize("reason", ["signature_requires_oidc_identity", "signature_requires_signer_name"])
def test_signature_refusals_are_on_the_error_reason(reason: str):
    from agledger._errors import APIError

    respx.post(f"{BASE}/v1/records/rec-1/verdict").mock(
        return_value=httpx.Response(422, json={"error": "UNPROCESSABLE", "detail": "x", "reason": reason})
    )
    with pytest.raises(APIError) as excinfo:
        _client().records.submit_verdict("rec-1", completion_id="c-1", verdict="accept", signature_meaning="review")
    assert excinfo.value.reason == reason


def test_whoami_reads_oidc_name():
    from agledger.types import AccountProfile

    profile = AccountProfile.model_validate(
        {
            "apiKeyId": "k", "role": "agent", "ownerId": "a", "ownerType": "agent",
            "authType": "ephemeral_cert", "oidc": {"iss": "https://idp.example", "sub": "u-1", "name": "Ada"},
        }
    )
    assert profile.oidc is not None and profile.oidc["name"] == "Ada"


HTML = "<!doctype html><html><body><script type=\"application/json\" id=\"agledger-audit-export\">{}</script>é</body></html>"


@respx.mock
def test_audit_export_html_returns_the_raw_page():
    route = respx.get(f"{BASE}/v1/records/rec-1/audit-export").mock(
        return_value=httpx.Response(200, content=HTML.encode(), headers={"content-type": "text/html; charset=utf-8"})
    )
    page = _client().records.get_audit_export_html("rec-1", evidence=True)
    assert page == HTML
    request = route.calls.last.request
    assert request.url.params["format"] == "html" and request.url.params["evidence"] == "true"
    assert request.headers["accept"] == "text/html"


@respx.mock
@pytest.mark.asyncio
async def test_async_audit_export_html():
    respx.get(f"{BASE}/v1/records/rec-1/audit-export").mock(
        return_value=httpx.Response(200, content=HTML.encode(), headers={"content-type": "text/html"})
    )
    async with AsyncAgledgerClient(base_url=BASE, api_key="test-key") as client:
        assert await client.records.get_audit_export_html("rec-1") == HTML


def test_agent_models_read_origin_ids():
    from agledger.types import AgentDirectoryEntry, AgentProfile

    for model in (AgentProfile, AgentDirectoryEntry):
        agent = model.model_validate({"id": "a-1", "originAgentId": "o-1", "originPeerHubId": "hub-2"})
        assert (agent.origin_agent_id, agent.origin_peer_hub_id) == ("o-1", "hub-2")


def test_conformance_limits_accept_the_per_route_map_and_depth():
    from agledger.types import ConformanceResponse

    result = ConformanceResponse.model_validate(
        {"limits": {"jsonBodyMaxDepth": 32, "paginationLimitMax": 100, "paginationLimitMaxByRoute": {"GET /v1/events": 500}}}
    )
    assert result.limits is not None
    assert result.limits["jsonBodyMaxDepth"] == 32
    assert result.limits["paginationLimitMaxByRoute"] == {"GET /v1/events": 500}


def test_compliance_export_reads_next_from():
    from agledger.types import ComplianceExport

    export = ComplianceExport.model_validate({"status": "ready", "nextFrom": "2026-11-20T00:00:00.000000Z"})
    assert export.next_from == "2026-11-20T00:00:00.000000Z"
