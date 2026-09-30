"""The last twelve pinned enums are named types, on the parameters and fields
their spec sites describe.

A closed alias on a request parameter is the one the route validates as a
strict enum, so a value outside it is refused by the type checker instead of by
the Server with a 400. An open alias (``| str``) names the known values without
making a value a newer Server adds a typing break.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from agledger import AgledgerClient
from agledger.types import Completion, ComplianceRecord, VerdictResult, Webhook
from tests.test_admin_typed_reads import _pyright

BASE = "https://agledger.example.com"

_TYPED_CALLER = """
from typing import assert_type

from agledger import (
    AgledgerClient,
    ComplianceRecordType,
    SettlementSignal,
    StructuralValidation,
    WebhookSigningAlg,
)
from agledger.types import Completion, ComplianceRecord, VerdictResult, Webhook


def calls(client: AgledgerClient) -> None:
    client.webhooks.create(url="u", event_types=["record.created"], signing_alg="ecdsa-p256-sha256")
    client.federation.relay_signal(
        record_id="r",
        recommendation="RELEASE",
        outcome_hash="h",
        valid_until="t",
        idempotency_key="k",
        outcome="accept",
        schema_ref={},
        reason_code=None,
        failing_rule_ids=None,
    )
    client.schemas.update_version("t", 2, {"compatibilityMode": "backward"})


def reads(c: Completion, w: Webhook, r: ComplianceRecord, v: VerdictResult) -> None:
    assert_type(c.structural_validation, StructuralValidation | None)
    assert_type(w.signing_alg, WebhookSigningAlg | str | None)
    assert_type(r.record_type, ComplianceRecordType)
    assert_type(v.recommendation, SettlementSignal)
"""


def test_the_named_enums_type_check(tmp_path: Path) -> None:
    ok = _pyright(tmp_path, _TYPED_CALLER)
    assert ok.returncode == 0, ok.stdout


def test_a_value_outside_a_closed_request_enum_is_rejected(tmp_path: Path) -> None:
    """Each probe swaps one value the route refuses into a caller that passes,
    so a failure can only come from that value."""
    for good, bad, named in [
        ('signing_alg="ecdsa-p256-sha256"', 'signing_alg="rsa-sha256"', "rsa-sha256"),
        ('recommendation="RELEASE"', 'recommendation="PAY"', "PAY"),
        ('outcome="accept"', 'outcome="ACCEPT"', "ACCEPT"),
        ('{"compatibilityMode": "backward"}', '{"compatibility": "backward"}', "compatibility"),
    ]:
        assert good in _TYPED_CALLER
        wrong = _pyright(tmp_path, _TYPED_CALLER.replace(good, bad))
        assert wrong.returncode != 0, bad
        assert named in wrong.stdout, wrong.stdout


def test_response_fields_parse_values_a_newer_server_adds() -> None:
    """The open aliases keep a response field parseable on an unnamed value."""
    completion = Completion.model_validate(
        {"id": "c", "recordId": "r", "agentId": "a", "evidence": {},
         "structuralValidation": "DEFERRED", "createdAt": "t"}
    )
    assert completion.structural_validation == "DEFERRED"
    webhook = Webhook.model_validate(
        {"id": "w", "url": "u", "isActive": True, "createdAt": "t", "signingAlg": "ml-dsa-65"}
    )
    assert webhook.signing_alg == "ml-dsa-65"
    record = ComplianceRecord.model_validate(
        {"id": "i", "recordId": "r", "orgId": "o", "recordType": "post_market_monitoring",
         "attestation": {}, "attestedBy": "a", "attestedAt": "t", "createdAt": "t"}
    )
    assert record.record_type == "post_market_monitoring"
    verdict = VerdictResult.model_validate(
        {"recordId": "r", "completionId": "c", "verdict": "accept", "recommendation": "SETTLE",
         "reporterType": "principal", "reportedAt": "t"}
    )
    assert verdict.recommendation == "SETTLE"


@respx.mock
def test_the_typed_params_reach_the_wire_unchanged() -> None:
    signal = respx.post(f"{BASE}/federation/v1/signals").mock(
        return_value=httpx.Response(200, json={"relayed": True})
    )
    patch = respx.patch(f"{BASE}/v1/schemas/t/versions/2").mock(
        return_value=httpx.Response(200, json={})
    )
    client = AgledgerClient(api_key="agl_agt_test", base_url=BASE)
    client.federation.relay_signal(
        record_id="r", recommendation="HOLD", outcome_hash="h", valid_until="t",
        idempotency_key="k", outcome="reject", schema_ref={}, reason_code=None,
        failing_rule_ids=None,
    )
    client.schemas.update_version("t", 2, {"compatibilityMode": "full"})
    sent = json.loads(signal.calls.last.request.content)
    assert (sent["recommendation"], sent["outcome"]) == ("HOLD", "reject")
    assert json.loads(patch.calls.last.request.content) == {"compatibilityMode": "full"}
