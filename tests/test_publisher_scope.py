"""Multi-publisher record creation and schema scoping.

Two publishers offering the same ``record_type`` in one org is a supported
state, and once it happens a bare ``type`` no longer names a schema. The engine
refuses rather than picking (422 ``/problems/ambiguous-publisher``), because the
pick would change the moment the other publisher shipped a higher version.
Everything here is about the caller being able to see that refusal and act on it
from the typed API.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient, UnprocessableError
from agledger.types import BulkCreateResult, RecordRow

BASE = "https://agledger.example.com"

AMBIGUOUS = {
    "type": "/problems/ambiguous-publisher",
    "title": "Ambiguous publisher",
    "error": "AMBIGUOUS_PUBLISHER",
    "message": "Type acme-po-v1 is offered by more than one publisher",
    "publishers": ["acme-corp", "local"],
    "recordType": "acme-po-v1",
    "recoveryHint": "Re-send with a publisher field naming one of `publishers`.",
}


def client() -> AgledgerClient:
    return AgledgerClient(api_key="agl_agt_test", base_url=BASE, max_retries=0)


def record_json(**overrides: object) -> dict[str, object]:
    """A RecordRow wire body carrying every required field."""
    base: dict[str, object] = {
        "id": "rec-1",
        "orgId": "org-1",
        "type": "acme-po-v1",
        "platform": "test",
        "status": "CREATED",
        "criteria": {},
        "submissionCount": 0,
        "version": 1,
        "createdAt": "2026-08-08T00:00:00Z",
        "updatedAt": "2026-08-08T00:00:00Z",
    }
    base.update(overrides)
    return base


@respx.mock
def test_create_sends_publisher_alongside_type() -> None:
    route = respx.post(f"{BASE}/v1/records").mock(
        return_value=httpx.Response(201, json=record_json(publisher="acme-corp"))
    )
    client().records.create(type="acme-po-v1", criteria={"poNumber": "PO-1"}, publisher="acme-corp")

    body = json.loads(route.calls[0].request.content)
    assert body["type"] == "acme-po-v1"
    assert body["publisher"] == "acme-corp"


@respx.mock
def test_create_omits_publisher_when_unpinned() -> None:
    route = respx.post(f"{BASE}/v1/records").mock(
        return_value=httpx.Response(201, json=record_json(type="t"))
    )
    client().records.create(type="t", criteria={})
    assert "publisher" not in json.loads(route.calls[0].request.content)


@respx.mock
def test_ambiguous_422_carries_the_candidates_not_just_prose() -> None:
    respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(422, json=AMBIGUOUS))

    with pytest.raises(UnprocessableError) as exc:
        client().records.create(type="acme-po-v1", criteria={})

    # The whole point: recover in code, without parsing the message.
    assert exc.value.type == "/problems/ambiguous-publisher"
    assert exc.value.publishers == ["acme-corp", "local"]
    assert exc.value.recovery_hint is not None


@respx.mock
@pytest.mark.asyncio
async def test_ambiguous_422_on_the_async_client_too() -> None:
    respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(422, json=AMBIGUOUS))

    async with AsyncAgledgerClient(api_key="agl_agt_test", base_url=BASE, max_retries=0) as ac:
        with pytest.raises(UnprocessableError) as exc:
            await ac.records.create(type="acme-po-v1", criteria={}, publisher=None)

    assert exc.value.publishers == ["acme-corp", "local"]


def test_bulk_item_reports_the_same_failure_per_item() -> None:
    result = BulkCreateResult.model_validate({
        "results": [{
            "index": 0,
            "status": "error",
            "error": "Ambiguous publisher",
            "problemType": "/problems/ambiguous-publisher",
            "context": {"publishers": ["acme-corp", "local"], "recordType": "acme-po-v1"},
        }],
        "summary": {"total": 1, "succeeded": 0, "failed": 1},
    })

    item = result.results[0]
    assert item.problem_type == "/problems/ambiguous-publisher"
    assert item.context is not None
    assert item.context["publishers"] == ["acme-corp", "local"]


def test_record_reports_its_binding_and_a_scoped_schema_url() -> None:
    record = RecordRow.model_validate(record_json(
        publisher="acme-corp",
        schemaUrl="/v1/schemas/acme-po-v1?publisher=acme-corp",
    ))
    assert record.publisher == "acme-corp"
    # Follow it verbatim; a bare path 422s in the ambiguous case.
    assert record.schema_url is not None and "?publisher=" in record.schema_url


def test_publisher_is_none_on_a_record_with_no_local_binding() -> None:
    # Federation-received and backfill-imported records. None means "ask the
    # originator", not "the schema is missing here".
    record = RecordRow.model_validate(record_json(id="rec-2", type="peer-v1", publisher=None))
    assert record.publisher is None


@respx.mock
def test_schema_read_sends_the_publisher_query() -> None:
    route = respx.get(f"{BASE}/v1/schemas/acme-po-v1").mock(
        return_value=httpx.Response(200, json={"type": "acme-po-v1"})
    )
    client().schemas.get("acme-po-v1", publisher="acme-corp")
    assert route.calls[0].request.url.params["publisher"] == "acme-corp"


@respx.mock
def test_schema_read_omits_the_query_when_unpinned() -> None:
    route = respx.get(f"{BASE}/v1/schemas/acme-po-v1").mock(
        return_value=httpx.Response(200, json={"type": "acme-po-v1"})
    )
    client().schemas.get("acme-po-v1")
    assert "publisher" not in route.calls[0].request.url.params


@respx.mock
def test_schema_writes_scope_too_since_they_carry_the_same_422() -> None:
    route = respx.patch(f"{BASE}/v1/schemas/acme-po-v1/disable").mock(
        return_value=httpx.Response(200, json={"type": "acme-po-v1", "status": "DISABLED"})
    )
    client().schemas.disable("acme-po-v1", publisher="acme-corp")
    assert route.calls[0].request.url.params["publisher"] == "acme-corp"


@respx.mock
def test_get_manifest_reaches_the_route_that_had_no_method() -> None:
    route = respx.get(f"{BASE}/v1/schemas/acme-po-v1/manifest").mock(
        return_value=httpx.Response(200, json={
            "manifest": {"manifestVersion": "1.0", "publisher": "acme-corp",
                         "type": "acme-po-v1", "version": "1", "recordSchema": {}},
            "manifestDigest": "sha256:" + "0" * 64,
        })
    )
    out = client().schemas.get_manifest("acme-po-v1", publisher="acme-corp")
    assert out["manifestDigest"].startswith("sha256:")
    assert route.calls[0].request.url.params["publisher"] == "acme-corp"


def test_unsupported_algorithm_export_parses_instead_of_raising() -> None:
    """A strict Literal that lags the wire is a runtime failure here, not just a
    type error: the model refuses to parse a real export."""
    from agledger.types import AuditExportMetadata

    meta = AuditExportMetadata.model_validate({
        "recordId": "rec-1",
        "type": "acme-po-v1",
        "exportDate": "2026-08-08T00:00:00Z",
        "exportFormatVersion": "2.0",
        "canonicalization": "RFC8949-CDE",
        "totalEntries": 3,
        "chainIntegrity": False,
        "chainIntegrityReason": "unsupported_algorithm",
        "chainIntegrityDetail": {"failure": "unsupported_algorithm"},
    })
    assert meta.chain_integrity_reason == "unsupported_algorithm"
    assert meta.chain_integrity_detail is not None
    assert meta.chain_integrity_detail.failure == "unsupported_algorithm"
