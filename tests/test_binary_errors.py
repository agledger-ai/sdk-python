"""Errors on the binary (SCITT, attestation) routes."""

import httpx
import pytest
import respx

from agledger import AgledgerClient
from agledger._errors import BadRequestError, NotFoundError

BASE = "https://agledger.example.com"
ENTRY = "00000000-0000-0000-0000-000000000000"
CBOR_PROBLEM = b"\xa2\x20\x69Not Found\x21\x78\x1ascitt entry x is not found!"


@respx.mock
def test_cbor_problem_details_stay_on_raw_body_and_the_status_names_the_error():
    respx.get(f"{BASE}/v1/scitt/entries/{ENTRY}").mock(
        return_value=httpx.Response(
            404,
            content=CBOR_PROBLEM,
            headers={"content-type": "application/concise-problem-details+cbor"},
        )
    )
    with pytest.raises(NotFoundError) as excinfo:
        AgledgerClient(base_url=BASE, api_key="k").scitt.entries.get(ENTRY)
    assert excinfo.value.detail == "Not Found"
    assert excinfo.value.raw_body == CBOR_PROBLEM


@respx.mock
def test_a_json_problem_on_a_binary_route_maps_its_code_and_detail():
    respx.get(f"{BASE}/v1/scitt/entries/x").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "VALIDATION_ERROR",
                "detail": 'params/entryId must match format "uuid"',
            },
            headers={"content-type": "application/problem+json"},
        )
    )
    with pytest.raises(BadRequestError) as excinfo:
        AgledgerClient(base_url=BASE, api_key="k").scitt.entries.get("x")
    assert excinfo.value.code == "VALIDATION_ERROR"
    assert excinfo.value.detail == 'params/entryId must match format "uuid"'


@respx.mock
def test_a_text_error_page_is_still_the_message():
    respx.get(f"{BASE}/v1/records").mock(
        return_value=httpx.Response(
            502, text="upstream connect error", headers={"content-type": "text/plain"}
        )
    )
    with pytest.raises(Exception) as excinfo:
        AgledgerClient(base_url=BASE, api_key="k", max_retries=0).records.list()
    assert getattr(excinfo.value, "detail", None) == "upstream connect error"
