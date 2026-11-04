"""Errors on the binary (SCITT, attestation) routes."""

import httpx
import pytest
import respx

from agledger import AgledgerClient
from agledger._errors import APIError, BadRequestError, NotFoundError

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


@respx.mock
def test_a_proxy_html_page_on_a_json_route_stays_on_raw_body():
    page = b"<html>bad gateway</html>"
    respx.get(f"{BASE}/v1/records/x").mock(
        return_value=httpx.Response(502, content=page, headers={"content-type": "text/html"})
    )
    with pytest.raises(APIError) as excinfo:
        AgledgerClient(base_url=BASE, api_key="k", max_retries=0).records.get("x")
    err = excinfo.value
    assert err.status == 502
    assert err.raw_body == page
    assert err.detail == page.decode()
    assert err.body == {}


@respx.mock
def test_a_json_error_body_leaves_raw_body_unset():
    respx.get(f"{BASE}/v1/records/x").mock(
        return_value=httpx.Response(
            404, json={"error": "NOT_FOUND", "detail": "gone"}, headers={"content-type": "application/problem+json"}
        )
    )
    with pytest.raises(NotFoundError) as excinfo:
        AgledgerClient(base_url=BASE, api_key="k").records.get("x")
    assert excinfo.value.raw_body is None
    assert excinfo.value.body == {"error": "NOT_FOUND", "detail": "gone"}


@respx.mock
def test_a_json_array_error_body_is_not_an_object_and_does_not_crash():
    respx.get(f"{BASE}/v1/records/x").mock(
        return_value=httpx.Response(400, json=["nope"], headers={"content-type": "application/json"})
    )
    with pytest.raises(BadRequestError) as excinfo:
        AgledgerClient(base_url=BASE, api_key="k").records.get("x")
    assert excinfo.value.raw_body == b'["nope"]'
    assert excinfo.value.body == {}
