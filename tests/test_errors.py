"""Tests for error hierarchy and classification."""

import httpx
import pytest
import respx

from agledger import AgledgerClient
from agledger._errors import (
    APIError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    UnprocessableError,
)


@respx.mock
def test_401_raises_authentication_error():
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(401, json={"message": "Invalid key", "code": "invalid_key"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="bad-key", max_retries=0)
    with pytest.raises(AuthenticationError) as exc_info:
        client.records.get("x")
    assert exc_info.value.status == 401
    assert exc_info.value.is_auth_error()
    assert not exc_info.value.is_retryable()


@respx.mock
def test_403_raises_permission_denied_with_scopes_top_level():
    """RFC 9457 — missingScopes is a top-level extension field."""
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(403, json={
            "message": "Missing scope",
            "code": "insufficient_scopes",
            "missingScopes": ["records:read"],
            "details": {"keyScopes": ["health:read"]},
        })
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(PermissionDeniedError) as exc_info:
        client.records.get("x")
    assert exc_info.value.missing_scopes == ["records:read"]
    assert exc_info.value.key_scopes == ["health:read"]


@respx.mock
def test_403_legacy_nested_missing_scopes():
    """Falls back to details.missingScopes when not at top level."""
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(403, json={
            "message": "Missing scope",
            "code": "insufficient_scopes",
            "details": {"missingScopes": ["records:read"], "keyScopes": ["health:read"]},
        })
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(PermissionDeniedError) as exc_info:
        client.records.get("x")
    assert exc_info.value.missing_scopes == ["records:read"]


@respx.mock
def test_404_raises_not_found():
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(404, json={"message": "Not found", "code": "not_found"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(NotFoundError):
        client.records.get("x")


@respx.mock
def test_400_raises_bad_request():
    respx.post("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(400, json={"message": "Missing field", "code": "validation_error"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(BadRequestError) as exc_info:
        client.records.create(type="notarize-generic-v1", criteria={})
    assert exc_info.value.is_input_error()


@respx.mock
def test_422_raises_unprocessable_with_recovery_hint():
    respx.post("https://agledger.example.com/v1/records/x/transition").mock(
        return_value=httpx.Response(422, json={
            "message": "Wrong state",
            "code": "INVALID_ACTION",
            "recoveryHint": "Re-fetch nextActions",
            "refreshUrl": "/v1/records/x",
        })
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(UnprocessableError) as exc_info:
        client.records.transition("x", "activate")
    assert exc_info.value.is_state_error()
    assert exc_info.value.recovery_hint == "Re-fetch nextActions"
    assert exc_info.value.refresh_url == "/v1/records/x"


@respx.mock
def test_429_raises_rate_limit_with_retry_after():
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(
            429,
            json={"message": "Rate limited"},
            headers={"retry-after": "2.5"},
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(RateLimitError) as exc_info:
        client.records.get("x")
    assert exc_info.value.retry_after == 2.5
    assert exc_info.value.is_retryable()


def test_doc_url_forwards_api_field():
    err = APIError(
        422,
        code="RECORD_NOT_ACTIVE",
        message="Wrong state",
        doc_url="https://www.agledger.ai/docs/errors/RECORD_NOT_ACTIVE",
    )
    assert err.doc_url == "https://www.agledger.ai/docs/errors/RECORD_NOT_ACTIVE"


def test_doc_url_none_when_api_omits_it():
    err = APIError(422, code="RECORD_NOT_ACTIVE", message="Wrong state")
    assert err.doc_url is None


def test_suggestion_forwards_api_field():
    err = APIError(404, message="Not found", suggestion="Check the ID")
    assert err.suggestion == "Check the ID"


def test_suggestion_none_when_api_omits_it():
    err = APIError(404, message="Not found")
    assert err.suggestion is None


def test_recovery_hint_forwards_api_field():
    err = APIError(422, message="Bad state", recovery_hint="Re-fetch state", refresh_url="/v1/records/x")
    assert err.recovery_hint == "Re-fetch state"
    assert err.refresh_url == "/v1/records/x"


def test_recovery_hint_none_when_api_omits_it():
    err = APIError(422, message="Bad state")
    assert err.recovery_hint is None
    assert err.refresh_url is None


def test_error_repr():
    err = APIError(422, code="RECORD_NOT_ACTIVE", message="Wrong state")
    assert "RECORD_NOT_ACTIVE" in repr(err)
    assert "422" in repr(err)


@respx.mock
def test_non_json_error_response():
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(APIError) as exc_info:
        client.records.get("x")
    assert exc_info.value.status == 500
