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
        return_value=httpx.Response(401, json={"detail": "Invalid key", "error": "UNAUTHORIZED"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="bad-key", max_retries=0)
    with pytest.raises(AuthenticationError) as exc_info:
        client.records.get("x")
    assert exc_info.value.status == 401
    assert exc_info.value.is_auth_error()
    assert not exc_info.value.is_retryable()


@respx.mock
def test_403_raises_permission_denied_with_scopes_top_level():
    """RFC 9457: missingScopes is a top-level extension field."""
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(403, json={
            "detail": "Missing scope",
            "error": "FORBIDDEN",
            "missingScopes": ["records:read"],
        })
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(PermissionDeniedError) as exc_info:
        client.records.get("x")
    assert exc_info.value.missing_scopes == ["records:read"]
    assert exc_info.value.code == "FORBIDDEN"
    assert str(exc_info.value) == "Missing scope"


@respx.mock
def test_403_without_missing_scopes_is_an_empty_list():
    """``details`` is an array on API 2.0, so nothing is read out of it."""
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(403, json={
            "detail": "Not a party to this record",
            "error": "FORBIDDEN",
            "details": [{"field": "recordId"}],
        })
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(PermissionDeniedError) as exc_info:
        client.records.get("x")
    assert exc_info.value.missing_scopes == []
    assert exc_info.value.details == [{"field": "recordId"}]


@respx.mock
def test_404_raises_not_found():
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(404, json={"detail": "Not found", "error": "NOT_FOUND"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(NotFoundError):
        client.records.get("x")


@respx.mock
def test_400_raises_bad_request():
    respx.post("https://agledger.example.com/v1/records").mock(
        return_value=httpx.Response(400, json={"detail": "Missing field", "error": "VALIDATION_ERROR"})
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(BadRequestError) as exc_info:
        client.records.create(type="notarize-generic-v1", criteria={})
    assert exc_info.value.is_input_error()


@respx.mock
def test_422_raises_unprocessable_with_recovery_hint():
    respx.post("https://agledger.example.com/v1/records/x/transition").mock(
        return_value=httpx.Response(422, json={
            "detail": "Wrong state",
            "error": "INVALID_ACTION",
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
            json={"detail": "Rate limited", "error": "RATE_LIMITED"},
            headers={"retry-after": "2.5"},
        )
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(RateLimitError) as exc_info:
        client.records.get("x")
    assert exc_info.value.retry_after == 2.5
    assert exc_info.value.is_retryable()


@respx.mock
def test_the_error_is_built_from_detail():
    """API 2.0 error bodies carry no ``message``: ``detail`` is the one
    human-readable field, and a body naming ``message`` is not read."""
    respx.get("https://agledger.example.com/v1/records/x").mock(
        return_value=httpx.Response(422, json={
            "type": "/problems/unprocessable",
            "title": "Unprocessable Entity",
            "status": 422,
            "detail": "Record is not ACTIVE.",
            "instance": "/v1/records/x",
            "retryable": False,
            "error": "RECORD_NOT_ACTIVE",
            "requestId": "req-1",
            "message": "ignored",
        })
    )
    client = AgledgerClient(base_url="https://agledger.example.com", api_key="test", max_retries=0)
    with pytest.raises(UnprocessableError) as exc_info:
        client.records.get("x")
    err = exc_info.value
    assert str(err) == "Record is not ACTIVE."
    assert err.detail == "Record is not ACTIVE."
    assert err.code == "RECORD_NOT_ACTIVE"
    assert err.request_id == "req-1"
    assert err.type == "/problems/unprocessable"
    assert not hasattr(err, "doc_url")
    assert not hasattr(err, "docs")


def test_detail_defaults_to_the_status():
    assert str(APIError(503)) == "API error 503"


def test_suggestion_forwards_api_field():
    err = APIError(404, detail="Not found", suggestion="Check the ID")
    assert err.suggestion == "Check the ID"


def test_suggestion_none_when_api_omits_it():
    err = APIError(404, detail="Not found")
    assert err.suggestion is None


def test_recovery_hint_forwards_api_field():
    err = APIError(422, detail="Bad state", recovery_hint="Re-fetch state", refresh_url="/v1/records/x")
    assert err.recovery_hint == "Re-fetch state"
    assert err.refresh_url == "/v1/records/x"


def test_recovery_hint_none_when_api_omits_it():
    err = APIError(422, detail="Bad state")
    assert err.recovery_hint is None
    assert err.refresh_url is None


def test_error_repr():
    err = APIError(422, code="RECORD_NOT_ACTIVE", detail="Wrong state")
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
    assert str(exc_info.value) == "Internal Server Error"


@respx.mock
def test_a_409_carries_the_row_it_collided_with_and_its_reason():
    """``existingId`` names the row a 409 TRUSTED_ISSUER_EXISTS collided with,
    so the caller can read or PATCH it instead of creating another."""
    respx.post("https://agledger.example.com/v1/admin/trusted-issuers").mock(
        return_value=httpx.Response(
            409,
            json={
                "error": "CONFLICT",
                "detail": "A trusted issuer already holds this key.",
                "reason": "TRUSTED_ISSUER_EXISTS",
                "existingId": "22222222-2222-4222-8222-222222222222",
            },
        )
    )
    client = AgledgerClient(api_key="agl_plt_test", base_url="https://agledger.example.com")
    with pytest.raises(APIError) as info:
        client.request("POST", "/v1/admin/trusted-issuers", json={})
    assert info.value.reason == "TRUSTED_ISSUER_EXISTS"
    assert info.value.existing_id == "22222222-2222-4222-8222-222222222222"


@respx.mock
def test_a_422_carries_current_state_and_allowed_actions():
    respx.post("https://agledger.example.com/v1/records/r/transition").mock(
        return_value=httpx.Response(
            422,
            json={
                "error": "INVALID_ACTION",
                "detail": "Not in this state.",
                "currentState": "ACTIVE",
                "allowedActions": ["cancel", "submit-completion"],
            },
        )
    )
    client = AgledgerClient(api_key="agl_agt_test", base_url="https://agledger.example.com")
    with pytest.raises(UnprocessableError) as info:
        client.request("POST", "/v1/records/r/transition", json={"action": "activate"})
    assert info.value.current_state == "ACTIVE"
    assert info.value.allowed_actions == ["cancel", "submit-completion"]
    assert info.value.valid_transitions is None
    assert info.value.existing_id is None
    assert info.value.reason is None


@respx.mock
def test_a_refusal_about_a_record_carries_its_valid_transitions():
    respx.post("https://agledger.example.com/v1/records/r/verdict").mock(
        return_value=httpx.Response(
            422,
            json={
                "error": "INVALID_ACTION",
                "detail": "A verdict is refused on a FAILED record.",
                "currentState": "FAILED",
                "allowedActions": [],
                "validTransitions": ["DISPUTED"],
            },
        )
    )
    client = AgledgerClient(api_key="agl_agt_test", base_url="https://agledger.example.com")
    with pytest.raises(UnprocessableError) as info:
        client.request("POST", "/v1/records/r/verdict", json={"completionId": "c", "verdict": "accept"})
    assert info.value.valid_transitions == ["DISPUTED"]
