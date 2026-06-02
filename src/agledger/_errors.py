"""
AGLedger SDK — Error classes.
Follows Anthropic/OpenAI naming conventions. Never shadows Python builtins.
"""

from __future__ import annotations

from typing import Any


class AgledgerError(Exception):
    """Base error for all SDK errors."""

    pass


class APIError(AgledgerError):
    """API returned an error response.

    Fields mirror the API error body verbatim. The SDK does not invent content:
    ``doc_url``, ``suggestion``, ``recovery_hint``, and ``refresh_url`` only
    appear when the API returns them.

    Key properties for consumers:

    - ``status`` — HTTP status code
    - ``code`` — stable machine-readable error code (from API body)
    - ``retryable`` — API's ``retryable`` flag, falling back to status-based classification (429/5xx)
    - ``request_id`` — correlation ID (from API body or ``X-Request-Id`` header)
    - ``doc_url`` — documentation link, only if the API returned one
    - ``suggestion`` — typo-correction hint, only if the API returned one
    - ``recovery_hint`` — machine-readable recovery guidance (e.g. on 422 INVALID_ACTION)
    - ``refresh_url`` — concrete GET URL to re-fetch state (e.g. on 422 INVALID_ACTION)
    """

    status: int
    code: str
    request_id: str | None
    details: Any | None
    retryable: bool
    doc_url: str | None
    suggestion: str | None
    recovery_hint: str | None
    refresh_url: str | None
    raw_body: bytes | None
    """Raw response body for binary endpoints (``application/cose``,
    ``application/concise-problem-details+cbor``). Set when the API returns
    a 4xx/5xx on a SCITT or attestation endpoint — decode with ``cbor2`` for
    SCITT problem-details (RFC 9290)."""

    def __init__(
        self,
        status: int,
        *,
        message: str = "",
        code: str = "unknown",
        request_id: str | None = None,
        details: Any | None = None,
        retryable: bool | None = None,
        suggestion: str | None = None,
        doc_url: str | None = None,
        recovery_hint: str | None = None,
        refresh_url: str | None = None,
        raw_body: bytes | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.request_id = request_id
        self.details = details
        self.retryable = retryable if retryable is not None else (status == 429 or status >= 500)
        self.doc_url = doc_url
        self.suggestion = suggestion
        self.recovery_hint = recovery_hint
        self.refresh_url = refresh_url
        self.raw_body = raw_body
        super().__init__(message or f"API error {status}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(status={self.status}, code={self.code!r}, message={str(self)!r})"

    def is_retryable(self) -> bool:
        """Whether this error can be retried (429, 5xx, network errors)."""
        return self.retryable

    def is_input_error(self) -> bool:
        """Whether this is a 400 validation error — fix the request and retry."""
        return self.status == 400

    def is_state_error(self) -> bool:
        """Whether this is a 422 state error — resource is in the wrong state."""
        return self.status == 422

    def is_auth_error(self) -> bool:
        """Whether this is an auth error (401/403)."""
        return self.status in (401, 403)


class AuthenticationError(APIError):
    """401 — invalid or missing API key."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(401, **kwargs)


class PermissionDeniedError(APIError):
    """403 — insufficient scopes or permissions."""

    missing_scopes: list[str]
    key_scopes: list[str] | None

    def __init__(
        self,
        *,
        missing_scopes: list[str] | None = None,
        key_scopes: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.missing_scopes = missing_scopes or []
        self.key_scopes = key_scopes
        super().__init__(403, **kwargs)


class NotFoundError(APIError):
    """404 — resource not found."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(404, **kwargs)


class BadRequestError(APIError):
    """400 — request validation failed."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(400, **kwargs)


class ConflictError(APIError):
    """409 — conflict (e.g., idempotency key reuse, state conflict)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(409, **kwargs)


class UnprocessableError(APIError):
    """422 — resource in wrong state for the requested operation.

    On INVALID_ACTION the API attaches ``recovery_hint`` and ``refresh_url``
    (and ``current_state`` / ``allowed_actions`` via ``details``) — surfaced on
    the base ``APIError`` properties.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(422, **kwargs)


class RateLimitError(APIError):
    """429 — rate limit exceeded."""

    retry_after: float | None

    def __init__(self, *, retry_after: float | None = None, **kwargs: Any) -> None:
        self.retry_after = retry_after
        super().__init__(429, **kwargs)


class APIConnectionError(AgledgerError):
    """Network connectivity error."""

    pass


class APITimeoutError(APIConnectionError):
    """Request timed out."""

    pass


class SignatureVerificationError(Exception):
    """Raised when webhook signature verification fails."""

    def __init__(self, message: str, payload: bytes | None = None) -> None:
        super().__init__(message)
        self.payload = payload
