"""
AGLedger SDK: Error classes.
Follows Anthropic/OpenAI naming conventions. Never shadows Python builtins.
"""

from __future__ import annotations

from typing import Any


class AgledgerError(Exception):
    """Base error for all SDK errors."""



class ConfigurationError(AgledgerError):
    """The client was constructed with configuration it cannot work from.

    Raised at construction, not on the first call, because that is where the
    mistake is. Distinct from :class:`APIError`: nothing was sent, so no
    request was made and nothing was rejected. Mirrors the TypeScript SDK's
    ``ConfigurationError``.
    """



class APIError(AgledgerError):
    """API returned an error response.

    Fields mirror the API error body verbatim. The SDK does not invent content:
    ``suggestion``, ``recovery_hint`` and ``refresh_url`` only appear when the
    API returns them.

    ``str(error)`` is the body's ``detail``, the one human-readable field an API
    2.0 error carries, and ``detail`` holds the same string.

    Key properties for consumers:

    - ``type``: RFC 9457 problem URI (e.g. ``/problems/ambiguous-publisher``). Branch on this, not on prose.
    - ``publishers``: candidate publisher labels on an ambiguous-publisher 422
    - ``registry_version``: the registry slot a schema version conflict is on
    - ``pinned_records`` / ``unattributable_records``: why a schema delete was refused

    - ``status``: HTTP status code
    - ``code``: stable machine-readable error code (the body's ``error``)
    - ``detail``: human-readable explanation of this occurrence
    - ``retryable``: API's ``retryable`` flag, falling back to status-based classification (429/5xx)
    - ``request_id``: correlation ID (from API body or ``X-Request-Id`` header)
    - ``suggestion``: typo-correction hint, only if the API returned one
    - ``recovery_hint``: machine-readable recovery guidance (e.g. on 422 INVALID_ACTION)
    - ``reason`` / ``current_state`` / ``allowed_actions``: the refusal's reason code, the
      state it found, and what is allowed now
    - ``existing_id``: the row a 409 collided with (e.g. TRUSTED_ISSUER_EXISTS)
    - ``refresh_url``: concrete GET URL to re-fetch state (e.g. on 422 INVALID_ACTION)
    """

    status: int
    code: str
    detail: str
    """Human-readable explanation of this occurrence, from the body's ``detail``.
    Also what ``str(error)`` returns."""
    request_id: str | None
    details: Any | None
    retryable: bool
    type: str | None
    """RFC 9457 problem URI, from the body's ``type``, when the failure carries a
    narrower one than its status class (e.g. ``/problems/ambiguous-publisher``).
    Branch on this rather than on detail prose. The bulk-create envelope calls
    the same value ``problemType``."""
    publishers: list[str] | None
    """Candidate publisher labels on a 422 ``/problems/ambiguous-publisher``: the
    type is offered by more than one publisher, so the engine refuses to pick.
    Re-send pinned to one of these (``publisher=`` on ``records.create``, or on a
    schema read)."""
    registry_version: int | None
    """Registry version slot a schema conflict is on: the integer MAJOR component
    of ``manifest.version``. Minor and patch bumps stay in the same slot, so
    escaping a ``CONFLICTING_VERSION`` 409 needs a major bump."""
    pinned_records: int | None
    """Why a ``schemas.delete()`` was refused: Records written against the exact
    registration the delete would have removed. Paired with
    ``unattributable_records``, and the pair is the whole diagnosis. A non-zero
    ``pinned_records`` is fixable by deleting the other publisher's registration
    instead; a non-zero ``unattributable_records`` is not."""
    unattributable_records: int | None
    """Records of this type carrying no registration pin. They block a delete
    under any publisher label, so this can be non-zero while ``pinned_records``
    is 0 and the delete still fails."""
    suggestion: str | None
    recovery_hint: str | None
    reason: str | None
    """Machine-readable reason code, forwarded from the body. On a 401 OIDC
    refusal it names the token check that failed (``expired``,
    ``wrong_audience``, ``wrong_azp``, ``jti_replayed``, ...); on a 409 it
    names the conflict (``TRUSTED_ISSUER_EXISTS``, ``AGENT_NAME_IN_USE``,
    ...). Branch on this rather than on the detail prose."""
    current_state: str | None
    """State the resource was in when the request was refused, forwarded from
    the body. Some refusals name their precondition here instead, such as the
    cert exchange's 422 ``scope_claim_admin_only``."""
    allowed_actions: list[str] | None
    """Actions the resource accepts right now, forwarded from the body. Ground
    truth for the next call."""
    existing_id: str | None
    """ID of the row already holding the unique key this request collided
    with. Present on 409 ``TRUSTED_ISSUER_EXISTS``: read or PATCH that row
    rather than creating another."""
    refresh_url: str | None
    deadline: str | None
    """ISO deadline that had already passed on a system TIME_OUT 422 (API v1.3.2)."""
    raw_body: bytes | None
    """Raw response body for binary endpoints (``application/cose``,
    ``application/concise-problem-details+cbor``). Set when the API returns
    a 4xx/5xx on a SCITT or attestation endpoint: decode with ``cbor2`` for
    SCITT problem-details (RFC 9290)."""

    def __init__(
        self,
        status: int,
        *,
        detail: str = "",
        code: str = "unknown",
        request_id: str | None = None,
        details: Any | None = None,
        retryable: bool | None = None,
        suggestion: str | None = None,
        recovery_hint: str | None = None,
        refresh_url: str | None = None,
        deadline: str | None = None,
        reason: str | None = None,
        current_state: str | None = None,
        allowed_actions: list[str] | None = None,
        existing_id: str | None = None,
        type: str | None = None,
        publishers: list[str] | None = None,
        registry_version: int | None = None,
        pinned_records: int | None = None,
        unattributable_records: int | None = None,
        raw_body: bytes | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.request_id = request_id
        self.details = details
        self.retryable = retryable if retryable is not None else (status == 429 or status >= 500)
        self.type = type
        self.publishers = publishers
        self.registry_version = registry_version
        self.pinned_records = pinned_records
        self.unattributable_records = unattributable_records
        self.suggestion = suggestion
        self.recovery_hint = recovery_hint
        self.reason = reason
        self.current_state = current_state
        self.allowed_actions = allowed_actions
        self.existing_id = existing_id
        self.refresh_url = refresh_url
        self.deadline = deadline
        self.raw_body = raw_body
        self.detail = detail or f"API error {status}"
        super().__init__(self.detail)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(status={self.status}, code={self.code!r}, detail={self.detail!r})"

    def is_retryable(self) -> bool:
        """Whether this error can be retried (429, 5xx, network errors)."""
        return self.retryable

    def is_input_error(self) -> bool:
        """Whether this is a 400 validation error; fix the request and retry."""
        return self.status == 400

    def is_state_error(self) -> bool:
        """Whether this is a 422 state error: resource is in the wrong state."""
        return self.status == 422

    def is_auth_error(self) -> bool:
        """Whether this is an auth error (401/403)."""
        return self.status in (401, 403)


class AuthenticationError(APIError):
    """401: invalid or missing API key."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(401, **kwargs)


class PermissionDeniedError(APIError):
    """403: insufficient scopes or permissions."""

    missing_scopes: list[str]
    """Scopes the route requires that the credential does not hold, from the
    body's ``missingScopes``. Empty when the refusal is not a scope check."""

    def __init__(
        self,
        *,
        missing_scopes: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.missing_scopes = missing_scopes or []
        super().__init__(403, **kwargs)


class NotFoundError(APIError):
    """404: resource not found."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(404, **kwargs)


class BadRequestError(APIError):
    """400: request validation failed."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(400, **kwargs)


class ConflictError(APIError):
    """409: conflict (e.g., idempotency key reuse, state conflict)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(409, **kwargs)


class UnprocessableError(APIError):
    """422: resource in wrong state for the requested operation.

    On INVALID_ACTION the API attaches ``recovery_hint`` and ``refresh_url``
    (and ``current_state`` / ``allowed_actions`` via ``details``); surfaced on
    the base ``APIError`` properties.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(422, **kwargs)


class RateLimitError(APIError):
    """429: rate limit exceeded."""

    retry_after: float | None

    def __init__(self, *, retry_after: float | None = None, **kwargs: Any) -> None:
        self.retry_after = retry_after
        super().__init__(429, **kwargs)


class APIConnectionError(AgledgerError):
    """Network connectivity error."""



class APITimeoutError(APIConnectionError):
    """Request timed out."""



class PaginationLimitError(AgledgerError):
    """An auto-paginating walk stopped short of the listing without being asked
    to, so the rows it yielded are a prefix rather than all of it.

    Usually the default page ceiling, with pages still available. The ceiling is
    a runaway guard, not a result. Raising is what separates it from the
    intentional stop: pass ``max_pages`` explicitly and the walk ends quietly at
    your bound, because you asked for one.

    Recover by raising ``limit`` so the same rows arrive in fewer pages, by
    passing a ``max_pages`` large enough for the listing, or by narrowing the
    filters.

    The same rule covers the other unrequested truncation: a page that carries
    rows but no resume token leaves the walk with nowhere to go, and returning
    quietly there would read as the end of the data. Pass ``message`` to say so
    in those words; ``max_pages`` then describes the ceiling that was in force,
    not the reason it stopped.
    """

    def __init__(
        self,
        path: str,
        pages_read: int,
        items_yielded: int,
        max_pages: int,
        *,
        message: str | None = None,
    ) -> None:
        super().__init__(
            message
            or f"Pagination of {path} stopped at the {max_pages}-page ceiling after "
            f"{items_yielded} item(s), and the listing has more. Raise 'limit' to fit "
            f"the walk in fewer pages, or pass 'max_pages' to lift the ceiling."
        )
        self.path = path
        """Path being walked."""
        self.pages_read = pages_read
        """Pages fetched before stopping: equal to the ceiling that stopped it."""
        self.items_yielded = items_yielded
        """Items yielded before stopping. All are valid; they are just not all of them."""
        self.max_pages = max_pages
        """Ceiling that was hit."""


class SignatureVerificationError(Exception):
    """Raised when webhook signature verification fails."""

    def __init__(self, message: str, payload: bytes | None = None) -> None:
        super().__init__(message)
        self.payload = payload


class SignatureAlgorithmUnavailableError(Exception):
    """The host runtime refuses to compute the algorithm a signing key commits
    to, so the signature could not be checked at all.

    Distinct from :class:`SignatureVerificationError` on purpose, and raised
    rather than reported as a verification failure. "I could not check this"
    and "I checked this and it failed" call for opposite responses: the first
    is your server's configuration, the second is a rejected delivery.
    Returning ``False`` for both made a FIPS-locked receiver 401 every
    legitimate ed25519 delivery as though it were forged, with nothing anywhere
    saying why.

    The usual cause is an active OpenSSL FIPS provider, which carries no EdDSA.
    Either terminate the ed25519 webhook signature somewhere unrestricted, or
    configure the sender for ``ecdsa-p256-sha256``, which FIPS does permit.
    """

    def __init__(self, message: str, algorithm: str | None = None) -> None:
        super().__init__(message)
        self.algorithm = algorithm
