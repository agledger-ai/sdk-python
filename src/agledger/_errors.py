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
    - ``valid_transitions``: targets reachable now, on a 422 refusal (a Record's
      display states, or a dispute's statuses)
    - ``existing_id``: the row a 409 collided with (e.g. TRUSTED_ISSUER_EXISTS)
    - ``refresh_url``: concrete GET URL to re-fetch state (e.g. on 422 INVALID_ACTION)
    - ``required_fields`` / ``optional_fields`` / ``example_payload`` / ``schema_url`` /
      ``record_type``: the rebuild kit a 400 carries when a Record or Completion body
      failed its schema
    - ``hint``: the 404's pointer at what to list or create instead
    - ``attempted_action`` / ``attempted_transition`` / ``attempted_state``: what a 422 refused
    - ``retry_after``: seconds the Server or a proxy asked the client to wait, from the
      ``Retry-After`` header on any status (a 429 body's ``retryAfterSeconds`` fills it too)
    - ``body``: the parsed error body as sent, every field included, for anything this
      class does not name
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
    ``wrong_audience``, ``wrong_azp``, ``jti_replayed``, ...); on a 409 that
    carries one it names the conflict: ``STATUS_NOT_DISABLED``,
    ``ACCOUNT_DEACTIVATED``, ``RECORDS_REFERENCE_TYPE``, ``CONFLICTING_VERSION``,
    ``RESERVED_PUBLISHER_LABEL``, ``PROVISIONING_MANAGED``, ``OIDC_JTI_REPLAY``,
    ``ROW_HAS_DEPENDENT_RECORDS``, ``CHAIN_REWIND_DETECTED``,
    ``VAULT_SCAN_IN_FLIGHT``, ``AGENT_NAME_IN_USE``, ``TRUSTED_ISSUER_EXISTS`` or
    ``KEY_ALREADY_ROTATED``. Not every 409 names one (a duplicate agent
    ``displayName`` answers ``error: CONFLICT`` with no reason today), so branch
    on ``code`` first and on ``reason`` when present."""
    current_state: str | None
    """State the resource was in when the request was refused, forwarded from
    the body. Some refusals name their precondition here instead, such as the
    cert exchange's 422 ``scope_claim_admin_only``."""
    allowed_actions: list[str] | None
    """Actions the resource accepts right now, forwarded from the body. Ground
    truth for the next call."""
    valid_transitions: list[str] | None
    """Targets reachable now, forwarded from the body on a 422 refusal: the
    display states a Record can reach on a refusal about a Record, or the
    dispute's own target statuses on a refused dispute move."""
    existing_id: str | None
    """ID of the row already holding the unique key this request collided
    with. Present on 409 ``TRUSTED_ISSUER_EXISTS``: read or PATCH that row
    rather than creating another."""
    refresh_url: str | None
    deadline: str | None
    """ISO deadline that had already passed on a system TIME_OUT 422 (API v1.3.2)."""
    title: str | None
    """RFC 9457 ``title``: the short name of the problem class."""
    instance: str | None
    """RFC 9457 ``instance``: the request path this occurrence belongs to."""
    errors: list[Any] | None
    """Field-level errors as the body carries them top level (RFC 9457
    extension). ``validation_errors`` is the normalized view."""
    validation_errors: list[dict[str, Any]] | None
    """Schema violations on a 400 or 422, each with ``field`` (or Ajv's
    ``instancePath``) and ``message``, from the body's top-level
    ``validationErrors``."""
    hint: str | None
    """The 404's pointer at what to do instead of retrying the same id: which
    listing to read, or which create to run first."""
    required_fields: list[str] | None
    """Fields the schema requires, on a 400 that refused a Record or
    Completion body."""
    optional_fields: list[str] | None
    """Fields the schema allows beyond the required ones, on the same 400."""
    example_payload: dict[str, Any] | None
    """A payload that passes the schema the 400 refused against. Rebuild
    from it rather than from prose."""
    schema_url: str | None
    """Where the schema the 400 validated against is served."""
    record_type: str | None
    """The contract type the 400 validated against."""
    attempted_action: str | None
    """The action a 422 refused (``transition``, ``verdict``, ``cancel``, ...)."""
    attempted_transition: str | None
    """The transition name a 422 refused."""
    attempted_state: str | None
    """The display state a refused transition tried to reach."""
    allowed_values: list[Any] | None
    """Values the refused field accepts, when a 400 or 422 can enumerate them."""
    allowed_actors: list[str] | None
    """Role labels permitted to take the refused action."""
    constraint_violations: list[dict[str, Any]] | None
    """The bounds the request broke (``field``, ``parentValue``,
    ``childValue``, ``reason``, ``tolerance``)."""
    missing_features: list[str] | None
    """License features the current tier lacks, on a 403 license refusal."""
    current_tier: str | None
    required_tier: str | None
    next_steps: list[dict[str, Any]] | None
    """Guided next actions the error body carries."""
    terminal_reason: str | None
    """The system action that terminalized the Record (``OVERFLOW_REJECT``,
    ``TIME_OUT``, ...), beside ``previous_status``."""
    previous_status: str | None
    current_status: str | None
    """Display status of the Record when the request was refused."""
    retry_after: float | None
    """Seconds the client was asked to wait before retrying, from the
    ``Retry-After`` header on any status (a load balancer sends one on a 503
    as the Server does on a 429), or from a 429 body's ``retryAfterSeconds``
    when the header was stripped. None when neither was given. The SDK's own
    retries wait at least this long."""
    body: dict[str, Any]
    """The error body as the Server sent it, parsed, every field included.
    Everything this class names is a typed view onto it; read this for a
    field the view does not name yet. Empty for a body that was not JSON."""
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
        valid_transitions: list[str] | None = None,
        existing_id: str | None = None,
        type: str | None = None,
        publishers: list[str] | None = None,
        registry_version: int | None = None,
        pinned_records: int | None = None,
        unattributable_records: int | None = None,
        raw_body: bytes | None = None,
        title: str | None = None,
        instance: str | None = None,
        errors: list[Any] | None = None,
        validation_errors: list[dict[str, Any]] | None = None,
        hint: str | None = None,
        required_fields: list[str] | None = None,
        optional_fields: list[str] | None = None,
        example_payload: dict[str, Any] | None = None,
        schema_url: str | None = None,
        record_type: str | None = None,
        attempted_action: str | None = None,
        attempted_transition: str | None = None,
        attempted_state: str | None = None,
        allowed_values: list[Any] | None = None,
        allowed_actors: list[str] | None = None,
        constraint_violations: list[dict[str, Any]] | None = None,
        missing_features: list[str] | None = None,
        current_tier: str | None = None,
        required_tier: str | None = None,
        next_steps: list[dict[str, Any]] | None = None,
        terminal_reason: str | None = None,
        previous_status: str | None = None,
        current_status: str | None = None,
        retry_after: float | None = None,
        body: dict[str, Any] | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.title = title
        self.instance = instance
        self.errors = errors
        self.validation_errors = validation_errors
        self.hint = hint
        self.required_fields = required_fields
        self.optional_fields = optional_fields
        self.example_payload = example_payload
        self.schema_url = schema_url
        self.record_type = record_type
        self.attempted_action = attempted_action
        self.attempted_transition = attempted_transition
        self.attempted_state = attempted_state
        self.allowed_values = allowed_values
        self.allowed_actors = allowed_actors
        self.constraint_violations = constraint_violations
        self.missing_features = missing_features
        self.current_tier = current_tier
        self.required_tier = required_tier
        self.next_steps = next_steps
        self.terminal_reason = terminal_reason
        self.previous_status = previous_status
        self.current_status = current_status
        self.retry_after = retry_after
        self.body = body if body is not None else {}
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
        self.valid_transitions = valid_transitions
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
    """429: rate limit exceeded. ``retry_after`` is on every :class:`APIError`;
    here it is also read from the body's ``retryAfterSeconds``."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(429, **kwargs)


class APIConnectionError(AgledgerError):
    """Network connectivity error.

    ``idempotency_key`` is the ``Idempotency-Key`` the failed request carried,
    on a write. The SDK reuses it across its own retries, so once they are
    spent the first attempt may still have reached the Server (a proxy can hold
    a 201 past the timeout). Re-send the same call with this key and the Server answers
    with the original result instead of writing twice. The value is the full header as sent
    (any prefix included), so replay it verbatim through
    ``client.request(method, path, json=..., headers={"Idempotency-Key": key})``.
    ``None`` on a request that carries no key (a read).
    """

    idempotency_key: str | None

    def __init__(self, message: str = "", *, idempotency_key: str | None = None) -> None:
        super().__init__(message)
        self.idempotency_key = idempotency_key



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
