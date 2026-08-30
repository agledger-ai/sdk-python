"""
AGLedger SDK: HTTP client with retry, idempotency, and error mapping.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
import uuid
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import Any, cast

import httpx

from agledger._errors import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    ConfigurationError,
    ConflictError,
    NotFoundError,
    PaginationLimitError,
    PermissionDeniedError,
    RateLimitError,
    UnprocessableError,
)

# No default base URL. A placeholder resolved nowhere, so a client built
# without one constructed fine and then failed every call against a host the
# caller never named and could only find by reading the SDK source. Every
# AGLedger deployment is self-hosted, so there was never a sensible default
# (fixed in the TypeScript SDK at 1.7.0 and mirrored here).
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
MAX_BACKOFF = 30.0
# Runaway guard on an unbounded auto-paginating walk. Hitting it is an error,
# not a stopping point: see HttpClient.paginate.
DEFAULT_MAX_PAGES = 100
# Single source of truth for the SDK version: the installed package metadata
# (pyproject `version`). Used in the User-Agent header and re-exported as
# `agledger.__version__`, so neither can drift from the published distribution.
def _resolve_sdk_version() -> str:
    try:
        return _pkg_version("agledger")
    except PackageNotFoundError:  # pragma: no cover - source tree without install
        return "0.0.0+unknown"


SDK_VERSION = _resolve_sdk_version()

# Aligned with TS SDK (http.ts:#DEFAULT_RETRY_STATUSES). 408 is excluded
# because the API never emits it. 409 IDEMPOTENCY_CONFLICT is excluded
# because auto-retrying it would mask a real client error: a 409 means
# "this idempotency key was already used with a different request body",
# which is structural, not transient.
_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class RateLimitInfo:
    """Snapshot of the ``X-RateLimit-*`` headers from a single API response.

    Captured on every response; readable via ``client.rate_limit_info`` (or
    ``client._http.rate_limit_info``) for the most recent call. Mirrors the TS
    SDK's ``RateLimitInfo`` shape exactly.
    """

    limit: int
    """Max requests allowed in the current window."""
    remaining: int
    """Requests remaining in the current window."""
    reset: int
    """Unix timestamp (seconds) when the window resets."""


def _parse_rate_limit_headers(headers: httpx.Headers) -> RateLimitInfo | None:
    limit = headers.get("x-ratelimit-limit")
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if limit is None or remaining is None or reset is None:
        return None
    try:
        return RateLimitInfo(int(limit), int(remaining), int(reset))
    except (TypeError, ValueError):
        return None
_ERROR_MAP: dict[int, type[APIError]] = {
    400: BadRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    422: UnprocessableError,
    429: RateLimitError,
}


def _parse_holdback_seconds(headers: httpx.Headers) -> int | None:
    """Seconds by which a SIEM stream page stops short of now.

    ``X-AGLedger-Stream-Holdback-Seconds`` rides every 200, including an empty
    one, and a non-zero value is why an empty page is not evidence that nothing
    has happened. Absent (a pre-1.6.0 Server) is reported as ``None`` rather
    than 0, because "no holdback" and "the Server did not say" are different
    answers for a caller deciding whether to keep polling.
    """
    raw = headers.get("x-agledger-stream-holdback-seconds")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def resolve_api_key(api_key: str | None) -> str:
    """Resolve API key from argument or AGLEDGER_API_KEY env var."""
    key = api_key or os.environ.get("AGLEDGER_API_KEY")
    if not key:
        raise AuthenticationError(message="No API key provided. Pass api_key or set AGLEDGER_API_KEY.")
    return key


def _parse_error_body(response: httpx.Response) -> dict[str, Any]:
    try:
        return response.json()
    except Exception:
        return {"message": response.text or f"HTTP {response.status_code}"}


def _build_error(response: httpx.Response) -> APIError:
    body = _parse_error_body(response)
    status = response.status_code
    cls = _ERROR_MAP.get(status, APIError)

    kwargs: dict[str, Any] = {
        "message": body.get("message") or body.get("detail") or body.get("title") or f"API error {status}",
        "code": body.get("code") or body.get("error", "unknown"),
        "request_id": body.get("requestId") or response.headers.get("x-request-id"),
        "details": body.get("details"),
        "retryable": body.get("retryable"),
        "suggestion": body.get("suggestion"),
        "doc_url": body.get("docUrl"),
        "docs": body.get("docs"),
        "recovery_hint": body.get("recoveryHint"),
        "refresh_url": body.get("refreshUrl"),
        "deadline": body.get("deadline"),
        # RFC 9457 problem URI + the ambiguous-publisher candidate list. Both
        # were dropped here, which left the 422 unactionable in code: the
        # recovery hint named a list the caller had no way to read.
        "type": body.get("type"),
        "publishers": body.get("publishers"),
        "registry_version": body.get("registryVersion"),
        # Delete-precondition counts. Same trap as `publishers` above: the
        # recovery hint says the type is still referenced, and without these
        # the caller cannot tell a fixable pin from an unattributable Record
        # that blocks the delete under every label.
        "pinned_records": body.get("pinnedRecords"),
        "unattributable_records": body.get("unattributableRecords"),
    }

    if cls is PermissionDeniedError:
        details: dict[str, Any] = body.get("details") or {}
        # RFC 9457 surfaces missingScopes as a top-level extension field;
        # older bodies nested it under details.
        missing: Any = body.get("missingScopes")
        if not isinstance(missing, list):
            missing = details.get("missingScopes", [])
        kwargs["missing_scopes"] = missing
        kwargs["key_scopes"] = details.get("keyScopes")
    elif cls is RateLimitError:
        # The header is the primary source, but a 429 body also carries
        # `retryAfterSeconds`, and a proxy that strips headers used to leave
        # retry_after None with the answer sitting in the body unread.
        retry_after = response.headers.get("retry-after")
        body_seconds = body.get("retryAfterSeconds")
        if retry_after:
            kwargs["retry_after"] = float(retry_after)
        elif isinstance(body_seconds, (int, float)) and not isinstance(body_seconds, bool):
            kwargs["retry_after"] = float(body_seconds)
        else:
            kwargs["retry_after"] = None

    if cls is APIError:
        return cls(status, **kwargs)
    return cls(**kwargs)


def _backoff(attempt: int, retry_after: float | None = None) -> float:
    if retry_after and retry_after > 0:
        return min(retry_after, MAX_BACKOFF)
    base = min(0.5 * (2**attempt), MAX_BACKOFF)
    jitter = random.uniform(0, base * 0.25)
    return base + jitter


def _query_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Drop empty values and expand mappings into the API's bracket notation.

    ``httpx`` serializes a dict parameter as its Python repr, so
    ``search(metadata={"state": "blocked"})`` went out as
    ``metadata={'state': 'blocked'}`` and came back 400. The engine wants
    ``metadata[state]=blocked``, which is what the ``criteria`` and ``metadata``
    filters on ``GET /v1/records/search`` are documented to take.

    ``datetime`` becomes ISO-8601 rather than ``str(dt)``, whose space separator
    the date-time query params reject.
    """
    out: dict[str, Any] = {}
    for key, value in (params or {}).items():
        if value is None:
            continue
        if isinstance(value, datetime):
            out[key] = value.isoformat()
        elif isinstance(value, Mapping):
            nested = cast("Mapping[str, Any]", value)
            for sub, sub_value in nested.items():
                if sub_value is None:
                    continue
                out[f"{key}[{sub}]"] = (
                    sub_value.isoformat() if isinstance(sub_value, datetime) else sub_value
                )
        else:
            out[key] = value
    return out


def _base_headers(
    api_key: str,
    method: str,
    idempotency_key: str | None = None,
    auth_override: str | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": f"agledger-python/{SDK_VERSION}",
    }
    # Auth override: "none" omits header; any other string becomes Bearer token
    if auth_override == "none":
        pass  # No Authorization header (federation register / self-revoke)
    elif auth_override:
        headers["Authorization"] = f"Bearer {auth_override}"
    else:
        headers["Authorization"] = f"Bearer {api_key}"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
    return headers


class HttpClient:
    """Synchronous HTTP client for AGLedger API."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        idempotency_key_prefix: str = "",
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key
        if not base_url:
            raise ConfigurationError(
                "base_url is required. AGLedger is self-hosted, so the SDK cannot guess "
                "your Server: pass the base URL of your instance, e.g. "
                'AgledgerClient(api_key=..., base_url="https://agledger.internal").'
            )
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._timeout = timeout
        self._idempotency_key_prefix = idempotency_key_prefix
        self._client = http_client or httpx.Client(timeout=timeout)
        self._owns_client = http_client is None
        self.last_request_id: str | None = None
        """Request ID from the most recent API response (``X-Request-Id`` header)."""
        self.rate_limit_info: RateLimitInfo | None = None
        """Rate-limit headers from the most recent response (``X-RateLimit-*``).
        ``None`` until the first response that carries them."""

    def _capture_response_meta(self, response: httpx.Response) -> None:
        """Pull ``X-Request-Id`` + ``X-RateLimit-*`` headers off a response onto
        ``self``. Called from every request path so observability fields stay in
        sync. Missing rate-limit headers leave the previous snapshot intact."""
        self.last_request_id = response.headers.get("x-request-id")
        self.rate_limit_info = _parse_rate_limit_headers(response.headers) or self.rate_limit_info

    def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owns_client:
            self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        timeout: float | None = None,
        auth_override: str | None = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        key = f"{self._idempotency_key_prefix}{idempotency_key}" if idempotency_key else None
        headers = _base_headers(self._api_key, method, key, auth_override=auth_override)
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(
                    method,
                    url,
                    headers=headers,
                    json=json,
                    params=_query_params(params),
                    timeout=timeout or self._timeout,
                )

                self._capture_response_meta(response)

                if response.status_code >= 400:
                    error = _build_error(response)
                    if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                        retry_after = getattr(error, "retry_after", None)
                        time.sleep(_backoff(attempt, retry_after))
                        last_error = error
                        continue
                    raise error

                if response.status_code == 204:
                    return None
                return response.json()

            except httpx.ConnectError as e:
                last_error = APIConnectionError(str(e))
                if attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    continue
                raise last_error from e
            except httpx.TimeoutException as e:
                last_error = APITimeoutError(str(e))
                if attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    continue
                raise last_error from e

        raise last_error or APIError(500, message="Max retries exceeded")

    def get(self, path: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return self.request("GET", path, params=params, **kwargs)

    def post(self, path: str, *, json: Any | None = None, **kwargs: Any) -> Any:
        return self.request("POST", path, json=json, **kwargs)

    def patch(self, path: str, *, json: Any | None = None, **kwargs: Any) -> Any:
        return self.request("PATCH", path, json=json, **kwargs)

    def put(self, path: str, *, json: Any | None = None, **kwargs: Any) -> Any:
        return self.request("PUT", path, json=json, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs)

    def get_bytes(
        self,
        path: str,
        *,
        accept: str = "application/octet-stream",
        params: dict[str, Any] | None = None,
        auth_override: str | None = None,
    ) -> bytes:
        """Binary GET. Returns raw response bytes (no JSON parse). Use for SCITT
        ``application/cose`` / ``application/cose-sequence`` flows.

        Errors: the response body is captured on the raised ``APIError.raw_body``
        attribute (SCITT errors are ``application/concise-problem-details+cbor``
        per RFC 9290, not JSON).
        """
        return self._request_bytes("GET", path, accept=accept, params=params, auth_override=auth_override)

    def post_bytes(
        self,
        path: str,
        *,
        body: bytes,
        content_type: str = "application/octet-stream",
        accept: str = "application/octet-stream",
        auth_override: str | None = None,
    ) -> bytes:
        """Binary POST. Sends ``body`` with ``content_type`` and reads the
        response as raw bytes."""
        return self._request_bytes(
            "POST", path, body=body, content_type=content_type, accept=accept, auth_override=auth_override,
        )

    def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str = "application/octet-stream",
        accept: str = "application/octet-stream",
        params: dict[str, Any] | None = None,
        auth_override: str | None = None,
        timeout: float | None = None,
    ) -> bytes:
        url = f"{self._base_url}{path}"
        idempotency_key = f"{self._idempotency_key_prefix}{uuid.uuid4()}" if method == "POST" else None
        headers = _base_headers(self._api_key, method, idempotency_key, auth_override=auth_override)
        headers["Accept"] = accept
        if body is not None:
            headers["Content-Type"] = content_type
        else:
            headers.pop("Content-Type", None)
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(
                    method,
                    url,
                    headers=headers,
                    content=body,
                    params=_query_params(params),
                    timeout=timeout or self._timeout,
                )
                self._capture_response_meta(response)
                raw = response.content
                if response.status_code >= 400:
                    error = _build_error(response)
                    error.raw_body = raw
                    if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                        retry_after = getattr(error, "retry_after", None)
                        time.sleep(_backoff(attempt, retry_after))
                        last_error = error
                        continue
                    raise error
                return raw
            except httpx.ConnectError as e:
                last_error = APIConnectionError(str(e))
                if attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    continue
                raise last_error from e
            except httpx.TimeoutException as e:
                last_error = APITimeoutError(str(e))
                if attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    continue
                raise last_error from e
        raise last_error or APIError(500, message="Max retries exceeded")

    def get_ndjson(self, path: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Fetch an NDJSON endpoint.

        Returns ``{"data": [...], "cursor": ..., "holdbackSeconds": ...}``.
        """
        url = f"{self._base_url}{path}"
        headers = _base_headers(self._api_key, "GET")
        headers["Accept"] = "application/x-ndjson"
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(
                    "GET",
                    url,
                    headers=headers,
                    params=_query_params(params),
                    timeout=kwargs.get("timeout") or self._timeout,
                )

                if response.status_code >= 400:
                    error = _build_error(response)
                    if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                        retry_after = getattr(error, "retry_after", None)
                        time.sleep(_backoff(attempt, retry_after))
                        last_error = error
                        continue
                    raise error

                import json as _json
                text = response.text
                lines = [line for line in text.split("\n") if line.strip()]
                data = [_json.loads(line) for line in lines]
                cursor = response.headers.get("x-agledger-stream-cursor")
                return {
                    "data": data,
                    "cursor": cursor,
                    "holdbackSeconds": _parse_holdback_seconds(response.headers),
                }

            except httpx.ConnectError as e:
                last_error = APIConnectionError(str(e))
                if attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    continue
                raise last_error from e
            except httpx.TimeoutException as e:
                last_error = APITimeoutError(str(e))
                if attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    continue
                raise last_error from e

        raise last_error or APIError(500, message="Max retries exceeded")

    def get_page(self, path: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self.get(path, params=params, **kwargs)
        if isinstance(raw, list):
            return {"data": raw, "hasMore": False}
        if isinstance(raw, dict) and "data" in raw:
            return cast("dict[str, Any]", raw)
        if isinstance(raw, dict):
            return {"data": [raw], "hasMore": False}
        return {"data": [], "hasMore": False}

    def paginate(
        self, path: str, *, params: dict[str, Any] | None = None, max_pages: int | None = None
    ) -> Iterator[dict[str, Any]]:
        """Walk every page of a listing, yielding rows.

        Unbounded, the walk runs to the end of the listing behind
        :data:`DEFAULT_MAX_PAGES` as a runaway guard, and hitting that guard
        raises :class:`PaginationLimitError` rather than returning a prefix that
        looks like the whole listing. Pass ``max_pages`` to stop early on
        purpose: that bound is yours, so the walk ends at it quietly.
        """
        ceiling = DEFAULT_MAX_PAGES if max_pages is None else max_pages
        p = dict(params or {})
        pages_read = 0
        yielded = 0
        for _ in range(ceiling):
            page = self.get_page(path, params=p)
            pages_read += 1
            rows = page.get("data", [])
            yield from rows
            yielded += len(rows)
            if not page.get("hasMore"):
                return
            cursor = page.get("nextCursor") or page.get("next_cursor")
            if not cursor:
                return
            p["cursor"] = cursor
        if max_pages is None:
            raise PaginationLimitError(path, pages_read, yielded, ceiling)


class AsyncHttpClient:
    """Async HTTP client for AGLedger API."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        idempotency_key_prefix: str = "",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
        if not base_url:
            raise ConfigurationError(
                "base_url is required. AGLedger is self-hosted, so the SDK cannot guess "
                "your Server: pass the base URL of your instance, e.g. "
                'AgledgerClient(api_key=..., base_url="https://agledger.internal").'
            )
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._timeout = timeout
        self._idempotency_key_prefix = idempotency_key_prefix
        self._client = http_client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = http_client is None
        self.last_request_id: str | None = None
        """Request ID from the most recent API response (``X-Request-Id`` header)."""
        self.rate_limit_info: RateLimitInfo | None = None
        """Rate-limit headers from the most recent response (``X-RateLimit-*``).
        ``None`` until the first response that carries them."""

    def _capture_response_meta(self, response: httpx.Response) -> None:
        """Pull ``X-Request-Id`` + ``X-RateLimit-*`` headers off a response onto
        ``self``. Called from every request path so observability fields stay in
        sync. Missing rate-limit headers leave the previous snapshot intact."""
        self.last_request_id = response.headers.get("x-request-id")
        self.rate_limit_info = _parse_rate_limit_headers(response.headers) or self.rate_limit_info

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        timeout: float | None = None,
        auth_override: str | None = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        key = f"{self._idempotency_key_prefix}{idempotency_key}" if idempotency_key else None
        headers = _base_headers(self._api_key, method, key, auth_override=auth_override)
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=headers,
                    json=json,
                    params=_query_params(params),
                    timeout=timeout or self._timeout,
                )

                self._capture_response_meta(response)

                if response.status_code >= 400:
                    error = _build_error(response)
                    if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                        retry_after = getattr(error, "retry_after", None)
                        await asyncio.sleep(_backoff(attempt, retry_after))
                        last_error = error
                        continue
                    raise error

                if response.status_code == 204:
                    return None
                return response.json()

            except httpx.ConnectError as e:
                last_error = APIConnectionError(str(e))
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from e
            except httpx.TimeoutException as e:
                last_error = APITimeoutError(str(e))
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from e

        raise last_error or APIError(500, message="Max retries exceeded")

    async def get(self, path: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self.request("GET", path, params=params, **kwargs)

    async def post(self, path: str, *, json: Any | None = None, **kwargs: Any) -> Any:
        return await self.request("POST", path, json=json, **kwargs)

    async def patch(self, path: str, *, json: Any | None = None, **kwargs: Any) -> Any:
        return await self.request("PATCH", path, json=json, **kwargs)

    async def put(self, path: str, *, json: Any | None = None, **kwargs: Any) -> Any:
        return await self.request("PUT", path, json=json, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> Any:
        return await self.request("DELETE", path, **kwargs)

    async def get_bytes(
        self,
        path: str,
        *,
        accept: str = "application/octet-stream",
        params: dict[str, Any] | None = None,
        auth_override: str | None = None,
    ) -> bytes:
        return await self._request_bytes(
            "GET", path, accept=accept, params=params, auth_override=auth_override,
        )

    async def post_bytes(
        self,
        path: str,
        *,
        body: bytes,
        content_type: str = "application/octet-stream",
        accept: str = "application/octet-stream",
        auth_override: str | None = None,
    ) -> bytes:
        return await self._request_bytes(
            "POST", path, body=body, content_type=content_type, accept=accept, auth_override=auth_override,
        )

    async def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str = "application/octet-stream",
        accept: str = "application/octet-stream",
        params: dict[str, Any] | None = None,
        auth_override: str | None = None,
        timeout: float | None = None,
    ) -> bytes:
        url = f"{self._base_url}{path}"
        idempotency_key = f"{self._idempotency_key_prefix}{uuid.uuid4()}" if method == "POST" else None
        headers = _base_headers(self._api_key, method, idempotency_key, auth_override=auth_override)
        headers["Accept"] = accept
        if body is not None:
            headers["Content-Type"] = content_type
        else:
            headers.pop("Content-Type", None)
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=headers,
                    content=body,
                    params=_query_params(params),
                    timeout=timeout or self._timeout,
                )
                self._capture_response_meta(response)
                raw = response.content
                if response.status_code >= 400:
                    error = _build_error(response)
                    error.raw_body = raw
                    if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                        retry_after = getattr(error, "retry_after", None)
                        await asyncio.sleep(_backoff(attempt, retry_after))
                        last_error = error
                        continue
                    raise error
                return raw
            except httpx.ConnectError as e:
                last_error = APIConnectionError(str(e))
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from e
            except httpx.TimeoutException as e:
                last_error = APITimeoutError(str(e))
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from e
        raise last_error or APIError(500, message="Max retries exceeded")

    async def get_ndjson(self, path: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Fetch an NDJSON endpoint.

        Returns ``{"data": [...], "cursor": ..., "holdbackSeconds": ...}``.
        """
        url = f"{self._base_url}{path}"
        headers = _base_headers(self._api_key, "GET")
        headers["Accept"] = "application/x-ndjson"
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(
                    "GET",
                    url,
                    headers=headers,
                    params=_query_params(params),
                    timeout=kwargs.get("timeout") or self._timeout,
                )

                if response.status_code >= 400:
                    error = _build_error(response)
                    if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                        retry_after = getattr(error, "retry_after", None)
                        await asyncio.sleep(_backoff(attempt, retry_after))
                        last_error = error
                        continue
                    raise error

                import json as _json
                text = response.text
                lines = [line for line in text.split("\n") if line.strip()]
                data = [_json.loads(line) for line in lines]
                cursor = response.headers.get("x-agledger-stream-cursor")
                return {
                    "data": data,
                    "cursor": cursor,
                    "holdbackSeconds": _parse_holdback_seconds(response.headers),
                }

            except httpx.ConnectError as e:
                last_error = APIConnectionError(str(e))
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from e
            except httpx.TimeoutException as e:
                last_error = APITimeoutError(str(e))
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from e

        raise last_error or APIError(500, message="Max retries exceeded")

    async def get_page(self, path: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = await self.get(path, params=params, **kwargs)
        if isinstance(raw, list):
            return {"data": raw, "hasMore": False}
        if isinstance(raw, dict) and "data" in raw:
            return cast("dict[str, Any]", raw)
        if isinstance(raw, dict):
            return {"data": [raw], "hasMore": False}
        return {"data": [], "hasMore": False}

    async def paginate(
        self, path: str, *, params: dict[str, Any] | None = None, max_pages: int | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Walk every page of a listing, yielding rows.

        Unbounded, the walk runs to the end of the listing behind
        :data:`DEFAULT_MAX_PAGES` as a runaway guard, and hitting that guard
        raises :class:`PaginationLimitError` rather than returning a prefix that
        looks like the whole listing. Pass ``max_pages`` to stop early on
        purpose: that bound is yours, so the walk ends at it quietly.
        """
        ceiling = DEFAULT_MAX_PAGES if max_pages is None else max_pages
        p = dict(params or {})
        pages_read = 0
        yielded = 0
        for _ in range(ceiling):
            page = await self.get_page(path, params=p)
            pages_read += 1
            rows = page.get("data", [])
            for item in rows:
                yield item
            yielded += len(rows)
            if not page.get("hasMore"):
                return
            cursor = page.get("nextCursor") or page.get("next_cursor")
            if not cursor:
                return
            p["cursor"] = cursor
        if max_pages is None:
            raise PaginationLimitError(path, pages_read, yielded, ceiling)
