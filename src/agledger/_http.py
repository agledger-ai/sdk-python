"""
AGLedger SDK — HTTP client with retry, idempotency, and error mapping.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
import uuid
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import Any, AsyncIterator, Iterator, cast

import httpx

from agledger._errors import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    UnprocessableError,
)

DEFAULT_BASE_URL = "https://agledger.example.com"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
MAX_BACKOFF = 30.0
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
# because auto-retrying it would mask a real client error — a 409 means
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
        "recovery_hint": body.get("recoveryHint"),
        "refresh_url": body.get("refreshUrl"),
        "deadline": body.get("deadline"),
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
        retry_after = response.headers.get("retry-after")
        kwargs["retry_after"] = float(retry_after) if retry_after else None

    if cls is APIError:
        return cls(status, **kwargs)
    return cls(**kwargs)


def _backoff(attempt: int, retry_after: float | None = None) -> float:
    if retry_after and retry_after > 0:
        return min(retry_after, MAX_BACKOFF)
    base = min(0.5 * (2**attempt), MAX_BACKOFF)
    jitter = random.uniform(0, base * 0.25)
    return base + jitter


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
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        idempotency_key_prefix: str = "",
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key
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
                    params={k: v for k, v in (params or {}).items() if v is not None},
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
                    params={k: v for k, v in (params or {}).items() if v is not None},
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
        """Fetch an NDJSON endpoint. Returns {"data": [...], "cursor": "..."}."""
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
                    params={k: v for k, v in (params or {}).items() if v is not None},
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
                return {"data": data, "cursor": cursor}

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

    def paginate(self, path: str, *, params: dict[str, Any] | None = None, max_pages: int = 100) -> Iterator[dict[str, Any]]:
        p = dict(params or {})
        for _ in range(max_pages):
            page = self.get_page(path, params=p)
            yield from page.get("data", [])
            if not page.get("hasMore"):
                break
            cursor = page.get("nextCursor") or page.get("next_cursor")
            if not cursor:
                break
            p["cursor"] = cursor


class AsyncHttpClient:
    """Async HTTP client for AGLedger API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        idempotency_key_prefix: str = "",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
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
                    params={k: v for k, v in (params or {}).items() if v is not None},
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
                    params={k: v for k, v in (params or {}).items() if v is not None},
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
        """Fetch an NDJSON endpoint. Returns {"data": [...], "cursor": "..."}."""
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
                    params={k: v for k, v in (params or {}).items() if v is not None},
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
                return {"data": data, "cursor": cursor}

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

    async def paginate(self, path: str, *, params: dict[str, Any] | None = None, max_pages: int = 100) -> AsyncIterator[dict[str, Any]]:
        p = dict(params or {})
        for _ in range(max_pages):
            page = await self.get_page(path, params=p)
            for item in page.get("data", []):
                yield item
            if not page.get("hasMore"):
                break
            cursor = page.get("nextCursor") or page.get("next_cursor")
            if not cursor:
                break
            p["cursor"] = cursor
