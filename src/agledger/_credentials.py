"""
AGLedger SDK: bearer credentials the HTTP client drives.

A client authenticates with exactly one of ``api_key`` or ``bearer_token``.
``bearer_token`` takes three forms:

- a string, sent as ``Authorization: Bearer <value>`` on every request;
- a function returning one, called before every request and never cached, so
  an IdP token source that must mint a fresh token per request (an issuer the
  operator registered with ``jtiSingleUse``) works as written;
- a :class:`BearerCredential`, an object the client asks for a token before
  every request. The credential owns its own caching and refresh, and may also
  sign request bodies. :func:`agledger.oidc_cert_credential` returns one.

The same three forms exist on the async client, where the function may return
an awaitable and the credential's ``get_token`` is a coroutine.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx


@dataclass(frozen=True)
class CredentialContext:
    """What a :class:`BearerCredential` gets from the client on each request."""

    base_url: str
    """The client's base URL, without a trailing slash. A credential that has
    to call the Server (the OIDC cert exchange) calls this one."""
    http_client: httpx.Client
    """The client's own ``httpx.Client``, so a credential's calls go through the
    same transport, proxies and TLS settings as every other request."""
    force_refresh: bool
    """True when the Server just refused a token this credential returned, with
    a 401. A credential that caches should obtain a new one unless it already
    holds a token other than ``rejected_token``. The client asks at most once
    per request, and a second 401 reaches the caller as
    :class:`~agledger.AuthenticationError`."""
    rejected_token: str | None = None
    """The token the Server refused, when ``force_refresh`` is set. Several
    requests in flight on one stale token all come back 401; comparing against
    this lets a credential refresh once for all of them."""


@dataclass(frozen=True)
class AsyncCredentialContext:
    """The async twin of :class:`CredentialContext`."""

    base_url: str
    http_client: httpx.AsyncClient
    force_refresh: bool
    rejected_token: str | None = None


@runtime_checkable
class BearerCredential(Protocol):
    """A bearer token source with its own cache and refresh policy."""

    def get_token(self, context: CredentialContext) -> str:
        """Return the token to send as ``Authorization: Bearer <token>``."""
        ...


@runtime_checkable
class AsyncBearerCredential(Protocol):
    """A bearer token source for :class:`~agledger.AsyncAgledgerClient`."""

    async def get_token(self, context: AsyncCredentialContext) -> str:
        """Return the token to send as ``Authorization: Bearer <token>``."""
        ...


@runtime_checkable
class BodySigner(Protocol):
    """A credential that also signs request bodies.

    The client calls :meth:`sign_body` with the exact bytes it is about to send
    and adds the returned headers to the request, on every request that has a
    body. Credentials that hold no key do not implement it."""

    def sign_body(self, body: bytes) -> Mapping[str, str]:
        """Headers attesting to ``body``, or an empty mapping to send none."""
        ...


BearerToken = str | Callable[[], str] | BearerCredential
"""What :class:`~agledger.AgledgerClient` accepts as ``bearer_token``."""

AsyncBearerToken = str | Callable[[], str | Awaitable[str]] | AsyncBearerCredential
"""What :class:`~agledger.AsyncAgledgerClient` accepts as ``bearer_token``."""
