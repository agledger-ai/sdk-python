"""
AGLedger SDK: the OIDC ephemeral-cert credential.

An agent that holds an OIDC token from an issuer the operator registered
(``admin.trusted_issuers``) trades it at ``POST /v1/auth/oidc/cert`` for a
short-lived cert the Server signs, bound to a key pair the agent generated. The
cert is then the agent's bearer token, and the private key signs the agent's
request bodies. No long-lived AGLedger credential exists at rest anywhere.

The key pair lives in memory for the life of the credential object and is never
written, logged or exported. Needs ``cryptography``:
``pip install 'agledger[oidc]'``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

import httpx

from agledger._credentials import AsyncCredentialContext, CredentialContext
from agledger._errors import APIError, ConfigurationError
from agledger._http import SDK_VERSION, build_error, encode_json

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EXCHANGE_PATH = "/v1/auth/oidc/cert"
_POP_CONTEXT = "agledger.oidc.cert.v1\n"
_BODY_SIGNATURE_CONTEXT = "agledger.agent.sig.v1\n"


class OidcCertExchangeError(APIError):
    """``POST /v1/auth/oidc/cert`` refused the exchange.

    Distinct from :class:`~agledger.AuthenticationError`: the request you made
    was never sent, because the credential could not obtain a cert to send it
    with. Carries the Server's error verbatim, and ``recovery_hint`` names what
    to fix (an unregistered issuer, an unbound subject, an OIDC token id that
    was already exchanged)."""


def _monotonic() -> float:
    # Indirection so tests can move the clock without sleeping.
    return time.monotonic()


def _load_ed25519() -> type[Ed25519PrivateKey]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as err:  # pragma: no cover - exercised without the extra
        raise ImportError(
            "The OIDC cert credential needs the 'cryptography' package to hold its "
            "Ed25519 key. Install via: pip install 'agledger[oidc]'"
        ) from err
    return Ed25519PrivateKey


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _claims_of(oidc_token: str) -> dict[str, Any]:
    """The token's claims, read without verifying anything. The Server verifies
    the token; the client needs only ``sub`` for the proof of possession and
    ``jti`` to know whether the token can be exchanged twice."""
    parts = oidc_token.split(".")
    if len(parts) != 3:
        raise ConfigurationError(
            "get_oidc_token returned something that is not a compact JWS "
            "(three dot-separated segments)."
        )
    try:
        claims: Any = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as err:
        raise ConfigurationError("get_oidc_token returned a JWT whose payload is not JSON.") from err
    if not isinstance(claims, dict):
        raise ConfigurationError("get_oidc_token returned a JWT whose payload is not a JSON object.")
    fields = cast("dict[str, Any]", claims)
    sub = fields.get("sub")
    if not isinstance(sub, str) or not sub:
        raise ConfigurationError("get_oidc_token returned a JWT with no 'sub' claim.")
    return fields


_REDACTED = "[redacted]"


def _scrub(value: Any, secret: str) -> Any:
    """``value`` with every trace of ``secret`` replaced.

    The Server's 400 on this route echoes the submitted input in
    ``details[].received``, which includes the OIDC token, and an exception is
    exactly the object that ends up in a log. The token is a bearer credential
    until it expires, so it never leaves this module inside an error."""
    if isinstance(value, str):
        return value.replace(secret, _REDACTED) if secret else value
    if isinstance(value, dict):
        return {
            key: (_REDACTED if key == "oidcToken" else _scrub(item, secret))
            for key, item in cast("dict[str, Any]", value).items()
        }
    if isinstance(value, list):
        return [_scrub(item, secret) for item in cast("list[Any]", value)]
    return value


def _parse_instant(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


# After a scheduled refresh fails while the cert still works, ask again after
# this long, or a quarter of the remaining lifetime if that is shorter, and
# never sooner than a second. Matches the TypeScript SDK.
_RECHECK_MAX_SECONDS = 30.0
_RECHECK_MIN_SECONDS = 1.0


@dataclass(frozen=True)
class _Cert:
    cert_jws: str = field(repr=False)
    cert: dict[str, Any] = field(repr=False)
    refresh_at: float
    """Monotonic instant at which to exchange again."""
    expires_at: float
    """Monotonic instant at which the Server stops accepting the cert."""


class _CertState:
    """What the sync and async credentials share: the key, the exchange body,
    and the refresh arithmetic. Everything that waits lives on the subclasses."""

    def __init__(self, agent_id: str | None, refresh_fraction: float) -> None:
        if not 0 < refresh_fraction <= 1:
            raise ConfigurationError(
                f"refresh_fraction must be greater than 0 and at most 1, got {refresh_fraction!r}."
            )
        self._key = _load_ed25519().generate()
        self._agent_id = agent_id
        self._refresh_fraction = refresh_fraction
        self._current: _Cert | None = None
        raw = self._key.public_key().public_bytes_raw()
        self._public_key_jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        }

    @property
    def cert(self) -> dict[str, Any] | None:
        """The ``cert`` object from the most recent exchange, or ``None`` before
        the first. Its ``expiresAt``, ``agentId`` and ``scopes`` say what the
        credential currently acts as."""
        return self._current.cert if self._current else None

    @property
    def public_key_jwk(self) -> dict[str, str]:
        """The public half of this credential's key pair, as the JWK every
        exchange binds. The private half never leaves the object."""
        return dict(self._public_key_jwk)

    def _refused(self, force_refresh: bool, rejected_token: str | None) -> bool:
        """Whether the Server refused the cert this credential holds. Several
        requests in flight on one stale cert all come back 401; once one of them
        has refreshed, the rest take the new cert rather than exchanging again."""
        current = self._current
        return (
            current is not None
            and force_refresh
            and (rejected_token is None or rejected_token == current.cert_jws)
        )

    def _usable(self, refused: bool) -> str | None:
        current = self._current
        if current is not None and not refused and _monotonic() < current.refresh_at:
            return current.cert_jws
        return None

    def _keep_after_failure(self, forced: bool) -> str | None:
        """A scheduled refresh failed: the token source raised, the IdP or the
        Server was unreachable, or the Server answered 5xx, 429 or 409. While
        the cert in hand still works, requests keep going out on it, and the
        exchange is tried again after a short recheck delay. A forced exchange
        (the Server refused the cert) or one after expiry has nothing to fall
        back on, so it fails."""
        current = self._current
        now = _monotonic()
        if forced or current is None or now >= current.expires_at:
            return None
        delay = max(_RECHECK_MIN_SECONDS, min(_RECHECK_MAX_SECONDS, (current.expires_at - now) / 4))
        self._current = replace(current, refresh_at=now + delay)
        return current.cert_jws

    def _checked_token(self, oidc_token: object) -> str:
        if not isinstance(oidc_token, str) or not oidc_token.strip():
            raise ConfigurationError(
                f"get_oidc_token returned {type(oidc_token).__name__}; expected a non-empty JWT string."
            )
        return oidc_token.strip()

    def _exchange_body(self, token: str) -> bytes:
        proof = self._key.sign(f"{_POP_CONTEXT}{_claims_of(token)['sub']}".encode())
        body: dict[str, Any] = {
            "oidcToken": token,
            "publicKeyJwk": self._public_key_jwk,
            "proofOfPossession": base64.b64encode(proof).decode("ascii"),
        }
        if self._agent_id is not None:
            body["agentId"] = self._agent_id
        return encode_json(body)

    def _accept(self, response: httpx.Response, token: str) -> str:
        if response.status_code >= 400:
            source = build_error(response)
            if response.status_code == 409:
                summary = (
                    "OIDC cert exchange failed (409): the token source returned a token that was "
                    "already exchanged. get_oidc_token must return a new token, with a new jti, on "
                    f"every call. Server: {source}"
                )
            else:
                summary = f"OIDC cert exchange failed ({response.status_code}): {source}"
            raise OidcCertExchangeError(
                response.status_code,
                message=_scrub(summary, token),
                code=source.code,
                request_id=source.request_id,
                details=_scrub(source.details, token),
                retryable=source.retryable,
                docs=source.docs,
                recovery_hint=_scrub(source.recovery_hint, token),
                type=source.type,
            )
        try:
            raw_payload: Any = response.json()
        except ValueError:
            raw_payload = None
        payload = cast("dict[str, Any]", raw_payload) if isinstance(raw_payload, dict) else {}
        cert_jws: object = payload.get("certJws")
        cert: object = payload.get("cert")
        cert_fields = dict(cast("dict[str, Any]", cert)) if isinstance(cert, dict) else {}
        issued = _parse_instant(cert_fields.get("issuedAt"))
        expires = _parse_instant(cert_fields.get("expiresAt"))
        if not isinstance(cert_jws, str) or issued is None or expires is None:
            raise OidcCertExchangeError(
                response.status_code,
                code="invalid_exchange_response",
                message=(
                    "OIDC cert exchange failed: the response carried no certJws or no cert "
                    "validity window."
                ),
            )
        # The lifetime comes from the Server's own two timestamps and is laid
        # onto this host's monotonic clock from the moment the cert arrived, so
        # clock skew against the Server can neither make a fresh cert look
        # stale nor an expired one look fresh.
        lifetime = max(expires - issued, 0.0)
        received = _monotonic()
        self._current = _Cert(
            cert_jws=cert_jws,
            cert=cert_fields,
            refresh_at=received + self._refresh_fraction * lifetime,
            expires_at=received + lifetime,
        )
        return cert_jws

    def sign_body(self, body: bytes) -> Mapping[str, str]:
        """``X-Agent-Signature`` headers over exactly these body bytes.

        The Server verifies an Ed25519 signature, under the key the cert binds,
        over ``agledger.agent.sig.v1\\n`` followed by the lowercase hex SHA-256
        of the raw body, and seals it into the chain entry as
        ``predicate.on_behalf_of.agent_signature``."""
        digest = hashlib.sha256(body).hexdigest()
        signature = self._key.sign(f"{_BODY_SIGNATURE_CONTEXT}{digest}".encode())
        return {
            "X-Agent-Signature-Content-Hash": f"sha256:{digest}",
            "X-Agent-Signature": base64.b64encode(signature).decode("ascii"),
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(agent_id={self._agent_id!r}, refresh_fraction={self._refresh_fraction})"


def _exchange_headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": f"agledger-python/{SDK_VERSION}",
    }


class OidcCertCredential(_CertState):
    """A :class:`~agledger.BearerCredential` backed by the OIDC cert exchange.

    Build it with :func:`oidc_cert_credential`. Thread-safe: concurrent requests
    that find the cert due for refresh share one exchange, and share its
    failure too."""

    def __init__(
        self,
        get_oidc_token: Callable[[], str],
        agent_id: str | None = None,
        refresh_fraction: float = 0.5,
    ) -> None:
        super().__init__(agent_id, refresh_fraction)
        self._get_oidc_token = get_oidc_token
        self._lock = threading.Lock()
        self._inflight: Future[str] | None = None

    def get_token(self, context: CredentialContext) -> str:
        """The current ``certJws``, exchanging first when there is none, when
        the refresh point has passed, or when ``context.force_refresh`` says
        the Server refused the one this credential holds."""
        with self._lock:
            inflight = self._inflight
            if inflight is None:
                refused = self._refused(context.force_refresh, context.rejected_token)
                usable = self._usable(refused)
                if usable is not None:
                    return usable
                inflight = self._inflight = Future()
                owner = True
            else:
                refused = False
                owner = False
        if not owner:
            return inflight.result()
        try:
            token = self._exchange(context, refused)
        except BaseException as err:
            inflight.set_exception(err)
            raise
        else:
            inflight.set_result(token)
            return token
        finally:
            with self._lock:
                self._inflight = None

    def _exchange(self, context: CredentialContext, forced: bool) -> str:
        try:
            token = self._checked_token(self._get_oidc_token())
            body = self._exchange_body(token)
            response = context.http_client.post(
                f"{context.base_url}{EXCHANGE_PATH}", content=body, headers=_exchange_headers()
            )
            return self._accept(response, token)
        except Exception:
            kept = self._keep_after_failure(forced)
            if kept is not None:
                return kept
            raise


class AsyncOidcCertCredential(_CertState):
    """An :class:`~agledger.AsyncBearerCredential` backed by the OIDC cert
    exchange. Build it with :func:`async_oidc_cert_credential`. Task-safe:
    concurrent requests that find the cert due for refresh share one exchange,
    and share its failure too."""

    def __init__(
        self,
        get_oidc_token: Callable[[], str | Awaitable[str]],
        agent_id: str | None = None,
        refresh_fraction: float = 0.5,
    ) -> None:
        super().__init__(agent_id, refresh_fraction)
        self._get_oidc_token = get_oidc_token
        self._inflight: asyncio.Task[str] | None = None

    async def get_token(self, context: AsyncCredentialContext) -> str:
        """Async twin of :meth:`OidcCertCredential.get_token`."""
        inflight = self._inflight
        if inflight is None:
            refused = self._refused(context.force_refresh, context.rejected_token)
            usable = self._usable(refused)
            if usable is not None:
                return usable
            inflight = self._inflight = asyncio.ensure_future(self._exchange(context, refused))
            inflight.add_done_callback(self._clear_inflight)
        # Shielded, so one cancelled caller does not cancel the exchange the
        # others are waiting on.
        return await asyncio.shield(inflight)

    def _clear_inflight(self, task: asyncio.Task[str]) -> None:
        if self._inflight is task:
            self._inflight = None
        if not task.cancelled():
            task.exception()  # retrieved, so an unawaited failure is not logged

    async def _exchange(self, context: AsyncCredentialContext, forced: bool) -> str:
        try:
            fetched = self._get_oidc_token()
            if inspect.isawaitable(fetched):
                fetched = await fetched
            token = self._checked_token(fetched)
            body = self._exchange_body(token)
            response = await context.http_client.post(
                f"{context.base_url}{EXCHANGE_PATH}", content=body, headers=_exchange_headers()
            )
            return self._accept(response, token)
        except Exception:
            kept = self._keep_after_failure(forced)
            if kept is not None:
                return kept
            raise


def oidc_cert_credential(
    get_oidc_token: Callable[[], str],
    *,
    agent_id: str | None = None,
    refresh_fraction: float = 0.5,
) -> OidcCertCredential:
    """A credential that authenticates as an agent through the OIDC cert exchange.

    Pass the result as ``bearer_token=`` to :class:`~agledger.AgledgerClient`.
    It generates an Ed25519 key pair in memory, and before the first request
    calls ``get_oidc_token()`` and exchanges that token for a cert bound to the
    key. Every request then carries ``Authorization: Bearer <certJws>`` and,
    when it has a body, ``X-Agent-Signature`` headers the key made over it.

    The credential exchanges again once ``refresh_fraction`` of the cert's
    lifetime has passed (half, by default), and once, before surfacing it, on
    a 401 to a request it authenticated. Concurrent requests share one
    exchange. A refused exchange raises :class:`OidcCertExchangeError` with the
    Server's ``recovery_hint``.

    ``get_oidc_token`` is called on every exchange and must return a new
    token, with a new ``jti``, each time: the Server takes each OIDC token id
    once and refuses a second exchange with 409.

    A scheduled refresh that fails (the token source raises, the IdP or the
    Server is unreachable, or the Server answers 5xx, 429 or 409) does not fail
    the request while the current cert is still valid: the request goes out on
    that cert and the exchange is tried again shortly. Once the cert has
    expired, or after the Server refused it with a 401, a failed exchange
    raises; a 409 there says the token source returned a token that was
    already exchanged.

    ``agent_id`` binds the cert to one agent in the trusted issuer's org. Omit
    it to let the Server bind from the token's mapped ``agent_id`` claim, an
    agent already registered under the token's ``(iss, sub)``, or the issuer's
    auto-provisioning.

    Requires ``pip install 'agledger[oidc]'``.
    """
    return OidcCertCredential(get_oidc_token, agent_id=agent_id, refresh_fraction=refresh_fraction)


def async_oidc_cert_credential(
    get_oidc_token: Callable[[], str | Awaitable[str]],
    *,
    agent_id: str | None = None,
    refresh_fraction: float = 0.5,
) -> AsyncOidcCertCredential:
    """:func:`oidc_cert_credential` for :class:`~agledger.AsyncAgledgerClient`.

    ``get_oidc_token`` may be a plain function or a coroutine function."""
    return AsyncOidcCertCredential(get_oidc_token, agent_id=agent_id, refresh_fraction=refresh_fraction)
