"""
Authentication resource: `GET /v1/auth/me` (identity + scopes),
`POST /v1/auth/keys/rotate` (atomic key rotation), and
`POST /v1/auth/oidc/cert` (OIDC-token → ephemeral signing cert exchange).
Account provisioning happens via the admin endpoints.
"""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import AccountProfile


class AuthResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get_me(self) -> AccountProfile:
        """Get the authenticated account profile (identity, role, scopes)."""
        return AccountProfile.model_validate(self._http.get("/v1/auth/me"))

    def rotate_key(self, *, grace_period_seconds: int | None = None) -> dict[str, Any]:
        """Rotate the current API key.

        The old key is revoked immediately unless ``grace_period_seconds`` is given
        (API #793), which keeps it valid for an overlap window so in-flight callers
        can swap without a hard cutover.
        """
        body = {"gracePeriodSeconds": grace_period_seconds} if grace_period_seconds is not None else None
        return self._http.post("/v1/auth/keys/rotate", json=body)

    def issue_ephemeral_cert(
        self,
        *,
        oidc_token: str,
        public_key_jwk: dict[str, Any],
        proof_of_possession: str,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Exchange an OIDC token for a short-lived ephemeral signing cert bound
        to a caller-supplied public key. The issuer must be registered as a
        trusted issuer (``admin.trusted_issuers.create``)."""
        body: dict[str, Any] = {
            "oidcToken": oidc_token,
            "publicKeyJwk": public_key_jwk,
            "proofOfPossession": proof_of_possession,
        }
        if agent_id is not None:
            body["agentId"] = agent_id
        return self._http.post("/v1/auth/oidc/cert", json=body)


class AsyncAuthResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get_me(self) -> AccountProfile:
        """Get the authenticated account profile (identity, role, scopes)."""
        return AccountProfile.model_validate(await self._http.get("/v1/auth/me"))

    async def rotate_key(self, *, grace_period_seconds: int | None = None) -> dict[str, Any]:
        """Rotate the current API key.

        The old key is revoked immediately unless ``grace_period_seconds`` is given
        (API #793), which keeps the old key valid for an overlap window.
        """
        body = {"gracePeriodSeconds": grace_period_seconds} if grace_period_seconds is not None else None
        return await self._http.post("/v1/auth/keys/rotate", json=body)

    async def issue_ephemeral_cert(
        self,
        *,
        oidc_token: str,
        public_key_jwk: dict[str, Any],
        proof_of_possession: str,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Exchange an OIDC token for a short-lived ephemeral signing cert bound
        to a caller-supplied public key. The issuer must be registered as a
        trusted issuer (``admin.trusted_issuers.create``)."""
        body: dict[str, Any] = {
            "oidcToken": oidc_token,
            "publicKeyJwk": public_key_jwk,
            "proofOfPossession": proof_of_possession,
        }
        if agent_id is not None:
            body["agentId"] = agent_id
        return await self._http.post("/v1/auth/oidc/cert", json=body)
