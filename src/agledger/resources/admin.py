"""Admin resource — org governance, key management, org provisioning,
vault inspection, and platform operations. Requires an ``admin``-role key."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient


class AdminRecordsResource:
    """Admin sub-resource for Records — org-wide listing and historical backfill."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, **params: Any) -> dict[str, Any]:
        """List Records across all orgs (platform admin). Supports filters."""
        return self._http.get_page("/v1/admin/records", params=params)

    def import_(
        self,
        *,
        org_id: str,
        source: str,
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Backfill historical Records from an external source. Up to 100 entries per
        batch, atomic per request. Each imported entry lands directly in its declared
        terminal state with backdated timestamps and a ``BACKFILL_IMPORT`` vault entry
        tagged with the given source label.

        Platform-tier: this is a cross-org operator surface, so an org ``admin``
        key is refused with 403 naming ``BACKFILL_IMPORT``. Use a platform key.

        Returns ``{"source", "count", "imported": [...], "nextSteps"}``, where
        each ``imported`` entry is ``{"index", "recordId", "chainPosition"}``
        aligned 1:1 with ``records``. Set ``"publisher"`` on an item when two
        publishers offer the same type in the org, otherwise the batch is
        refused with 422 naming the offending index.
        """
        return self._http.post(
            "/v1/admin/records/import",
            json={"orgId": org_id, "source": source, "records": records},
        )


class AdminVaultAnchorsResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, *, record_id: str | None = None) -> dict[str, Any]:
        """List vault anchors."""
        params: dict[str, Any] = {}
        if record_id is not None: params["recordId"] = record_id
        return self._http.get("/v1/admin/vault/anchors", params=params)

    def verify(self, *, record_id: str, chain_position: int | None = None) -> dict[str, Any]:
        """Verify vault trust anchors for a Record."""
        body: dict[str, Any] = {"recordId": record_id}
        if chain_position is not None:
            body["chainPosition"] = chain_position
        return self._http.post("/v1/admin/vault/anchors/verify", json=body)


class AdminVaultScanResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def run(
        self,
        *,
        record_ids: list[str] | None = None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        """Start a vault integrity scan job."""
        body: dict[str, Any] = {}
        if record_ids is not None: body["recordIds"] = record_ids
        if record_id is not None: body["recordId"] = record_id
        return self._http.post("/v1/admin/vault/scan", json=body)

    def status(self, job_id: str) -> dict[str, Any]:
        """Get the status of a vault scan job."""
        return self._http.get(f"/v1/admin/vault/scan/{job_id}")

    def list(self) -> dict[str, Any]:
        """List current and recent vault scan jobs (active, last completed, recent)."""
        return self._http.get("/v1/admin/vault/scan")


class AdminVaultSigningKeysResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self) -> dict[str, Any]:
        """List vault signing keys."""
        return self._http.get("/v1/admin/vault/signing-keys")

    def rotate(self) -> dict[str, Any]:
        """Rotate the vault signing key."""
        return self._http.post("/v1/admin/vault/signing-keys/rotate", json={})


class AdminVaultResource:
    """Admin sub-resource for vault inspection and signing-key management."""

    def __init__(self, http: HttpClient) -> None:
        self.anchors: AdminVaultAnchorsResource = AdminVaultAnchorsResource(http)
        self.scan: AdminVaultScanResource = AdminVaultScanResource(http)
        self.signing_keys: AdminVaultSigningKeysResource = AdminVaultSigningKeysResource(http)


def _trusted_issuer_body(params: dict[str, Any]) -> dict[str, Any]:
    """Map snake_case trusted-issuer kwargs to the camelCase wire body."""
    mapping = {
        "org_id": "orgId",
        "issuer_url": "issuerUrl",
        "jwks_uri": "jwksUri",
        "expected_audience": "expectedAudience",
        "expected_azp": "expectedAzp",
        "applies_to": "appliesTo",
        "claim_mapping": "claimMapping",
        "allowed_algs": "allowedAlgs",
        "max_credential_ttl_seconds": "maxCredentialTtlSeconds",
        "label": "label",
        "enabled": "enabled",
    }
    return {mapping.get(k, k): v for k, v in params.items() if v is not None}


class AdminTrustedIssuersResource:
    """Trusted OIDC issuers — register the IdPs whose tokens may be exchanged
    for ephemeral signing certs via ``POST /v1/auth/oidc/cert``."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, **params: Any) -> dict[str, Any]:
        """List trusted issuers, optionally filtered by org, scope, or enabled state."""
        return self._http.get_page("/v1/admin/trusted-issuers", params=params)

    def create(
        self,
        *,
        issuer_url: str,
        expected_audience: str,
        org_id: str | None = None,
        jwks_uri: str | None = None,
        expected_azp: str | None = None,
        applies_to: str | None = None,
        claim_mapping: dict[str, str] | None = None,
        allowed_algs: list[str] | None = None,
        max_credential_ttl_seconds: int | None = None,
        label: str | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        """Register a trusted OIDC issuer."""
        body = _trusted_issuer_body(
            {
                "issuer_url": issuer_url,
                "expected_audience": expected_audience,
                "org_id": org_id,
                "jwks_uri": jwks_uri,
                "expected_azp": expected_azp,
                "applies_to": applies_to,
                "claim_mapping": claim_mapping,
                "allowed_algs": allowed_algs,
                "max_credential_ttl_seconds": max_credential_ttl_seconds,
                "label": label,
                "enabled": enabled,
            }
        )
        return self._http.post("/v1/admin/trusted-issuers", json=body)

    def get(self, issuer_id: str) -> dict[str, Any]:
        """Get a trusted issuer by ID."""
        return self._http.get(f"/v1/admin/trusted-issuers/{issuer_id}")

    def update(self, issuer_id: str, **params: Any) -> dict[str, Any]:
        """Merge-update a trusted issuer (PATCH semantics)."""
        return self._http.patch(
            f"/v1/admin/trusted-issuers/{issuer_id}",
            json=_trusted_issuer_body(params),
        )

    def delete(self, issuer_id: str) -> dict[str, Any]:
        """Delete a trusted issuer. Returns 409 if live certs still reference it —
        disable it (``update(id, enabled=False)``) and revoke its certs first."""
        return self._http.delete(f"/v1/admin/trusted-issuers/{issuer_id}")

    def revoke_certs(self, issuer_id: str) -> dict[str, Any]:
        """Revoke every live ephemeral cert issued under this issuer."""
        return self._http.post(f"/v1/admin/trusted-issuers/{issuer_id}/revoke-certs", json={})


class AdminResource:
    """Admin operations: orgs, API keys, records, vault, and trusted issuers."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self.records: AdminRecordsResource = AdminRecordsResource(http)
        self.vault: AdminVaultResource = AdminVaultResource(http)
        self.trusted_issuers: AdminTrustedIssuersResource = AdminTrustedIssuersResource(http)

    # --- Ops summary + ephemeral certs ---

    def get_ops_summary(self) -> dict[str, Any]:
        """Get a consolidated operations snapshot (license, system, queues,
        federation, vault, webhooks)."""
        return self._http.get("/v1/admin/ops-summary")

    def revoke_ephemeral_cert(self, cert_id: str) -> dict[str, Any]:
        """Revoke a single ephemeral signing cert by ID."""
        return self._http.post(f"/v1/admin/ephemeral-certs/{cert_id}/revoke", json={})

    # --- Orgs ---

    def list_orgs(self, **params: Any) -> dict[str, Any]:
        """List all orgs on the platform."""
        return self._http.get_page("/v1/admin/orgs", params=params)

    def create_org(
        self,
        *,
        name: str | None = None,
        display_name: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new org.

        Dev/test only — ``POST /v1/admin/orgs`` is not registered in production
        (dropped from the canonical OpenAPI spec in API v1.0.1) and 404s there.
        Provision production orgs via the operator ``provisioning/`` YAML.
        """
        body: dict[str, Any] = {}
        if name is not None: body["name"] = name
        if display_name is not None: body["displayName"] = display_name
        if config is not None: body["config"] = config
        return self._http.post("/v1/admin/orgs", json=body)

    def get_org_config(self, org_id: str) -> dict[str, Any]:
        """Get an org's configuration."""
        return self._http.get(f"/v1/admin/orgs/{org_id}/config")

    def update_org_config(self, org_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Partially update an org's configuration (PATCH semantics)."""
        return self._http.patch(f"/v1/admin/orgs/{org_id}/config", json=config)

    # --- Agents ---

    def list_agents(self, **params: Any) -> dict[str, Any]:
        """List all registered agents on the platform."""
        return self._http.get_page("/v1/admin/agents", params=params)

    def create_agent(
        self,
        *,
        org_id: str,
        name: str | None = None,
        display_name: str | None = None,
        agent_card_url: str | None = None,
    ) -> dict[str, Any]:
        """Create a new agent."""
        body: dict[str, Any] = {"orgId": org_id}
        if name is not None: body["name"] = name
        if display_name is not None: body["displayName"] = display_name
        if agent_card_url is not None: body["agentCardUrl"] = agent_card_url
        return self._http.post("/v1/admin/agents", json=body)

    def set_capabilities(self, agent_id: str, *, contract_types: list[str]) -> dict[str, Any]:
        """Set an agent's Type capabilities (PUT — replaces all).

        Body field is ``contractTypes`` on the wire.
        """
        return self._http.put(
            f"/v1/admin/agents/{agent_id}/capabilities",
            json={"contractTypes": contract_types},
        )

    def get_fleet_capabilities(self, **params: Any) -> dict[str, Any]:
        """Get capabilities of all agents in the fleet."""
        return self._http.get_page("/v1/admin/agents/capabilities", params=params)

    # --- Deactivate ---

    def deactivate_org(
        self,
        org_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Deactivate an org. Revokes all API keys owned by the org."""
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._http.post(f"/v1/admin/orgs/{org_id}/deactivate", json=body)

    def deactivate_agent(
        self,
        agent_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Deactivate an agent. Revokes the agent's API keys."""
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._http.post(f"/v1/admin/agents/{agent_id}/deactivate", json=body)

    # --- API keys ---

    def list_api_keys(self, **params: Any) -> dict[str, Any]:
        """List API keys."""
        return self._http.get_page("/v1/admin/api-keys", params=params)

    def create_api_key(
        self,
        *,
        role: str,
        owner_id: str,
        owner_type: str,
        label: str | None = None,
        scopes: list[str] | None = None,
        scope_profile: str | None = None,
        expires_at: str | None = None,
        environment: str | None = None,
    ) -> dict[str, Any]:
        """Create an API key."""
        body: dict[str, Any] = {
            "role": role,
            "ownerId": owner_id,
            "ownerType": owner_type,
        }
        if label is not None: body["label"] = label
        if scopes is not None: body["scopes"] = scopes
        if scope_profile is not None: body["scopeProfile"] = scope_profile
        if expires_at is not None: body["expiresAt"] = expires_at
        if environment is not None: body["environment"] = environment
        return self._http.post("/v1/admin/api-keys", json=body)

    def update_api_key(self, key_id: str, **params: Any) -> dict[str, Any]:
        """Update an API key's status or scopes.

        The API accepts only ``is_active`` (→ ``isActive``), ``reason``,
        ``scopes``, and ``scope_profile`` (→ ``scopeProfile``) here. ``label``,
        ``expires_at``, and ``allowed_ips`` are settable only at create time —
        the server rejects them on update (``additionalProperties: false``)."""
        # Snake-to-camel for the fields the PATCH route actually accepts.
        mapping = {"is_active": "isActive", "scope_profile": "scopeProfile"}
        body = {mapping.get(k, k): v for k, v in params.items()}
        return self._http.patch(f"/v1/admin/api-keys/{key_id}", json=body)

    def toggle_api_key(self, key_id: str, *, is_active: bool) -> dict[str, Any]:
        """Enable or disable an API key. Convenience wrapper around update_api_key."""
        return self._http.patch(f"/v1/admin/api-keys/{key_id}", json={"isActive": is_active})

    def bulk_revoke_api_keys(self, key_ids: list[str]) -> dict[str, Any]:
        """Revoke multiple API keys at once."""
        return self._http.post("/v1/admin/api-keys/bulk-revoke", json={"keyIds": key_ids})

    # --- Webhook DLQ ---

    def list_dlq(self, **params: Any) -> dict[str, Any]:
        """List webhook dead-letter queue entries."""
        return self._http.get_page("/v1/admin/webhook-dlq", params=params)

    def retry_dlq(self, dlq_id: str) -> dict[str, Any]:
        """Retry a single DLQ entry."""
        return self._http.post(f"/v1/admin/webhook-dlq/{dlq_id}/retry")

    def retry_all_dlq(self) -> dict[str, Any]:
        """Retry all DLQ entries."""
        return self._http.post("/v1/admin/webhook-dlq/retry-all")

    def get_webhook_health(self, **params: Any) -> dict[str, Any]:
        """Get health status of all webhooks."""
        return self._http.get_page("/v1/admin/webhooks/health", params=params)

    def update_circuit_breaker(self, webhook_id: str, *, state: str) -> dict[str, Any]:
        """Update a webhook's circuit breaker state (closed / open / half_open)."""
        return self._http.patch(
            f"/v1/admin/webhooks/{webhook_id}/circuit-breaker",
            json={"state": state},
        )

    # --- License ---

    def get_license(self) -> dict[str, Any]:
        """Get license information."""
        return self._http.get("/v1/admin/license")

    def get_license_instance_id(self) -> dict[str, Any]:
        """Get the unique instance ID for this AGLedger installation."""
        return self._http.get("/v1/admin/license/instance-id")

    def reload_license(self) -> dict[str, Any]:
        """Re-read the license from environment/file and re-validate."""
        return self._http.post("/v1/admin/license/reload", json={})

    # --- Provisioning + discovery ---

    def reload_provisioning(self) -> dict[str, Any]:
        """Reload the static-provisioning config from disk."""
        return self._http.post("/v1/admin/provisioning/reload", json={})

    def get_provisioning_status(self) -> dict[str, Any]:
        """Get the current static-provisioning status."""
        return self._http.get("/v1/admin/provisioning/status")

    def reload_discovery(self) -> dict[str, Any]:
        """Reload the agent discovery cache."""
        return self._http.post("/v1/admin/discovery/reload", json={})

    # --- Support / system health ---

    def get_system_health(self) -> dict[str, Any]:
        """Get system health metrics (platform admin)."""
        return self._http.get("/v1/admin/system-health")

    def get_support_bundle(self) -> dict[str, Any]:
        """Download a diagnostic support bundle."""
        return self._http.get("/v1/admin/support-bundle")

    def upload_support_bundle(self) -> dict[str, Any]:
        """Upload a support bundle to AGLedger support."""
        return self._http.post("/v1/admin/support-bundle/upload", json={})

    # --- Auth + schema cache ---

    def flush_auth_cache(self) -> dict[str, Any]:
        """Flush the authentication cache."""
        return self._http.post("/v1/admin/auth-cache/flush", json={})

    def get_auth_cache_stats(self) -> dict[str, Any]:
        """Get authentication cache statistics."""
        return self._http.get("/v1/admin/auth-cache/stats")

    def flush_schema_cache(self) -> dict[str, Any]:
        """Flush the schema cache."""
        return self._http.post("/v1/admin/schemas/cache/flush", json={})

    # --- Rate-limit exemptions ---

    def list_rate_limit_exemptions(self) -> dict[str, Any]:
        """List all owner-level rate-limit exemptions."""
        return self._http.get("/v1/admin/rate-limit-exemptions")

    def get_rate_limit_exemption(self, owner_id: str) -> dict[str, Any]:
        """Get a specific owner's rate-limit exemption."""
        return self._http.get(f"/v1/admin/rate-limit-exemptions/{owner_id}")

    def set_rate_limit_exemption(self, owner_id: str, **params: Any) -> dict[str, Any]:
        """Grant rate-limit exemption to an owner."""
        return self._http.put(f"/v1/admin/rate-limit-exemptions/{owner_id}", json=params or {})

    def delete_rate_limit_exemption(self, owner_id: str) -> dict[str, Any]:
        """Remove rate-limit exemption from an owner."""
        return self._http.delete(f"/v1/admin/rate-limit-exemptions/{owner_id}")


# --- Async resources ---


class AsyncAdminRecordsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/records", params=params)

    async def import_(
        self,
        *,
        org_id: str,
        source: str,
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return await self._http.post(
            "/v1/admin/records/import",
            json={"orgId": org_id, "source": source, "records": records},
        )


class AsyncAdminVaultAnchorsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, *, record_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if record_id is not None: params["recordId"] = record_id
        return await self._http.get("/v1/admin/vault/anchors", params=params)

    async def verify(self, *, record_id: str, chain_position: int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"recordId": record_id}
        if chain_position is not None:
            body["chainPosition"] = chain_position
        return await self._http.post("/v1/admin/vault/anchors/verify", json=body)


class AsyncAdminVaultScanResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def run(
        self,
        *,
        record_ids: list[str] | None = None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if record_ids is not None: body["recordIds"] = record_ids
        if record_id is not None: body["recordId"] = record_id
        return await self._http.post("/v1/admin/vault/scan", json=body)

    async def status(self, job_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/admin/vault/scan/{job_id}")

    async def list(self) -> dict[str, Any]:
        """List current and recent vault scan jobs (active, last completed, recent)."""
        return await self._http.get("/v1/admin/vault/scan")


class AsyncAdminVaultSigningKeysResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/vault/signing-keys")

    async def rotate(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/vault/signing-keys/rotate", json={})


class AsyncAdminVaultResource:
    """Admin sub-resource for vault inspection and signing-key management."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self.anchors: AsyncAdminVaultAnchorsResource = AsyncAdminVaultAnchorsResource(http)
        self.scan: AsyncAdminVaultScanResource = AsyncAdminVaultScanResource(http)
        self.signing_keys: AsyncAdminVaultSigningKeysResource = AsyncAdminVaultSigningKeysResource(http)


class AsyncAdminTrustedIssuersResource:
    """Trusted OIDC issuers (async) — register the IdPs whose tokens may be
    exchanged for ephemeral signing certs via ``POST /v1/auth/oidc/cert``."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, **params: Any) -> dict[str, Any]:
        """List trusted issuers, optionally filtered by org, scope, or enabled state."""
        return await self._http.get_page("/v1/admin/trusted-issuers", params=params)

    async def create(
        self,
        *,
        issuer_url: str,
        expected_audience: str,
        org_id: str | None = None,
        jwks_uri: str | None = None,
        expected_azp: str | None = None,
        applies_to: str | None = None,
        claim_mapping: dict[str, str] | None = None,
        allowed_algs: list[str] | None = None,
        max_credential_ttl_seconds: int | None = None,
        label: str | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        """Register a trusted OIDC issuer."""
        body = _trusted_issuer_body(
            {
                "issuer_url": issuer_url,
                "expected_audience": expected_audience,
                "org_id": org_id,
                "jwks_uri": jwks_uri,
                "expected_azp": expected_azp,
                "applies_to": applies_to,
                "claim_mapping": claim_mapping,
                "allowed_algs": allowed_algs,
                "max_credential_ttl_seconds": max_credential_ttl_seconds,
                "label": label,
                "enabled": enabled,
            }
        )
        return await self._http.post("/v1/admin/trusted-issuers", json=body)

    async def get(self, issuer_id: str) -> dict[str, Any]:
        """Get a trusted issuer by ID."""
        return await self._http.get(f"/v1/admin/trusted-issuers/{issuer_id}")

    async def update(self, issuer_id: str, **params: Any) -> dict[str, Any]:
        """Merge-update a trusted issuer (PATCH semantics)."""
        return await self._http.patch(
            f"/v1/admin/trusted-issuers/{issuer_id}",
            json=_trusted_issuer_body(params),
        )

    async def delete(self, issuer_id: str) -> dict[str, Any]:
        """Delete a trusted issuer. Returns 409 if live certs still reference it —
        disable it (``update(id, enabled=False)``) and revoke its certs first."""
        return await self._http.delete(f"/v1/admin/trusted-issuers/{issuer_id}")

    async def revoke_certs(self, issuer_id: str) -> dict[str, Any]:
        """Revoke every live ephemeral cert issued under this issuer."""
        return await self._http.post(f"/v1/admin/trusted-issuers/{issuer_id}/revoke-certs", json={})


class AsyncAdminResource:
    """Admin operations: orgs, API keys, records, vault, and trusted issuers."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http
        self.records: AsyncAdminRecordsResource = AsyncAdminRecordsResource(http)
        self.vault: AsyncAdminVaultResource = AsyncAdminVaultResource(http)
        self.trusted_issuers: AsyncAdminTrustedIssuersResource = AsyncAdminTrustedIssuersResource(http)

    async def get_ops_summary(self) -> dict[str, Any]:
        """Get a consolidated operations snapshot (license, system, queues,
        federation, vault, webhooks)."""
        return await self._http.get("/v1/admin/ops-summary")

    async def revoke_ephemeral_cert(self, cert_id: str) -> dict[str, Any]:
        """Revoke a single ephemeral signing cert by ID."""
        return await self._http.post(f"/v1/admin/ephemeral-certs/{cert_id}/revoke", json={})

    async def list_orgs(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/orgs", params=params)

    async def create_org(
        self,
        *,
        name: str | None = None,
        display_name: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if name is not None: body["name"] = name
        if display_name is not None: body["displayName"] = display_name
        if config is not None: body["config"] = config
        return await self._http.post("/v1/admin/orgs", json=body)

    async def get_org_config(self, org_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/admin/orgs/{org_id}/config")

    async def update_org_config(self, org_id: str, config: dict[str, Any]) -> dict[str, Any]:
        return await self._http.patch(f"/v1/admin/orgs/{org_id}/config", json=config)

    async def list_agents(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/agents", params=params)

    async def create_agent(
        self,
        *,
        org_id: str,
        name: str | None = None,
        display_name: str | None = None,
        agent_card_url: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"orgId": org_id}
        if name is not None: body["name"] = name
        if display_name is not None: body["displayName"] = display_name
        if agent_card_url is not None: body["agentCardUrl"] = agent_card_url
        return await self._http.post("/v1/admin/agents", json=body)

    async def set_capabilities(self, agent_id: str, *, contract_types: list[str]) -> dict[str, Any]:
        return await self._http.put(
            f"/v1/admin/agents/{agent_id}/capabilities",
            json={"contractTypes": contract_types},
        )

    async def get_fleet_capabilities(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/agents/capabilities", params=params)

    async def deactivate_org(
        self,
        org_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return await self._http.post(f"/v1/admin/orgs/{org_id}/deactivate", json=body)

    async def deactivate_agent(
        self,
        agent_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return await self._http.post(f"/v1/admin/agents/{agent_id}/deactivate", json=body)

    async def list_api_keys(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/api-keys", params=params)

    async def create_api_key(
        self,
        *,
        role: str,
        owner_id: str,
        owner_type: str,
        label: str | None = None,
        scopes: list[str] | None = None,
        scope_profile: str | None = None,
        expires_at: str | None = None,
        environment: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "role": role,
            "ownerId": owner_id,
            "ownerType": owner_type,
        }
        if label is not None: body["label"] = label
        if scopes is not None: body["scopes"] = scopes
        if scope_profile is not None: body["scopeProfile"] = scope_profile
        if expires_at is not None: body["expiresAt"] = expires_at
        if environment is not None: body["environment"] = environment
        return await self._http.post("/v1/admin/api-keys", json=body)

    async def update_api_key(self, key_id: str, **params: Any) -> dict[str, Any]:
        mapping = {"is_active": "isActive", "scope_profile": "scopeProfile",
                   "expires_at": "expiresAt", "allowed_ips": "allowedIps"}
        body = {mapping.get(k, k): v for k, v in params.items()}
        return await self._http.patch(f"/v1/admin/api-keys/{key_id}", json=body)

    async def toggle_api_key(self, key_id: str, *, is_active: bool) -> dict[str, Any]:
        return await self._http.patch(f"/v1/admin/api-keys/{key_id}", json={"isActive": is_active})

    async def bulk_revoke_api_keys(self, key_ids: list[str]) -> dict[str, Any]:
        return await self._http.post("/v1/admin/api-keys/bulk-revoke", json={"keyIds": key_ids})

    async def list_dlq(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/webhook-dlq", params=params)

    async def retry_dlq(self, dlq_id: str) -> dict[str, Any]:
        return await self._http.post(f"/v1/admin/webhook-dlq/{dlq_id}/retry")

    async def retry_all_dlq(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/webhook-dlq/retry-all")

    async def get_webhook_health(self, **params: Any) -> dict[str, Any]:
        return await self._http.get_page("/v1/admin/webhooks/health", params=params)

    async def update_circuit_breaker(self, webhook_id: str, *, state: str) -> dict[str, Any]:
        return await self._http.patch(
            f"/v1/admin/webhooks/{webhook_id}/circuit-breaker",
            json={"state": state},
        )

    async def get_license(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/license")

    async def get_license_instance_id(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/license/instance-id")

    async def reload_license(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/license/reload", json={})

    async def reload_provisioning(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/provisioning/reload", json={})

    async def get_provisioning_status(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/provisioning/status")

    async def reload_discovery(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/discovery/reload", json={})

    async def get_system_health(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/system-health")

    async def get_support_bundle(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/support-bundle")

    async def upload_support_bundle(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/support-bundle/upload", json={})

    async def flush_auth_cache(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/auth-cache/flush", json={})

    async def get_auth_cache_stats(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/auth-cache/stats")

    async def flush_schema_cache(self) -> dict[str, Any]:
        return await self._http.post("/v1/admin/schemas/cache/flush", json={})

    async def list_rate_limit_exemptions(self) -> dict[str, Any]:
        return await self._http.get("/v1/admin/rate-limit-exemptions")

    async def get_rate_limit_exemption(self, owner_id: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/admin/rate-limit-exemptions/{owner_id}")

    async def set_rate_limit_exemption(self, owner_id: str, **params: Any) -> dict[str, Any]:
        return await self._http.put(f"/v1/admin/rate-limit-exemptions/{owner_id}", json=params or {})

    async def delete_rate_limit_exemption(self, owner_id: str) -> dict[str, Any]:
        return await self._http.delete(f"/v1/admin/rate-limit-exemptions/{owner_id}")
