"""
AGLedger SDK — Client with resource sub-clients.
Supports context manager protocol for proper connection cleanup.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Literal

import httpx

from agledger._http import (
    AsyncHttpClient,
    HttpClient,
    RateLimitInfo,
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    resolve_api_key,
)
from agledger.resources.a2a import A2AResource, AsyncA2AResource
from agledger.resources.admin import AdminResource, AsyncAdminResource
from agledger.resources.agents import AgentsResource, AsyncAgentsResource
from agledger.resources.audit import AsyncAuditResource, AuditResource
from agledger.resources.auth import AsyncAuthResource, AuthResource
from agledger.resources.capabilities import AsyncCapabilitiesResource, CapabilitiesResource
from agledger.resources.compliance import AsyncComplianceResource, ComplianceResource
from agledger.resources.discovery import AsyncDiscoveryResource, DiscoveryResource
from agledger.resources.disputes import AsyncDisputesResource, DisputesResource
from agledger.resources.events import AsyncEventsResource, EventsResource
from agledger.resources.federation import AsyncFederationResource, FederationResource
from agledger.resources.federation_admin import AsyncFederationAdminResource, FederationAdminResource
from agledger.resources.health import AsyncHealthResource, HealthResource
from agledger.resources.completions import AsyncCompletionsResource, CompletionsResource
from agledger.resources.predicates import AsyncPredicatesResource, PredicatesResource
from agledger.resources.scitt import AsyncScittResource, ScittResource
from agledger.resources.records import AsyncRecordsResource, RecordsResource
from agledger.resources.references import AsyncReferencesResource, ReferencesResource
from agledger.resources.reputation import AsyncReputationResource, ReputationResource
from agledger.resources.schemas import AsyncSchemasResource, SchemasResource
from agledger.resources.gate import AsyncGateResource, GateResource
from agledger.resources.verification_keys import AsyncVerificationKeysResource, VerificationKeysResource
from agledger.resources.webhooks import AsyncWebhooksResource, WebhooksResource


class AgledgerClient:
    """Synchronous AGLedger API client.

    Supports context manager for automatic connection cleanup::

        with AgledgerClient(api_key="agl_agt_...") as client:
            record = client.records.create(
                type="notarize-generic-v1",
                criteria={"task_description": "summarize Q3 filings"},
            )

    Or pass ``AGLEDGER_API_KEY`` env var::

        client = AgledgerClient()  # reads from env
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        idempotency_key_prefix: str = "",
        http_client: httpx.Client | None = None,
    ) -> None:
        resolved_key = resolve_api_key(api_key)
        self._http = HttpClient(
            api_key=resolved_key,
            base_url=base_url,
            max_retries=max_retries,
            timeout=timeout,
            idempotency_key_prefix=idempotency_key_prefix,
            http_client=http_client,
        )
        self.records: RecordsResource = RecordsResource(self._http)
        self.completions: CompletionsResource = CompletionsResource(self._http)
        self.gate: GateResource = GateResource(self._http)
        self.disputes: DisputesResource = DisputesResource(self._http)
        self.webhooks: WebhooksResource = WebhooksResource(self._http)
        self.reputation: ReputationResource = ReputationResource(self._http)
        self.events: EventsResource = EventsResource(self._http)
        self.schemas: SchemasResource = SchemasResource(self._http)
        self.compliance: ComplianceResource = ComplianceResource(self._http)
        self.health: HealthResource = HealthResource(self._http)
        self.admin: AdminResource = AdminResource(self._http)
        self.a2a: A2AResource = A2AResource(self._http)
        self.agents: AgentsResource = AgentsResource(self._http)
        self.audit: AuditResource = AuditResource(self._http)
        self.auth: AuthResource = AuthResource(self._http)
        self.capabilities: CapabilitiesResource = CapabilitiesResource(self._http)
        self.discovery: DiscoveryResource = DiscoveryResource(self._http)
        self.references: ReferencesResource = ReferencesResource(self._http)
        self.federation: FederationResource = FederationResource(self._http)
        self.federation_admin: FederationAdminResource = FederationAdminResource(self._http)
        self.verification_keys: VerificationKeysResource = VerificationKeysResource(self._http)
        self.scitt: ScittResource = ScittResource(self._http)
        self.predicates: PredicatesResource = PredicatesResource(self._http)

    @property
    def last_request_id(self) -> str | None:
        """Request ID from the most recent API response (``X-Request-Id`` header)."""
        return self._http.last_request_id

    @property
    def rate_limit_info(self) -> RateLimitInfo | None:
        """Rate-limit snapshot from the most recent API response (``X-RateLimit-*``).

        ``None`` until the first response that carries the headers.
        """
        return self._http.rate_limit_info

    def request(
        self,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Escape hatch for API routes the SDK does not model.

        Forwards ``method`` + ``path`` + body/query to the API verbatim.
        Returns the parsed JSON response (or ``None`` on 204). Caller narrows
        the type themselves.

        Example::

            result = client.request("POST", "/v1/custom/endpoint", json={"foo": "bar"})
        """
        return self._http.request(method, path, json=json, params=params, timeout=timeout)

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> AgledgerClient:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.close()


class AsyncAgledgerClient:
    """Async AGLedger API client.

    Supports async context manager::

        async with AsyncAgledgerClient(api_key="agl_agt_...") as client:
            record = await client.records.get("rec-123")
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        idempotency_key_prefix: str = "",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        resolved_key = resolve_api_key(api_key)
        self._http = AsyncHttpClient(
            api_key=resolved_key,
            base_url=base_url,
            max_retries=max_retries,
            timeout=timeout,
            idempotency_key_prefix=idempotency_key_prefix,
            http_client=http_client,
        )
        self.records: AsyncRecordsResource = AsyncRecordsResource(self._http)
        self.completions: AsyncCompletionsResource = AsyncCompletionsResource(self._http)
        self.gate: AsyncGateResource = AsyncGateResource(self._http)
        self.disputes: AsyncDisputesResource = AsyncDisputesResource(self._http)
        self.webhooks: AsyncWebhooksResource = AsyncWebhooksResource(self._http)
        self.reputation: AsyncReputationResource = AsyncReputationResource(self._http)
        self.events: AsyncEventsResource = AsyncEventsResource(self._http)
        self.schemas: AsyncSchemasResource = AsyncSchemasResource(self._http)
        self.compliance: AsyncComplianceResource = AsyncComplianceResource(self._http)
        self.health: AsyncHealthResource = AsyncHealthResource(self._http)
        self.admin: AsyncAdminResource = AsyncAdminResource(self._http)
        self.a2a: AsyncA2AResource = AsyncA2AResource(self._http)
        self.agents: AsyncAgentsResource = AsyncAgentsResource(self._http)
        self.audit: AsyncAuditResource = AsyncAuditResource(self._http)
        self.auth: AsyncAuthResource = AsyncAuthResource(self._http)
        self.capabilities: AsyncCapabilitiesResource = AsyncCapabilitiesResource(self._http)
        self.discovery: AsyncDiscoveryResource = AsyncDiscoveryResource(self._http)
        self.references: AsyncReferencesResource = AsyncReferencesResource(self._http)
        self.federation: AsyncFederationResource = AsyncFederationResource(self._http)
        self.federation_admin: AsyncFederationAdminResource = AsyncFederationAdminResource(self._http)
        self.verification_keys: AsyncVerificationKeysResource = AsyncVerificationKeysResource(self._http)
        self.scitt: AsyncScittResource = AsyncScittResource(self._http)
        self.predicates: AsyncPredicatesResource = AsyncPredicatesResource(self._http)

    @property
    def last_request_id(self) -> str | None:
        """Request ID from the most recent API response (``X-Request-Id`` header)."""
        return self._http.last_request_id

    @property
    def rate_limit_info(self) -> RateLimitInfo | None:
        """Rate-limit snapshot from the most recent API response (``X-RateLimit-*``).

        ``None`` until the first response that carries the headers.
        """
        return self._http.rate_limit_info

    async def request(
        self,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Escape hatch for API routes the SDK does not model."""
        return await self._http.request(method, path, json=json, params=params, timeout=timeout)

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._http.close()

    async def __aenter__(self) -> AsyncAgledgerClient:
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        await self.close()
