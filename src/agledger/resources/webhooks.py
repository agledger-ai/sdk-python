"""Webhooks resource."""

from __future__ import annotations
from typing import Any
from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Page, Webhook, WebhookTestResult


class WebhooksResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(
        self,
        *,
        url: str,
        event_types: list[str],
        format: str | None = None,
        signing_alg: str | None = None,
    ) -> Webhook:
        """Register a new webhook subscription.

        Set ``signing_alg="ed25519"`` for non-repudiable RFC 9421 deliveries
        signed with the Server vault key (verify them with ``verify_rfc9421``
        from ``agledger.webhooks``). Settlement-event subscriptions default to
        ``ed25519`` when the Server has a vault signing key.
        """
        body: dict[str, Any] = {"url": url, "eventTypes": event_types}
        if format is not None:
            body["format"] = format
        if signing_alg is not None:
            body["signingAlg"] = signing_alg
        data = self._http.post("/v1/webhooks", json=body)
        return Webhook.model_validate(data)

    def get(self, webhook_id: str) -> Webhook:
        """Get a single webhook by ID."""
        data = self._http.get(f"/v1/webhooks/{webhook_id}")
        return Webhook.model_validate(data)

    def update(
        self,
        webhook_id: str,
        *,
        url: str | None = None,
        event_types: list[str] | None = None,
        is_paused: bool | None = None,
    ) -> Webhook:
        """Update a webhook subscription. The API accepts only url, eventTypes, isPaused here
        (signing scheme and payload format are fixed at create time)."""
        body: dict[str, Any] = {}
        if url is not None:
            body["url"] = url
        if event_types is not None:
            body["eventTypes"] = event_types
        if is_paused is not None:
            body["isPaused"] = is_paused
        data = self._http.patch(f"/v1/webhooks/{webhook_id}", json=body)
        return Webhook.model_validate(data)

    def list(self, *, url: str | None = None, **params: Any) -> Page[dict[str, Any]]:
        """List webhooks, optionally filtered by exact URL match.

        Example::

            all_hooks = client.webhooks.list()
            filtered = client.webhooks.list(url="https://example.com/webhook")
        """
        if url is not None:
            params["url"] = url
        return Page[dict[str, Any]].model_validate(self._http.get_page("/v1/webhooks", params=params))

    def delete(self, webhook_id: str) -> None:
        self._http.delete(f"/v1/webhooks/{webhook_id}")

    def rotate(self, webhook_id: str) -> Webhook:
        """Rotate webhook signing secret."""
        data = self._http.post(f"/v1/webhooks/{webhook_id}/rotate")
        return Webhook.model_validate(data)

    def ping(self, webhook_id: str) -> WebhookTestResult:
        """Send a test ping to the webhook URL."""
        return WebhookTestResult.model_validate(self._http.post(f"/v1/webhooks/{webhook_id}/ping"))

    def pause(self, webhook_id: str) -> Webhook:
        """Pause a webhook (stop delivering events)."""
        data = self._http.post(f"/v1/webhooks/{webhook_id}/pause")
        return Webhook.model_validate(data)

    def resume(self, webhook_id: str) -> Webhook:
        """Resume a paused webhook."""
        data = self._http.post(f"/v1/webhooks/{webhook_id}/resume")
        return Webhook.model_validate(data)

    def list_deliveries(self, webhook_id: str, **params: Any) -> Page[dict[str, Any]]:
        """List delivery attempts for a webhook."""
        return Page[dict[str, Any]].model_validate(self._http.get_page(f"/v1/webhooks/{webhook_id}/deliveries", params=params))

    def list_dlq(self, webhook_id: str, **params: Any) -> Page[dict[str, Any]]:
        """List dead-letter queue entries for a webhook."""
        return Page[dict[str, Any]].model_validate(self._http.get_page(f"/v1/webhooks/{webhook_id}/dlq", params=params))

    def retry_all_dlq(self, webhook_id: str) -> dict[str, Any]:
        """Retry all DLQ entries for a webhook."""
        return self._http.post(f"/v1/webhooks/{webhook_id}/dlq/retry-all")

    def retry_dlq(self, webhook_id: str, dlq_id: str) -> dict[str, Any]:
        """Retry a single DLQ entry for a webhook."""
        return self._http.post(f"/v1/webhooks/{webhook_id}/dlq/{dlq_id}/retry")


class AsyncWebhooksResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def create(
        self,
        *,
        url: str,
        event_types: list[str],
        format: str | None = None,
        signing_alg: str | None = None,
    ) -> Webhook:
        """Register a new webhook subscription.

        Set ``signing_alg="ed25519"`` for non-repudiable RFC 9421 deliveries
        signed with the Server vault key (verify them with ``verify_rfc9421``
        from ``agledger.webhooks``). Settlement-event subscriptions default to
        ``ed25519`` when the Server has a vault signing key.
        """
        body: dict[str, Any] = {"url": url, "eventTypes": event_types}
        if format is not None:
            body["format"] = format
        if signing_alg is not None:
            body["signingAlg"] = signing_alg
        data = await self._http.post("/v1/webhooks", json=body)
        return Webhook.model_validate(data)

    async def get(self, webhook_id: str) -> Webhook:
        """Get a single webhook by ID."""
        data = await self._http.get(f"/v1/webhooks/{webhook_id}")
        return Webhook.model_validate(data)

    async def update(
        self,
        webhook_id: str,
        *,
        url: str | None = None,
        event_types: list[str] | None = None,
        is_paused: bool | None = None,
    ) -> Webhook:
        """Update a webhook subscription. The API accepts only url, eventTypes, isPaused here
        (signing scheme and payload format are fixed at create time)."""
        body: dict[str, Any] = {}
        if url is not None:
            body["url"] = url
        if event_types is not None:
            body["eventTypes"] = event_types
        if is_paused is not None:
            body["isPaused"] = is_paused
        data = await self._http.patch(f"/v1/webhooks/{webhook_id}", json=body)
        return Webhook.model_validate(data)

    async def list(self, *, url: str | None = None, **params: Any) -> Page[dict[str, Any]]:
        """List webhooks, optionally filtered by exact URL match."""
        if url is not None:
            params["url"] = url
        return Page[dict[str, Any]].model_validate(await self._http.get_page("/v1/webhooks", params=params))

    async def delete(self, webhook_id: str) -> None:
        await self._http.delete(f"/v1/webhooks/{webhook_id}")

    async def rotate(self, webhook_id: str) -> Webhook:
        """Rotate webhook signing secret."""
        data = await self._http.post(f"/v1/webhooks/{webhook_id}/rotate")
        return Webhook.model_validate(data)

    async def ping(self, webhook_id: str) -> WebhookTestResult:
        """Send a test ping to the webhook URL."""
        return WebhookTestResult.model_validate(await self._http.post(f"/v1/webhooks/{webhook_id}/ping"))

    async def pause(self, webhook_id: str) -> Webhook:
        """Pause a webhook (stop delivering events)."""
        data = await self._http.post(f"/v1/webhooks/{webhook_id}/pause")
        return Webhook.model_validate(data)

    async def resume(self, webhook_id: str) -> Webhook:
        """Resume a paused webhook."""
        data = await self._http.post(f"/v1/webhooks/{webhook_id}/resume")
        return Webhook.model_validate(data)

    async def list_deliveries(self, webhook_id: str, **params: Any) -> Page[dict[str, Any]]:
        """List delivery attempts for a webhook."""
        return Page[dict[str, Any]].model_validate(await self._http.get_page(f"/v1/webhooks/{webhook_id}/deliveries", params=params))

    async def list_dlq(self, webhook_id: str, **params: Any) -> Page[dict[str, Any]]:
        """List dead-letter queue entries for a webhook."""
        return Page[dict[str, Any]].model_validate(await self._http.get_page(f"/v1/webhooks/{webhook_id}/dlq", params=params))

    async def retry_all_dlq(self, webhook_id: str) -> dict[str, Any]:
        """Retry all DLQ entries for a webhook."""
        return await self._http.post(f"/v1/webhooks/{webhook_id}/dlq/retry-all")

    async def retry_dlq(self, webhook_id: str, dlq_id: str) -> dict[str, Any]:
        """Retry a single DLQ entry for a webhook."""
        return await self._http.post(f"/v1/webhooks/{webhook_id}/dlq/{dlq_id}/retry")
