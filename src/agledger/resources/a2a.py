"""A2A (Agent-to-Agent) protocol resource."""

from __future__ import annotations

import uuid
from typing import Any

from agledger._http import AsyncHttpClient, HttpClient, on_behalf_of_headers
from agledger.types import AgentCard


def _cancel_params(
    *, name: str | None, task_id: str | None, reason: str | None
) -> dict[str, Any]:
    """The ``CancelTask`` params: the task named one way, and the reason under
    the one metadata key the method reads, ``agledger:reason``. No reason, no
    ``metadata`` key at all, since any other metadata key is refused."""
    if (name is None) == (task_id is None):
        raise ValueError("cancel_task takes exactly one of name= and task_id=")
    params: dict[str, Any] = {"name": name} if name is not None else {"id": task_id}
    if reason is not None:
        params["metadata"] = {"agledger:reason": reason}
    return params


def _envelope(method: str, params: dict[str, Any] | None) -> dict[str, Any]:
    """The JSON-RPC envelope for ``call``. ``params`` is left out when ``None``:
    the Server refuses ``"params": null`` (-32600) but takes the key absent."""
    request: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": str(uuid.uuid4())}
    if params is not None:
        request["params"] = params
    return request


class A2AResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get_agent_card(self) -> AgentCard:
        """Fetch the platform's AgentCard for A2A discovery."""
        return AgentCard.model_validate(self._http.get("/.well-known/agent-card.json"))

    def dispatch(self, request: dict[str, Any], *, on_behalf_of: str | None = None) -> dict[str, Any]:
        """Dispatch a JSON-RPC 2.0 request to the A2A endpoint.

        ``on_behalf_of`` is sent as the ``AGLedger-On-Behalf-Of`` header, as on
        ``records.create``."""
        return self._http.post("/a2a", json=request, headers=on_behalf_of_headers(on_behalf_of))

    def call(
        self, method: str, params: dict[str, Any] | None = None, *, on_behalf_of: str | None = None
    ) -> dict[str, Any]:
        """Convenience: call a named A2A method with params. Auto-generates JSON-RPC envelope."""
        return self.dispatch(_envelope(method, params), on_behalf_of=on_behalf_of)

    def cancel_task(
        self,
        *,
        name: str | None = None,
        task_id: str | None = None,
        reason: str | None = None,
        on_behalf_of: str | None = None,
    ) -> dict[str, Any]:
        """``CancelTask`` with its one typed extension. Name the task by
        ``name`` (``tasks/<uuid>``, the v1.0 resource name) or ``task_id`` (the
        bare id, which is the record id), not both. ``reason`` rides in
        ``metadata["agledger:reason"]``, held to the same cap as the ``reason``
        on ``POST /v1/records/{id}/cancel``, and lands where that one does: the
        record's ``lastTransitionReason`` and the signed state-change entry."""
        return self.call(
            "CancelTask",
            _cancel_params(name=name, task_id=task_id, reason=reason),
            on_behalf_of=on_behalf_of,
        )


class AsyncA2AResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get_agent_card(self) -> AgentCard:
        """Fetch the platform's AgentCard for A2A discovery."""
        return AgentCard.model_validate(await self._http.get("/.well-known/agent-card.json"))

    async def dispatch(self, request: dict[str, Any], *, on_behalf_of: str | None = None) -> dict[str, Any]:
        """Dispatch a JSON-RPC 2.0 request to the A2A endpoint."""
        return await self._http.post("/a2a", json=request, headers=on_behalf_of_headers(on_behalf_of))

    async def call(
        self, method: str, params: dict[str, Any] | None = None, *, on_behalf_of: str | None = None
    ) -> dict[str, Any]:
        """Convenience: call a named A2A method with params. Auto-generates JSON-RPC envelope."""
        return await self.dispatch(_envelope(method, params), on_behalf_of=on_behalf_of)

    async def cancel_task(
        self,
        *,
        name: str | None = None,
        task_id: str | None = None,
        reason: str | None = None,
        on_behalf_of: str | None = None,
    ) -> dict[str, Any]:
        """``CancelTask`` with its one typed extension; see the sync client."""
        return await self.call(
            "CancelTask",
            _cancel_params(name=name, task_id=task_id, reason=reason),
            on_behalf_of=on_behalf_of,
        )

