"""Agent drift: what an agent did in the current window, the same counts for
the window before it, and the difference.

The difference is the signal. There is no score, no weighting and no threshold:
an acceptance rate that moves from 0.8 to 1.0 is as much of a change as one that
moves to 0.6, and both are for whoever watches the agent to look into.
Everything is computed on read from records, completions, verdicts and disputes.

This replaces the reputation resource, which scored agents. The routes it called
(``/v1/agents/{id}/reputation`` and its per-type sibling) no longer exist.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import (
    AgentDrift,
    AgentHistoryEntry,
    FleetDriftPage,
    FleetDriftRow,
    Page,
)


def _drift_params(window: int | None, type: str | None) -> dict[str, Any]:
    """Query for ``GET /v1/agents/{agentId}/drift``."""
    params: dict[str, Any] = {}
    if window is not None: params["window"] = window
    if type is not None: params["type"] = type
    return params


def _fleet_params(window: int | None, limit: int | None, cursor: str | None) -> dict[str, Any]:
    """Query for ``GET /v1/agents/drift``."""
    params: dict[str, Any] = {}
    if window is not None: params["window"] = window
    if limit is not None: params["limit"] = limit
    if cursor is not None: params["cursor"] = cursor
    return params


def _history_params(
    limit: int | None,
    offset: int | None,
    cursor: str | None,
    type: str | None,
    outcome: str | None,
    from_: str | None,
    to: str | None,
) -> dict[str, Any]:
    """Query for ``GET /v1/agents/{agentId}/history``.

    ``from_`` carries the trailing underscore only in Python, where ``from`` is
    a keyword; it goes out as ``from``.
    """
    params: dict[str, Any] = {}
    if limit is not None: params["limit"] = limit
    if offset is not None: params["offset"] = offset
    if cursor is not None: params["cursor"] = cursor
    if type is not None: params["type"] = type
    if outcome is not None: params["outcome"] = outcome
    if from_ is not None: params["from"] = from_
    if to is not None: params["to"] = to
    return params


class DriftResource:
    """Agent drift readings (``drift:read``)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get_agent(
        self,
        agent_id: str,
        *,
        window: int | None = None,
        type: str | None = None,
    ) -> AgentDrift:
        """Drift for one agent, overall and per type.

        Admin keys read any agent in their org; an agent key reads itself. A
        notarize-only agent shows records and nothing else, since its records
        carry no completion and no verdict, so its drift is volume.

        ``window`` is the window length in days (1 to 365, default 7). ``type``
        narrows ``by_type`` to one type; ``overall`` still covers every type.
        """
        return AgentDrift.model_validate(
            self._http.get(f"/v1/agents/{agent_id}/drift", params=_drift_params(window, type))
        )

    def list_fleet(
        self,
        *,
        window: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> FleetDriftPage:
        """One roll-up row per agent in the caller's org.

        Takes an org-bound admin key: a platform key carries no org, so there is
        no fleet to list. Pages by cursor, and the ``window`` the page was
        computed over rides alongside ``data`` rather than on each row.
        """
        return FleetDriftPage.model_validate(
            self._http.get_page("/v1/agents/drift", params=_fleet_params(window, limit, cursor))
        )

    def list_all_fleet(
        self,
        *,
        window: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        max_pages: int | None = None,
    ) -> Iterator[FleetDriftRow]:
        """Auto-paginate every agent's drift row in the org.

        ``window`` is resent with each cursor, which the cursor requires: the
        query parameters are bound into the token, and a page replayed under
        different ones is refused rather than answered from a stale offset.
        Every page is therefore computed over the same window, so the rows are
        comparable across the walk.

        Raises :class:`~agledger.PaginationLimitError` if the walk hits the
        runaway guard, rather than returning a prefix that looks like the whole
        fleet. Pass ``max_pages`` to bound it yourself.
        """
        for row in self._http.paginate(
            "/v1/agents/drift",
            params=_fleet_params(window, limit, cursor),
            max_pages=max_pages,
        ):
            yield FleetDriftRow.model_validate(row)

    def get_agent_history(
        self,
        agent_id: str,
        *,
        limit: int | None = None,
        offset: int | None = None,
        cursor: str | None = None,
        type: str | None = None,
        outcome: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> Page[AgentHistoryEntry]:
        """Per-record history for an agent: one row per record with its status
        and gate outcome. This is the per-record feed behind the drift counts.

        Cursor-paged, and the filters are bound into the cursor, so replay it
        with the same parameters that produced it. ``from_`` and ``to`` are
        ISO-8601 instants bounding record creation.
        """
        raw = self._http.get_page(
            f"/v1/agents/{agent_id}/history",
            params=_history_params(limit, offset, cursor, type, outcome, from_, to),
        )
        raw["data"] = [AgentHistoryEntry.model_validate(d) for d in raw.get("data", [])]
        return Page[AgentHistoryEntry].model_validate(raw)


class AsyncDriftResource:
    """Async agent drift readings (``drift:read``)."""

    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def get_agent(
        self,
        agent_id: str,
        *,
        window: int | None = None,
        type: str | None = None,
    ) -> AgentDrift:
        """Drift for one agent, overall and per type."""
        return AgentDrift.model_validate(
            await self._http.get(f"/v1/agents/{agent_id}/drift", params=_drift_params(window, type))
        )

    async def list_fleet(
        self,
        *,
        window: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> FleetDriftPage:
        """One roll-up row per agent in the caller's org, with the window the
        page was computed over."""
        return FleetDriftPage.model_validate(
            await self._http.get_page("/v1/agents/drift", params=_fleet_params(window, limit, cursor))
        )

    async def list_all_fleet(
        self,
        *,
        window: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        max_pages: int | None = None,
    ) -> AsyncIterator[FleetDriftRow]:
        """Auto-paginate every agent's drift row in the org, resending ``window``
        with each cursor so the rows stay comparable across the walk."""
        async for row in self._http.paginate(
            "/v1/agents/drift",
            params=_fleet_params(window, limit, cursor),
            max_pages=max_pages,
        ):
            yield FleetDriftRow.model_validate(row)

    async def get_agent_history(
        self,
        agent_id: str,
        *,
        limit: int | None = None,
        offset: int | None = None,
        cursor: str | None = None,
        type: str | None = None,
        outcome: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> Page[AgentHistoryEntry]:
        """Per-record history for an agent. ``from_`` goes out as ``from``."""
        raw = await self._http.get_page(
            f"/v1/agents/{agent_id}/history",
            params=_history_params(limit, offset, cursor, type, outcome, from_, to),
        )
        raw["data"] = [AgentHistoryEntry.model_validate(d) for d in raw.get("data", [])]
        return Page[AgentHistoryEntry].model_validate(raw)
