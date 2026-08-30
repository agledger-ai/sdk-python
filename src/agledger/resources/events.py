"""Events resource."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Event, Page


class EventsResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, *, since: str, until: str | None = None, order: str = "desc", limit: int | None = None, cursor: str | None = None) -> Page[Event]:
        """List events globally. Requires ``since`` (ISO timestamp, inclusive:
        events at or after it).

        Pair it with ``until`` (exclusive: strictly before) to close the window.
        Consecutive windows compose without overlap when the next ``since``
        equals the previous ``until``."""
        params: dict[str, Any] = {"since": since, "order": order}
        if until is not None: params["until"] = until
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = self._http.get_page("/v1/events", params=params)
        raw["data"] = [Event.model_validate(e) for e in raw.get("data", [])]
        return Page[Event].model_validate(raw)

    def list_all(
        self, *, since: str, until: str | None = None, order: str = "desc", limit: int | None = None, max_pages: int | None = None
    ) -> Iterator[Event]:
        """Auto-paginating iterator. Yields individual events across all pages.

        ``since`` is inclusive and ``until`` is exclusive, so the two close a
        window that replays identically. ``limit`` sets the page size.
        Unbounded, the walk raises :class:`PaginationLimitError` if it hits the
        runaway guard rather than returning a prefix; pass ``max_pages`` to
        bound it yourself."""
        params: dict[str, Any] = {"since": since, "order": order}
        if until is not None:
            params["until"] = until
        if limit is not None:
            params["limit"] = limit
        for item in self._http.paginate("/v1/events", params=params, max_pages=max_pages):
            yield Event.model_validate(item)


class AsyncEventsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, *, since: str, until: str | None = None, order: str = "desc", limit: int | None = None, cursor: str | None = None) -> Page[Event]:
        """See the sync counterpart: ``since`` is inclusive, ``until`` exclusive."""
        params: dict[str, Any] = {"since": since, "order": order}
        if until is not None: params["until"] = until
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = await self._http.get_page("/v1/events", params=params)
        raw["data"] = [Event.model_validate(e) for e in raw.get("data", [])]
        return Page[Event].model_validate(raw)

    async def list_all(
        self, *, since: str, until: str | None = None, order: str = "desc", limit: int | None = None, max_pages: int | None = None
    ) -> AsyncIterator[Event]:
        params: dict[str, Any] = {"since": since, "order": order}
        if until is not None:
            params["until"] = until
        if limit is not None:
            params["limit"] = limit
        async for item in self._http.paginate("/v1/events", params=params, max_pages=max_pages):
            yield Event.model_validate(item)
