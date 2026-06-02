"""Events resource."""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Event, Page


class EventsResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, *, since: str, order: str = "desc", limit: int | None = None, cursor: str | None = None) -> Page[Event]:
        """List events globally. Requires ``since`` parameter (ISO timestamp)."""
        params: dict[str, Any] = {"since": since, "order": order}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = self._http.get_page("/v1/events", params=params)
        raw["data"] = [Event.model_validate(e) for e in raw.get("data", [])]
        return Page[Event].model_validate(raw)

    def list_all(self, *, since: str, order: str = "desc") -> Iterator[Event]:
        """Auto-paginating iterator. Yields individual events across all pages."""
        for item in self._http.paginate("/v1/events", params={"since": since, "order": order}):
            yield Event.model_validate(item)


class AsyncEventsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, *, since: str, order: str = "desc", limit: int | None = None, cursor: str | None = None) -> Page[Event]:
        params: dict[str, Any] = {"since": since, "order": order}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = await self._http.get_page("/v1/events", params=params)
        raw["data"] = [Event.model_validate(e) for e in raw.get("data", [])]
        return Page[Event].model_validate(raw)

    async def list_all(self, *, since: str, order: str = "desc") -> AsyncIterator[Event]:
        async for item in self._http.paginate("/v1/events", params={"since": since, "order": order}):
            yield Event.model_validate(item)
