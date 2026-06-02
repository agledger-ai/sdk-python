"""Completions resource."""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Completion, Page


class CompletionsResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def submit(
        self,
        record_id: str,
        *,
        evidence: dict[str, Any],
        evidence_hash: str | None = None,
        idempotency_key: str | None = None,
    ) -> Completion:
        """Submit a Completion (evidence of completion) for a Record.

        The API infers agent identity from the bearer token, so no agent_id
        parameter is needed. ``evidence_hash`` is the client-computed SHA-256 of
        the canonicalized evidence (required in encrypted mode — the server
        cannot compute it). To carry AI-agent rationale, declare a field in your
        Type's ``completionSchema`` and put it inside ``evidence``; the server
        rejects unknown root-level keys.
        """
        body: dict[str, Any] = {"evidence": evidence}
        if evidence_hash is not None: body["evidenceHash"] = evidence_hash
        if idempotency_key is not None: body["idempotencyKey"] = idempotency_key
        return Completion.model_validate(self._http.post(f"/v1/records/{record_id}/completions", json=body))

    def get(self, record_id: str, completion_id: str) -> Completion:
        return Completion.model_validate(self._http.get(f"/v1/records/{record_id}/completions/{completion_id}"))

    def list(self, record_id: str, *, limit: int | None = None, cursor: str | None = None) -> Page[Completion]:
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = self._http.get_page(f"/v1/records/{record_id}/completions", params=params)
        raw["data"] = [Completion.model_validate(r) for r in raw.get("data", [])]
        return Page[Completion].model_validate(raw)

    def list_all(self, record_id: str) -> Iterator[Completion]:
        for item in self._http.paginate(f"/v1/records/{record_id}/completions"):
            yield Completion.model_validate(item)


class AsyncCompletionsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def submit(
        self,
        record_id: str,
        *,
        evidence: dict[str, Any],
        evidence_hash: str | None = None,
        idempotency_key: str | None = None,
    ) -> Completion:
        """Submit a Completion (evidence of completion) for a Record.

        ``evidence_hash`` is the client-computed SHA-256 of the canonicalized
        evidence (required in encrypted mode). Carry AI-agent rationale inside
        ``evidence`` via a ``completionSchema`` field — the server rejects
        unknown root-level keys.
        """
        body: dict[str, Any] = {"evidence": evidence}
        if evidence_hash is not None: body["evidenceHash"] = evidence_hash
        if idempotency_key is not None: body["idempotencyKey"] = idempotency_key
        return Completion.model_validate(await self._http.post(f"/v1/records/{record_id}/completions", json=body))

    async def get(self, record_id: str, completion_id: str) -> Completion:
        return Completion.model_validate(await self._http.get(f"/v1/records/{record_id}/completions/{completion_id}"))

    async def list(self, record_id: str, *, limit: int | None = None, cursor: str | None = None) -> Page[Completion]:
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        if cursor is not None: params["cursor"] = cursor
        raw = await self._http.get_page(f"/v1/records/{record_id}/completions", params=params)
        raw["data"] = [Completion.model_validate(r) for r in raw.get("data", [])]
        return Page[Completion].model_validate(raw)

    async def list_all(self, record_id: str) -> AsyncIterator[Completion]:
        async for item in self._http.paginate(f"/v1/records/{record_id}/completions"):
            yield Completion.model_validate(item)
