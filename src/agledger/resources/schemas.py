"""Schemas resource: Type schema registry, custom Type authoring, version management."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Page


def _scope(publisher: str | None) -> dict[str, Any] | None:
    """The publisher scope as a query param, or None when unpinned.

    A bare ``type`` names a schema only while one publisher offers it. Once two
    do (an imported peer manifest alongside a local registration), these routes
    return 422 ``/problems/ambiguous-publisher`` with the candidate list rather
    than picking one.
    """
    return None if publisher is None else {"publisher": publisher}


class SchemasResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, *, org_id: str | None = None) -> Page[dict[str, Any]]:
        """List available Type schemas, one row per (publisher, type).

        Two rows sharing a ``type`` under different ``publisher`` labels is the
        state that makes every other call on this resource ambiguous. Read
        ``publisher`` off the row you want and pass it back.
        """
        params: dict[str, Any] = {}
        if org_id is not None: params["orgId"] = org_id
        return Page[dict[str, Any]].model_validate(self._http.get_page("/v1/schemas", params=params))

    def get(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Get the full JSON Schema for a Type.

        ``publisher`` scopes the read when two publishers offer the same type in
        this org; without it that case is a 422 ``/problems/ambiguous-publisher``
        listing the candidates. See ``list()``.
        """
        return self._http.get(f"/v1/schemas/{type}", params=_scope(publisher))

    def delete(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Delete a custom Type schema."""
        return self._http.delete(f"/v1/schemas/{type}", params=_scope(publisher))

    def get_rules(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Get the verification rules for a Type."""
        return self._http.get(f"/v1/schemas/{type}/rules", params=_scope(publisher))

    def get_manifest(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Get this Server's canonical manifest for a Type.

        Returns ``{"manifest": ..., "manifestDigest": ...}``, shaped exactly as
        ``import_()`` accepts. The bytes are JCS-canonicalized before hashing, so
        the digest matches what a peer computes on import.
        """
        return self._http.get(f"/v1/schemas/{type}/manifest", params=_scope(publisher))

    def validate_completion(
        self, type: str, evidence: dict[str, Any], *, publisher: str | None = None
    ) -> dict[str, Any]:
        """Dry-run completion validation against a Type's schema."""
        return self._http.post(
            f"/v1/schemas/{type}/validate", json={"evidence": evidence}, params=_scope(publisher)
        )

    def meta_schema(self) -> dict[str, Any]:
        """Get the meta-schema describing constraints and limits for custom schema authoring."""
        return self._http.get("/v1/schemas/meta-schema")

    def get_template(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Get a template for creating a new schema based on an existing Type."""
        return self._http.get(f"/v1/schemas/{type}/template", params=_scope(publisher))

    def blank(self) -> dict[str, Any]:
        """Get a blank template for creating a custom Type from scratch."""
        return self._http.get("/v1/schemas/_blank")

    def preview(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        """Preview a schema before registration."""
        return self._http.post("/v1/schemas/preview", json=schema_input)

    def diff(
        self, type: str, *, from_version: int, to_version: int, publisher: str | None = None
    ) -> dict[str, Any]:
        """Diff two versions of a Type schema.

        Pin ``publisher`` on a type two publishers offer. Unpinned, the call
        answers 422 rather than resolving each side independently, which could
        otherwise compare two unrelated publishers' schemas and report the
        difference as a breaking change.
        """
        return self._http.get(
            f"/v1/schemas/{type}/diff",
            params={"from": from_version, "to": to_version, **(_scope(publisher) or {})},
        )

    def export_schema(
        self,
        type: str,
        *,
        versions: str | None = None,
        org_id: str | None = None,
        publisher: str | None = None,
    ) -> dict[str, Any]:
        """Export a Type schema bundle.

        Pin ``publisher`` on a type two publishers offer. Without it the engine
        emits both registrations, whose ``versions`` entries can carry the same
        number with nothing to tell them apart.
        """
        params: dict[str, Any] = {}
        if versions is not None:
            params["versions"] = versions
        if org_id is not None:
            params["orgId"] = org_id
        if publisher is not None:
            params["publisher"] = publisher
        return self._http.post(f"/v1/schemas/{type}/export", params=params)

    def import_(
        self,
        manifest: dict[str, Any],
        *,
        org_id: str | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        """Import a third-party schema manifest (DESIGN-SCHEMA-CATALOG.md §4).

        ``manifest`` requires ``manifestVersion``, ``publisher``, ``type``,
        ``version`` and ``recordSchema``. Row-only metadata options
        (``federatable``, ``defaultShare``, ``defaultGateMode``,
        ``coSignRequired``, ``flipRecordStatusOnDispute``,
        ``federateDisputes``) ride alongside the manifest in the body.
        Idempotent on full-tuple match (publisher, type, version, org,
        digest): re-posting the same manifest returns the existing row (HTTP
        200 instead of 201); same identity with different bytes is a 409.
        Requires the ``schemas:admin`` scope.
        """
        body: dict[str, Any] = {"manifest": manifest, **options}
        if org_id is not None:
            body["orgId"] = org_id
        return self._http.post("/v1/schemas/import", json=body)

    def register(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        """Register a new custom Type schema."""
        return self._http.post("/v1/schemas", json=schema_input)

    def get_versions(self, type: str, *, publisher: str | None = None) -> Page[dict[str, Any]]:
        """List all versions of a Type schema."""
        raw = self._http.get_page(f"/v1/schemas/{type}/versions", params=_scope(publisher))
        return Page[dict[str, Any]].model_validate(raw)

    def get_version(self, type: str, version: int, *, publisher: str | None = None) -> dict[str, Any]:
        """Get a specific version of a Type schema.

        The version counter is per (publisher, type) and shared across
        publishers, so a second publisher's v2 reflects registration order, not a
        newer schema. Pin ``publisher`` before comparing across the two.
        """
        return self._http.get(
            f"/v1/schemas/{type}/versions/{version}", params=_scope(publisher)
        )

    def check_compatibility(self, type: str, schemas: dict[str, Any]) -> dict[str, Any]:
        """Check compatibility of new record/completion schemas against an existing Type."""
        return self._http.post(f"/v1/schemas/{type}/check-compatibility", json=schemas)

    def update_version(
        self, type: str, version: int, params: dict[str, Any], *, publisher: str | None = None
    ) -> dict[str, Any]:
        """Change a schema version's compatibility mode, which is all this route updates.

        The body takes ``compatibilityMode`` and nothing else (it declares
        ``additionalProperties: false``), and the values are lowercase:
        ``none``, ``backward``, ``forward``, ``full``. There is no deprecate
        here; disabling a Type is :meth:`disable`.
        """
        return self._http.patch(
            f"/v1/schemas/{type}/versions/{version}", json=params, params=_scope(publisher)
        )

    def disable(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Disable a Type. Records of this Type can no longer be created."""
        return self._http.patch(
            f"/v1/schemas/{type}/disable", json={}, params=_scope(publisher)
        )

    def enable(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """Re-enable a previously disabled Type."""
        return self._http.patch(
            f"/v1/schemas/{type}/enable", json={}, params=_scope(publisher)
        )


class AsyncSchemasResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, *, org_id: str | None = None) -> Page[dict[str, Any]]:
        params: dict[str, Any] = {}
        if org_id is not None: params["orgId"] = org_id
        return Page[dict[str, Any]].model_validate(await self._http.get_page("/v1/schemas", params=params))

    async def get(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}", params=_scope(publisher))

    async def delete(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        return await self._http.delete(f"/v1/schemas/{type}", params=_scope(publisher))

    async def get_rules(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}/rules", params=_scope(publisher))

    async def get_manifest(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        """See the sync ``get_manifest`` docstring."""
        return await self._http.get(f"/v1/schemas/{type}/manifest", params=_scope(publisher))

    async def validate_completion(
        self, type: str, evidence: dict[str, Any], *, publisher: str | None = None
    ) -> dict[str, Any]:
        return await self._http.post(
            f"/v1/schemas/{type}/validate", json={"evidence": evidence}, params=_scope(publisher)
        )

    async def meta_schema(self) -> dict[str, Any]:
        return await self._http.get("/v1/schemas/meta-schema")

    async def get_template(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}/template", params=_scope(publisher))

    async def blank(self) -> dict[str, Any]:
        return await self._http.get("/v1/schemas/_blank")

    async def preview(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post("/v1/schemas/preview", json=schema_input)

    async def diff(
        self, type: str, *, from_version: int, to_version: int, publisher: str | None = None
    ) -> dict[str, Any]:
        return await self._http.get(
            f"/v1/schemas/{type}/diff",
            params={"from": from_version, "to": to_version, **(_scope(publisher) or {})},
        )

    async def export_schema(
        self,
        type: str,
        *,
        versions: str | None = None,
        org_id: str | None = None,
        publisher: str | None = None,
    ) -> dict[str, Any]:
        """Export a Type schema bundle. Pin ``publisher`` on an ambiguous type."""
        params: dict[str, Any] = {}
        if versions is not None:
            params["versions"] = versions
        if org_id is not None:
            params["orgId"] = org_id
        if publisher is not None:
            params["publisher"] = publisher
        return await self._http.post(f"/v1/schemas/{type}/export", params=params)

    async def import_(
        self,
        manifest: dict[str, Any],
        *,
        org_id: str | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        """Import a third-party schema manifest: see the sync ``import_`` docstring."""
        body: dict[str, Any] = {"manifest": manifest, **options}
        if org_id is not None:
            body["orgId"] = org_id
        return await self._http.post("/v1/schemas/import", json=body)

    async def register(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post("/v1/schemas", json=schema_input)

    async def get_versions(
        self, type: str, *, publisher: str | None = None
    ) -> Page[dict[str, Any]]:
        raw = await self._http.get_page(f"/v1/schemas/{type}/versions", params=_scope(publisher))
        return Page[dict[str, Any]].model_validate(raw)

    async def get_version(
        self, type: str, version: int, *, publisher: str | None = None
    ) -> dict[str, Any]:
        return await self._http.get(
            f"/v1/schemas/{type}/versions/{version}", params=_scope(publisher)
        )

    async def check_compatibility(self, type: str, schemas: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post(f"/v1/schemas/{type}/check-compatibility", json=schemas)

    async def update_version(
        self, type: str, version: int, params: dict[str, Any], *, publisher: str | None = None
    ) -> dict[str, Any]:
        return await self._http.patch(
            f"/v1/schemas/{type}/versions/{version}", json=params, params=_scope(publisher)
        )

    async def disable(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        return await self._http.patch(
            f"/v1/schemas/{type}/disable", json={}, params=_scope(publisher)
        )

    async def enable(self, type: str, *, publisher: str | None = None) -> dict[str, Any]:
        return await self._http.patch(
            f"/v1/schemas/{type}/enable", json={}, params=_scope(publisher)
        )
