"""Schemas resource — Type schema registry, custom Type authoring, version management."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import Page


class SchemasResource:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, *, org_id: str | None = None) -> Page[dict[str, Any]]:
        """List available Type schemas."""
        params: dict[str, Any] = {}
        if org_id is not None: params["orgId"] = org_id
        return Page[dict[str, Any]].model_validate(self._http.get_page("/v1/schemas", params=params))

    def get(self, type: str) -> dict[str, Any]:
        """Get the full JSON Schema for a Type."""
        return self._http.get(f"/v1/schemas/{type}")

    def delete(self, type: str) -> dict[str, Any]:
        """Delete a custom Type schema."""
        return self._http.delete(f"/v1/schemas/{type}")

    def get_rules(self, type: str) -> dict[str, Any]:
        """Get the verification rules for a Type."""
        return self._http.get(f"/v1/schemas/{type}/rules")

    def validate_completion(self, type: str, evidence: dict[str, Any]) -> dict[str, Any]:
        """Dry-run completion validation against a Type's schema."""
        return self._http.post(f"/v1/schemas/{type}/validate", json={"evidence": evidence})

    def meta_schema(self) -> dict[str, Any]:
        """Get the meta-schema describing constraints and limits for custom schema authoring."""
        return self._http.get("/v1/schemas/meta-schema")

    def get_template(self, type: str) -> dict[str, Any]:
        """Get a template for creating a new schema based on an existing Type."""
        return self._http.get(f"/v1/schemas/{type}/template")

    def blank(self) -> dict[str, Any]:
        """Get a blank template for creating a custom Type from scratch."""
        return self._http.get("/v1/schemas/_blank")

    def preview(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        """Preview a schema before registration."""
        return self._http.post("/v1/schemas/preview", json=schema_input)

    def diff(self, type: str, *, from_version: int, to_version: int) -> dict[str, Any]:
        """Diff two versions of a Type schema."""
        return self._http.get(
            f"/v1/schemas/{type}/diff",
            params={"from": from_version, "to": to_version},
        )

    def export_schema(
        self,
        type: str,
        *,
        versions: str | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """Export a Type schema bundle."""
        params: dict[str, Any] = {}
        if versions is not None:
            params["versions"] = versions
        if org_id is not None:
            params["orgId"] = org_id
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

    def get_versions(self, type: str) -> Page[dict[str, Any]]:
        """List all versions of a Type schema."""
        raw = self._http.get_page(f"/v1/schemas/{type}/versions")
        return Page[dict[str, Any]].model_validate(raw)

    def get_version(self, type: str, version: int) -> dict[str, Any]:
        """Get a specific version of a Type schema."""
        return self._http.get(f"/v1/schemas/{type}/versions/{version}")

    def check_compatibility(self, type: str, schemas: dict[str, Any]) -> dict[str, Any]:
        """Check compatibility of new record/completion schemas against an existing Type."""
        return self._http.post(f"/v1/schemas/{type}/check-compatibility", json=schemas)

    def update_version(self, type: str, version: int, params: dict[str, Any]) -> dict[str, Any]:
        """Update a schema version (e.g., deprecate or change compatibility mode)."""
        return self._http.patch(f"/v1/schemas/{type}/versions/{version}", json=params)

    def disable(self, type: str) -> dict[str, Any]:
        """Disable a Type — Records of this Type can no longer be created."""
        return self._http.patch(f"/v1/schemas/{type}/disable", json={})

    def enable(self, type: str) -> dict[str, Any]:
        """Re-enable a previously disabled Type."""
        return self._http.patch(f"/v1/schemas/{type}/enable", json={})


class AsyncSchemasResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, *, org_id: str | None = None) -> Page[dict[str, Any]]:
        params: dict[str, Any] = {}
        if org_id is not None: params["orgId"] = org_id
        return Page[dict[str, Any]].model_validate(await self._http.get_page("/v1/schemas", params=params))

    async def get(self, type: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}")

    async def delete(self, type: str) -> dict[str, Any]:
        return await self._http.delete(f"/v1/schemas/{type}")

    async def get_rules(self, type: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}/rules")

    async def validate_completion(self, type: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post(f"/v1/schemas/{type}/validate", json={"evidence": evidence})

    async def meta_schema(self) -> dict[str, Any]:
        return await self._http.get("/v1/schemas/meta-schema")

    async def get_template(self, type: str) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}/template")

    async def blank(self) -> dict[str, Any]:
        return await self._http.get("/v1/schemas/_blank")

    async def preview(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post("/v1/schemas/preview", json=schema_input)

    async def diff(self, type: str, *, from_version: int, to_version: int) -> dict[str, Any]:
        return await self._http.get(
            f"/v1/schemas/{type}/diff",
            params={"from": from_version, "to": to_version},
        )

    async def export_schema(
        self,
        type: str,
        *,
        versions: str | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if versions is not None:
            params["versions"] = versions
        if org_id is not None:
            params["orgId"] = org_id
        return await self._http.post(f"/v1/schemas/{type}/export", params=params)

    async def import_(
        self,
        manifest: dict[str, Any],
        *,
        org_id: str | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        """Import a third-party schema manifest — see the sync ``import_`` docstring."""
        body: dict[str, Any] = {"manifest": manifest, **options}
        if org_id is not None:
            body["orgId"] = org_id
        return await self._http.post("/v1/schemas/import", json=body)

    async def register(self, schema_input: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post("/v1/schemas", json=schema_input)

    async def get_versions(self, type: str) -> Page[dict[str, Any]]:
        raw = await self._http.get_page(f"/v1/schemas/{type}/versions")
        return Page[dict[str, Any]].model_validate(raw)

    async def get_version(self, type: str, version: int) -> dict[str, Any]:
        return await self._http.get(f"/v1/schemas/{type}/versions/{version}")

    async def check_compatibility(self, type: str, schemas: dict[str, Any]) -> dict[str, Any]:
        return await self._http.post(f"/v1/schemas/{type}/check-compatibility", json=schemas)

    async def update_version(self, type: str, version: int, params: dict[str, Any]) -> dict[str, Any]:
        return await self._http.patch(f"/v1/schemas/{type}/versions/{version}", json=params)

    async def disable(self, type: str) -> dict[str, Any]:
        return await self._http.patch(f"/v1/schemas/{type}/disable", json={})

    async def enable(self, type: str) -> dict[str, Any]:
        return await self._http.patch(f"/v1/schemas/{type}/enable", json={})
