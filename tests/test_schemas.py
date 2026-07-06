"""Tests for the SchemasResource (sync + async)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient

BASE = "https://agledger.example.com"

SCHEMA_JSON = {
    "type": "notarize-generic-v1",
    "recordSchema": {"type": "object"},
    "completionSchema": {"type": "object"},
}
META_SCHEMA_JSON = {
    "constraints": {"maxDepth": 5, "maxNodes": 200},
    "allowedFormats": ["date-time"],
    "limits": {"typeMaxLength": 64},
}
TEMPLATE_JSON = {
    "sourceType": "notarize-generic-v1",
    "template": {"type": "", "displayName": "", "description": "", "recordSchema": {}, "completionSchema": {}, "fieldMappings": []},
}
VERSION_JSON = {"id": "sv-1", "type": "notarize-generic-v1", "version": 1, "status": "ACTIVE"}
DIFF_JSON = {
    "type": "notarize-generic-v1",
    "from": {"version": 1},
    "to": {"version": 2},
    "record": {"changes": []},
    "completion": {"changes": []},
    "overallCompatibility": {"backward": True, "forward": True},
}
EXPORT_JSON = {"exportVersion": 1, "type": "notarize-generic-v1", "versions": []}
MANIFEST = {
    "manifestVersion": "1.0",
    "publisher": "acme",
    "type": "my-custom-v1",
    "version": "1.0",
    "recordSchema": {"type": "object"},
}
IMPORT_JSON = {"type": "my-custom-v1", "version": 1, "status": "ACTIVE", "publisher": "acme", "trustClass": "imported"}
PREVIEW_JSON = {"valid": True, "compiled": {}}
COMPAT_JSON = {"record": {"compatible": True, "changes": []}, "completion": {"compatible": True, "changes": []}}
RULES_JSON = {"type": "notarize-generic-v1", "syncRuleIds": ["r1"], "asyncRuleIds": []}
VALIDATE_JSON = {"valid": True}


# --- Sync tests ---

@respx.mock
def test_get_schema():
    respx.get(f"{BASE}/v1/schemas/notarize-generic-v1").mock(return_value=httpx.Response(200, json=SCHEMA_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.get("notarize-generic-v1")
    assert result["type"] == "notarize-generic-v1"


@respx.mock
def test_list_schemas():
    respx.get(f"{BASE}/v1/schemas").mock(return_value=httpx.Response(200, json={"data": [SCHEMA_JSON], "hasMore": False}))
    client = AgledgerClient(api_key="test-key")
    page = client.schemas.list()
    assert len(page.data) == 1


@respx.mock
def test_get_rules():
    respx.get(f"{BASE}/v1/schemas/notarize-generic-v1/rules").mock(return_value=httpx.Response(200, json=RULES_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.get_rules("notarize-generic-v1")
    assert result["syncRuleIds"] == ["r1"]


@respx.mock
def test_validate_completion():
    respx.post(f"{BASE}/v1/schemas/notarize-generic-v1/validate").mock(return_value=httpx.Response(200, json=VALIDATE_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.validate_completion("notarize-generic-v1", {"quantity": 100})
    assert result["valid"] is True
    body = json.loads(respx.calls[0].request.content)
    assert body["evidence"]["quantity"] == 100


@respx.mock
def test_meta_schema():
    respx.get(f"{BASE}/v1/schemas/meta-schema").mock(return_value=httpx.Response(200, json=META_SCHEMA_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.meta_schema()
    assert "constraints" in result


@respx.mock
def test_get_template():
    route = respx.get(f"{BASE}/v1/schemas/notarize-generic-v1/template").mock(return_value=httpx.Response(200, json=TEMPLATE_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.get_template("notarize-generic-v1")
    assert result["sourceType"] == "notarize-generic-v1"
    assert route.calls.call_count == 1


@respx.mock
def test_blank():
    respx.get(f"{BASE}/v1/schemas/_blank").mock(return_value=httpx.Response(200, json=TEMPLATE_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.blank()
    assert "template" in result


@respx.mock
def test_preview():
    respx.post(f"{BASE}/v1/schemas/preview").mock(return_value=httpx.Response(200, json=PREVIEW_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.preview({"type": "my-custom-v1", "recordSchema": {}, "completionSchema": {}})
    assert result["valid"] is True


@respx.mock
def test_diff():
    route = respx.get(f"{BASE}/v1/schemas/notarize-generic-v1/diff").mock(return_value=httpx.Response(200, json=DIFF_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.diff("notarize-generic-v1", from_version=1, to_version=2)
    assert result["type"] == "notarize-generic-v1"
    url = str(route.calls[0].request.url)
    assert "from=1" in url
    assert "to=2" in url


@respx.mock
def test_export_schema():
    route = respx.post(f"{BASE}/v1/schemas/notarize-generic-v1/export").mock(return_value=httpx.Response(200, json=EXPORT_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.export_schema("notarize-generic-v1", versions="1,2")
    assert result["type"] == "notarize-generic-v1"
    url = str(route.calls[0].request.url)
    assert "versions=1" in url


@respx.mock
def test_import():
    route = respx.post(f"{BASE}/v1/schemas/import").mock(return_value=httpx.Response(201, json=IMPORT_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.import_(MANIFEST, defaultGateMode="principal")
    assert result["type"] == "my-custom-v1"
    req = route.calls[0].request
    # manifest and row-only options ride in the body; nothing in the query string
    assert req.url.query == b""
    import json as _json
    body = _json.loads(req.content)
    assert body["manifest"] == MANIFEST
    assert body["defaultGateMode"] == "principal"


@respx.mock
def test_register():
    respx.post(f"{BASE}/v1/schemas").mock(return_value=httpx.Response(200, json=VERSION_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.register({"type": "my-custom-v1", "displayName": "Custom", "recordSchema": {}, "completionSchema": {}})
    assert result["type"] == "notarize-generic-v1"


@respx.mock
def test_get_versions():
    page_json = {"data": [VERSION_JSON], "hasMore": False, "total": 1}
    respx.get(f"{BASE}/v1/schemas/notarize-generic-v1/versions").mock(return_value=httpx.Response(200, json=page_json))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.get_versions("notarize-generic-v1")
    assert len(result.data) == 1
    assert result.has_more is False


@respx.mock
def test_get_version():
    respx.get(f"{BASE}/v1/schemas/notarize-generic-v1/versions/1").mock(return_value=httpx.Response(200, json=VERSION_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.get_version("notarize-generic-v1", 1)
    assert result["version"] == 1


@respx.mock
def test_check_compatibility():
    respx.post(f"{BASE}/v1/schemas/notarize-generic-v1/check-compatibility").mock(return_value=httpx.Response(200, json=COMPAT_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.check_compatibility("notarize-generic-v1", {"recordSchema": {}, "completionSchema": {}})
    assert result["record"]["compatible"] is True


@respx.mock
def test_update_version():
    respx.patch(f"{BASE}/v1/schemas/notarize-generic-v1/versions/1").mock(return_value=httpx.Response(200, json=VERSION_JSON))
    client = AgledgerClient(api_key="test-key")
    result = client.schemas.update_version("notarize-generic-v1", 1, {"status": "DEPRECATED"})
    assert result["id"] == "sv-1"


@respx.mock
def test_disable_enable():
    respx.patch(f"{BASE}/v1/schemas/notarize-generic-v1/disable").mock(
        return_value=httpx.Response(200, json={"type": "notarize-generic-v1", "status": "DISABLED"})
    )
    respx.patch(f"{BASE}/v1/schemas/notarize-generic-v1/enable").mock(
        return_value=httpx.Response(200, json={"type": "notarize-generic-v1", "status": "ACTIVE"})
    )
    client = AgledgerClient(api_key="test-key")
    assert client.schemas.disable("notarize-generic-v1")["status"] == "DISABLED"
    assert client.schemas.enable("notarize-generic-v1")["status"] == "ACTIVE"


# --- Async tests ---

@respx.mock
@pytest.mark.asyncio
async def test_async_meta_schema():
    respx.get(f"{BASE}/v1/schemas/meta-schema").mock(return_value=httpx.Response(200, json=META_SCHEMA_JSON))
    async with AsyncAgledgerClient(api_key="test-key") as client:
        result = await client.schemas.meta_schema()
        assert "constraints" in result


@respx.mock
@pytest.mark.asyncio
async def test_async_diff():
    route = respx.get(f"{BASE}/v1/schemas/notarize-generic-v1/diff").mock(return_value=httpx.Response(200, json=DIFF_JSON))
    async with AsyncAgledgerClient(api_key="test-key") as client:
        result = await client.schemas.diff("notarize-generic-v1", from_version=1, to_version=2)
        assert result["type"] == "notarize-generic-v1"
        url = str(route.calls[0].request.url)
        assert "from=1" in url


@respx.mock
@pytest.mark.asyncio
async def test_async_export_schema():
    respx.post(f"{BASE}/v1/schemas/notarize-generic-v1/export").mock(return_value=httpx.Response(200, json=EXPORT_JSON))
    async with AsyncAgledgerClient(api_key="test-key") as client:
        result = await client.schemas.export_schema("notarize-generic-v1")
        assert result["type"] == "notarize-generic-v1"


@respx.mock
@pytest.mark.asyncio
async def test_async_import_schema():
    route = respx.post(f"{BASE}/v1/schemas/import").mock(return_value=httpx.Response(201, json=IMPORT_JSON))
    async with AsyncAgledgerClient(api_key="test-key") as client:
        result = await client.schemas.import_(MANIFEST)
        assert result["type"] == "my-custom-v1"
        import json as _json
        body = _json.loads(route.calls[0].request.content)
        assert body["manifest"] == MANIFEST
