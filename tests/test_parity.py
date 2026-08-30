"""
SDK ↔ API Parity Test (Python)

Mirrors the TypeScript SDK parity test: a focused invariant check against
the shared route manifest. The snapshot is vendored into this repo at
``tests/parity/routes.json`` (regenerated upstream by the weekly
update-route-manifest workflow and synced here) so the standalone repo is
self-contained. Skips when the manifest is unavailable (PyPI install).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_MANIFEST_PATH = Path(__file__).resolve().parent / "parity" / "routes.json"


@pytest.fixture(scope="module")
def route_map() -> dict[str, dict[str, Any]]:
    if not _MANIFEST_PATH.exists():
        pytest.skip(f"Route manifest not available at {_MANIFEST_PATH} (skip in standalone checkout)")
    manifest = json.loads(_MANIFEST_PATH.read_text())
    return {f"{r['method']} {r['path']}": r for r in manifest["routes"]}


CRITICAL_ROUTES: list[tuple[str, str]] = [
    ("POST", "/v1/records"),
    ("GET", "/v1/records"),
    ("GET", "/v1/records/{id}"),
    ("POST", "/v1/records/{id}/transition"),
    ("POST", "/v1/records/{id}/accept"),
    ("POST", "/v1/records/{id}/reject"),
    ("POST", "/v1/records/{id}/counter-propose"),
    ("POST", "/v1/records/{id}/verdict"),
    ("POST", "/v1/records/{recordId}/completions"),
    ("GET", "/v1/records/{recordId}/completions"),
    ("POST", "/v1/records/{id}/evaluate"),
    ("POST", "/v1/records/{recordId}/dispute"),
    ("POST", "/v1/records/{recordId}/compliance-records"),
    ("GET", "/v1/records/{recordId}/audit-export"),
    ("POST", "/v1/records/batch"),
    ("POST", "/v1/records/bulk"),
    ("GET", "/v1/records/me/verdict-statistics"),
    ("GET", "/v1/records/agent/proposals"),
    ("GET", "/v1/disputes"),
    ("GET", "/v1/audit/org-reads"),
    ("GET", "/v1/audit/org-reads/checkpoints"),
    ("GET", "/v1/audit/org-reads/checkpoints/{id}"),
    ("POST", "/v1/audit/org-reads/checkpoints/{id}/cosign"),
    ("GET", "/v1/audit/org-reads/checkpoints/{id}/proof"),
    ("GET", "/federation/v1/admin/peers/{peerHubId}"),
    ("DELETE", "/federation/v1/admin/peers/{peerHubId}"),
    ("POST", "/federation/v1/admin/peers/{peerHubId}/resync"),
    ("POST", "/federation/v1/admin/peers/{peerHubId}/revoke"),
    ("POST", "/v1/webhooks"),
    ("POST", "/v1/schemas"),
    ("GET", "/v1/schemas/meta-schema"),
    ("GET", "/v1/schemas/_blank"),
    ("POST", "/v1/schemas/preview"),
    ("POST", "/v1/schemas/import"),
    ("POST", "/v1/compliance/export"),
    ("GET", "/v1/auth/me"),
    ("POST", "/v1/auth/keys/rotate"),
    ("GET", "/v1/scope-profiles"),
    ("GET", "/v1/conformance"),
    ("GET", "/v1/events"),
    ("GET", "/v1/references"),
    ("GET", "/v1/verification-keys"),
    # NB: POST /v1/admin/orgs (create-org) is intentionally NOT here; it was
    # dropped from the canonical OpenAPI spec in API v1.0.1 (dev/test-only, never
    # registered in production). admin.create_org() still reaches it for local
    # bootstrap; GET (list) remains canonical.
    ("GET", "/v1/admin/orgs"),
    ("POST", "/v1/admin/orgs/{id}/deactivate"),
    ("POST", "/v1/admin/agents/{id}/deactivate"),
    ("POST", "/v1/admin/api-keys"),
    ("POST", "/v1/admin/agents"),
    ("GET", "/v1/admin/records"),
    ("POST", "/v1/admin/records/import"),
    ("GET", "/v1/admin/vault/anchors"),
    ("POST", "/v1/admin/vault/anchors/verify"),
    ("POST", "/v1/admin/vault/scan"),
    ("GET", "/v1/admin/vault/signing-keys"),
    ("POST", "/v1/admin/vault/signing-keys/rotate"),
    ("GET", "/v1/siem/stream"),
]


RETIRED_ROUTES: list[tuple[str, str]] = [
    # Legacy mandate routes
    ("POST", "/v1/mandates"),
    ("GET", "/v1/mandates"),
    ("GET", "/v1/mandates/{id}"),
    ("POST", "/v1/mandates/agent"),
    ("GET", "/v1/mandates/agent/principal"),
    ("GET", "/v1/mandates/{mandateId}/audit"),
    ("GET", "/v1/mandates/summary"),
    # Other retired
    ("GET", "/v1/dashboard/summary"),
    ("GET", "/v1/dashboard/metrics"),
    ("POST", "/v1/proxy/sessions"),
    ("POST", "/v1/notarize/mandates"),
    ("POST", "/v1/projects"),
    ("POST", "/v1/audit/enterprise-report/analyze"),
    ("GET", "/v1/audit/enterprise-report"),
    ("PATCH", "/v1/admin/accounts/{id}/trust-level"),
    ("GET", "/v1/audit/stream"),  # renamed to /v1/siem/stream
]


@pytest.mark.parametrize("method,path", CRITICAL_ROUTES)
def test_critical_route_exists(
    route_map: dict[str, dict[str, Any]], method: str, path: str
) -> None:
    """Each critical route must exist in the API spec."""
    key = f"{method} {path}"
    assert key in route_map, f"Missing route {key}: API may have renamed or removed it"


@pytest.mark.parametrize("method,path", RETIRED_ROUTES)
def test_retired_route_is_gone(
    route_map: dict[str, dict[str, Any]], method: str, path: str
) -> None:
    """Retired routes must not resurface in the manifest."""
    key = f"{method} {path}"
    assert key not in route_map, (
        f"{key} was supposed to be retired but still appears in the manifest"
    )


def test_records_post_does_not_require_principal_type(
    route_map: dict[str, dict[str, Any]],
) -> None:
    entry = route_map["POST /v1/records"]
    assert "principalType" not in entry["bodyFields"]
    assert "principalType" not in entry["requiredFields"]


def test_records_post_exposes_principal_agent_id(
    route_map: dict[str, dict[str, Any]],
) -> None:
    entry = route_map["POST /v1/records"]
    assert "principalAgentId" in entry["bodyFields"]


def test_webhook_create_requires_event_types(
    route_map: dict[str, dict[str, Any]],
) -> None:
    entry = route_map["POST /v1/webhooks"]
    required = entry["requiredFields"]
    assert "eventTypes" in required, f"Expected eventTypes required; got {required}"
    assert "events" not in required, f"Unexpected legacy 'events' field: {required}"


def test_capabilities_uses_put(route_map: dict[str, dict[str, Any]]) -> None:
    assert "PUT /v1/agents/{agentId}/capabilities" in route_map


def test_verdict_requires_completion_and_verdict(
    route_map: dict[str, dict[str, Any]],
) -> None:
    entry = route_map["POST /v1/records/{id}/verdict"]
    for field in ("completionId", "verdict"):
        assert field in entry["requiredFields"]
