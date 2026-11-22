"""
AGLedger SDK: API Key Scopes

Mirrors the Server's scope profiles, as served by ``GET /v1/scope-profiles``.
A scope or profile the Server adds appears here only in a later release of
this SDK.
"""

from __future__ import annotations

from typing import Literal, TypedDict

ApiKeyRole = Literal["admin", "agent", "platform"]


class Scopes:
    """API key scope constants."""

    # Record lifecycle
    RECORDS_READ: str = "records:read"
    RECORDS_WRITE: str = "records:write"

    # Completions
    COMPLETIONS_READ: str = "completions:read"
    COMPLETIONS_WRITE: str = "completions:write"

    # Webhooks
    WEBHOOKS_READ: str = "webhooks:read"
    WEBHOOKS_MANAGE: str = "webhooks:manage"

    # Audit & compliance
    AUDIT_READ: str = "audit:read"
    COMPLIANCE_READ: str = "compliance:read"
    COMPLIANCE_WRITE: str = "compliance:write"

    # Agents
    AGENTS_READ: str = "agents:read"
    AGENTS_MANAGE: str = "agents:manage"

    # Disputes. ``disputes:read`` views a dispute; ``disputes:write`` opens one,
    # adds evidence, withdraws and resolves.
    DISPUTES_READ: str = "disputes:read"
    DISPUTES_WRITE: str = "disputes:write"

    # Events & drift
    EVENTS_READ: str = "events:read"
    DRIFT_READ: str = "drift:read"

    # Schemas
    SCHEMAS_READ: str = "schemas:read"
    SCHEMAS_WRITE: str = "schemas:write"
    SCHEMAS_ADMIN: str = "schemas:admin"

    # Administration
    ADMIN_KEYS: str = "admin:keys"
    ADMIN_SYSTEM: str = "admin:system"
    ADMIN_BACKFILL: str = "admin:backfill"


class ScopeProfile(TypedDict):
    """Scope profile definition. Mirrors an entry of the Server's scope profiles."""

    name: str
    description: str
    allowed_roles: tuple[ApiKeyRole, ...]
    scopes: tuple[str, ...]


ScopeProfileName = Literal[
    "admin-observer",
    "admin-standard",
    "admin-iac",
    "admin-schema",
    "agent-full",
    "agent-readonly",
    "agent-performer-only",
]

SCOPE_PROFILES: dict[ScopeProfileName, ScopeProfile] = {
    "admin-observer": {
        "name": "admin-observer",
        "description": "Read-only admin; audit, compliance, events, disputes, drift, schemas, webhooks, records, completions",
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
            Scopes.EVENTS_READ,
            Scopes.DISPUTES_READ,
            Scopes.DRIFT_READ,
            Scopes.SCHEMAS_READ,
            Scopes.WEBHOOKS_READ,
            Scopes.RECORDS_READ,
            Scopes.COMPLETIONS_READ,
        ),
    },
    "admin-standard": {
        "name": "admin-standard",
        "description": (
            "Default admin for an org: manages agents, webhooks, API keys and the org's own Types, acts on any "
            "record in the org, and reads audit and compliance data. Cannot manage platform-level Types or other "
            "orgs; use admin-schema for platform-level Type authority."
        ),
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
            Scopes.COMPLIANCE_WRITE,
            Scopes.EVENTS_READ,
            Scopes.DISPUTES_READ,
            Scopes.DISPUTES_WRITE,
            Scopes.DRIFT_READ,
            Scopes.SCHEMAS_READ,
            Scopes.SCHEMAS_WRITE,
            Scopes.WEBHOOKS_READ,
            Scopes.WEBHOOKS_MANAGE,
            Scopes.AGENTS_READ,
            Scopes.AGENTS_MANAGE,
            Scopes.ADMIN_KEYS,
            Scopes.ADMIN_SYSTEM,
            Scopes.RECORDS_READ,
            Scopes.RECORDS_WRITE,
            Scopes.COMPLETIONS_READ,
            Scopes.COMPLETIONS_WRITE,
        ),
    },
    "admin-iac": {
        "name": "admin-iac",
        "description": (
            "Infrastructure provisioning for a pipeline: manages agents, webhooks and API keys, and registers and "
            "manages the org's own Types, including testing a payload against a Type. Cannot reach "
            "platform-level Types or other orgs."
        ),
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.ADMIN_KEYS,
            Scopes.AGENTS_READ,
            Scopes.AGENTS_MANAGE,
            Scopes.WEBHOOKS_READ,
            Scopes.WEBHOOKS_MANAGE,
            Scopes.SCHEMAS_READ,
            Scopes.SCHEMAS_WRITE,
        ),
    },
    "admin-schema": {
        "name": "admin-schema",
        "description": (
            "Type registry management: create, version, disable and enable Types, including platform-level "
            "Types. For operators who manage the Type catalogue and need nothing else."
        ),
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.SCHEMAS_READ,
            Scopes.SCHEMAS_WRITE,
            Scopes.SCHEMAS_ADMIN,
        ),
    },
    "agent-full": {
        "name": "agent-full",
        "description": (
            "Full agent; record lifecycle, completions, disputes, events, schemas, self-audit of own records, "
            "and self-introspection of own drift"
        ),
        "allowed_roles": ("agent",),
        "scopes": (
            Scopes.RECORDS_READ,
            Scopes.RECORDS_WRITE,
            Scopes.COMPLETIONS_READ,
            Scopes.COMPLETIONS_WRITE,
            Scopes.AGENTS_READ,
            Scopes.DISPUTES_READ,
            Scopes.DISPUTES_WRITE,
            Scopes.EVENTS_READ,
            Scopes.SCHEMAS_READ,
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
            Scopes.DRIFT_READ,
        ),
    },
    "agent-readonly": {
        "name": "agent-readonly",
        "description": "Read-only agent; view own records, completions, and audit trail",
        "allowed_roles": ("agent",),
        "scopes": (
            Scopes.RECORDS_READ,
            Scopes.COMPLETIONS_READ,
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
        ),
    },
    "agent-performer-only": {
        "name": "agent-performer-only",
        "description": (
            "Performer agent; can deliver completions, read records, and self-audit, but cannot be principal "
            "of new records. It does not carry records:write, so it cannot accept or reject a proposal "
            "(POST /v1/records/{id}/accept or /reject): it performs records that reach it already ACTIVE "
            "(autoActivate, or activated by the principal). A performer that must consent to proposals needs "
            "agent-full, or custom scopes that add records:write."
        ),
        "allowed_roles": ("agent",),
        "scopes": (
            Scopes.RECORDS_READ,
            Scopes.COMPLETIONS_READ,
            Scopes.COMPLETIONS_WRITE,
            Scopes.SCHEMAS_READ,
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
        ),
    },
}


def default_profile_for(role: ApiKeyRole) -> ScopeProfileName | None:
    """Default profile for a role when the caller does not pick one (mirrors API)."""
    if role == "admin":
        return "admin-standard"
    if role == "agent":
        return "agent-full"
    return None
