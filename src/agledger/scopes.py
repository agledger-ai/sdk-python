"""
AGLedger SDK — API Key Scopes

Mirrors the authoritative definitions in agledger-api/src/shared/scopes.ts.
Keep this file in lockstep with the API.
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

    # Disputes
    DISPUTES_READ: str = "disputes:read"
    DISPUTES_MANAGE: str = "disputes:manage"

    # Events & reputation
    EVENTS_READ: str = "events:read"
    REPUTATION_READ: str = "reputation:read"

    # Schemas
    SCHEMAS_READ: str = "schemas:read"
    SCHEMAS_WRITE: str = "schemas:write"
    SCHEMAS_ADMIN: str = "schemas:admin"

    # Administration
    ADMIN_KEYS: str = "admin:keys"
    ADMIN_SYSTEM: str = "admin:system"
    ADMIN_BACKFILL: str = "admin:backfill"


class ScopeProfile(TypedDict):
    """Scope profile definition. Mirrors the API's SCOPE_PROFILES entry."""

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
        "description": "Read-only admin — audit, compliance, events, disputes, reputation, schemas, webhooks, records, completions",
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
            Scopes.EVENTS_READ,
            Scopes.DISPUTES_READ,
            Scopes.REPUTATION_READ,
            Scopes.SCHEMAS_READ,
            Scopes.WEBHOOKS_READ,
            Scopes.RECORDS_READ,
            Scopes.COMPLETIONS_READ,
        ),
    },
    "admin-standard": {
        "name": "admin-standard",
        "description": "Default admin — full org governance plus Record/Completion action rights (admin actions signed as admin in vault)",
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.AUDIT_READ,
            Scopes.COMPLIANCE_READ,
            Scopes.COMPLIANCE_WRITE,
            Scopes.EVENTS_READ,
            Scopes.DISPUTES_READ,
            Scopes.DISPUTES_MANAGE,
            Scopes.REPUTATION_READ,
            Scopes.SCHEMAS_READ,
            Scopes.SCHEMAS_WRITE,
            Scopes.SCHEMAS_ADMIN,
            Scopes.WEBHOOKS_READ,
            Scopes.WEBHOOKS_MANAGE,
            Scopes.AGENTS_READ,
            Scopes.AGENTS_MANAGE,
            Scopes.ADMIN_KEYS,
            Scopes.ADMIN_SYSTEM,
            Scopes.ADMIN_BACKFILL,
            Scopes.RECORDS_READ,
            Scopes.RECORDS_WRITE,
            Scopes.COMPLETIONS_READ,
            Scopes.COMPLETIONS_WRITE,
        ),
    },
    "admin-iac": {
        "name": "admin-iac",
        "description": "Infrastructure provisioning — agents, webhooks, keys, schemas",
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.ADMIN_KEYS,
            Scopes.AGENTS_MANAGE,
            Scopes.WEBHOOKS_MANAGE,
            Scopes.SCHEMAS_ADMIN,
        ),
    },
    "admin-schema": {
        "name": "admin-schema",
        "description": "Schema registry management — create, version, disable/enable custom types",
        "allowed_roles": ("admin",),
        "scopes": (
            Scopes.SCHEMAS_READ,
            Scopes.SCHEMAS_WRITE,
            Scopes.SCHEMAS_ADMIN,
        ),
    },
    "agent-full": {
        "name": "agent-full",
        "description": "Full agent — Record lifecycle, Completions, disputes, events, and schemas",
        "allowed_roles": ("agent",),
        "scopes": (
            Scopes.RECORDS_READ,
            Scopes.RECORDS_WRITE,
            Scopes.COMPLETIONS_READ,
            Scopes.COMPLETIONS_WRITE,
            Scopes.AGENTS_READ,
            Scopes.DISPUTES_READ,
            Scopes.EVENTS_READ,
            Scopes.SCHEMAS_READ,
        ),
    },
    "agent-readonly": {
        "name": "agent-readonly",
        "description": "Read-only agent — view Record history",
        "allowed_roles": ("agent",),
        "scopes": (
            Scopes.RECORDS_READ,
            Scopes.COMPLETIONS_READ,
        ),
    },
    "agent-performer-only": {
        "name": "agent-performer-only",
        "description": "Performer agent — can deliver Completions and read Records, but cannot be principal of new Records",
        "allowed_roles": ("agent",),
        "scopes": (
            Scopes.RECORDS_READ,
            Scopes.COMPLETIONS_READ,
            Scopes.COMPLETIONS_WRITE,
            Scopes.SCHEMAS_READ,
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
