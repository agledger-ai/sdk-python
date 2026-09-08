"""Scope constants and profiles.

``SCOPE_PROFILES`` is a hand-mirror of the Server's own table: nothing
regenerates it, and nothing at runtime tells a caller that the profile they
minted a key under does not hold what this file says it holds. The profiles had
drifted on every entry before this test existed, and the SDK exported a scope
(``disputes:manage``) the API has never declared at any tag, so a caller who
built a custom scope list from the constants got a key the Server refuses.

Pinning the exact sets is the whole point: a "profile still exists" check passes
on a profile that grants the wrong thing.
"""

from __future__ import annotations

import pytest

from agledger.scopes import SCOPE_PROFILES, Scopes, default_profile_for

EXPECTED: dict[str, tuple[str, ...]] = {
    "admin-observer": (
        "audit:read", "compliance:read", "events:read", "disputes:read", "drift:read",
        "schemas:read", "webhooks:read", "records:read", "completions:read",
    ),
    "admin-standard": (
        "audit:read", "compliance:read", "compliance:write", "events:read",
        "disputes:read", "drift:read", "schemas:read", "schemas:write",
        "webhooks:read", "webhooks:manage", "agents:read", "agents:manage",
        "admin:keys", "admin:system", "records:read", "records:write",
        "completions:read", "completions:write",
    ),
    "admin-iac": ("admin:keys", "agents:manage", "webhooks:manage", "schemas:write"),
    "admin-schema": ("schemas:read", "schemas:write", "schemas:admin"),
    "agent-full": (
        "records:read", "records:write", "completions:read", "completions:write",
        "agents:read", "disputes:read", "events:read", "schemas:read",
        "audit:read", "compliance:read", "drift:read",
    ),
    "agent-readonly": ("records:read", "completions:read", "audit:read", "compliance:read"),
    "agent-performer-only": (
        "records:read", "completions:read", "completions:write", "schemas:read",
        "audit:read", "compliance:read",
    ),
}


def test_the_profile_names_are_exactly_the_seven_the_server_serves() -> None:
    assert sorted(SCOPE_PROFILES) == sorted(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_profile_grants_exactly_what_the_server_grants(name: str) -> None:
    assert SCOPE_PROFILES[name]["scopes"] == EXPECTED[name]
    assert SCOPE_PROFILES[name]["name"] == name


def test_retired_scopes_appear_nowhere() -> None:
    """``disputes:manage`` was never an API scope at any tag, and
    ``reputation:read`` went away with the reputation routes. Either one in a
    key create is refused by the Server."""
    declared = {
        value for key, value in vars(Scopes).items()
        if not key.startswith("_") and isinstance(value, str)
    }
    assert "disputes:manage" not in declared
    assert "reputation:read" not in declared
    assert not hasattr(Scopes, "DISPUTES_MANAGE")
    assert not hasattr(Scopes, "REPUTATION_READ")
    assert Scopes.DRIFT_READ == "drift:read"

    granted = {scope for profile in SCOPE_PROFILES.values() for scope in profile["scopes"]}
    assert "disputes:manage" not in granted
    assert "reputation:read" not in granted


def test_every_granted_scope_is_a_declared_constant() -> None:
    declared = {
        value for key, value in vars(Scopes).items()
        if not key.startswith("_") and isinstance(value, str)
    }
    granted = {scope for profile in SCOPE_PROFILES.values() for scope in profile["scopes"]}
    assert granted <= declared


def test_default_profile_for_role() -> None:
    assert default_profile_for("admin") == "admin-standard"
    assert default_profile_for("agent") == "agent-full"
    assert default_profile_for("platform") is None
