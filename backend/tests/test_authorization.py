"""Authorization is deny by default.

These tests fail the build when a route neither declares a permission through
`require(...)` nor appears in the public allowlist, and when a permission string
is not part of any role.
"""

from __future__ import annotations

from typing import ClassVar

from fastapi.routing import APIRoute

from app.api.deps import PERMISSIONS, require
from app.main import create_app
from app.models.user import Role
from tests.routes import declared_permission, route_pairs

# A floor, not an exact count: it only has to catch an enumeration that silently
# stops finding routes, which is how a deny-by-default test goes vacuous.
MINIMUM_ROUTES = 40

# Routes reachable without authentication, each with the reason it must be.
PUBLIC_ROUTES: dict[tuple[str, str], str] = {
    ("GET", "/api/health"): "liveness probe for the container runtime",
    ("GET", "/api/v1/auth/methods"): "the sign-in page needs to know what to offer",
    ("POST", "/api/v1/auth/login"): "sign-in itself",
    ("POST", "/api/v1/auth/login/mfa"): "the second sign-in step, before a session exists",
    ("POST", "/api/v1/auth/logout"): "clearing a cookie must work for an expired session",
    ("GET", "/api/v1/auth/oidc/start"): "starting single sign-on, before any identity exists",
    ("GET", "/api/v1/auth/oidc/callback"): "the provider redirect that creates the session",
}

# Routes that only need an authenticated identity, with no further permission.
SELF_SERVICE_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/api/v1/auth/me"),
        ("POST", "/api/v1/auth/password"),
        ("GET", "/api/v1/auth/api-keys"),
        ("POST", "/api/v1/auth/api-keys"),
        ("DELETE", "/api/v1/auth/api-keys/{key_id}"),
        ("GET", "/api/v1/auth/mfa"),
        ("POST", "/api/v1/auth/mfa/enrol"),
        ("POST", "/api/v1/auth/mfa/confirm"),
        ("POST", "/api/v1/auth/mfa/recovery-codes"),
        ("POST", "/api/v1/auth/mfa/disable"),
        # An analyst editing their own scan defaults. It reads and writes
        # nothing but the signed-in account, so it needs a session rather
        # than a permission.
        ("PUT", "/api/v1/auth/me/preferences"),
    }
)


# Routes that carry their own admission and cannot express it as a static
# permission: an MCP server authenticates a personal API token, then checks an
# instance setting and, for the administration server, an allow-list of
# accounts. There is no single permission that captures "enabled, and this
# account is named"; `test_the_mcp_servers_refuse_an_anonymous_call` below is
# what keeps this exception honest.
TOKEN_GATED_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/v1/mcp"),
        ("POST", "/api/v1/mcp/user"),
    }
)


def test_the_route_enumeration_is_not_vacuous() -> None:
    """Guards every other test in this file: they are worthless on an empty list."""
    pairs = route_pairs(create_app())
    assert len(pairs) >= MINIMUM_ROUTES, (
        f"only {len(pairs)} routes were found; the collector in tests/routes.py "
        "is probably no longer following how FastAPI nests routers"
    )
    paths = {path for _, path, _ in pairs}
    assert "/api/v1/jobs" in paths
    assert "/api/v1/admin/users" in paths


def test_every_route_declares_a_permission_or_is_explicitly_public() -> None:
    undeclared: list[str] = []
    for method, path, route in route_pairs(create_app()):
        key = (method, path)
        if key in PUBLIC_ROUTES or key in SELF_SERVICE_ROUTES or key in TOKEN_GATED_ROUTES:
            continue
        if declared_permission(route) is None:
            undeclared.append(f"{method} {path}")
    assert not undeclared, f"routes without a declared permission: {undeclared}"


def test_declared_permissions_exist_in_a_role() -> None:
    known = set().union(*PERMISSIONS.values())
    unknown: list[str] = []
    for _, path, route in route_pairs(create_app()):
        permission = declared_permission(route)
        if permission and permission not in known:
            unknown.append(f"{path}: {permission}")
    assert not unknown, f"permissions not granted to any role: {unknown}"


def test_admin_routes_require_an_admin_permission() -> None:
    analyst_permissions = PERMISSIONS[Role.ANALYST]
    offenders: list[str] = []
    for method, path, route in route_pairs(create_app()):
        if not path.startswith("/api/v1/admin/"):
            continue
        permission = declared_permission(route)
        if permission is None or permission in analyst_permissions:
            offenders.append(f"{method} {path}: {permission}")
    assert not offenders, f"admin routes reachable by an analyst: {offenders}"


def test_an_analyst_cannot_manage_identity_or_settings() -> None:
    analyst = PERMISSIONS[Role.ANALYST]
    for permission in ("users:manage", "groups:manage", "settings:manage", "plugins:manage"):
        assert permission not in analyst


def test_mutating_routes_are_not_public() -> None:
    """A public route may not change state, apart from the sign-in endpoints."""
    allowed = {
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/login/mfa"),
        ("POST", "/api/v1/auth/logout"),
    }
    offenders = [
        f"{method} {path}"
        for (method, path) in PUBLIC_ROUTES
        if method in {"POST", "PUT", "PATCH", "DELETE"} and (method, path) not in allowed
    ]
    assert not offenders, f"public routes that change state: {offenders}"


def test_require_builds_an_introspectable_dependency() -> None:
    dependency = require("jobs:read")
    assert dependency.__xenoproxy_permission__ == "jobs:read"


def test_collected_routes_are_api_routes() -> None:
    assert all(isinstance(route, APIRoute) for _, _, route in route_pairs(create_app()))


async def test_the_mcp_servers_refuse_a_call_without_a_token() -> None:
    """The compensating check for TOKEN_GATED_ROUTES.

    Those two routes are exempt from the permission declaration because their
    admission is dynamic. This asserts the exemption is not a hole: the gate is
    reached before anything else, and refuses outright with no token.
    """
    import pytest

    from app.api.v1 import mcp
    from app.core.errors import UnauthorizedError

    class _Request:
        """Only what the gate reads before it refuses."""

        headers: ClassVar[dict[str, str]] = {}

    for admin in (False, True):
        with pytest.raises(UnauthorizedError):
            await mcp._admit(_Request(), admin=admin)  # type: ignore[arg-type]


def test_both_mcp_routes_are_accounted_for() -> None:
    """The exemption list must not silently cover a route added later."""
    served = {
        (method, path)
        for method, path, _route in route_pairs(create_app())
        if path.startswith("/api/v1/mcp")
    }
    assert served == TOKEN_GATED_ROUTES
