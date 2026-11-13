"""Request dependencies: session, identity and permission enforcement.

Authorization is deny by default: a route either declares a permission through
`require(...)` or is explicitly listed as public in `app.api.v1.public_routes`.
`tests/test_authorization.py` fails the build if a route declares neither.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ForbiddenError, UnauthorizedError
from app.core.logging import actor_var
from app.models.user import AuthSource, Role, User
from app.services import auth, mfa

PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ANALYST: frozenset(
        {
            "jobs:read",
            "jobs:write",
            "jobs:tag",
            "jobs:export",
            "analyzers:read",
            "playbooks:read",
            "keys:manage",
        }
    ),
    Role.ADMIN: frozenset(
        {
            "jobs:read",
            "jobs:write",
            "jobs:tag",
            "jobs:export",
            "analyzers:read",
            "analyzers:manage",
            "secrets:manage",
            "playbooks:read",
            "playbooks:manage",
            "users:manage",
            "groups:manage",
            "settings:manage",
            "plugins:manage",
            "audit:read",
            "keys:manage",
        }
    ),
}


def permissions_for(role: Role) -> list[str]:
    return sorted(PERMISSIONS.get(role, frozenset()))


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield the request-scoped session, committing on a clean response."""
    factory = request.app.state.session_factory
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


DbSession = Annotated[AsyncSession, Depends(get_db)]


def client_ip(request: Request) -> str | None:
    """Resolve the client IP, trusting exactly `trusted_proxy_count` hops."""
    settings = get_settings()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and settings.trusted_proxy_count > 0:
        hops = [part.strip() for part in forwarded.split(",") if part.strip()]
        index = len(hops) - settings.trusted_proxy_count
        if 0 <= index < len(hops):
            return hops[index][:64]
        if hops:
            return hops[0][:64]
    return request.client.host if request.client else None


async def optional_user(request: Request, session: DbSession) -> User | None:
    """Resolve the caller from a session cookie, an API key or proxy headers."""
    settings = get_settings()

    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        user = await auth.resolve_api_key(session, authorization[7:].strip())
        if user is not None:
            actor_var.set(user.username)
            return user

    cookie = request.cookies.get(auth.SESSION_COOKIE)
    if cookie:
        user = await auth.resolve_session(session, cookie)
        if user is not None:
            actor_var.set(user.username)
            return user

    if settings.proxy_auth_enabled:
        username = request.headers.get(settings.proxy_auth_user_header.lower())
        if username:
            groups_header = request.headers.get(settings.proxy_auth_groups_header.lower(), "")
            user = await auth.upsert_federated_user(
                session,
                username=username,
                email=request.headers.get(settings.proxy_auth_email_header.lower()),
                display_name=username,
                groups=[group.strip() for group in groups_header.split(",") if group.strip()],
                source=AuthSource.PROXY,
            )
            actor_var.set(user.username)
            return user

    return None


CurrentUserOptional = Annotated[User | None, Depends(optional_user)]


async def current_user(user: CurrentUserOptional) -> User:
    if user is None:
        raise UnauthorizedError("Authentication is required.")
    return user


CurrentUser = Annotated[User, Depends(current_user)]


# Permissions still reachable while the account is in a setup state, so the user
# can see enough of the interface to finish setting the account up.
_SETUP_SAFE = frozenset({"jobs:read", "analyzers:read"})


def require(permission: str) -> Callable[..., Coroutine[Any, Any, User]]:
    """Build a dependency enforcing one permission.

    Beyond the permission itself, it blocks an account that still has to change
    its initial password or enrol an authenticator, so neither obligation can be
    skipped by calling the API directly.
    """

    async def dependency(user: CurrentUser, session: DbSession) -> User:
        if permission not in PERMISSIONS.get(user.role, frozenset()):
            raise ForbiddenError("You are not allowed to perform this action.")

        if permission not in _SETUP_SAFE:
            if user.must_change_password:
                raise ForbiddenError(
                    "The initial password must be changed before using the platform.",
                    code="PASSWORD_CHANGE_REQUIRED",
                )
            if await mfa.enrolment_pending(session, user):
                raise ForbiddenError(
                    "Two-factor authentication must be enrolled before using the platform.",
                    code="MFA_ENROLMENT_REQUIRED",
                )
        return user

    dependency.__xenoproxy_permission__ = permission  # type: ignore[attr-defined]
    return dependency
