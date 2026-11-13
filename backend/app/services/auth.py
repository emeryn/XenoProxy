"""Authentication: local sessions, personal API keys and reverse-proxy delegation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import hash_password, new_token, token_fingerprint, verify_password
from app.core.errors import UnauthorizedError
from app.core.logging import get_logger
from app.models.user import ApiKey, AuthSource, MfaRecoveryCode, Role, Session, User
from app.services import audit, group_mapping, settings_store

logger = get_logger(__name__)

SESSION_COOKIE = "__Host-session"
API_KEY_PREFIX = "xenoproxy_"


async def authenticate_local(session: AsyncSession, username: str, password: str) -> User | None:
    """Verify a local credential. The same work is done for unknown users."""
    user = (
        await session.execute(select(User).where(User.username == username.strip().lower()))
    ).scalar_one_or_none()

    if user is None or not user.password_hash:
        # Spend comparable time so a missing account is not distinguishable.
        verify_password(
            "$argon2id$v=19$m=65536,t=3,p=2$"
            "c29tZXNhbHRzb21lc2FsdA$0000000000000000000000000000000000000000000",
            password,
        )
        return None
    if not user.is_active or user.auth_source is not AuthSource.LOCAL:
        return None
    if not verify_password(user.password_hash, password):
        return None
    return user


async def open_session(
    session: AsyncSession, user: User, *, ip_address: str | None, user_agent: str | None
) -> tuple[Session, str]:
    """Create a server-side session and return it with its bearer token."""
    settings = get_settings()
    token = new_token(32)
    record = Session(
        token_hash=token_fingerprint(token),
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=settings.session_absolute_hours),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512] or None,
    )
    session.add(record)
    user.last_login_at = datetime.now(UTC)
    await session.flush()
    return record, token


async def resolve_session(session: AsyncSession, token: str) -> User | None:
    """Validate a session token against idle and absolute expiry."""
    settings = get_settings()
    record = (
        await session.execute(select(Session).where(Session.token_hash == token_fingerprint(token)))
    ).scalar_one_or_none()
    if record is None or record.revoked:
        return None

    now = datetime.now(UTC)
    if record.expires_at <= now:
        record.revoked = True
        await session.flush()
        return None
    idle_limit = timedelta(minutes=settings.session_idle_minutes)
    if now - record.last_seen_at > idle_limit:
        record.revoked = True
        await session.flush()
        return None

    user = (
        await session.execute(select(User).where(User.id == record.user_id))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    record.last_seen_at = now
    await session.flush()
    return user


async def revoke_session(session: AsyncSession, token: str) -> None:
    record = (
        await session.execute(select(Session).where(Session.token_hash == token_fingerprint(token)))
    ).scalar_one_or_none()
    if record is not None:
        record.revoked = True
        await session.flush()


async def create_api_key(
    session: AsyncSession, user: User, *, name: str, days_valid: int | None
) -> tuple[ApiKey, str]:
    """Create a personal API key. The plaintext is returned once and never stored."""
    token = f"{API_KEY_PREFIX}{new_token(32)}"
    record = ApiKey(
        name=name[:128],
        prefix=token[: len(API_KEY_PREFIX) + 6],
        token_hash=token_fingerprint(token),
        user_id=user.id,
        scopes=["jobs:read", "jobs:write"],
        expires_at=(datetime.now(UTC) + timedelta(days=days_valid) if days_valid else None),
    )
    session.add(record)
    await session.flush()
    return record, token


async def resolve_api_key(session: AsyncSession, token: str) -> User | None:
    record = (
        await session.execute(select(ApiKey).where(ApiKey.token_hash == token_fingerprint(token)))
    ).scalar_one_or_none()
    if record is None or record.revoked:
        return None
    if record.expires_at is not None and record.expires_at <= datetime.now(UTC):
        return None
    user = (
        await session.execute(select(User).where(User.id == record.user_id))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    record.last_used_at = datetime.now(UTC)
    await session.flush()
    return user


async def upsert_federated_user(
    session: AsyncSession,
    *,
    username: str,
    email: str | None,
    display_name: str | None,
    groups: list[str],
    source: AuthSource,
) -> User:
    """Provision or refresh a user coming from the proxy or the identity provider.

    Membership and role are recomputed from the groups the provider reported on
    every sign-in, so the directory stays authoritative: removing somebody from
    a group upstream removes them here the next time they sign in, rather than
    leaving a membership nobody remembers granting.
    """
    settings = get_settings()
    normalised = username.strip().lower()[:128]
    if not normalised:
        raise UnauthorizedError("The identity provider supplied no username.")

    user = (
        await session.execute(select(User).where(User.username == normalised))
    ).scalar_one_or_none()

    # The legacy single-group setting still grants administration when it
    # matches, so a deployment configured before the mapping keeps working.
    legacy_admin = bool(settings.oidc_admin_group) and settings.oidc_admin_group in groups
    resolution = await group_mapping.resolve(
        session, groups, fallback_admin=legacy_admin, source=source.value
    )

    if user is None:
        user = User(
            username=normalised,
            email=email,
            display_name=display_name or normalised,
            role=resolution.role,
            auth_source=source,
            is_active=True,
        )
        session.add(user)
    else:
        user.email = email or user.email
        user.display_name = display_name or user.display_name
        user.auth_source = source
        user.role = resolution.role

    await session.flush()
    # An unmapped sign-in keeps whatever it already had: the account is not
    # emptied of its groups because nothing upstream matched yet.
    if not resolution.matched_by_default or not user.groups:
        user.groups = list(resolution.groups)
    await session.flush()

    logger.info(
        "federated_user_provisioned",
        username=normalised,
        source=source.value,
        role=user.role.value,
        groups=resolution.group_names(),
        unmatched=resolution.unmatched[:10],
    )
    return user


@dataclass(frozen=True)
class ResetOutcome:
    """What resetting the first administrator actually changed."""

    username: str
    sessions_revoked: int
    mfa_cleared: bool
    password_change_required: bool


async def ensure_bootstrap_admin(session: AsyncSession) -> None:
    """Create the first administrator from the generated bootstrap password."""
    settings = get_settings()
    username = settings.bootstrap_admin_username.strip().lower()
    existing = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if existing is not None:
        return

    password = settings.bootstrap_admin_password
    if not password:
        logger.warning(
            "bootstrap_admin_skipped",
            reason="no bootstrap password is configured",
            username=username,
        )
        return

    session.add(
        User(
            id=uuid.uuid4(),
            username=username,
            display_name="Administrator",
            role=Role.ADMIN,
            auth_source=AuthSource.LOCAL,
            password_hash=hash_password(password),
            must_change_password=await settings_store.get(
                session, "force_password_change_at_first_login"
            ),
            is_active=True,
        )
    )
    await session.flush()
    logger.info("bootstrap_admin_created", username=username)


async def reset_bootstrap_admin(session: AsyncSession, password: str | None = None) -> ResetOutcome:
    """Reset the bootstrap administrator password and re-arm the forced change.

    This is the recovery path when the password is lost, when the authenticator
    is lost, or when the configured first-sign-in credential no longer matches
    because the account was already used. It is deliberately not reachable over
    the API: it runs as a one-shot container command, which requires access to
    the host.

    It clears the two-factor enrolment as well. Resetting only the password
    would leave an administrator who lost their authenticator locked out with no
    host-side recovery, which would defeat the purpose of the command.
    """
    settings = get_settings()
    username = settings.bootstrap_admin_username.strip().lower()
    secret = (password or settings.bootstrap_admin_password or "").strip()
    if not secret:
        raise ValueError(
            "No password is configured. Set XENOPROXY_ADMIN_PASSWORD in docker-compose.yml "
            "or pass one as an argument."
        )

    user = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()

    if user is None:
        user = User(
            username=username,
            display_name="Administrator",
            role=Role.ADMIN,
            auth_source=AuthSource.LOCAL,
            is_active=True,
        )
        session.add(user)

    user.password_hash = hash_password(secret)
    user.must_change_password = await settings_store.get(
        session, "force_password_change_at_first_login"
    )
    user.is_active = True
    user.role = Role.ADMIN
    user.auth_source = AuthSource.LOCAL

    # Drop the authenticator and its recovery codes. Where the instance requires
    # two-factor for administrators, the next sign-in enrols a fresh one.
    mfa_was_enabled = user.mfa_enabled
    user.mfa_enabled = False
    user.mfa_secret_ciphertext = None
    user.mfa_secret_wrapped_key = None
    user.mfa_confirmed_at = None
    user.mfa_last_counter = None
    await session.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    await session.flush()

    # Any session opened with the previous password stops working immediately.
    sessions = (await session.execute(select(Session).where(Session.user_id == user.id))).scalars()
    revoked = 0
    for record in sessions:
        if not record.revoked:
            record.revoked = True
            revoked += 1

    await audit.record(
        session,
        action="user.password_reset",
        actor="system",
        target=username,
        details={
            "method": "reset-admin command",
            "sessions_revoked": revoked,
            "mfa_cleared": mfa_was_enabled,
        },
    )
    logger.info(
        "bootstrap_admin_reset",
        username=username,
        sessions_revoked=revoked,
        mfa_cleared=mfa_was_enabled,
    )
    return ResetOutcome(
        username=username,
        sessions_revoked=revoked,
        mfa_cleared=mfa_was_enabled,
        password_change_required=user.must_change_password,
    )


MFA_CHALLENGE_TTL_SECONDS = 300


def issue_mfa_challenge(user: User) -> str:
    """Sign a short-lived token proving the password step already succeeded."""
    payload = json.dumps(
        {"sub": str(user.id), "ts": int(time.time())}, separators=(",", ":")
    ).encode()
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(
        get_settings().secret_key.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return f"{body}.{signature}"


def open_mfa_challenge(token: str) -> uuid.UUID:
    """Validate a challenge token and return the user it was issued for."""
    try:
        body, signature = token.split(".", 1)
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError) as exc:
        raise UnauthorizedError("The sign-in attempt is malformed; start again.") from exc

    expected = hmac.new(
        get_settings().secret_key.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise UnauthorizedError("The sign-in attempt could not be verified; start again.")

    data = json.loads(payload)
    if int(time.time()) - int(data.get("ts", 0)) > MFA_CHALLENGE_TTL_SECONDS:
        raise UnauthorizedError("The sign-in attempt expired; start again.")
    return uuid.UUID(str(data["sub"]))


async def load_user(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()


async def assign_default_groups(session: AsyncSession, user: User) -> None:
    """Put a user in every default group, so shared history works out of the box."""
    from app.models.group import Group

    if user.groups:
        return
    defaults = (await session.execute(select(Group).where(Group.is_default.is_(True)))).scalars()
    user.groups = list(defaults)
    await session.flush()
