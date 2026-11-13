"""Backend-only vault for plugin credentials.

Plaintext credentials exist in memory only for the duration of a plugin run.
The API layer is never given a way to read one back: it can write a credential,
see its last four characters and delete it.

Credentials live at two levels. The instance level is the team's shared
subscription, managed by an administrator. The user level is an analyst's own
account for the same provider, and it is accepted only for a credential the
plugin marks `user_overridable` — which is what stops an individual from
shadowing a shared enterprise key for everyone else's jobs.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import CryptoError, SealedSecret, seal, unseal
from app.core.logging import get_logger
from app.models.plugin_config import PluginSecret, UserPluginSecret

logger = get_logger(__name__)

MIN_SECRET_LENGTH = 8
MAX_SECRET_LENGTH = 2048


class SecretTooShortError(ValueError):
    """Raised when a submitted credential is implausibly short."""


def _validate(value: str) -> str:
    value = value.strip()
    if len(value) < MIN_SECRET_LENGTH:
        raise SecretTooShortError(
            f"A credential must be at least {MIN_SECRET_LENGTH} characters long."
        )
    if len(value) > MAX_SECRET_LENGTH:
        raise SecretTooShortError("The credential is too long.")
    return value


def _unseal_row(row: PluginSecret | UserPluginSecret, *, scope: str) -> str | None:
    """Decrypt one row, logging rather than raising when the key cannot open it."""
    try:
        return unseal(
            SealedSecret(
                ciphertext=row.ciphertext,
                wrapped_key=row.wrapped_key,
                key_version=row.key_version,
            )
        )
    except CryptoError:
        logger.error(
            "secret_undecryptable",
            plugin=row.plugin_name,
            secret_name=row.secret_name,
            scope=scope,
        )
        return None


# -- instance-level credentials ---------------------------------------------


async def set_secret(
    session: AsyncSession,
    *,
    plugin_name: str,
    secret_name: str,
    value: str,
    actor: str,
) -> PluginSecret:
    """Store or replace an instance credential, sealed with envelope encryption."""
    value = _validate(value)
    sealed = seal(value)
    existing = await _get_row(session, plugin_name, secret_name)
    if existing is None:
        existing = PluginSecret(plugin_name=plugin_name, secret_name=secret_name)
        session.add(existing)

    existing.ciphertext = sealed.ciphertext
    existing.wrapped_key = sealed.wrapped_key
    existing.key_version = sealed.key_version
    existing.hint = value[-4:]
    existing.updated_by = actor
    await session.flush()
    return existing


async def delete_secret(session: AsyncSession, *, plugin_name: str, secret_name: str) -> bool:
    result = await session.execute(
        delete(PluginSecret).where(
            PluginSecret.plugin_name == plugin_name,
            PluginSecret.secret_name == secret_name,
        )
    )
    return bool(result.rowcount)


async def list_hints(session: AsyncSession, plugin_name: str) -> dict[str, str]:
    """Return `{secret_name: last four characters}` for one plugin."""
    rows = (
        await session.execute(select(PluginSecret).where(PluginSecret.plugin_name == plugin_name))
    ).scalars()
    return {row.secret_name: row.hint for row in rows}


async def configured_plugins(session: AsyncSession) -> dict[str, set[str]]:
    """Map every plugin to the set of instance credential names it has stored."""
    rows = (await session.execute(select(PluginSecret))).scalars()
    mapping: dict[str, set[str]] = {}
    for row in rows:
        mapping.setdefault(row.plugin_name, set()).add(row.secret_name)
    return mapping


async def _get_row(
    session: AsyncSession, plugin_name: str, secret_name: str
) -> PluginSecret | None:
    return (
        await session.execute(
            select(PluginSecret).where(
                PluginSecret.plugin_name == plugin_name,
                PluginSecret.secret_name == secret_name,
            )
        )
    ).scalar_one_or_none()


# -- user-level credentials --------------------------------------------------


async def set_user_secret(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    plugin_name: str,
    secret_name: str,
    value: str,
) -> UserPluginSecret:
    """Store or replace one analyst's own credential for a plugin.

    The caller is responsible for having checked that the plugin marks this
    credential `user_overridable`; the API layer does that so the refusal can
    carry a useful message.
    """
    value = _validate(value)
    sealed = seal(value)
    existing = (
        await session.execute(
            select(UserPluginSecret).where(
                UserPluginSecret.user_id == user_id,
                UserPluginSecret.plugin_name == plugin_name,
                UserPluginSecret.secret_name == secret_name,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = UserPluginSecret(
            user_id=user_id, plugin_name=plugin_name, secret_name=secret_name
        )
        session.add(existing)

    existing.ciphertext = sealed.ciphertext
    existing.wrapped_key = sealed.wrapped_key
    existing.key_version = sealed.key_version
    existing.hint = value[-4:]
    await session.flush()
    return existing


async def delete_user_secret(
    session: AsyncSession, *, user_id: uuid.UUID, plugin_name: str, secret_name: str
) -> bool:
    result = await session.execute(
        delete(UserPluginSecret).where(
            UserPluginSecret.user_id == user_id,
            UserPluginSecret.plugin_name == plugin_name,
            UserPluginSecret.secret_name == secret_name,
        )
    )
    return bool(result.rowcount)


async def list_user_hints(session: AsyncSession, user_id: uuid.UUID) -> dict[str, dict[str, str]]:
    """Return `{plugin_name: {secret_name: hint}}` for one analyst."""
    rows = (
        await session.execute(select(UserPluginSecret).where(UserPluginSecret.user_id == user_id))
    ).scalars()
    hints: dict[str, dict[str, str]] = {}
    for row in rows:
        hints.setdefault(row.plugin_name, {})[row.secret_name] = row.hint
    return hints


# -- resolution --------------------------------------------------------------


async def resolve_secrets(
    session: AsyncSession, plugin_name: str, *, user_id: uuid.UUID | None = None
) -> dict[str, str]:
    """Decrypt every credential of one plugin for an imminent run.

    The analyst's own credentials are layered over the instance ones, so a
    personal account wins for the credentials they set and the shared
    subscription still covers the rest.
    """
    resolved: dict[str, str] = {}

    rows = (
        await session.execute(select(PluginSecret).where(PluginSecret.plugin_name == plugin_name))
    ).scalars()
    for row in rows:
        plaintext = _unseal_row(row, scope="instance")
        if plaintext is not None:
            resolved[row.secret_name] = plaintext

    if user_id is not None:
        user_rows = (
            await session.execute(
                select(UserPluginSecret).where(
                    UserPluginSecret.user_id == user_id,
                    UserPluginSecret.plugin_name == plugin_name,
                )
            )
        ).scalars()
        for row in user_rows:
            plaintext = _unseal_row(row, scope="user")
            if plaintext is not None:
                resolved[row.secret_name] = plaintext

    return resolved
