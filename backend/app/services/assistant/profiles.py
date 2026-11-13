"""Saved connections to an inference server, and the one in use.

A profile answers *where the model is and how it answers*; the assistant
settings answer *what the assistant is allowed to do*. Keeping them apart means
switching from a local Ollama to a hosted gateway changes nothing about who may
use the assistant or whether it may write.

One profile is active. `overlay()` lays it over the stored assistant settings,
so every caller — the chat, the judgement connector, the connection test — goes
on reading a single object. With no profile at all the settings are used as
they stand, which is what an instance that predates profiles starts from.

**Secrets.** The API key and the header *values* are sealed together in one
blob, because a gateway key routinely lives in a header rather than in
`Authorization`. Neither is ever returned: the API answers whether a key is set
and the header names. Submitting an empty key keeps the stored one, which is
how the interface can save a profile it never held the secrets of.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import CryptoError, SealedSecret, seal, unseal
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.models.plugin_config import LlmProfile

logger = get_logger(__name__)

# What a profile owns. Everything else in the assistant settings is policy.
CONNECTION_FIELDS = ("provider", "base_url", "model", "timeout")
GENERATION_FIELDS = ("temperature", "top_p", "max_tokens", "context_tokens")


@dataclass(frozen=True)
class ProfileSecrets:
    api_key: str = ""
    headers: dict[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"api_key": self.api_key, "headers": dict(self.headers or {})}


def secrets_of(profile: LlmProfile) -> ProfileSecrets:
    """Open a profile's sealed blob, or an empty one when it cannot be read."""
    if not profile.secrets_ciphertext or not profile.secrets_wrapped_key:
        return ProfileSecrets()
    try:
        opened = unseal(
            SealedSecret(
                ciphertext=profile.secrets_ciphertext,
                wrapped_key=profile.secrets_wrapped_key,
                key_version=profile.secrets_key_version,
            )
        )
    except CryptoError:
        # A master key that no longer opens this blob is an operational fact,
        # not a crash: the profile degrades to having no credentials.
        logger.error("llm_profile_secrets_undecryptable", profile=profile.name)
        return ProfileSecrets()
    try:
        payload = json.loads(opened)
    except ValueError:
        return ProfileSecrets()
    headers = payload.get("headers")
    return ProfileSecrets(
        api_key=str(payload.get("api_key") or ""),
        headers={str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {},
    )


def _store_secrets(profile: LlmProfile, secrets: ProfileSecrets) -> None:
    sealed = seal(json.dumps(secrets.as_dict()))
    profile.secrets_ciphertext = sealed.ciphertext
    profile.secrets_wrapped_key = sealed.wrapped_key
    profile.secrets_key_version = sealed.key_version
    profile.header_names = sorted(secrets.headers or {})


async def list_profiles(session: AsyncSession) -> list[LlmProfile]:
    result = await session.execute(select(LlmProfile).order_by(LlmProfile.name))
    return list(result.scalars())


async def get(session: AsyncSession, profile_id: Any) -> LlmProfile:
    profile = await session.get(LlmProfile, profile_id)
    if profile is None:
        raise NotFoundError("Unknown assistant profile.", code="PROFILE_NOT_FOUND")
    return profile


async def active(session: AsyncSession) -> LlmProfile | None:
    result = await session.execute(select(LlmProfile).where(LlmProfile.is_active.is_(True)))
    return result.scalars().first()


async def save(
    session: AsyncSession,
    *,
    profile_id: Any | None,
    values: dict[str, Any],
    api_key: str | None,
    headers: dict[str, str] | None,
    actor: str,
) -> LlmProfile:
    """Create or update a profile, keeping secrets that were not resubmitted."""
    name = str(values.get("name") or "").strip()
    if not name:
        raise ValidationFailedError("A profile needs a name.")

    clash = await session.execute(select(LlmProfile).where(LlmProfile.name == name))
    existing = clash.scalars().first()
    if existing is not None and (profile_id is None or existing.id != profile_id):
        raise ValidationFailedError(f"A profile named '{name}' already exists.")

    profile = await get(session, profile_id) if profile_id is not None else LlmProfile(name=name)
    profile.name = name
    for field in (*CONNECTION_FIELDS, *GENERATION_FIELDS):
        if field in values and values[field] is not None:
            setattr(profile, field, values[field])

    current = secrets_of(profile)
    # An empty key means "keep what is stored": the interface never holds the
    # secret, so it cannot send it back on every save.
    next_key = current.api_key if api_key in (None, "") else api_key
    next_headers = current.headers or {} if headers is None else headers
    _store_secrets(profile, ProfileSecrets(api_key=next_key, headers=next_headers))

    profile.updated_by = actor
    if profile_id is None:
        session.add(profile)
        await session.flush()
        # The first profile saved is the one in use; otherwise an operator
        # would have to create it and then remember to activate it.
        if await active(session) is None:
            await activate(session, profile.id, actor=actor)
    return profile


async def activate(session: AsyncSession, profile_id: Any, *, actor: str) -> LlmProfile:
    """Make one profile the active one, clearing the others."""
    profile = await get(session, profile_id)
    for other in await list_profiles(session):
        other.is_active = other.id == profile.id
    profile.updated_by = actor
    return profile


async def delete(session: AsyncSession, profile_id: Any) -> LlmProfile:
    profile = await get(session, profile_id)
    await session.delete(profile)
    # Deleting the active one leaves none active, and the assistant falls back
    # to the settings. Promoting an arbitrary other profile would silently
    # point the assistant at a different server.
    return profile


def overlay(settings: Any, profile: LlmProfile | None) -> Any:
    """Lay a profile over the assistant settings, returning what to use.

    The settings object is not mutated: the caller may be holding the cached
    instance, and a request must not change what the next one reads.
    """
    if profile is None:
        return settings

    secrets = secrets_of(profile)
    merged = settings.model_copy(
        update={
            **{field: getattr(profile, field) for field in CONNECTION_FIELDS},
            **{field: getattr(profile, field) for field in GENERATION_FIELDS},
            "api_key": secrets.api_key,
            "headers": dict(secrets.headers or {}),
        }
    )
    return merged


async def effective_settings(session: AsyncSession, *, fresh: bool = False) -> Any:
    """The assistant settings a caller should use: policy plus the active profile.

    `fresh` bypasses the per-process settings cache, which the worker needs
    because it is a different process from the API.
    """
    from app.services import app_settings

    settings = (
        await app_settings.reload(session, "assistant")
        if fresh
        else await app_settings.load(session, "assistant")
    )
    return overlay(settings, await active(session))
