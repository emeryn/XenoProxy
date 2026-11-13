"""Structured settings an administrator edits from the interface.

Two kinds of instance configuration live side by side, and they are different
enough to be stored differently:

- the scalar switches and thresholds of `settings_store`, declared one by one
  with their bounds, which an administrator changes individually;
- the **sections** here, each a Pydantic model describing one subsystem —
  outbound network, the assistant, the directory, mail. A section is saved and
  validated as a whole, because its fields only make sense together: a proxy
  URL without its credentials, or a model without its server, is not a state
  worth storing.

Both use the same `instance_settings` table. A section is one row whose key is
`section:<name>` and whose value is the model dump, so no separate table and no
second migration are needed.

Secret fields are sealed with the same envelope encryption as the plugin vault
and never leave the backend: the API answers `<field>_set: true` instead, an
empty value on update keeps what is stored, and `<field>_clear: true` removes
it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import CryptoError, SealedSecret, seal, unseal
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.models.setting import InstanceSetting
from app.services.settings_sections import SECRET_FIELDS, SECTIONS

__all__ = [
    "SECRET_FIELDS",
    "SECTIONS",
    "audit_safe",
    "clear_cache",
    "load",
    "load_all",
    "merge_secrets",
    "model_for",
    "public",
    "save",
    "section_names",
    "validate",
]

logger = get_logger(__name__)

KEY_PREFIX = "section:"

_cache: dict[str, BaseModel] = {}
_lock = asyncio.Lock()


def section_names() -> list[str]:
    return sorted(SECTIONS)


def model_for(name: str) -> type[BaseModel]:
    try:
        return SECTIONS[name]
    except KeyError as exc:
        raise NotFoundError(
            f"Unknown settings section '{name}'.", code="SECTION_NOT_FOUND"
        ) from exc


def _row_key(name: str) -> str:
    return f"{KEY_PREFIX}{name}"


def _unseal_field(name: str, field: str, stored: Any) -> str:
    """Open one sealed field, returning empty rather than failing the section.

    A master key that changed makes every secret unreadable. Refusing to load
    the section would take the whole settings page down with it, so the field
    comes back empty and the administrator is told to enter it again.
    """
    if not isinstance(stored, dict):
        # A value written before the field was marked secret, or a plain string
        # restored from a configuration export.
        return str(stored or "")
    try:
        return unseal(
            SealedSecret(
                ciphertext=stored["ciphertext"],
                wrapped_key=stored["wrapped_key"],
                key_version=int(stored.get("key_version", 1)),
            )
        )
    except (CryptoError, KeyError, TypeError, ValueError):
        logger.error("section_secret_undecryptable", section=name, field=field)
        return ""


async def _read(session: AsyncSession, name: str) -> BaseModel:
    model = model_for(name)
    row = (
        await session.execute(select(InstanceSetting).where(InstanceSetting.key == _row_key(name)))
    ).scalar_one_or_none()
    data: dict[str, Any] = dict(row.value) if row and isinstance(row.value, dict) else {}

    for field in SECRET_FIELDS.get(name, ()):
        if data.get(field):
            data[field] = _unseal_field(name, field, data[field])

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        # Only which field is wrong and why. A pydantic message quotes the input
        # it rejected, and that input may be a decrypted secret.
        detail = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['type']}" for err in exc.errors()
        )
        logger.error("section_invalid", section=name, detail=detail)
        return model()


async def load(session: AsyncSession, name: str) -> Any:
    """Return one section, from the cache when it is warm."""
    async with _lock:
        cached = _cache.get(name)
    if cached is not None:
        return cached

    value = await _read(session, name)
    async with _lock:
        _cache[name] = value
    return value


async def reload(session: AsyncSession, name: str) -> Any:
    """Read one section from the database, ignoring the cache.

    The cache is per process, and the API and the worker are separate
    processes: a section saved in one is stale in the other until something
    re-reads it. The worker calls this at the start of each job, which costs
    one row and is what makes a new proxy or a new certificate authority apply
    to analyzer traffic without a restart.
    """
    value = await _read(session, name)
    async with _lock:
        _cache[name] = value
    return value


async def load_all(session: AsyncSession) -> dict[str, BaseModel]:
    return {name: await load(session, name) for name in section_names()}


def merge_secrets(name: str, incoming: dict[str, Any], current: BaseModel) -> dict[str, Any]:
    """Empty or missing secrets keep the stored value; `<field>_clear` removes it."""
    data = {key: value for key, value in incoming.items() if not key.endswith("_set")}
    for field in SECRET_FIELDS.get(name, ()):
        if data.pop(f"{field}_clear", False):
            data[field] = ""
        elif not data.get(field):
            data[field] = getattr(current, field, "")
    return data


def validate(name: str, merged: dict[str, Any]) -> BaseModel:
    """Build the section model, turning a schema error into an API error."""
    try:
        return model_for(name).model_validate(merged)
    except ValidationError as exc:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ValidationFailedError(detail) from exc


async def save(session: AsyncSession, name: str, value: BaseModel, actor: str) -> None:
    """Persist a section, sealing its secret fields."""
    stored = value.model_dump()
    for field in SECRET_FIELDS.get(name, ()):
        secret = stored.get(field)
        if secret:
            sealed = seal(str(secret))
            stored[field] = {
                "ciphertext": sealed.ciphertext,
                "wrapped_key": sealed.wrapped_key,
                "key_version": sealed.key_version,
            }

    row = (
        await session.execute(select(InstanceSetting).where(InstanceSetting.key == _row_key(name)))
    ).scalar_one_or_none()
    if row is None:
        row = InstanceSetting(key=_row_key(name), value=stored)
        session.add(row)
    else:
        row.value = stored
    row.updated_by = actor
    await session.flush()

    async with _lock:
        _cache[name] = value


def public(name: str, value: BaseModel) -> dict[str, Any]:
    """The section as the browser may see it: every secret replaced by a flag."""
    data = value.model_dump()
    for field in SECRET_FIELDS.get(name, ()):
        data[f"{field}_set"] = bool(data.get(field))
        data[field] = ""
    return data


def audit_safe(name: str, value: BaseModel) -> dict[str, Any]:
    """What a settings change may be written to the audit trail.

    Sealed fields are replaced, and so are the **values** of free-form header
    maps: a gateway key is routinely carried in a header, and a credential has
    no business in an audit line.
    """
    out: dict[str, Any] = {}
    for field, content in value.model_dump().items():
        if field in SECRET_FIELDS.get(name, ()):
            out[field] = "***" if content else ""
        elif field == "headers" and isinstance(content, dict):
            out[field] = dict.fromkeys(content, "***")
        else:
            out[field] = content
    return out


async def clear_cache() -> None:
    async with _lock:
        _cache.clear()
