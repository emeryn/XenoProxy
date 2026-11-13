"""Read-only plugin and playbook catalogue, plus each analyst's own preferences.

The catalogue is available to every analyst because the scan page needs it. The
personal preferences live here rather than under `/admin` for the same reason:
they are the analyst's own configuration layer, not an administrative one.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.deps import DbSession, require
from app.core.errors import NotFoundError, ValidationFailedError
from app.models.job import PluginKind
from app.models.playbook import Playbook
from app.models.user import User
from app.plugins import load_all
from app.plugins.base.registry import describe, get_plugin, iter_plugins
from app.repositories import plugin_configs
from app.schemas.admin import PlaybookOut, PluginOut, SecretUpdate
from app.schemas.common import MessageResponse
from app.services import plugin_runtime, secrets_vault
from app.services.secrets_vault import SecretTooShortError

router = APIRouter(tags=["catalog"])

CatalogReader = Annotated[User, Depends(require("analyzers:read"))]
PlaybookReader = Annotated[User, Depends(require("playbooks:read"))]


async def build_plugin_views(
    session: DbSession,
    *,
    include_hints: bool,
    plugin_type: PluginKind | None = None,
) -> list[PluginOut]:
    """Join plugin declarations with their stored configuration and credential state."""
    load_all()
    configs = await plugin_configs.list_all(session)
    stored = await secrets_vault.configured_plugins(session)

    views: list[PluginOut] = []
    for cls in iter_plugins(plugin_type):
        declaration = describe(cls)
        config = configs.get(cls.name)
        present = stored.get(cls.name, set())
        missing = sorted(set(cls.required_secret_names()) - present)
        hints = await secrets_vault.list_hints(session, cls.name) if include_hints else {}
        views.append(
            PluginOut(
                **declaration,
                enabled=bool(config and config.enabled),
                configured=not missing,
                missing_secrets=missing,
                secret_hints=hints,
                options=dict(config.options or {}) if config else {},
                timeout_seconds=config.timeout_seconds if config else cls.default_timeout,
                cache_ttl_seconds=config.cache_ttl_seconds if config else cls.default_cache_ttl,
                health_ok=config.health_ok if config else None,
                health_detail=config.health_detail if config else None,
                health_checked_at=config.health_checked_at if config else None,
                updated_at=config.updated_at if config else None,
                updated_by=config.updated_by if config else None,
            )
        )
    return views


@router.get("/plugins", response_model=list[PluginOut], summary="List plugins")
async def list_plugins(
    session: DbSession,
    _user: CatalogReader,
    plugin_type: PluginKind | None = None,
) -> list[PluginOut]:
    """Every registered plugin, optionally narrowed to one type."""
    return await build_plugin_views(session, include_hints=False, plugin_type=plugin_type)


@router.get("/playbooks", response_model=list[PlaybookOut], summary="List playbooks")
async def list_playbooks(session: DbSession, _user: PlaybookReader) -> list[PlaybookOut]:
    rows = (await session.execute(select(Playbook).order_by(Playbook.name))).scalars()
    return [PlaybookOut.model_validate(row, from_attributes=True) for row in rows]


# --------------------------------------------------------------------------
# The analyst's own configuration layer
# --------------------------------------------------------------------------


@router.get(
    "/me/plugin-config",
    response_model=dict,
    summary="Read your own plugin options and credentials",
)
async def get_my_plugin_config(session: DbSession, user: CatalogReader) -> dict[str, Any]:
    """What this analyst has overridden, and what they are allowed to override."""
    load_all()
    options = await plugin_runtime.load_user_options(session, user.id)
    hints = await secrets_vault.list_user_hints(session, user.id)

    overridable = {}
    for cls in iter_plugins():
        option_names = sorted(plugin_runtime.user_overridable_options(cls))
        secret_names = cls.user_overridable_secret_names()
        if option_names or secret_names:
            overridable[cls.name] = {
                "label": cls.label,
                "plugin_type": cls.plugin_type.value,
                "options": option_names,
                "secrets": secret_names,
            }

    return {"overridable": overridable, "options": options, "secret_hints": hints}


@router.put(
    "/me/plugin-config/{plugin_name}",
    response_model=dict,
    summary="Set your own options for one plugin",
)
async def put_my_plugin_options(
    plugin_name: str,
    payload: dict[str, Any],
    session: DbSession,
    user: CatalogReader,
) -> dict[str, Any]:
    """Store personal option defaults. Anything not personal is dropped."""
    load_all()
    cls = get_plugin(plugin_name)
    allowed = plugin_runtime.user_overridable_options(cls)
    rejected = sorted(set(payload) - allowed)
    if rejected:
        raise ValidationFailedError(
            f"These options of '{cls.name}' are set by an administrator, not per user: "
            + ", ".join(rejected)
        )

    row = await plugin_runtime.set_user_options(
        session, user_id=user.id, plugin_name=cls.name, options=payload
    )
    await session.commit()
    return {"plugin_name": cls.name, "options": row.options}


@router.put(
    "/me/plugin-config/{plugin_name}/secrets/{secret_name}",
    response_model=MessageResponse,
    summary="Store your own credential for one plugin",
)
async def put_my_plugin_secret(
    plugin_name: str,
    secret_name: str,
    payload: SecretUpdate,
    session: DbSession,
    user: CatalogReader,
) -> MessageResponse:
    """Use a personal provider account instead of the team's shared one."""
    load_all()
    cls = get_plugin(plugin_name)
    if secret_name not in cls.user_overridable_secret_names():
        raise ValidationFailedError(
            f"The credential '{secret_name}' of {cls.label} is managed by an administrator "
            "and cannot be set per user."
        )

    try:
        record = await secrets_vault.set_user_secret(
            session,
            user_id=user.id,
            plugin_name=cls.name,
            secret_name=secret_name,
            value=payload.value,
        )
    except SecretTooShortError as exc:
        raise ValidationFailedError(str(exc)) from exc

    await session.commit()
    return MessageResponse(
        message="Your credential has been stored and will be used for your own jobs.",
        details={"hint": record.hint},
    )


@router.delete(
    "/me/plugin-config/{plugin_name}/secrets/{secret_name}",
    response_model=MessageResponse,
    summary="Delete your own credential for one plugin",
)
async def delete_my_plugin_secret(
    plugin_name: str,
    secret_name: str,
    session: DbSession,
    user: CatalogReader,
) -> MessageResponse:
    """Removing it falls back to the team's shared credential."""
    deleted = await secrets_vault.delete_user_secret(
        session, user_id=user.id, plugin_name=plugin_name[:64], secret_name=secret_name[:64]
    )
    if not deleted:
        raise NotFoundError("You have no credential stored for this plugin.")
    await session.commit()
    return MessageResponse(
        message="Your credential has been deleted; the shared one applies again."
    )
