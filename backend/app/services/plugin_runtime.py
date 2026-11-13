"""Resolution of a plugin's effective configuration, then its instantiation.

This is the single place that turns a plugin name into a ready-to-run instance,
so the scan preview, the orchestrator and the health probe can never disagree
about what a plugin is configured with.

Precedence, lowest first:

1. the class declaration — `options_schema` defaults and `default_timeout`;
2. the instance configuration an administrator set;
3. the analyst's own preferences, for the options and credentials the plugin
   marks `user_overridable`;
4. the `runtime_configuration` carried by this one job.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.job import PluginKind, Tlp
from app.models.plugin_config import PluginConfig, UserPluginConfig
from app.plugins.base.plugin import BasePlugin, SampleAccess
from app.plugins.base.registry import get_plugin
from app.repositories import plugin_configs
from app.services import secrets_vault

logger = get_logger(__name__)


@dataclass(frozen=True)
class BuiltPlugin:
    """A configured plugin instance and the settings the caller still needs."""

    plugin: BasePlugin
    cache_ttl_seconds: int
    config: PluginConfig


def class_defaults(cls: type[BasePlugin]) -> dict[str, Any]:
    """Layer 1: the defaults the plugin declares in its options schema."""
    return {
        key: spec.get("default")
        for key, spec in (cls.options_schema or {}).items()
        if isinstance(spec, dict) and "default" in spec
    }


def user_overridable_options(cls: type[BasePlugin]) -> frozenset[str]:
    """Options an analyst may set for themselves.

    An option is personal only when it says so. Anything that points the plugin
    at a different endpoint, or relaxes a network restriction, stays with the
    administrator — otherwise a per-user option would become a way around the
    instance's SSRF policy.
    """
    return frozenset(
        key
        for key, spec in (cls.options_schema or {}).items()
        if isinstance(spec, dict) and bool(spec.get("user_overridable"))
    )


async def load_user_options(session: AsyncSession, user_id: uuid.UUID) -> dict[str, dict[str, Any]]:
    """Return `{plugin_name: options}` for one analyst."""
    rows = (
        await session.execute(select(UserPluginConfig).where(UserPluginConfig.user_id == user_id))
    ).scalars()
    return {row.plugin_name: dict(row.options or {}) for row in rows}


async def set_user_options(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    plugin_name: str,
    options: dict[str, Any],
) -> UserPluginConfig:
    """Store one analyst's option defaults, keeping only the personal ones."""
    allowed = user_overridable_options(get_plugin(plugin_name))
    kept = {key: value for key, value in options.items() if key in allowed}

    row = (
        await session.execute(
            select(UserPluginConfig).where(
                UserPluginConfig.user_id == user_id,
                UserPluginConfig.plugin_name == plugin_name,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = UserPluginConfig(user_id=user_id, plugin_name=plugin_name)
        session.add(row)
    row.options = kept
    await session.flush()
    return row


def resolve_options(
    cls: type[BasePlugin],
    *,
    instance_options: dict[str, Any] | None,
    user_options: dict[str, Any] | None = None,
    runtime_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collapse the four configuration layers into one option mapping."""
    options = class_defaults(cls)
    options.update(instance_options or {})

    if user_options:
        allowed = user_overridable_options(cls)
        options.update({key: value for key, value in user_options.items() if key in allowed})

    options.update(runtime_options or {})
    return options


async def build(
    session: AsyncSession,
    name: str,
    *,
    expected_type: PluginKind | None = None,
    user_id: uuid.UUID | None = None,
    runtime_options: dict[str, Any] | None = None,
    require_enabled: bool = True,
    job_tlp: Tlp | None = None,
    sample: SampleAccess | None = None,
) -> BuiltPlugin | None:
    """Instantiate a plugin with its effective options, timeout and credentials.

    Returns None when the plugin is disabled, or when it is not of the expected
    type, so the caller can record an explicit SKIPPED report rather than
    raising inside a job.
    """
    cls = get_plugin(name)
    if expected_type is not None and cls.plugin_type is not expected_type:
        logger.warning(
            "plugin_type_mismatch",
            plugin=name,
            declared=cls.plugin_type.value,
            expected=expected_type.value,
        )
        return None

    config = await plugin_configs.get(session, name)
    if config is None:
        return None
    if require_enabled and not config.enabled:
        return None

    user_options: dict[str, Any] = {}
    if user_id is not None:
        stored = (
            await session.execute(
                select(UserPluginConfig).where(
                    UserPluginConfig.user_id == user_id,
                    UserPluginConfig.plugin_name == name,
                )
            )
        ).scalar_one_or_none()
        user_options = dict(stored.options or {}) if stored else {}

    options = resolve_options(
        cls,
        instance_options=dict(config.options or {}),
        user_options=user_options,
        runtime_options=runtime_options,
    )
    secrets = await secrets_vault.resolve_secrets(session, name, user_id=user_id)

    plugin = cls(
        secrets=secrets,
        options=options,
        timeout=config.timeout_seconds,
        job_tlp=job_tlp,
        sample=sample,
    )
    return BuiltPlugin(plugin=plugin, cache_ttl_seconds=config.cache_ttl_seconds, config=config)
