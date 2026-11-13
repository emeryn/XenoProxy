"""Data access for plugin runtime configuration."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.plugin_config import (
    PluginConfig,
    PluginSecret,
    UserPluginConfig,
    UserPluginSecret,
)
from app.plugins.base.plugin import BasePlugin, HealthCheck


async def get(session: AsyncSession, plugin_name: str) -> PluginConfig | None:
    return (
        await session.execute(select(PluginConfig).where(PluginConfig.plugin_name == plugin_name))
    ).scalar_one_or_none()


async def list_all(session: AsyncSession) -> dict[str, PluginConfig]:
    rows = (await session.execute(select(PluginConfig))).scalars()
    return {row.plugin_name: row for row in rows}


async def ensure(session: AsyncSession, cls: type[BasePlugin]) -> PluginConfig:
    """Return the stored configuration for a plugin, creating defaults if absent."""
    config = await get(session, cls.name)
    if config is None:
        config = PluginConfig(
            plugin_name=cls.name,
            plugin_type=cls.plugin_type,
            enabled=False,
            timeout_seconds=cls.default_timeout,
            cache_ttl_seconds=cls.default_cache_ttl,
            options={
                key: spec.get("default")
                for key, spec in (cls.options_schema or {}).items()
                if isinstance(spec, dict)
            },
        )
        session.add(config)
        await session.flush()
    elif config.plugin_type is not cls.plugin_type:
        # A plugin changed type between releases: the declaration wins, because
        # it is what the orchestrator schedules on.
        config.plugin_type = cls.plugin_type
        await session.flush()
    return config


async def set_enabled(
    session: AsyncSession, plugin_name: str, enabled: bool, actor: str
) -> PluginConfig | None:
    config = await get(session, plugin_name)
    if config is None:
        return None
    config.enabled = enabled
    config.updated_by = actor
    await session.flush()
    return config


async def record_health(
    session: AsyncSession, plugin_name: str, check: HealthCheck
) -> PluginConfig | None:
    """Store the outcome of a health probe so the Admin list can show it."""
    config = await get(session, plugin_name)
    if config is None:
        return None
    config.health_ok = check.healthy
    config.health_detail = check.detail[:512]
    config.health_checked_at = datetime.now(UTC)
    await session.flush()
    return config


async def orphans(session: AsyncSession, known_names: set[str]) -> list[PluginConfig]:
    """Stored configurations whose plugin is no longer registered.

    A plugin removed from a release, or a custom plugin that failed to load,
    leaves its configuration row behind. They are reported rather than deleted:
    the row may hold a sealed credential, and a plugin that is merely failing to
    import would otherwise lose its configuration on the next restart.
    """
    return [row for name, row in (await list_all(session)).items() if name not in known_names]


async def prune(session: AsyncSession, known_names: set[str]) -> list[str]:
    """Delete orphaned configurations and their sealed credentials.

    This is destructive and deliberately not reachable over the API: it runs as
    a one-shot container command, which requires access to the host.
    """
    removed: list[str] = []
    for row in await orphans(session, known_names):
        await session.execute(
            delete(PluginSecret).where(PluginSecret.plugin_name == row.plugin_name)
        )
        await session.execute(
            delete(UserPluginSecret).where(UserPluginSecret.plugin_name == row.plugin_name)
        )
        await session.execute(
            delete(UserPluginConfig).where(UserPluginConfig.plugin_name == row.plugin_name)
        )
        await session.delete(row)
        removed.append(row.plugin_name)
    await session.flush()
    return removed
