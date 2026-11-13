"""Operator-installed plugins, loaded from the plugins volume."""

from app.plugins.custom.archive import ArchiveError, ExtractedPlugin, extract, inspect
from app.plugins.custom.loader import (
    LoadedPlugin,
    PluginState,
    current_state,
    discover,
    plugins_root,
    sync,
    unload_plugin,
)
from app.plugins.custom.manifest import MANIFEST_NAME, ManifestError, PluginManifest

__all__ = [
    "MANIFEST_NAME",
    "ArchiveError",
    "ExtractedPlugin",
    "LoadedPlugin",
    "ManifestError",
    "PluginManifest",
    "PluginState",
    "current_state",
    "discover",
    "extract",
    "inspect",
    "plugins_root",
    "sync",
    "unload_plugin",
]
