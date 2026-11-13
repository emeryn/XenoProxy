"""Discovery and loading of operator-installed plugins from the plugins directory.

A plugin is a folder holding a `plugin.json` manifest and at least the module
its entrypoint names. Loading imports that module and registers the plugin class
it exposes, exactly as a built-in plugin is registered — so a custom plugin may
be an analyzer, a connector or a pivot, and its type comes from the class it
declares rather than from the manifest.

A plugin runs inside the backend with the backend's privileges. It is operator-
supplied code, not sandboxed code: installing one is as consequential as
installing a Python package, which is why it is admin-only and audited. What
does constrain it is the container itself, which has no shell, is read-only and
refuses process creation.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.job import PluginKind
from app.plugins.base.plugin import BasePlugin
from app.plugins.base.registry import describe, registry
from app.plugins.custom.manifest import ManifestError, PluginManifest, read_manifest

logger = get_logger(__name__)

MODULE_PREFIX = "xenoproxy_plugin_"


@dataclass
class LoadedPlugin:
    """A plugin folder and what came out of loading it."""

    name: str
    directory: Path
    manifest: PluginManifest | None = None
    plugin_name: str | None = None
    loaded: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "loaded": self.loaded,
            "error": self.error,
            "plugin_name": self.plugin_name,
            "manifest": self.manifest.as_dict() if self.manifest else None,
        }
        if self.plugin_name and self.plugin_name in registry:
            payload["plugin"] = describe(registry[self.plugin_name])
        return payload


@dataclass
class PluginState:
    """Everything the API needs to report about the plugin directory."""

    directory: str
    enabled: bool
    plugins: list[LoadedPlugin] = field(default_factory=list)


_state: dict[str, LoadedPlugin] = {}


def plugins_root() -> Path:
    return Path(get_settings().plugins_dir)


def _import_plugin(directory: Path, manifest: PluginManifest) -> type[BasePlugin]:
    """Import the entrypoint module from the plugin folder and return its class."""
    module_relative = Path(*manifest.module_name.split(".")).with_suffix(".py")
    module_path = directory / module_relative
    if not module_path.is_file():
        raise ManifestError(f"entrypoint module '{module_relative}' is missing")

    module_name = f"{MODULE_PREFIX}{manifest.name}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ManifestError(f"'{module_relative}' could not be loaded as a Python module")

    module = importlib.util.module_from_spec(spec)
    # Registered before execution so a dataclass or a decorator inside the module
    # can resolve its own module by name.
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise

    candidate = getattr(module, manifest.class_name, None)
    if candidate is None:
        raise ManifestError(f"class '{manifest.class_name}' is not defined in {module_relative}")
    if not (isinstance(candidate, type) and issubclass(candidate, BasePlugin)):
        raise ManifestError(
            f"'{manifest.class_name}' does not inherit from BaseAnalyzer, "
            "BaseConnector or BasePivot"
        )
    if getattr(candidate, "name", "") != manifest.name:
        raise ManifestError(
            f"the plugin declares name '{getattr(candidate, 'name', '')}' "
            f"but the manifest declares '{manifest.name}'; they must match"
        )

    plugin_type = getattr(candidate, "plugin_type", None)
    if not isinstance(plugin_type, PluginKind):
        raise ManifestError("the plugin declares no plugin_type")
    # The same declaration checks the built-in registry applies, enforced here
    # too so a bad custom plugin fails at load with a readable reason rather
    # than inside a job.
    if plugin_type is PluginKind.ANALYZER and not candidate.supported_types:
        raise ManifestError("the analyzer declares no supported_types")
    if plugin_type is PluginKind.PIVOT and not getattr(candidate, "child_playbook", ""):
        raise ManifestError("the pivot declares no child_playbook")
    return candidate


def load_plugin(directory: Path) -> LoadedPlugin:
    """Load one plugin folder, never raising: failures are reported, not thrown."""
    entry = LoadedPlugin(name=directory.name, directory=directory)
    try:
        manifest = read_manifest(directory)
        entry.manifest = manifest
        if manifest.name != directory.name:
            raise ManifestError(
                f"the folder is named '{directory.name}' but the manifest declares "
                f"'{manifest.name}'; they must match"
            )

        existing = registry.get(manifest.name)
        if existing is not None and not getattr(existing, "is_custom", False):
            raise ManifestError(
                f"'{manifest.name}' is the name of a built-in plugin and cannot be replaced"
            )

        plugin_class = _import_plugin(directory, manifest)
        plugin_class.is_custom = True  # type: ignore[attr-defined]
        plugin_class.plugin_version = manifest.version  # type: ignore[attr-defined]
        registry[manifest.name] = plugin_class

        entry.plugin_name = manifest.name
        entry.loaded = True
        logger.info(
            "plugin_loaded",
            plugin=manifest.name,
            plugin_type=plugin_class.plugin_type.value,
            version=manifest.version,
        )
    except Exception as exc:
        entry.error = f"{type(exc).__name__}: {exc}"[:500]
        logger.warning("plugin_load_failed", plugin=directory.name, error=entry.error)
    return entry


def unload_plugin(name: str) -> None:
    """Drop a plugin from the registry and from the module table."""
    entry = _state.pop(name, None)
    plugin_name = entry.plugin_name if entry else name
    if plugin_name and getattr(registry.get(plugin_name), "is_custom", False):
        registry.pop(plugin_name, None)
    sys.modules.pop(f"{MODULE_PREFIX}{name}", None)
    logger.info("plugin_unloaded", plugin=name)


def discover() -> list[Path]:
    """List candidate plugin folders, ignoring staging and hidden entries."""
    root = plugins_root()
    if not root.is_dir():
        return []
    return sorted(
        path for path in root.iterdir() if path.is_dir() and not path.name.startswith((".", "_"))
    )


def sync() -> PluginState:
    """Load every plugin folder not already loaded, and forget the ones removed.

    Safe to call repeatedly. A plugin whose code changed on disk keeps the module
    already imported: picking the new code up needs a service restart, which the
    admin interface says plainly.
    """
    settings = get_settings()
    root = plugins_root()
    state = PluginState(directory=str(root), enabled=settings.plugins_enabled)
    if not settings.plugins_enabled:
        return state

    found = {path.name: path for path in discover()}

    for name in list(_state):
        if name not in found:
            unload_plugin(name)

    for name, path in found.items():
        existing = _state.get(name)
        if existing is None or not existing.loaded:
            _state[name] = load_plugin(path)

    state.plugins = [_state[name] for name in sorted(_state)]
    return state


def current_state() -> PluginState:
    settings = get_settings()
    return PluginState(
        directory=str(plugins_root()),
        enabled=settings.plugins_enabled,
        plugins=[_state[name] for name in sorted(_state)],
    )
