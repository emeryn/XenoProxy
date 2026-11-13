"""Declarative plugin registry.

Plugin classes register themselves with the `@register` decorator at import
time; `app.plugins.load_all()` imports the packages so the registry is complete
in both the API process and the worker process.

The registry is the single source of truth for a plugin's type. It is read from
the class declaration, never inferred from the module path, so moving a file
cannot silently change how a plugin is scheduled.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from app.core.errors import NotFoundError
from app.models.job import ObservableType
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.connector import BaseConnector
from app.plugins.base.pivot import BasePivot
from app.plugins.base.plugin import BasePlugin, PluginType

registry: dict[str, type[BasePlugin]] = {}

_EXPECTED_BASE: dict[PluginType, type[BasePlugin]] = {
    PluginType.ANALYZER: BaseAnalyzer,
    PluginType.CONNECTOR: BaseConnector,
    PluginType.PIVOT: BasePivot,
}


def register[T: type[BasePlugin]](cls: T) -> T:
    """Register a plugin class under its declared name.

    Every check here is a mistake that would otherwise surface as a confusing
    runtime failure inside a job: a nameless plugin, two plugins fighting over
    one name, a declared type that does not match the base class, or an analyzer
    that never says which observables it reads.
    """
    name = getattr(cls, "name", "")
    if not name:
        raise ValueError(f"{cls.__name__} must declare a name")
    if name in registry and registry[name] is not cls:
        raise ValueError(f"plugin name '{name}' is already registered")

    plugin_type = getattr(cls, "plugin_type", None)
    if not isinstance(plugin_type, PluginType):
        raise ValueError(f"{cls.__name__} must declare a plugin_type")

    expected = _EXPECTED_BASE[plugin_type]
    if not issubclass(cls, expected):
        raise ValueError(
            f"{cls.__name__} declares plugin_type '{plugin_type.value}' "
            f"but does not inherit from {expected.__name__}"
        )

    if plugin_type is PluginType.ANALYZER and not cls.supported_types:
        raise ValueError(f"{cls.__name__} must declare supported_types")

    if plugin_type is PluginType.PIVOT and not getattr(cls, "child_playbook", ""):
        raise ValueError(f"{cls.__name__} must declare the playbook its child jobs run")

    registry[name] = cls
    return cls


def get_plugin(name: str) -> type[BasePlugin]:
    try:
        return registry[name]
    except KeyError as exc:
        raise NotFoundError(f"Unknown plugin '{name}'.", code="PLUGIN_NOT_FOUND") from exc


def get_typed(name: str, plugin_type: PluginType) -> type[BasePlugin]:
    """Look a plugin up and refuse it when it is not of the expected type."""
    cls = get_plugin(name)
    if cls.plugin_type is not plugin_type:
        raise NotFoundError(
            f"Plugin '{name}' is a {cls.plugin_type.value}, not a {plugin_type.value}.",
            code="PLUGIN_WRONG_TYPE",
        )
    return cls


def get_analyzer(name: str) -> type[BaseAnalyzer]:
    cls = get_typed(name, PluginType.ANALYZER)
    assert issubclass(cls, BaseAnalyzer)
    return cls


def get_connector(name: str) -> type[BaseConnector]:
    cls = get_typed(name, PluginType.CONNECTOR)
    assert issubclass(cls, BaseConnector)
    return cls


def get_pivot(name: str) -> type[BasePivot]:
    cls = get_typed(name, PluginType.PIVOT)
    assert issubclass(cls, BasePivot)
    return cls


def iter_plugins(plugin_type: PluginType | None = None) -> Iterator[type[BasePlugin]]:
    """Yield every registered plugin, optionally of one type, ordered by name."""
    for cls in sorted(registry.values(), key=lambda entry: entry.name):
        if plugin_type is None or cls.plugin_type is plugin_type:
            yield cls


def iter_analyzers() -> Iterator[type[BasePlugin]]:
    yield from iter_plugins(PluginType.ANALYZER)


def analyzers_for(observable_type: ObservableType) -> list[type[BasePlugin]]:
    """Every analyzer that reads this observable type."""
    return [cls for cls in iter_plugins(PluginType.ANALYZER) if cls.supports(observable_type)]


def describe(cls: type[BasePlugin]) -> dict[str, Any]:
    """Serialise a plugin's declaration for the API and the UI."""
    payload: dict[str, Any] = {
        "name": cls.name,
        "label": cls.label,
        "description": cls.description,
        "plugin_type": cls.plugin_type.value,
        "supported_types": [entry.value for entry in cls.supported_types],
        "secrets": [
            {
                "name": spec.name,
                "label": spec.label,
                "required": spec.required,
                "help_text": spec.help_text,
                "placeholder": spec.placeholder,
                "user_overridable": spec.user_overridable,
            }
            for spec in cls.secrets
        ],
        "options_schema": cls.options_schema,
        "default_timeout": cls.default_timeout,
        "default_cache_ttl": cls.default_cache_ttl,
        "documentation_url": cls.documentation_url,
        "free_tier": cls.free_tier,
        "max_tlp": cls.max_tlp.value,
        "is_custom": cls.is_custom,
        "plugin_version": cls.plugin_version,
        "requires_network": cls.requires_network,
        "provider": cls.provider.as_dict(),
    }

    if issubclass(cls, BaseConnector):
        payload["run_on_verdicts"] = [entry.value for entry in cls.run_on_verdicts]
        payload["run_on_partial_failure"] = cls.run_on_partial_failure
    if issubclass(cls, BasePivot):
        payload["run_on_verdicts"] = [entry.value for entry in cls.run_on_verdicts]
        payload["child_playbook"] = cls.child_playbook
        payload["max_children"] = cls.max_children

    return payload
