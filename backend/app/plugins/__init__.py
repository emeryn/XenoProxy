"""Plugin packages.

`load_all()` imports every built-in plugin module so that the registry is
identical in the API process and in the worker process, then syncs the
operator-installed plugins from the plugins volume.
"""

from __future__ import annotations

import importlib
import pkgutil

from app.plugins.base.registry import registry

# One package per plugin type. A plugin's type comes from its class
# declaration, not from this list; the list only says where to look.
_PACKAGES = (
    "app.plugins.analyzer",
    "app.plugins.connector",
    "app.plugins.pivot",
)
_loaded = False


def load_all() -> dict[str, type]:
    """Import the built-in plugins once, then sync the plugins folder.

    The sync runs on every call because a custom plugin can be installed while
    the service is up; it only imports folders it has not imported yet.
    """
    global _loaded
    if not _loaded:
        for package_name in _PACKAGES:
            package = importlib.import_module(package_name)
            for module in pkgutil.iter_modules(package.__path__):
                importlib.import_module(f"{package_name}.{module.name}")
        _loaded = True

    from app.plugins.custom import sync

    sync()
    return dict(registry)
