"""Plugin manifest: the contract an external analyzer package must satisfy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MANIFEST_NAME = "plugin.json"
SUPPORTED_API_VERSIONS = frozenset({1})

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,47}$")
_VERSION_RE = re.compile(r"^\d{1,4}(\.\d{1,4}){0,3}([-+][0-9A-Za-z.-]{1,32})?$")
_ENTRYPOINT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63})*"
    r":[A-Za-z_][A-Za-z0-9_]{0,63}$"
)


class ManifestError(ValueError):
    """Raised when a manifest is missing, malformed or claims an unknown contract."""


@dataclass(frozen=True)
class PluginManifest:
    """A validated `plugin.json`.

    `name` is the plugin identifier and the folder it is installed under;
    `entrypoint` is `module:ClassName`, resolved relative to the plugin folder.
    """

    name: str
    version: str
    api_version: int
    entrypoint: str
    label: str
    description: str
    author: str
    homepage: str

    @property
    def module_name(self) -> str:
        return self.entrypoint.split(":", 1)[0]

    @property
    def class_name(self) -> str:
        return self.entrypoint.split(":", 1)[1]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "api_version": self.api_version,
            "entrypoint": self.entrypoint,
            "label": self.label,
            "description": self.description,
            "author": self.author,
            "homepage": self.homepage,
        }


def _require_string(data: dict[str, Any], key: str, *, maximum: int, required: bool = True) -> str:
    value = data.get(key)
    if value is None:
        if required:
            raise ManifestError(f"{MANIFEST_NAME} is missing the required field '{key}'.")
        return ""
    if not isinstance(value, str):
        raise ManifestError(f"{MANIFEST_NAME} field '{key}' must be a string.")
    value = value.strip()
    if required and not value:
        raise ManifestError(f"{MANIFEST_NAME} field '{key}' must not be empty.")
    if len(value) > maximum:
        raise ManifestError(f"{MANIFEST_NAME} field '{key}' exceeds {maximum} characters.")
    return value


def parse_manifest(payload: str | bytes) -> PluginManifest:
    """Validate a manifest document and return it, or raise ManifestError."""
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ManifestError(f"{MANIFEST_NAME} is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{MANIFEST_NAME} must contain a JSON object.")

    api_version = data.get("api_version")
    if not isinstance(api_version, int) or isinstance(api_version, bool):
        raise ManifestError(f"{MANIFEST_NAME} field 'api_version' must be an integer.")
    if api_version not in SUPPORTED_API_VERSIONS:
        supported = ", ".join(str(entry) for entry in sorted(SUPPORTED_API_VERSIONS))
        raise ManifestError(
            f"Plugin API version {api_version} is not supported by this XenoProxy "
            f"(supported: {supported})."
        )

    name = _require_string(data, "name", maximum=48)
    if not _NAME_RE.match(name):
        raise ManifestError(
            "Plugin 'name' must be lowercase letters, digits and underscores, "
            "3 to 48 characters, starting with a letter."
        )

    version = _require_string(data, "version", maximum=40)
    if not _VERSION_RE.match(version):
        raise ManifestError("Plugin 'version' must look like 1.0.0.")

    entrypoint = _require_string(data, "entrypoint", maximum=160)
    if not _ENTRYPOINT_RE.match(entrypoint):
        raise ManifestError("Plugin 'entrypoint' must be written as 'module:ClassName'.")

    return PluginManifest(
        name=name,
        version=version,
        api_version=api_version,
        entrypoint=entrypoint,
        label=_require_string(data, "label", maximum=80, required=False) or name,
        description=_require_string(data, "description", maximum=400, required=False),
        author=_require_string(data, "author", maximum=120, required=False),
        homepage=_require_string(data, "homepage", maximum=300, required=False),
    )


def read_manifest(plugin_dir: Path) -> PluginManifest:
    path = plugin_dir / MANIFEST_NAME
    if not path.is_file():
        raise ManifestError(f"{plugin_dir.name} has no {MANIFEST_NAME}.")
    return parse_manifest(path.read_bytes())
