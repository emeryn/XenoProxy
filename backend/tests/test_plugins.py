"""Plugin manifest validation, archive safety and loading."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from app.plugins.base.registry import registry
from app.plugins.custom import archive, loader
from app.plugins.custom.archive import ArchiveError
from app.plugins.custom.manifest import ManifestError, parse_manifest

VALID_MANIFEST = {
    "api_version": 1,
    "name": "demo_source",
    "version": "1.0.0",
    "label": "Demo Source",
    "description": "A demo analyzer.",
    "entrypoint": "analyzer:DemoSourceAnalyzer",
}

ANALYZER_SOURCE = '''
from typing import Any, ClassVar

from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary
from app.models.job import ObservableType, Verdict
from app.services.observables import Observable


class DemoSourceAnalyzer(BaseAnalyzer):
    """A plugin analyzer that answers without any network call."""

    name = "demo_source"
    label = "Demo Source"
    description = "A demo analyzer."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)

    async def run(self, observable: Observable) -> PluginResult:
        return self.ok(
            {"echo": observable.value},
            PluginSummary(verdict=Verdict.CLEAN, headline="Demo answered."),
        )
'''


def build_archive(files: dict[str, str | bytes], *, root: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for name, content in files.items():
            path = f"{root}/{name}" if root else name
            zip_file.writestr(path, content)
    return buffer.getvalue()


def valid_archive(root: str | None = None, manifest: dict | None = None) -> bytes:
    return build_archive(
        {
            "plugin.json": json.dumps(manifest or VALID_MANIFEST),
            "analyzer.py": ANALYZER_SOURCE,
        },
        root=root,
    )


# --- manifest ---------------------------------------------------------------


def test_a_valid_manifest_parses() -> None:
    manifest = parse_manifest(json.dumps(VALID_MANIFEST))
    assert manifest.name == "demo_source"
    assert manifest.module_name == "analyzer"
    assert manifest.class_name == "DemoSourceAnalyzer"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_version", 99),
        ("name", "Bad Name"),
        ("name", "x"),
        ("version", "not-a-version"),
        ("entrypoint", "analyzer"),
        ("entrypoint", "../escape:Class"),
    ],
)
def test_invalid_manifest_fields_are_refused(field: str, value: object) -> None:
    payload = {**VALID_MANIFEST, field: value}
    with pytest.raises(ManifestError):
        parse_manifest(json.dumps(payload))


def test_a_missing_required_field_is_refused() -> None:
    payload = {key: value for key, value in VALID_MANIFEST.items() if key != "entrypoint"}
    with pytest.raises(ManifestError):
        parse_manifest(json.dumps(payload))


def test_malformed_json_is_refused() -> None:
    with pytest.raises(ManifestError):
        parse_manifest("{not json")


# --- archive safety ---------------------------------------------------------


def test_a_well_formed_archive_is_accepted() -> None:
    manifest, zip_file, root = archive.inspect(valid_archive())
    zip_file.close()
    assert manifest.name == "demo_source"
    assert root is None


def test_a_single_root_folder_is_detected() -> None:
    manifest, zip_file, root = archive.inspect(valid_archive(root="demo_source-main"))
    zip_file.close()
    assert manifest.name == "demo_source"
    assert root == "demo_source-main"


def test_path_traversal_is_refused() -> None:
    payload = build_archive(
        {
            "plugin.json": json.dumps(VALID_MANIFEST),
            "analyzer.py": ANALYZER_SOURCE,
            "../../etc/passwd": "root:x:0:0",
        }
    )
    with pytest.raises(ArchiveError, match="traversal"):
        archive.inspect(payload)


def test_an_unexpected_file_type_is_refused() -> None:
    payload = build_archive(
        {
            "plugin.json": json.dumps(VALID_MANIFEST),
            "analyzer.py": ANALYZER_SOURCE,
            "payload.so": b"\x7fELF",
        }
    )
    with pytest.raises(ArchiveError, match="file type not allowed"):
        archive.inspect(payload)


def test_a_zip_bomb_is_refused() -> None:
    payload = build_archive(
        {
            "plugin.json": json.dumps(VALID_MANIFEST),
            "analyzer.py": ANALYZER_SOURCE,
            "big.txt": "A" * (archive.MAX_UNCOMPRESSED_BYTES + 1),
        }
    )
    with pytest.raises(ArchiveError):
        archive.inspect(payload)


def test_an_archive_without_a_manifest_is_refused() -> None:
    with pytest.raises(ArchiveError, match=r"plugin\.json"):
        archive.inspect(build_archive({"analyzer.py": ANALYZER_SOURCE}))


def test_a_missing_entrypoint_module_is_refused() -> None:
    payload = build_archive({"plugin.json": json.dumps(VALID_MANIFEST)})
    with pytest.raises(ArchiveError, match="entrypoint module"):
        archive.inspect(payload)


def test_a_non_zip_upload_is_refused() -> None:
    with pytest.raises(ArchiveError, match="valid zip"):
        archive.inspect(b"this is not a zip file")


def test_an_empty_upload_is_refused() -> None:
    with pytest.raises(ArchiveError, match="empty"):
        archive.inspect(b"")


# --- extraction and loading -------------------------------------------------


def test_extract_then_load_registers_the_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "plugins_root", lambda: tmp_path)
    registry.pop("demo_source", None)
    try:
        installed = archive.extract(valid_archive(), tmp_path)
        assert installed.directory == tmp_path / "demo_source"
        assert (installed.directory / "analyzer.py").is_file()
        assert len(installed.sha256) == 64

        entry = loader.load_plugin(installed.directory)
        assert entry.loaded, entry.error
        assert entry.plugin_name == "demo_source"

        analyzer_class = registry["demo_source"]
        assert analyzer_class.is_custom is True
        assert analyzer_class.plugin_version == "1.0.0"
    finally:
        loader.unload_plugin("demo_source")
        registry.pop("demo_source", None)


def test_a_plugin_cannot_shadow_a_builtin_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "plugins_root", lambda: tmp_path)
    manifest = {**VALID_MANIFEST, "name": "shodan", "entrypoint": "analyzer:DemoSourceAnalyzer"}
    directory = tmp_path / "shodan"
    directory.mkdir()
    (directory / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
    (directory / "analyzer.py").write_text(ANALYZER_SOURCE, encoding="utf-8")

    entry = loader.load_plugin(directory)
    assert not entry.loaded
    assert "built-in" in (entry.error or "")


def test_a_folder_name_mismatch_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "plugins_root", lambda: tmp_path)
    directory = tmp_path / "wrong_folder"
    directory.mkdir()
    (directory / "plugin.json").write_text(json.dumps(VALID_MANIFEST), encoding="utf-8")
    (directory / "analyzer.py").write_text(ANALYZER_SOURCE, encoding="utf-8")

    entry = loader.load_plugin(directory)
    assert not entry.loaded
    assert "must match" in (entry.error or "")


def test_a_plugin_that_raises_on_import_is_reported_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "plugins_root", lambda: tmp_path)
    directory = tmp_path / "demo_source"
    directory.mkdir()
    (directory / "plugin.json").write_text(json.dumps(VALID_MANIFEST), encoding="utf-8")
    (directory / "analyzer.py").write_text("raise RuntimeError('boom')", encoding="utf-8")

    entry = loader.load_plugin(directory)
    assert not entry.loaded
    assert "boom" in (entry.error or "")
    assert "demo_source" not in registry


def test_a_class_that_is_not_an_analyzer_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "plugins_root", lambda: tmp_path)
    directory = tmp_path / "demo_source"
    directory.mkdir()
    (directory / "plugin.json").write_text(json.dumps(VALID_MANIFEST), encoding="utf-8")
    (directory / "analyzer.py").write_text(
        "class DemoSourceAnalyzer:\n    pass\n", encoding="utf-8"
    )

    entry = loader.load_plugin(directory)
    assert not entry.loaded
    assert "BaseAnalyzer" in (entry.error or "")


def test_sync_forgets_a_removed_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil

    monkeypatch.setattr(loader, "plugins_root", lambda: tmp_path)
    registry.pop("demo_source", None)
    try:
        archive.extract(valid_archive(), tmp_path)
        state = loader.sync()
        assert any(plugin.name == "demo_source" and plugin.loaded for plugin in state.plugins)
        assert "demo_source" in registry

        shutil.rmtree(tmp_path / "demo_source")
        state = loader.sync()
        assert not state.plugins
        assert "demo_source" not in registry
    finally:
        loader.unload_plugin("demo_source")
        registry.pop("demo_source", None)
