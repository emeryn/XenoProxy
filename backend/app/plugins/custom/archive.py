"""Safe extraction of a plugin archive.

A plugin is operator-supplied code, so the archive itself is treated as hostile
input: path traversal, absolute paths, symlinks, zip bombs and unexpected file
types are refused before anything is written to disk.
"""

from __future__ import annotations

import hashlib
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from app.plugins.custom.manifest import MANIFEST_NAME, PluginManifest, parse_manifest

MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 300
MAX_COMPRESSION_RATIO = 120
ALLOWED_SUFFIXES = frozenset({".py", ".json", ".txt", ".md", ".cfg", ".ini", ".toml"})


class ArchiveError(ValueError):
    """Raised when an archive is unsafe or does not hold a usable plugin."""


@dataclass(frozen=True)
class ExtractedPlugin:
    manifest: PluginManifest
    directory: Path
    sha256: str
    file_count: int


def _normalise(member: zipfile.ZipInfo) -> PurePosixPath:
    """Return a safe relative path for an archive member, or raise."""
    raw = member.filename.replace("\\", "/")
    if raw.startswith("/") or ":" in raw.split("/")[0]:
        raise ArchiveError(f"absolute path in the archive: {member.filename}")
    path = PurePosixPath(raw)
    if any(part == ".." for part in path.parts):
        raise ArchiveError(f"path traversal in the archive: {member.filename}")
    # External attribute high bits carry the Unix mode; 0xA000 marks a symlink.
    if (member.external_attr >> 16) & 0xF000 == 0xA000:
        raise ArchiveError(f"symbolic link in the archive: {member.filename}")
    return path


def _strip_single_root(paths: list[PurePosixPath]) -> str | None:
    """Detect the common top folder GitHub-style archives wrap everything in."""
    roots = {path.parts[0] for path in paths if len(path.parts) > 1}
    top_level_files = [path for path in paths if len(path.parts) == 1]
    if len(roots) == 1 and not top_level_files:
        return next(iter(roots))
    return None


def inspect(archive_bytes: bytes) -> tuple[PluginManifest, zipfile.ZipFile, str | None]:
    """Validate the archive and return its manifest, the open zip and its root prefix."""
    if not archive_bytes:
        raise ArchiveError("the uploaded archive is empty")
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ArchiveError(f"the archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB")

    import io

    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise ArchiveError("the upload is not a valid zip archive") from exc

    members = [member for member in archive.infolist() if not member.is_dir()]
    if not members:
        raise ArchiveError("the archive contains no file")
    if len(members) > MAX_ENTRIES:
        raise ArchiveError(f"the archive contains more than {MAX_ENTRIES} files")

    total = 0
    paths: list[PurePosixPath] = []
    for member in members:
        path = _normalise(member)
        paths.append(path)
        total += member.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ArchiveError(
                f"the archive expands beyond {MAX_UNCOMPRESSED_BYTES // (1024 * 1024)} MiB"
            )
        if (
            member.compress_size > 0
            and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO
        ):
            raise ArchiveError(f"suspicious compression ratio for {member.filename}")
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            raise ArchiveError(
                f"file type not allowed in a plugin: {member.filename} "
                f"(allowed: {', '.join(sorted(ALLOWED_SUFFIXES))})"
            )

    root = _strip_single_root(paths)
    manifest_path = f"{root}/{MANIFEST_NAME}" if root else MANIFEST_NAME
    try:
        manifest_bytes = archive.read(manifest_path)
    except KeyError as exc:
        raise ArchiveError(
            f"the archive has no {MANIFEST_NAME} at its root "
            "(expected either at the top level or inside a single folder)"
        ) from exc

    manifest = parse_manifest(manifest_bytes)

    module_file = f"{manifest.module_name.replace('.', '/')}.py"
    expected = f"{root}/{module_file}" if root else module_file
    if expected not in {str(path) for path in paths}:
        raise ArchiveError(f"the entrypoint module '{module_file}' is missing from the archive")

    return manifest, archive, root


def extract(archive_bytes: bytes, plugins_root: Path) -> ExtractedPlugin:
    """Validate then write the plugin into `plugins_root/<name>`, replacing any previous copy."""
    manifest, archive, root = inspect(archive_bytes)
    destination = plugins_root / manifest.name
    staging = plugins_root / f".staging-{manifest.name}"

    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    written = 0
    try:
        for member in archive.infolist():
            if member.is_dir():
                continue
            path = _normalise(member)
            relative = PurePosixPath(*path.parts[1:]) if root else path
            if not relative.parts:
                continue
            target = staging / Path(*relative.parts)
            # Belt and braces: the resolved path must stay inside the staging folder.
            if not target.resolve().is_relative_to(staging.resolve()):
                raise ArchiveError(f"path escapes the plugin folder: {member.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
            target.chmod(0o640)
            written += 1

        if destination.exists():
            shutil.rmtree(destination)
        staging.rename(destination)
    finally:
        archive.close()
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    return ExtractedPlugin(
        manifest=manifest,
        directory=destination,
        sha256=hashlib.sha256(archive_bytes).hexdigest(),
        file_count=written,
    )
