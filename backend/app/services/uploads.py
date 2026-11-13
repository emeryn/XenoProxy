"""Storage for samples an analyst submits for analysis.

A hash is an identifier, not a sample. An analyst who already has the file
wants it analysed — sent to a sandbox, looked up by its digest, kept with the
job — and retyping a digest is not that.

Files are stored content-addressed under their SHA-256, which deduplicates the
same sample submitted twice and makes the path independent of whatever the
uploader called it.

**These bytes are untrusted and are frequently malware. That is the point.**
So there is no extension allowlist and no magic-byte filter: refusing a `.exe`
would refuse exactly what the feature exists for. Containment is what makes
that safe instead of reckless:

- Nothing ever executes them. The runtime image has no shell and an in-process
  seccomp filter denies process creation.
- Nothing ever serves them back. There is no download route, so a stored sample
  cannot be turned into a delivery vector through the browser.
- The name on disk is the digest, never the submitted filename, so a traversal
  attempt in the name cannot reach outside the directory.
- The submitted name is kept as metadata only, and only for display.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.core.errors import ValidationFailedError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Shown to a reader, never used to build a path.
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


@dataclass(frozen=True)
class StoredSample:
    """A sample on disk, identified by its digest."""

    sha256: str
    size: int
    display_name: str
    path: str


def uploads_root() -> Path:
    return Path(get_settings().uploads_dir)


def safe_display_name(name: str | None) -> str:
    """The submitted name, reduced to something harmless to display."""
    candidate = (name or "").strip().replace("\\", "/").split("/")[-1]
    candidate = _UNSAFE_NAME.sub("_", candidate)[:200]
    return candidate or "sample.bin"


def store(payload: bytes, *, filename: str | None) -> StoredSample:
    """Write the sample under its digest and describe where it landed."""
    settings = get_settings()
    if not payload:
        raise ValidationFailedError("The uploaded file is empty.")
    if len(payload) > settings.max_upload_bytes:
        limit = settings.max_upload_bytes // (1024 * 1024)
        raise ValidationFailedError(f"The file exceeds the {limit} MiB upload limit.")

    digest = hashlib.sha256(payload).hexdigest()
    root = uploads_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValidationFailedError(f"The uploads directory {root} is not writable: {exc}") from exc

    # Two levels of fan-out: a flat directory of a hundred thousand samples is
    # slow to list and unpleasant to operate.
    target = root / digest[:2] / digest[2:4] / digest
    target.parent.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        # Written beside and moved into place, so a crash mid-write cannot
        # leave a truncated file under a digest that claims to describe it.
        temporary = target.with_suffix(".partial")
        temporary.write_bytes(payload)
        temporary.replace(target)
        logger.info("sample_stored", sha256=digest, size=len(payload))

    return StoredSample(
        sha256=digest,
        size=len(payload),
        display_name=safe_display_name(filename),
        path=str(target.relative_to(root)),
    )


def read(relative_path: str) -> bytes | None:
    """Read a stored sample back, for an analyzer that submits the file itself.

    The path is re-resolved against the root and checked to be inside it, so a
    row tampered with in the database cannot read an arbitrary file.
    """
    root = uploads_root().resolve()
    try:
        target = (root / relative_path).resolve()
    except (OSError, ValueError):
        return None
    if not target.is_file() or root not in target.parents:
        return None
    return target.read_bytes()
