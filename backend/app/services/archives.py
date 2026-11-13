"""Reading a sample out of the archive it was shipped in.

A malware sample almost never arrives bare. It arrives zipped with a password —
`infected` by convention — precisely so that nothing opens it by accident on
the way. An analyst who has to unzip it by hand before pasting a hash has
already done the dangerous part on their own machine.

So the archive is opened here, in the backend, and **only to hash what is
inside**. Nothing is extracted to disk, nothing is executed, and no entry name
is ever used as a path.

What makes that safe rather than reckless:

- **Nothing is written.** Entries are read into memory in bounded chunks and
  hashed as they stream. Path traversal in an entry name cannot matter when the
  name is never used to open anything.
- **Decompression is bounded twice**, by the total bytes read and by the ratio
  of output to input. A zip bomb is a few kilobytes that expands to terabytes;
  the ratio is what catches it, because the compressed size looks harmless.
- **Nesting is refused.** An archive inside an archive is not followed: it is
  the classic way to smuggle a bomb past a single-level check.
- **The password is tried, not guessed indefinitely.** A short list of the
  conventional ones, plus whatever the analyst supplied.

The hashes are what reach a provider afterwards, and whether the bytes
themselves ever leave is a separate decision — see the scanning settings.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass, field

import pyzipper

from app.core.logging import get_logger

logger = get_logger(__name__)

# The passwords a sample is conventionally shipped under. Tried in order,
# before anything the analyst supplied.
CONVENTIONAL_PASSWORDS = ("infected", "malware", "virus", "password")

# One entry may expand to this much, and no more.
MAX_ENTRY_BYTES = 256 * 1024 * 1024
# And no entry may expand by more than this multiple of its stored size. A zip
# bomb is small on disk and enormous once read, which is exactly what a byte
# limit alone misses until it has already done the work.
MAX_RATIO = 500
# Reading more than this many entries says more about the archive than about
# the sample in it.
MAX_ENTRIES = 50

_ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
# Extensions whose content is itself an archive. Not followed.
_NESTED = (".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar", ".cab")


class ArchiveError(RuntimeError):
    """The archive could not be read, with a reason worth showing an analyst."""


@dataclass(frozen=True)
class ArchiveEntry:
    """One file inside the archive, identified but never written out."""

    name: str
    size: int
    sha256: str
    md5: str
    sha1: str


@dataclass(frozen=True)
class ArchiveContents:
    """What an archive turned out to hold."""

    encrypted: bool
    password_used: str = ""
    entries: list[ArchiveEntry] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def looks_like_archive(payload: bytes) -> bool:
    """Whether these bytes start like a zip container."""
    return payload[:4] in _ARCHIVE_MAGIC


def _digest_entry(handle: zipfile.ZipFile, info: zipfile.ZipInfo) -> ArchiveEntry:
    """Hash one entry while it decompresses, refusing to read it all first."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()  # noqa: S324 - an identifier for lookups, not a security claim
    sha1 = hashlib.sha1()  # noqa: S324 - same
    total = 0
    stored = max(1, info.compress_size)

    with handle.open(info) as stream:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ENTRY_BYTES:
                raise ArchiveError(f"'{info.filename}' is larger than the extraction limit.")
            if total // stored > MAX_RATIO:
                raise ArchiveError(
                    f"'{info.filename}' expands more than {MAX_RATIO} times its stored size, "
                    "which is what a decompression bomb looks like."
                )
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    return ArchiveEntry(
        # Kept for display only. It is never joined to a path.
        name=info.filename[-200:],
        size=total,
        sha256=sha256.hexdigest(),
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
    )


def _open(payload: bytes, password: str | None) -> pyzipper.AESZipFile:
    handle = pyzipper.AESZipFile(io.BytesIO(payload))
    if password:
        handle.setpassword(password.encode())
    return handle


def inspect(payload: bytes, *, passwords: list[str] | None = None) -> ArchiveContents:
    """Identify what an archive holds, by hash, without extracting anything.

    Raises `ArchiveError` when the archive is unreadable, when no password
    opens it, or when an entry looks like a decompression bomb.
    """
    try:
        probe = _open(payload, None)
        infos = [info for info in probe.infolist() if not info.is_dir()][:MAX_ENTRIES]
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise ArchiveError(f"The archive could not be read: {exc}") from exc

    if not infos:
        raise ArchiveError("The archive holds no file.")

    encrypted = any(info.flag_bits & 0x1 for info in infos)
    candidates: list[str | None] = [None]
    if encrypted:
        # The supplied password first: an analyst who typed one knows better
        # than the convention.
        candidates = [*(passwords or []), *CONVENTIONAL_PASSWORDS]

    last_error = ""
    for candidate in candidates:
        entries: list[ArchiveEntry] = []
        skipped: list[str] = []
        try:
            handle = _open(payload, candidate)
            for info in infos:
                if info.filename.lower().endswith(_NESTED):
                    # Refused rather than followed: nesting is how a bomb gets
                    # past a check that only looks at the outer layer.
                    skipped.append(f"{info.filename[-120:]} (nested archive, not opened)")
                    continue
                entries.append(_digest_entry(handle, info))
        except ArchiveError:
            raise
        except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
            # A wrong password surfaces here; try the next candidate.
            last_error = str(exc)
            continue

        if entries or skipped:
            logger.info(
                "archive_inspected",
                entries=len(entries),
                skipped=len(skipped),
                encrypted=encrypted,
            )
            return ArchiveContents(
                encrypted=encrypted,
                password_used=candidate or "",
                entries=entries,
                skipped=skipped,
            )

    raise ArchiveError(
        "The archive is encrypted and none of the passwords opened it. "
        f"Tried {len(candidates)}. Last error: {last_error[:120]}"
        if encrypted
        else f"The archive could not be read: {last_error[:160]}"
    )
