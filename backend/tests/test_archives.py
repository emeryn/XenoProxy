"""Reading a sample out of the archive it was shipped in.

The archive comes from whoever is under investigation, so these pin the
refusals as much as the successes: a bomb, a nested archive and a wrong
password must each fail in a way that says what happened.
"""

from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
import pyzipper

from app.services import archives


def _plain_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as handle:
        for name, payload in entries.items():
            handle.writestr(name, payload)
    return buffer.getvalue()


def _encrypted_zip(entries: dict[str, bytes], password: str) -> bytes:
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as handle:
        handle.setpassword(password.encode())
        for name, payload in entries.items():
            handle.writestr(name, payload)
    return buffer.getvalue()


def test_a_plain_archive_yields_the_hash_of_what_is_inside() -> None:
    payload = b"the sample bytes"
    blob = _plain_zip({"evil.exe": payload})

    contents = archives.inspect(blob)

    assert contents.encrypted is False
    assert len(contents.entries) == 1
    assert contents.entries[0].sha256 == hashlib.sha256(payload).hexdigest()
    assert contents.entries[0].size == len(payload)


def test_the_conventional_password_is_tried_without_being_given() -> None:
    """A sample is shipped under `infected` by convention."""
    payload = b"the sample bytes"
    blob = _encrypted_zip({"evil.exe": payload}, "infected")

    contents = archives.inspect(blob)

    assert contents.encrypted is True
    assert contents.password_used == "infected"
    assert contents.entries[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_a_supplied_password_is_tried_before_the_conventions() -> None:
    blob = _encrypted_zip({"evil.exe": b"x"}, "team-secret")
    contents = archives.inspect(blob, passwords=["team-secret"])
    assert contents.password_used == "team-secret"


def test_an_archive_no_password_opens_is_refused_with_a_reason() -> None:
    blob = _encrypted_zip({"evil.exe": b"x"}, "nobody-guesses-this")

    with pytest.raises(archives.ArchiveError) as caught:
        archives.inspect(blob)

    assert "encrypted" in str(caught.value).lower()


def test_a_decompression_bomb_is_refused_on_its_ratio() -> None:
    """A bomb is small on disk; only the expansion ratio catches it early."""
    blob = _plain_zip({"bomb.bin": b"\0" * (4 * 1024 * 1024)})

    with pytest.raises(archives.ArchiveError) as caught:
        archives.inspect(blob)

    assert "bomb" in str(caught.value).lower()


def test_a_nested_archive_is_reported_rather_than_opened() -> None:
    """Nesting is how a bomb gets past a check that looks at one layer."""
    inner = _plain_zip({"deep.bin": b"x"})
    blob = _plain_zip({"inner.zip": inner, "note.txt": b"readme"})

    contents = archives.inspect(blob)

    assert [entry.name for entry in contents.entries] == ["note.txt"]
    assert any("inner.zip" in line for line in contents.skipped)


def test_an_entry_name_is_kept_for_display_only() -> None:
    """A traversal attempt in a name cannot matter: no name opens anything."""
    blob = _plain_zip({"../../etc/passwd": b"root:x:0:0"})

    contents = archives.inspect(blob)

    assert contents.entries[0].name.endswith("etc/passwd")
    assert contents.entries[0].sha256 == hashlib.sha256(b"root:x:0:0").hexdigest()


def test_bytes_that_are_not_an_archive_are_not_treated_as_one() -> None:
    assert archives.looks_like_archive(b"MZ\x90\x00this is a binary") is False
    assert archives.looks_like_archive(_plain_zip({"a": b"b"})) is True
