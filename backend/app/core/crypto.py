"""Envelope encryption for secrets at rest, password hashing and token digests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

KEY_VERSION = 1

# These two strings are HKDF `info` parameters, not labels. They are part of
# the key derivation, so every byte of them decides which key comes out. They
# still read `argus` because the product was renamed after data existed under
# them: changing either one would derive different keys, and every sealed
# credential in the database would stop decrypting while every blind index
# would stop matching its column.
#
# To change them, bump KEY_VERSION, derive under both, and rewrite the stored
# rows. Do not simply rename them.
_WRAP_INFO = b"argus/dek/v1"
_INDEX_INFO = b"argus/blind-index/v1"

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


class CryptoError(RuntimeError):
    """Raised when a payload cannot be decrypted with the configured master key."""


@dataclass(frozen=True)
class SealedSecret:
    """An AES-256-GCM sealed value with its wrapped data encryption key."""

    ciphertext: str
    wrapped_key: str
    key_version: int


def _master_key() -> bytes:
    raw = get_settings().master_key
    if not raw:
        raise CryptoError("master key is not configured")
    try:
        key = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError):
        key = hashlib.sha256(raw.encode("utf-8")).digest()
    if len(key) != 32:
        key = hashlib.sha256(key).digest()
    return key


def _derive(info: bytes) -> bytes:
    return hmac.new(_master_key(), info, hashlib.sha256).digest()


def seal(plaintext: str) -> SealedSecret:
    """Encrypt a value with a fresh data key wrapped by the master key."""
    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)
    wrap_nonce = secrets.token_bytes(12)
    wrapped = AESGCM(_derive(_WRAP_INFO)).encrypt(wrap_nonce, dek, None)
    return SealedSecret(
        ciphertext=base64.b64encode(nonce + ciphertext).decode("ascii"),
        wrapped_key=base64.b64encode(wrap_nonce + wrapped).decode("ascii"),
        key_version=KEY_VERSION,
    )


def unseal(sealed: SealedSecret) -> str:
    """Decrypt a sealed value. Raises CryptoError when the master key no longer matches."""
    try:
        wrapped_blob = base64.b64decode(sealed.wrapped_key)
        dek = AESGCM(_derive(_WRAP_INFO)).decrypt(wrapped_blob[:12], wrapped_blob[12:], None)
        blob = base64.b64decode(sealed.ciphertext)
        return AESGCM(dek).decrypt(blob[:12], blob[12:], None).decode("utf-8")
    except Exception as exc:
        raise CryptoError("unable to decrypt secret with the current master key") from exc


def blind_index(value: str) -> str:
    """Deterministic searchable index over a value, keyed by the master key."""
    return hmac.new(_derive(_INDEX_INFO), value.lower().encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(hashed: str, password: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
