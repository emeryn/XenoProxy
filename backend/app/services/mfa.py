"""Time-based one-time passwords and recovery codes.

The shared secret is sealed with the master key, as an analyzer credential is,
so a database dump does not let anyone mint codes. A code is accepted once: the
time step it belongs to is stored, and an earlier or equal step is refused, so
a code read over the user's shoulder cannot be replayed.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import CryptoError, SealedSecret, seal, token_fingerprint, unseal
from app.core.errors import ConflictError, ValidationFailedError
from app.core.logging import get_logger
from app.models.user import MfaRecoveryCode, User

logger = get_logger(__name__)

ISSUER = "XenoProxy"
TIME_STEP_SECONDS = 30
# One step of tolerance each way absorbs clock drift without widening the window
# enough to matter.
VALID_WINDOW = 1
RECOVERY_CODE_COUNT = 10


@dataclass(frozen=True)
class MfaEnrolment:
    """What the user needs to add the account to an authenticator."""

    secret: str
    otpauth_uri: str


def _normalise(code: str) -> str:
    return "".join(character for character in code if character.isalnum()).upper()


def generate_enrolment(user: User, *, issuer: str = ISSUER) -> MfaEnrolment:
    """Create a fresh secret and the otpauth URI the authenticator scans."""
    secret = pyotp.random_base32()
    label = quote(f"{issuer}:{user.username}", safe="")
    uri = (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits=6&period={TIME_STEP_SECONDS}"
    )
    return MfaEnrolment(secret=secret, otpauth_uri=uri)


def store_secret(user: User, secret: str) -> None:
    """Seal the pending secret on the user, leaving MFA disabled until confirmed."""
    sealed = seal(secret)
    user.mfa_secret_ciphertext = sealed.ciphertext
    user.mfa_secret_wrapped_key = sealed.wrapped_key
    user.mfa_secret_key_version = sealed.key_version
    user.mfa_confirmed_at = None
    user.mfa_last_counter = None


def read_secret(user: User) -> str | None:
    if not (user.mfa_secret_ciphertext and user.mfa_secret_wrapped_key):
        return None
    try:
        return unseal(
            SealedSecret(
                ciphertext=user.mfa_secret_ciphertext,
                wrapped_key=user.mfa_secret_wrapped_key,
                key_version=user.mfa_secret_key_version,
            )
        )
    except CryptoError:
        logger.error("mfa_secret_undecryptable", username=user.username)
        return None


def clear_secret(user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret_ciphertext = None
    user.mfa_secret_wrapped_key = None
    user.mfa_confirmed_at = None
    user.mfa_last_counter = None


def verify_code(user: User, code: str, *, at: float | None = None) -> bool:
    """Check a six-digit code and consume its time step."""
    secret = read_secret(user)
    if not secret:
        return False

    digits = "".join(character for character in code if character.isdigit())
    if len(digits) != 6:
        return False

    now = at if at is not None else time.time()
    totp = pyotp.TOTP(secret, interval=TIME_STEP_SECONDS)

    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        moment = now + offset * TIME_STEP_SECONDS
        if not secrets.compare_digest(totp.at(moment), digits):
            continue
        counter = int(moment // TIME_STEP_SECONDS)
        if user.mfa_last_counter is not None and counter <= user.mfa_last_counter:
            logger.warning("mfa_code_replayed", username=user.username)
            return False
        user.mfa_last_counter = counter
        return True
    return False


async def generate_recovery_codes(session: AsyncSession, user: User) -> list[str]:
    """Replace the recovery codes and return the plaintext, shown once."""
    existing = (
        await session.execute(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    ).scalars()
    for record in existing:
        await session.delete(record)

    codes: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}".upper()
        codes.append(raw)
        session.add(
            MfaRecoveryCode(
                id=uuid.uuid4(), user_id=user.id, code_hash=token_fingerprint(_normalise(raw))
            )
        )
    await session.flush()
    return codes


async def consume_recovery_code(session: AsyncSession, user: User, code: str) -> bool:
    """Spend a recovery code. Each one works exactly once."""
    digest = token_fingerprint(_normalise(code))
    record = (
        await session.execute(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user.id,
                MfaRecoveryCode.code_hash == digest,
                MfaRecoveryCode.used_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if record is None:
        return False
    record.used_at = datetime.now(UTC)
    await session.flush()
    logger.info("mfa_recovery_code_used", username=user.username)
    return True


async def remaining_recovery_codes(session: AsyncSession, user: User) -> int:
    rows = (
        await session.execute(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)
            )
        )
    ).scalars()
    return len(list(rows))


async def begin_enrolment(session: AsyncSession, user: User) -> MfaEnrolment:
    if user.mfa_enabled:
        raise ConflictError("Two-factor authentication is already enabled on this account.")
    enrolment = generate_enrolment(user)
    store_secret(user, enrolment.secret)
    await session.flush()
    return enrolment


async def confirm_enrolment(session: AsyncSession, user: User, code: str) -> list[str]:
    """Turn MFA on once the user proves the authenticator works."""
    if user.mfa_enabled:
        raise ConflictError("Two-factor authentication is already enabled on this account.")
    if read_secret(user) is None:
        raise ValidationFailedError("Start the enrolment before confirming it.")
    if not verify_code(user, code):
        raise ValidationFailedError("That code is not valid. Check the clock on your device.")

    user.mfa_enabled = True
    user.mfa_confirmed_at = datetime.now(UTC)
    await session.flush()
    return await generate_recovery_codes(session, user)


async def disable(session: AsyncSession, user: User) -> None:
    clear_secret(user)
    existing = (
        await session.execute(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    ).scalars()
    for record in existing:
        await session.delete(record)
    await session.flush()


@dataclass(frozen=True)
class MfaRequirement:
    """Whether this account must use two-factor, and why."""

    required: bool
    reason: str | None


async def requirement(session: AsyncSession, user: User) -> MfaRequirement:
    """Decide whether two-factor is mandatory for one user.

    Three things can make it mandatory: the instance setting, the user being an
    administrator while the admin setting is on, or any of their groups
    requiring it.
    """
    from app.models.user import AuthSource, Role
    from app.services import settings_store

    values = await settings_store.load_all(session)

    # An account authenticated by the identity provider normally gets its
    # second factor there, and XenoProxy would only be duplicating it. A deployment
    # whose provider does not enforce one turns this on instead.
    external = user.auth_source is not AuthSource.LOCAL
    if external and not bool(values["allow_mfa_for_external_identities"]):
        return MfaRequirement(False, None)
    if bool(values["require_mfa_for_all"]):
        return MfaRequirement(
            True, "This instance requires two-factor authentication for everyone."
        )
    if user.role is Role.ADMIN and bool(values["require_mfa_for_admins"]):
        return MfaRequirement(
            True, "This instance requires two-factor authentication for administrators."
        )
    for group in user.groups:
        if group.require_mfa:
            return MfaRequirement(
                True, f"The group '{group.name}' requires two-factor authentication."
            )
    return MfaRequirement(False, None)


async def enrolment_pending(session: AsyncSession, user: User) -> bool:
    """True when the account must use two-factor but has not enrolled yet."""
    if user.mfa_enabled:
        return False
    return (await requirement(session, user)).required
