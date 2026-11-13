"""Instance settings an administrator edits from the interface.

Each setting has a declared type, bounds and a default. A setting pinned by an
environment variable is reported as managed and cannot be changed from the
interface, so a headless deployment stays authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ValidationFailedError
from app.models.job import ScanMode, Tlp
from app.models.setting import InstanceSetting

SettingType = Literal["boolean", "integer", "string", "choice"]


@dataclass(frozen=True)
class SettingSpec:
    """Declaration of one editable setting."""

    key: str
    label: str
    help_text: str
    type: SettingType
    default: Any
    section: str
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    # Environment variable that pins this setting when it is present.
    env_name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "help_text": self.help_text,
            "type": self.type,
            "default": self.default,
            "section": self.section,
            "choices": list(self.choices),
            "minimum": self.minimum,
            "maximum": self.maximum,
        }


SPECS: tuple[SettingSpec, ...] = (
    # --- Security ---
    SettingSpec(
        key="require_mfa_for_all",
        label="Require two-factor authentication for everyone",
        help_text=(
            "Every local account must enrol an authenticator before it can use the platform. "
            "Administrators are always required, whatever this is set to."
        ),
        type="boolean",
        default=False,
        section="security",
        env_name="BACKEND_REQUIRE_MFA_FOR_ALL",
    ),
    SettingSpec(
        key="require_mfa_for_admins",
        label="Require two-factor authentication for administrators",
        help_text=(
            "Leave this on unless an identity provider already enforces it. An account that "
            "still owes an enrolment cannot reach this page, so the deployment can pin this "
            "with BACKEND_REQUIRE_MFA_FOR_ADMINS instead."
        ),
        type="boolean",
        default=True,
        section="security",
        env_name="BACKEND_REQUIRE_MFA_FOR_ADMINS",
    ),
    SettingSpec(
        key="force_password_change_at_first_login",
        label="Force a password change at first sign-in",
        help_text=(
            "Applies to a password the account holder did not choose: the first administrator, "
            "an account an administrator creates, and an administrator's password reset. Leave "
            "it off only where those passwords are delivered over a channel you trust."
        ),
        type="boolean",
        default=False,
        section="security",
    ),
    SettingSpec(
        key="allow_mfa_for_external_identities",
        label="Let accounts from the directory enrol an authenticator",
        help_text=(
            "An account authenticated by OpenID Connect, LDAP or a reverse proxy normally gets "
            "its second factor from that provider. Turn this on where the provider does not "
            "enforce one, so those accounts can enrol a TOTP authenticator in XenoProxy and the "
            "two-factor requirements apply to them as well."
        ),
        type="boolean",
        default=False,
        section="security",
    ),
    SettingSpec(
        key="session_idle_minutes",
        label="Sign out after inactivity (minutes)",
        help_text="An idle session is revoked after this long.",
        type="integer",
        default=60,
        minimum=5,
        maximum=1440,
        section="security",
        env_name="BACKEND_SESSION_IDLE_MINUTES",
    ),
    SettingSpec(
        key="session_absolute_hours",
        label="Maximum session lifetime (hours)",
        help_text="A session is revoked after this long whatever the activity.",
        type="integer",
        default=12,
        minimum=1,
        maximum=168,
        section="security",
        env_name="BACKEND_SESSION_ABSOLUTE_HOURS",
    ),
    SettingSpec(
        key="allow_private_targets",
        label="Allow scanning non-routable targets",
        help_text=(
            "Permits loopback, link-local and RFC1918 observables. Only turn this on for "
            "internal analyzers; it widens the server-side request forgery surface."
        ),
        type="boolean",
        default=False,
        section="security",
        env_name="BACKEND_ALLOW_PRIVATE_TARGETS",
    ),
    # --- Scanning ---
    SettingSpec(
        key="default_tlp",
        label="Default TLP for a new scan",
        help_text=(
            "AMBER keeps a job visible to the submitter's groups. GREEN also disables "
            "analyzers that publish or retain the observable. RED disables every external source."
        ),
        type="choice",
        default=Tlp.AMBER.value,
        choices=tuple(level.value for level in Tlp),
        section="scanning",
    ),
    SettingSpec(
        key="default_scan_mode",
        label="Default scan mode",
        help_text=(
            "Reuse recent serves an identical lookup from the cache and spares the API quota. "
            "Force new always queries the provider."
        ),
        type="choice",
        default=ScanMode.REUSE_RECENT.value,
        choices=tuple(mode.value for mode in ScanMode),
        section="scanning",
    ),
    SettingSpec(
        key="default_scan_check_minutes",
        label="Reuse a report younger than (minutes)",
        help_text="0 falls back to each analyzer's own cache lifetime.",
        type="integer",
        default=0,
        minimum=0,
        maximum=43200,
        section="scanning",
    ),
    SettingSpec(
        key="send_files_to_providers",
        label="Allow a submitted file to be sent to a provider",
        help_text=(
            "Off, a sample stays in this instance and only its hashes are ever sent out. "
            "A source that would submit the file itself — a sandbox — is refused rather than "
            "silently downgraded, so an analyst is told the detonation did not happen. "
            "Turn it on only where sending a potentially confidential file to a third party "
            "is acceptable."
        ),
        type="boolean",
        # The safe default for the kind of organisation that runs this: a file
        # under investigation may be confidential, and sending it out cannot
        # be taken back.
        default=False,
        section="scanning",
    ),
    SettingSpec(
        key="archive_passwords",
        label="Extra passwords tried on a submitted archive",
        help_text=(
            "Comma-separated, tried before the conventional ones (infected, malware, virus). "
            "A sample is normally shipped in an encrypted archive so nothing opens it by "
            "accident; XenoProxy opens it only to hash what is inside."
        ),
        type="string",
        default="",
        section="scanning",
    ),
    SettingSpec(
        key="auto_select_analyzers",
        label="Run every compatible source when none is chosen",
        help_text=(
            "A scan submitted without an analyzer or a playbook runs every source that is "
            "enabled, configured and allowed at the chosen TLP. This is what makes the "
            "default scan automatic."
        ),
        type="boolean",
        default=True,
        section="scanning",
    ),
    SettingSpec(
        key="analyzer_max_concurrency",
        label="Analyzers running at once per job",
        help_text="Higher finishes sooner and puts more load on the providers.",
        type="integer",
        default=8,
        minimum=1,
        maximum=32,
        section="scanning",
        env_name="BACKEND_ANALYZER_MAX_CONCURRENCY",
    ),
    SettingSpec(
        key="max_analyzers_per_job",
        label="Maximum analyzers in one job",
        help_text="A guard against a single submission fanning out without bound.",
        type="integer",
        default=40,
        minimum=1,
        maximum=100,
        section="scanning",
    ),
    SettingSpec(
        key="pivots_enabled",
        label="Let pivots create child jobs",
        help_text=(
            "A pivot derives the next observable from a finished job and analyses it "
            "automatically. Turning this off keeps pivots selectable but makes them report "
            "what they would have done without creating anything."
        ),
        type="boolean",
        default=True,
        section="scanning",
    ),
    SettingSpec(
        key="max_pivot_depth",
        label="Maximum pivot depth",
        help_text=(
            "How far a chain of pivots may go from the job an analyst submitted. 1 allows one "
            "generation of child jobs. This is what makes a pivot loop terminate."
        ),
        type="integer",
        default=2,
        minimum=0,
        maximum=5,
        section="scanning",
    ),
    SettingSpec(
        key="max_pivot_children_per_job",
        label="Maximum child jobs one job may create",
        help_text="Summed across every pivot of a job, whatever each pivot allows on its own.",
        type="integer",
        default=8,
        minimum=1,
        maximum=50,
        section="scanning",
    ),
    # --- Retention ---
    SettingSpec(
        key="job_retention_days",
        label="Delete jobs older than (days)",
        help_text="0 keeps them for ever. Applies to the shared history and its reports.",
        type="integer",
        default=0,
        minimum=0,
        maximum=3650,
        section="retention",
    ),
    SettingSpec(
        key="inactive_account_days",
        label="Disable an account unused for (days)",
        help_text="0 never disables an account automatically.",
        type="integer",
        default=0,
        minimum=0,
        maximum=3650,
        section="retention",
    ),
)

BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in SPECS}


def _coerce(spec: SettingSpec, value: Any) -> Any:
    """Validate a submitted value against its declaration."""
    if spec.type == "boolean":
        if not isinstance(value, bool):
            raise ValidationFailedError(f"'{spec.key}' must be true or false.")
        return value
    if spec.type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationFailedError(f"'{spec.key}' must be a whole number.")
        if spec.minimum is not None and value < spec.minimum:
            raise ValidationFailedError(f"'{spec.key}' must be at least {spec.minimum}.")
        if spec.maximum is not None and value > spec.maximum:
            raise ValidationFailedError(f"'{spec.key}' must be at most {spec.maximum}.")
        return value
    if spec.type == "choice":
        if value not in spec.choices:
            allowed = ", ".join(spec.choices)
            raise ValidationFailedError(f"'{spec.key}' must be one of: {allowed}.")
        return value
    if not isinstance(value, str) or len(value) > 512:
        raise ValidationFailedError(f"'{spec.key}' must be a string of at most 512 characters.")
    return value


def is_managed(spec: SettingSpec) -> bool:
    """A setting pinned by the environment is read-only in the interface."""
    if spec.env_name is None:
        return False
    return get_settings().managed_by_environment(spec.env_name.removeprefix("BACKEND_"))


def _environment_value(spec: SettingSpec) -> Any:
    """Read the pinned value straight from the loaded configuration."""
    settings = get_settings()
    attribute = (spec.env_name or "").removeprefix("BACKEND_").lower()
    return getattr(settings, attribute, spec.default)


async def load_all(session: AsyncSession) -> dict[str, Any]:
    """Return every setting's effective value."""
    rows = {row.key: row for row in (await session.execute(select(InstanceSetting))).scalars()}
    effective: dict[str, Any] = {}
    for spec in SPECS:
        if is_managed(spec):
            effective[spec.key] = _environment_value(spec)
            continue
        row = rows.get(spec.key)
        effective[spec.key] = row.value.get("value", spec.default) if row else spec.default
    return effective


async def get(session: AsyncSession, key: str) -> Any:
    return (await load_all(session)).get(key, BY_KEY[key].default if key in BY_KEY else None)


async def describe(session: AsyncSession) -> list[dict[str, Any]]:
    """Every setting with its value, declaration and whether it is pinned."""
    values = await load_all(session)
    rows = {row.key: row for row in (await session.execute(select(InstanceSetting))).scalars()}
    described: list[dict[str, Any]] = []
    for spec in SPECS:
        row = rows.get(spec.key)
        described.append(
            {
                **spec.as_dict(),
                "value": values[spec.key],
                "managed_by_environment": is_managed(spec),
                "environment_variable": spec.env_name,
                "updated_at": row.updated_at if row else None,
                "updated_by": row.updated_by if row else None,
            }
        )
    return described


async def update(session: AsyncSession, changes: dict[str, Any], *, actor: str) -> dict[str, Any]:
    """Validate and persist a batch of settings, returning what changed."""
    unknown = set(changes) - set(BY_KEY)
    if unknown:
        raise ValidationFailedError(f"Unknown setting(s): {', '.join(sorted(unknown))}.")

    applied: dict[str, Any] = {}
    for key, raw in changes.items():
        spec = BY_KEY[key]
        if is_managed(spec):
            raise ValidationFailedError(
                f"'{key}' is pinned by {spec.env_name} and cannot be changed here."
            )
        value = _coerce(spec, raw)
        row = (
            await session.execute(select(InstanceSetting).where(InstanceSetting.key == key))
        ).scalar_one_or_none()
        if row is None:
            row = InstanceSetting(key=key, value={"value": value})
            session.add(row)
        else:
            row.value = {"value": value}
        row.updated_by = actor
        applied[key] = value

    await session.flush()
    return applied
