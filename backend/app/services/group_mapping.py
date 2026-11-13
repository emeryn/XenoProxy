"""Turning the groups a provider reports into XenoProxy groups and a role.

A directory is where memberships are managed, so XenoProxy reads them rather than
keeping a second copy. Each XenoProxy group lists the names it answers to upstream;
a sign-in matches the names the provider reported against those lists.

Two rules make the result predictable:

- **The provider is authoritative for a mapped account.** Every sign-in
  recomputes membership, so removing someone from a directory group removes
  them here at their next sign-in rather than leaving an orphan membership.
- **An unmapped sign-in still works.** When nothing matches, the account lands
  in the default groups as an analyst. A directory that has not been mapped yet
  must not lock everybody out.

The comparison is case-insensitive and ignores surrounding whitespace, because
a directory writes `Analysts`, an OIDC claim writes `analysts`, and nobody
should have to discover that difference from a failed sign-in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.group import Group
from app.models.user import Role

logger = get_logger(__name__)


def normalise(name: str) -> str:
    """How a group name is compared, whatever the provider writes.

    A directory often reports a full distinguished name; the first relative
    component is the group's own name, which is what an administrator maps.
    """
    cleaned = name.strip()
    if "=" in cleaned and "," in cleaned:
        head = cleaned.split(",", 1)[0]
        cleaned = head.split("=", 1)[1] if "=" in head else head
    return cleaned.strip().lower()


@dataclass(frozen=True)
class Resolution:
    """What a set of provider groups resolves to."""

    groups: list[Group] = field(default_factory=list)
    role: Role = Role.ANALYST
    # The provider names that matched nothing, so an administrator can see what
    # is missing from the mapping instead of guessing.
    unmatched: list[str] = field(default_factory=list)
    matched_by_default: bool = False

    def group_names(self) -> list[str]:
        return sorted(group.name for group in self.groups)


async def resolve(
    session: AsyncSession,
    provider_groups: list[str],
    *,
    fallback_admin: bool = False,
    source: str | None = None,
) -> Resolution:
    """Map provider group names onto XenoProxy groups and a role.

    `fallback_admin` is the legacy single-group setting (`BACKEND_OIDC_ADMIN_GROUP`).
    It still grants administration when it matches, so a deployment that
    configured it keeps working after the mapping is introduced.
    """
    all_groups = list((await session.execute(select(Group))).scalars())
    reported = {normalise(name) for name in provider_groups if name.strip()}

    matched: list[Group] = []
    consumed: set[str] = set()
    for group in all_groups:
        names = {normalise(name) for name in (group.external_names or []) if name.strip()}
        # A group's own name is always accepted as a mapping, so the obvious
        # case needs no configuration at all.
        names.add(normalise(group.name))
        overlap = names & reported
        if overlap:
            matched.append(group)
            consumed |= overlap

    # Stamp what actually matched. A group is only "from the directory" once a
    # sign-in has arrived through it, which is the honest thing to show.
    if source:
        stamped = datetime.now(UTC)
        for group in matched:
            group.matched_source = source
            group.matched_at = stamped

    role = Role.ADMIN if any(group.grants_admin for group in matched) else Role.ANALYST
    if role is Role.ANALYST and fallback_admin:
        role = Role.ADMIN

    by_default = False
    if not matched:
        matched = [group for group in all_groups if group.is_default]
        by_default = True

    unmatched = sorted(reported - consumed)
    if unmatched:
        logger.info("group_mapping_unmatched", names=unmatched[:20])

    return Resolution(groups=matched, role=role, unmatched=unmatched, matched_by_default=by_default)


async def preview(session: AsyncSession, provider_groups: list[str]) -> dict[str, object]:
    """What a sign-in reporting these groups would get.

    Offered to administrators because the alternative way to find out is to ask
    somebody to sign in, and a wrong mapping that grants administration is not
    something to discover that way.
    """
    resolution = await resolve(session, provider_groups)
    return {
        "reported": [normalise(name) for name in provider_groups if name.strip()],
        "groups": resolution.group_names(),
        "role": resolution.role.value,
        "unmatched": resolution.unmatched,
        "matched_by_default": resolution.matched_by_default,
        "note": (
            "Nothing matched, so the account would land in the default groups as an analyst."
            if resolution.matched_by_default
            else f"The account would be {resolution.role.value}."
        ),
    }
