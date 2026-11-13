"""First-boot provisioning: plugin configurations, built-in playbooks, admin."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.models.group import Group
from app.models.playbook import Playbook
from app.models.user import User
from app.plugins import load_all
from app.plugins.base.registry import iter_plugins
from app.repositories import plugin_configs
from app.services.auth import ensure_bootstrap_admin

logger = get_logger(__name__)

# A playbook names the plugins of each phase. Connectors and pivots are left
# empty on the built-ins on purpose: a stock playbook must never publish an
# observable to a third party, nor create extra jobs, without an administrator
# having chosen that. The two pivot playbooks below are the exception, and they
# are shipped disabled.
BUILTIN_PLAYBOOKS: tuple[dict[str, Any], ...] = (
    {
        "name": "Fast IP triage",
        "description": "Reputation, exposure and geolocation for an IP address.",
        "observable_types": ["ip"],
        "analyzers": [
            "abuseipdb",
            "shodan_internetdb",
            "ripestat",
            "dnsbl",
            "tor_exit",
            "virustotal",
            "ipinfo",
            "greynoise",
            "crowdsec",
        ],
    },
    {
        "name": "IP deep dive",
        "description": "Everything available on an IP address, including threat feeds.",
        "observable_types": ["ip"],
        "analyzers": [
            "abuseipdb",
            "shodan",
            "censys",
            "virustotal",
            "onyphe",
            "ipinfo",
            "feodotracker",
            "threatfox",
            "dns",
            "rdap",
            "shodan_internetdb",
            "ripestat",
            "dnsbl",
            "tor_exit",
            "greynoise",
            "crowdsec",
            "pulsedive",
            "passivetotal",
            "circl_passivedns",
            "circl_passivessl",
        ],
    },
    {
        "name": "Domain reconnaissance",
        "description": "Registration, DNS, certificates and reputation for a domain.",
        "observable_types": ["domain", "url"],
        "analyzers": [
            "dns",
            "rdap",
            "crtsh",
            "virustotal",
            "urlscan",
            "censys",
            "threatfox",
            "shodan_internetdb",
            "ipinfo",
            "securitytrails",
            "passivetotal",
            "circl_passivedns",
            "google_safebrowsing",
            "pulsedive",
        ],
    },
    {
        "name": "URL triage",
        "description": "Reputation and page analysis for a single URL.",
        "observable_types": ["url"],
        "analyzers": [
            "virustotal",
            "urlscan",
            "urlhaus",
            "threatfox",
            "shodan_internetdb",
            "ipinfo",
            "google_safebrowsing",
            "pulsedive",
        ],
    },
    {
        "name": "Hash triage",
        "description": "Known-good filtering first, then malware intelligence.",
        "observable_types": ["hash"],
        "analyzers": [
            "circl_hashlookup",
            "virustotal",
            "malwarebazaar",
            "threatfox",
            "hybridanalysis",
            "anyrun",
        ],
    },
    {
        "name": "Free sources only",
        "description": "Every source that needs no paid quota.",
        "observable_types": ["ip", "domain", "url", "hash"],
        "analyzers": [
            "dns",
            "rdap",
            "ipinfo",
            "feodotracker",
            "urlhaus",
            "threatfox",
            "circl_hashlookup",
            "urlscan",
            "shodan_internetdb",
            "ripestat",
            "crtsh",
            "tor_exit",
            "dnsbl",
        ],
    },
    {
        "name": "Domain investigation with pivots",
        "description": (
            "Domain reconnaissance that follows a bad verdict down to the hosting "
            "addresses. Enable it once you are comfortable with jobs creating jobs."
        ),
        "observable_types": ["domain"],
        "analyzers": ["dns", "rdap", "crtsh", "virustotal", "urlscan", "threatfox"],
        "pivots": ["domain_to_ip"],
        "enabled": False,
    },
    {
        "name": "URL investigation with pivots",
        "description": (
            "URL triage that follows a bad verdict to the domain and the hosting address."
        ),
        "observable_types": ["url"],
        "analyzers": ["virustotal", "urlscan", "urlhaus", "threatfox"],
        "pivots": ["url_to_domain", "url_to_ip"],
        "enabled": False,
    },
)

# Plugins that need no credential are enabled on first boot so a fresh
# deployment can run a real analysis before any key is configured. Connectors
# and pivots are never in this set: both act beyond the single analysis an
# analyst asked for, so they stay off until somebody turns them on.
ENABLED_BY_DEFAULT = frozenset(
    {
        "dns",
        "rdap",
        "ipinfo",
        "feodotracker",
        "urlscan",
        "shodan_internetdb",
        "ripestat",
        "crtsh",
        "tor_exit",
        "dnsbl",
    }
)


DEFAULT_GROUP_NAME = "Analysts"


async def _ensure_default_group(session: AsyncSession) -> Group:
    """Every deployment has one default group, so shared history works at once."""
    group = (
        await session.execute(select(Group).where(Group.name == DEFAULT_GROUP_NAME))
    ).scalar_one_or_none()
    if group is None:
        group = Group(
            name=DEFAULT_GROUP_NAME,
            description="Everyone in the team. Jobs are shared inside this group.",
            is_default=True,
        )
        session.add(group)
        await session.flush()
    return group


async def provision(session: AsyncSession) -> None:
    """Idempotent first-boot provisioning, run at API startup."""
    load_all()
    await _ensure_default_group(session)

    known_names: set[str] = set()
    for cls in iter_plugins():
        known_names.add(cls.name)
        config = await plugin_configs.ensure(session, cls)
        # The class declaration is the authority until an administrator
        # changes the row. `bootstrap` counts as untouched: a plugin enabled on
        # first boot is still carrying its declared cap, and a release that
        # tightens or relaxes one has to reach it. Without this a cap set on
        # the very first boot was frozen for the life of the deployment.
        if config.updated_by in (None, "bootstrap"):
            if config.max_tlp is not cls.max_tlp:
                logger.info(
                    "plugin_max_tlp_realigned",
                    plugin=cls.name,
                    was=config.max_tlp.value,
                    now=cls.max_tlp.value,
                )
            config.max_tlp = cls.max_tlp
            if cls.name in ENABLED_BY_DEFAULT:
                config.enabled = True
                config.updated_by = "bootstrap"

    for definition in BUILTIN_PLAYBOOKS:
        name = str(definition["name"])
        existing = (
            await session.execute(select(Playbook).where(Playbook.name == name))
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                Playbook(
                    name=name,
                    description=str(definition["description"]),
                    observable_types=list(definition["observable_types"]),
                    analyzers=list(definition.get("analyzers") or []),
                    connectors=list(definition.get("connectors") or []),
                    pivots=list(definition.get("pivots") or []),
                    is_builtin=True,
                    enabled=bool(definition.get("enabled", True)),
                )
            )

    # A plugin dropped from a release, or one failing to import, leaves its
    # configuration behind. Saying so is all that happens automatically: the row
    # may hold a sealed credential, so removing it is an explicit operator
    # action (`docker compose run --rm api prune-plugins`).
    stale = await plugin_configs.orphans(session, known_names)
    if stale:
        logger.warning(
            "orphaned_plugin_configs",
            plugins=sorted(row.plugin_name for row in stale),
            hint="run the prune-plugins command to delete them and their credentials",
        )

    await ensure_bootstrap_admin(session)

    # Any account without a group joins the defaults, which also covers accounts
    # created before groups existed.
    users = (await session.execute(select(User).options(selectinload(User.groups)))).scalars()
    defaults = list(
        (await session.execute(select(Group).where(Group.is_default.is_(True)))).scalars()
    )
    for user in users:
        if not user.groups:
            user.groups = list(defaults)

    await session.commit()
    logger.info("provisioning_complete")
