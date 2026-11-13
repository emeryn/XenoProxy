"""Turning the groups a provider reports into XenoProxy groups and a role."""

from __future__ import annotations

from app.services.group_mapping import normalise


def test_a_distinguished_name_reads_as_its_group_name() -> None:
    """A directory reports a DN; an administrator maps the name they know."""
    assert normalise("cn=soc-leads,ou=groups,dc=example,dc=com") == "soc-leads"
    assert normalise("CN=SOC-Leads,OU=Groups,DC=example,DC=com") == "soc-leads"


def test_comparison_ignores_case_and_surrounding_space() -> None:
    """A directory writes `Analysts`, an OIDC claim writes `analysts`."""
    assert normalise("  Analysts ") == "analysts"
    assert normalise("ANALYSTS") == normalise("analysts")


def test_a_plain_name_is_left_alone() -> None:
    assert normalise("soc_admins") == "soc_admins"
    # A single `=` without a comma is not a DN, so nothing is stripped.
    assert normalise("team=blue") == "team=blue"
