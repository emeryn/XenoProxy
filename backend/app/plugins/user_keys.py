"""Shared wording for a credential an analyst may hold personally.

A provider whose quota is counted per account is a provider where an analyst
may want to spend their own rather than the team's. Saying so the same way on
every such credential is what makes the Settings page readable.
"""

from __future__ import annotations

USER_KEY_HELP = (
    "Each analyst may store their own key under Settings; it is used for their "
    "own jobs and falls back to this shared one otherwise."
)
