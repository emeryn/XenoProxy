"""The system prompts, kept as Markdown rather than written inline.

A prompt is text an administrator reads, edits and resets, so it lives in a file
beside the code instead of in a string literal. `default_prompt()` is what the
settings page shows next to the editable one, and what an empty setting falls
back to.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

PROMPT_DIR = Path(__file__).parent


@lru_cache(maxsize=4)
def _read(name: str) -> str:
    try:
        return (PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def default_prompt() -> str:
    """The assistant prompt shipped with the application."""
    return _read("assistant")


def effective_prompt(configured: str) -> str:
    """What is actually sent, given what the administrator set."""
    return configured.strip() or default_prompt()
