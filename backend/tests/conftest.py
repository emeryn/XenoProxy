"""Test fixtures."""

from __future__ import annotations

import base64
import os
import secrets

os.environ.setdefault("BACKEND_ENVIRONMENT", "development")
os.environ.setdefault(
    "BACKEND_MASTER_KEY", base64.b64encode(secrets.token_bytes(32)).decode("ascii")
)
os.environ.setdefault("BACKEND_SECRET_KEY", secrets.token_urlsafe(32))

import pytest

from app.plugins import load_all


@pytest.fixture(scope="session", autouse=True)
def _registry() -> None:
    load_all()
