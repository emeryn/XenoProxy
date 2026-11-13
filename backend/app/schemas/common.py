"""Shared request and response models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base model refusing unknown fields, which blocks mass assignment."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Page[T](BaseModel):
    """One page of a server-side paginated list."""

    items: list[T]
    total: int
    page: int
    page_size: int


class MessageResponse(BaseModel):
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
