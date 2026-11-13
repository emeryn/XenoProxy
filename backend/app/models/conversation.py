"""Assistant conversations and their messages.

A conversation belongs to exactly one analyst. There is no sharing and no
organisation-wide view: a conversation quotes job content the analyst was
allowed to see at the time, and the TLP of a job can restrict who that is, so
the safe rule is that nobody reads somebody else's thread.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class MessageRole(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    # The result of a tool the model asked for, fed back into the next turn.
    TOOL = "tool"


class Conversation(Base):
    __tablename__ = "assistant_conversations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), default="")
    # The job the conversation was opened from, when it was opened from one.
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    messages: Mapped[list[Message]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="Message.created_at",
    )


class Message(Base):
    __tablename__ = "assistant_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assistant_conversations.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[MessageRole] = mapped_column(
        Enum(MessageRole, name="message_role"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, default="")
    # What the model asked to run this turn, and which tool answered.
    tool_calls: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    tool_name: Mapped[str | None] = mapped_column(String(64))
    # Steps the agent took to produce this answer, shown as a trace in the UI.
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    conversation: Mapped[Conversation] = relationship(back_populates="messages")


Index("ix_conversations_user", Conversation.user_id, Conversation.updated_at.desc())
Index("ix_messages_conversation", Message.conversation_id, Message.created_at)
