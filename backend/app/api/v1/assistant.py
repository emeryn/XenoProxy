"""The assistant: conversations, one turn, and the streamed variant."""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import StreamingResponse
from pydantic import Field

from app.api.deps import DbSession, client_ip, require
from app.models.conversation import MessageRole
from app.models.user import User
from app.schemas.common import MessageResponse, StrictModel
from app.services import audit
from app.services.assistant import engine, profiles, touched
from app.services.assistant.provider import ProviderError, build_provider

router = APIRouter(prefix="/assistant", tags=["assistant"])

AssistantUser = Annotated[User, Depends(require("jobs:read"))]


class ConversationCreate(StrictModel):
    job_id: uuid.UUID | None = None
    title: str = Field(default="", max_length=200)


class Ask(StrictModel):
    message: str = Field(min_length=1, max_length=8000)


def _conversation_view(conversation: Any, *, with_messages: bool = False) -> dict[str, Any]:
    view: dict[str, Any] = {
        "id": str(conversation.id),
        "title": conversation.title or "New conversation",
        "job_id": str(conversation.job_id) if conversation.job_id else None,
        "created_at": conversation.created_at,
        "updated_at": conversation.updated_at,
    }
    if with_messages:
        view["messages"] = [
            {
                "id": str(message.id),
                "role": message.role.value,
                "content": message.content,
                "steps": message.steps or [],
                "created_at": message.created_at,
            }
            for message in conversation.messages
            # A tool result is a working note of the agent; the trace on the
            # answer already shows it, and repeating it as a bubble is noise.
            if message.role is not MessageRole.TOOL
        ]
        # What the conversation has actually looked at, so twenty exchanges in
        # the analyst can still see which observables it covered.
        view["observables"] = touched.from_messages(list(conversation.messages))
    return view


@router.get("", response_model=dict, summary="Whether the assistant is available to you")
async def assistant_status(session: DbSession, user: AssistantUser) -> dict[str, Any]:
    """Drives the interface: whether to offer the panel, and with what."""
    settings = await profiles.effective_settings(session)
    try:
        engine.ensure_allowed(settings, user)
        available, reason = True, ""
    except Exception as exc:
        available, reason = False, str(exc)

    parameters: dict[str, Any] = {}
    if settings.configured:
        parameters = build_provider(settings).effective_parameters()

    return {
        "available": available,
        "reason": reason,
        "enabled": settings.enabled,
        "configured": settings.configured,
        "model": settings.model,
        "provider": settings.provider,
        "agent_enabled": settings.agent_enabled,
        "allow_writes": settings.allow_writes,
        "max_steps": settings.max_steps,
        "effective_parameters": parameters,
    }


@router.get("/conversations", response_model=list, summary="Your conversations")
async def list_conversations(session: DbSession, user: AssistantUser) -> list[dict[str, Any]]:
    settings = await profiles.effective_settings(session)
    engine.ensure_allowed(settings, user)
    return [
        _conversation_view(conversation)
        for conversation in await engine.list_conversations(session, user)
    ]


@router.post(
    "/conversations",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Open a conversation",
)
async def create_conversation(
    payload: ConversationCreate, session: DbSession, user: AssistantUser
) -> dict[str, Any]:
    settings = await profiles.effective_settings(session)
    engine.ensure_allowed(settings, user)
    conversation = await engine.create_conversation(
        session, user, job_id=payload.job_id, title=payload.title
    )
    await session.commit()
    return _conversation_view(conversation, with_messages=True)


@router.get("/conversations/{conversation_id}", response_model=dict, summary="Read a conversation")
async def read_conversation(
    conversation_id: uuid.UUID, session: DbSession, user: AssistantUser
) -> dict[str, Any]:
    settings = await profiles.effective_settings(session)
    engine.ensure_allowed(settings, user)
    conversation = await engine.get_conversation(session, user, conversation_id)
    view = _conversation_view(conversation, with_messages=True)
    # The transcript holds what a tool answered when it ran; a scan submitted
    # from the chat is PENDING in it forever. Reading the jobs back is what
    # makes the panel show where the investigation stands now.
    #
    # Re-reading needs no visibility check of its own: a conversation belongs
    # to one analyst, and the only job identifiers in it are ones that
    # analyst's own tools were allowed to return.
    view["observables"] = await touched.refresh(session, view["observables"])
    return view


@router.delete(
    "/conversations/{conversation_id}",
    response_model=MessageResponse,
    summary="Delete a conversation",
)
async def delete_conversation(
    conversation_id: uuid.UUID, session: DbSession, user: AssistantUser
) -> MessageResponse:
    await engine.delete_conversation(session, user, conversation_id)
    await session.commit()
    return MessageResponse(message="The conversation has been deleted.")


@router.post(
    "/conversations/{conversation_id}/ask", response_model=dict, summary="Ask the assistant"
)
async def ask(
    conversation_id: uuid.UUID,
    payload: Ask,
    request: Request,
    session: DbSession,
    user: AssistantUser,
) -> dict[str, Any]:
    """One full turn, tools included when agent mode is on."""
    settings = await profiles.effective_settings(session)
    engine.ensure_allowed(settings, user)
    engine.check_rate(settings, user)

    conversation = await engine.get_conversation(session, user, conversation_id)
    await engine.record(session, conversation, role=MessageRole.USER, content=payload.message)
    if not conversation.title:
        conversation.title = engine.title_from(payload.message)
    # Committed before the model is called. The question is the analyst's, not
    # the model's: a provider that answers 429 must not make what they typed
    # disappear from the conversation. It used to be rolled back with the
    # failed turn, so a refused answer took the question with it.
    await session.commit()
    await session.refresh(conversation, ["messages"])

    try:
        result = await engine.run_turn(
            session, user, conversation, settings, queue=request.app.state.queue
        )
    except ProviderError as exc:
        # Only whatever the failed turn left uncommitted is discarded; the
        # question above is already stored.
        await session.rollback()
        return {"error": str(exc)}

    answer = await engine.record(
        session,
        conversation,
        role=MessageRole.ASSISTANT,
        content=result.content,
        steps=result.steps,
    )
    if result.steps:
        # A tool that changed something is worth an audit line of its own: the
        # model asked for it, but the analyst's name is on it.
        await audit.record(
            session,
            action="assistant.tools",
            actor=user.username,
            actor_id=user.id,
            target=str(conversation.id),
            ip_address=client_ip(request),
            details={"tools": [step["tool"] for step in result.steps]},
        )
    await session.commit()

    return {
        "id": str(answer.id),
        "role": "assistant",
        "content": answer.content,
        "steps": answer.steps,
        "created_at": answer.created_at,
    }


@router.post("/conversations/{conversation_id}/stream", summary="Ask the assistant, streamed")
async def ask_streamed(
    conversation_id: uuid.UUID,
    payload: Ask,
    request: Request,
    session: DbSession,
    user: AssistantUser,
) -> StreamingResponse:
    """The same turn, delivered as it is generated.

    Agent mode is not streamed: its steps have to run before there is an answer
    worth showing. The interface falls back to `ask` when the agent is on.
    """
    settings = await profiles.effective_settings(session)
    engine.ensure_allowed(settings, user)
    engine.check_rate(settings, user)

    conversation = await engine.get_conversation(session, user, conversation_id)
    await engine.record(session, conversation, role=MessageRole.USER, content=payload.message)
    if not conversation.title:
        conversation.title = engine.title_from(payload.message)
    await session.flush()
    await session.refresh(conversation, ["messages"])
    await session.commit()

    factory = request.app.state.session_factory

    async def stream() -> Any:
        pieces: list[str] = []
        try:
            async for piece in engine.stream_turn(session, user, conversation, settings):
                pieces.append(piece)
                yield f"event: token\ndata: {json.dumps({'text': piece})}\n\n"
        except Exception as exc:
            yield f"event: error\ndata: {json.dumps({'message': str(exc)})}\n\n"

        # The answer is stored in its own session: the request's session is
        # finished by the time the generator drains.
        answer = "".join(pieces)
        if answer:
            async with factory() as writer:
                stored = await writer.get(type(conversation), conversation.id)
                if stored is not None:
                    await engine.record(writer, stored, role=MessageRole.ASSISTANT, content=answer)
                    await writer.commit()
        yield f"event: done\ndata: {json.dumps({'length': len(answer)})}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            # Nginx buffers by default, which makes a stream arrive all at once.
            "X-Accel-Buffering": "no",
        },
    )
