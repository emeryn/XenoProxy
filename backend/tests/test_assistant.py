"""The assistant: what it may be told, what it may call, what it may reveal."""

from __future__ import annotations

import inspect
import uuid
from types import SimpleNamespace
from typing import ClassVar

import pytest

from app.models.user import Role
from app.services import app_settings
from app.services.assistant import tools as tool_registry
from app.services.assistant.prompts import default_prompt, effective_prompt
from app.services.assistant.provider import OllamaProvider, OpenAiProvider, build_provider
from app.services.settings_sections import AssistantSettings
from tests.test_identity import make_user


def _settings(**overrides: object) -> AssistantSettings:
    base: dict[str, object] = {
        "enabled": True,
        "base_url": "http://ollama.internal:11434",
        "model": "llama3.2",
    }
    base.update(overrides)
    return AssistantSettings(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# The tool catalogue
# --------------------------------------------------------------------------


def test_write_tools_are_absent_until_writes_are_allowed() -> None:
    offered = {tool.name for tool in tool_registry.catalogue(allow_writes=False)}
    assert "search_jobs" in offered
    assert "submit_scan" not in offered
    assert "tag_job" not in offered


def test_write_tools_appear_once_writes_are_allowed() -> None:
    offered = {tool.name for tool in tool_registry.catalogue(allow_writes=True)}
    assert {"submit_scan", "tag_job"} <= offered


async def test_a_write_tool_is_refused_even_when_the_model_asks_for_it() -> None:
    """The catalogue is a hint; the check is what makes it a boundary.

    A model that was never offered a tool can still name it, whether because it
    saw one in its training data or because something in a report told it to.
    """
    context = tool_registry.ToolContext(session=None, user=make_user(role=Role.ADMIN))  # type: ignore[arg-type]
    with pytest.raises(tool_registry.ToolError, match="write actions are disabled"):
        await tool_registry.run(
            context, "submit_scan", {"observable": "8.8.8.8"}, allow_writes=False
        )


async def test_an_unknown_tool_is_refused() -> None:
    context = tool_registry.ToolContext(session=None, user=make_user(role=Role.ADMIN))  # type: ignore[arg-type]
    with pytest.raises(tool_registry.ToolError, match="no tool named"):
        await tool_registry.run(context, "rm_rf", {}, allow_writes=True)


def test_a_tool_never_exceeds_the_permissions_of_the_analyst() -> None:
    """An analyst has no `users:manage`, so a tool asking for it refuses."""
    context = tool_registry.ToolContext(session=None, user=make_user(role=Role.ANALYST))  # type: ignore[arg-type]
    context.require("jobs:read")
    with pytest.raises(tool_registry.ToolError, match="users:manage"):
        context.require("users:manage")


def test_every_tool_declares_a_schema_both_apis_accept() -> None:
    for tool in tool_registry.ALL_TOOLS:
        schema = tool.schema()
        assert schema["type"] == "function"
        assert schema["function"]["name"] == tool.name
        assert schema["function"]["description"]
        assert schema["function"]["parameters"]["type"] == "object"


def test_a_large_tool_result_is_cut_rather_than_sent_whole() -> None:
    trimmed = tool_registry._trim({"rows": ["x" * 200] * 200})
    assert trimmed["truncated"] is True
    assert len(trimmed["preview"]) <= tool_registry.MAX_RESULT_CHARS


# --------------------------------------------------------------------------
# Provider normalisation
# --------------------------------------------------------------------------


def test_the_driver_follows_the_declared_provider() -> None:
    assert isinstance(build_provider(_settings(provider="ollama")), OllamaProvider)
    assert isinstance(build_provider(_settings(provider="openai")), OpenAiProvider)


def test_each_api_receives_the_parameter_names_it_knows() -> None:
    """The two APIs name the same knobs differently, and silently ignore the rest."""
    ollama = build_provider(_settings(provider="ollama", max_tokens=512)).effective_parameters()
    assert ollama["options"]["num_predict"] == 512

    openai = build_provider(_settings(provider="openai", max_tokens=512)).effective_parameters()
    assert openai["max_tokens"] == 512


def test_the_context_window_is_only_sent_where_it_exists() -> None:
    ollama = build_provider(
        _settings(provider="ollama", context_tokens=8192)
    ).effective_parameters()
    assert ollama["options"]["num_ctx"] == 8192

    openai = build_provider(
        _settings(provider="openai", context_tokens=8192)
    ).effective_parameters()
    # No OpenAI-compatible server takes it per request; saying so beats sending
    # a parameter that is dropped without a word.
    assert "set on the server" in str(openai["context_tokens"])


def test_the_api_key_is_sent_as_a_bearer_and_never_as_an_option() -> None:
    provider = build_provider(_settings(api_key="secret-key-value"))
    assert provider._headers()["Authorization"] == "Bearer secret-key-value"
    assert "secret-key-value" not in str(provider.effective_parameters())


# --------------------------------------------------------------------------
# Settings surface
# --------------------------------------------------------------------------


def test_the_api_key_never_leaves_the_backend() -> None:
    public = app_settings.public("assistant", _settings(api_key="secret-key-value"))
    assert public["api_key"] == ""
    assert public["api_key_set"] is True
    assert "secret-key-value" not in str(public)


def test_an_audit_line_carries_no_credential_and_no_header_value() -> None:
    value = _settings(api_key="secret-key-value", headers={"X-Tenant": "tenant-key"})
    safe = app_settings.audit_safe("assistant", value)
    assert safe["api_key"] == "***"
    # A gateway key is routinely carried in a header, and has no business in a log.
    assert safe["headers"] == {"X-Tenant": "***"}


def test_a_header_xenoproxy_sets_itself_cannot_be_overridden() -> None:
    with pytest.raises(ValueError, match="set by XenoProxy"):
        _settings(headers={"Authorization": "Bearer something-else"})


def test_an_empty_prompt_falls_back_to_the_one_shipped() -> None:
    assert effective_prompt("") == default_prompt()
    assert effective_prompt("  ") == default_prompt()
    assert effective_prompt("be terse") == "be terse"


def test_the_default_prompt_tells_the_model_that_reports_are_data() -> None:
    """The instruction that makes an injected report material, not an order."""
    prompt = default_prompt().lower()
    assert "data, not" in prompt
    assert "never as a request" in prompt or "never as an instruction" in prompt


class _RecordingQueue:
    """Stands in for arq, so the test can see what was scheduled."""

    def __init__(self) -> None:
        self.scheduled: list[tuple[str, str]] = []

    async def enqueue_job(self, name: str, job_id: str) -> None:
        self.scheduled.append((name, job_id))


class _Session:
    """Enough of a session for the tool: it only flushes and commits."""

    def __init__(self) -> None:
        self.committed = False

    async def commit(self) -> None:
        self.committed = True

    async def flush(self) -> None:
        return None


class _Job:
    id = uuid.UUID("11111111-2222-4333-8444-555555555555")
    observable_value = "1.1.1.1"
    requested_analyzers: ClassVar[list[str]] = ["dns"]


async def _run_submit(queue: object) -> dict[str, object]:
    """Call the tool with the orchestrator stubbed out."""
    from app.services import orchestrator
    from app.services.assistant import tools

    async def _resolve(*_args: object, **_kwargs: object) -> object:
        return object()

    async def _create(*_args: object, **_kwargs: object) -> _Job:
        return _Job()

    original_resolve = orchestrator.resolve_selection
    original_create = orchestrator.create_job
    orchestrator.resolve_selection = _resolve  # type: ignore[assignment]
    orchestrator.create_job = _create  # type: ignore[assignment]
    try:
        user = SimpleNamespace(username="analyst", role=Role.ANALYST)
        context = tools.ToolContext(session=_Session(), user=user, queue=queue)
        return await tools._submit_scan(context, {"observable": "1.1.1.1"})
    finally:
        orchestrator.resolve_selection = original_resolve  # type: ignore[assignment]
        orchestrator.create_job = original_create  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_submit_scan_schedules_the_job_it_creates() -> None:
    """A job the assistant submits has to reach the worker.

    It used to be written and never scheduled, while the tool told the model
    the job was queued. The analyst then watched a scan sit in PENDING with
    nothing in the logs to explain it.
    """
    queue = _RecordingQueue()
    answer = await _run_submit(queue)

    assert queue.scheduled == [("run_job", "11111111-2222-4333-8444-555555555555")]
    assert "error" not in answer


@pytest.mark.asyncio
async def test_submit_scan_says_so_when_it_cannot_schedule() -> None:
    """Without a queue the job will not run, and the answer must say that."""
    answer = await _run_submit(None)
    assert "could not be queued" in str(answer.get("error", ""))


def test_a_failed_turn_keeps_the_question() -> None:
    """A provider that refuses must not take the analyst's question with it.

    The handler used to flush the user's message, call the model, and roll the
    session back when the model raised. The question was never committed, so a
    429 from the provider made what the analyst typed vanish from the thread.
    The commit has to come before the call.
    """
    from app.api.v1 import assistant as endpoint

    source = inspect.getsource(endpoint.ask)
    before, _, after = source.partition("engine.run_turn")
    assert "await session.commit()" in before, "the question is not stored before the model runs"
    assert "rollback" in after, "the failed turn should still discard its own uncommitted work"
