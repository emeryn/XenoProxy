"""One interface, two drivers: Ollama and any OpenAI-compatible server.

The two APIs differ in their paths, in the names of their generation parameters
and in the shape of their errors. Normalising all three here is what lets the
rest of the assistant — the agent loop, the chat endpoint, the settings probe —
be written once.

Every call goes through the central HTTP client, so the outbound proxy, the
certificate authorities of the Network section, the timeouts and the SSRF
validation apply to the inference server exactly as they apply to a provider.
The browser never talks to the model.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from app.core import http_client
from app.core.logging import get_logger

logger = get_logger(__name__)

# A tool result can be large; past this the prompt is what breaks, not the call.
MAX_TOOL_RESULT_CHARS = 8000


class ProviderError(RuntimeError):
    """The inference server refused, failed or answered something unusable."""


@dataclass
class ToolCall:
    """A tool the model asked to run."""

    name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass
class Completion:
    """One answer from the model."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = ""


class BaseProvider:
    """What the assistant needs from an inference server."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self.base_url = str(settings.base_url).rstrip("/")
        self.model = str(settings.model)
        self.timeout = int(settings.timeout)

    # -- transport ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(dict(self.settings.headers or {}))
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        return headers

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = await http_client.post(
            self._url(path),
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
            # An inference server almost always lives on the internal network;
            # that is the whole point of running the model yourself.
            allow_private=True,
        )
        if not result.ok:
            raise ProviderError(self._error_message(result))
        if not isinstance(result.json_body, dict):
            raise ProviderError("the inference server returned no JSON object")
        return result.json_body

    def _error_message(self, result: http_client.HttpResult) -> str:
        """Normalise the error shapes of the two APIs into one sentence."""
        body = result.json_body
        detail = ""
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                detail = str(error.get("message") or "")
            elif isinstance(error, str):
                detail = error
        detail = detail or (result.text or "")[:300]
        return f"the inference server answered HTTP {result.status_code}: {detail}".strip()

    async def _stream(self, path: str, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """Open a streamed response and yield one parsed chunk at a time."""
        url = self._url(path)
        http_client.validate_destination(url, allow_private=True)
        client = http_client.stream_client(float(self.timeout), url)
        async with (
            client,
            client.stream("POST", url, json=payload, headers=self._headers()) as response,
        ):
            if response.status_code >= 400:
                body = (await response.aread()).decode("utf-8", "replace")[:300]
                raise ProviderError(
                    f"the inference server answered HTTP {response.status_code}: {body}"
                )
            async for line in response.aiter_lines():
                chunk = self._parse_stream_line(line)
                if chunk is not None:
                    yield chunk

    def _parse_stream_line(self, line: str) -> dict[str, Any] | None:
        raise NotImplementedError

    # -- capabilities ------------------------------------------------------

    async def list_models(self) -> list[str]:
        raise NotImplementedError

    async def chat(
        self, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]] | None = None
    ) -> Completion:
        raise NotImplementedError

    def chat_stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[str]:
        """Yield the answer as it is produced.

        Declared as a plain method returning an async iterator, not as a
        coroutine: every implementation is an async generator, and calling an
        `async def` that merely *returns* one has to be awaited first. Getting
        that wrong on the base class made `async for` over it fail with a
        message about coroutines that says nothing about the cause.
        """
        raise NotImplementedError

    def effective_parameters(self) -> dict[str, Any]:
        """What the chosen API will actually receive.

        Shown in the interface because a server silently ignores a parameter it
        does not support, and the two APIs do not name them the same way.
        """
        raise NotImplementedError


class OllamaProvider(BaseProvider):
    """Driver for Ollama: /api/tags, /api/chat."""

    def _options(self) -> dict[str, Any]:
        settings = self.settings
        options: dict[str, Any] = {
            "temperature": settings.temperature,
            "top_p": settings.top_p,
            "num_predict": settings.max_tokens,
        }
        if settings.context_tokens:
            options["num_ctx"] = settings.context_tokens
        if settings.stop:
            options["stop"] = list(settings.stop)
        return options

    def effective_parameters(self) -> dict[str, Any]:
        return {"model": self.model, "options": self._options()}

    async def list_models(self) -> list[str]:
        result = await http_client.get(
            self._url("/api/tags"),
            headers=self._headers(),
            timeout=self.timeout,
            allow_private=True,
        )
        if not result.ok:
            raise ProviderError(self._error_message(result))
        models = (result.json_body or {}).get("models") or []
        return sorted(str(entry.get("model") or entry.get("name") or "") for entry in models)

    async def chat(
        self, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]] | None = None
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": self._options(),
        }
        if tools:
            payload["tools"] = tools

        body = await self._post("/api/chat", payload)
        message = body.get("message") or {}
        calls = [
            ToolCall(
                name=str((call.get("function") or {}).get("name") or ""),
                arguments=_as_object((call.get("function") or {}).get("arguments")),
            )
            for call in (message.get("tool_calls") or [])
        ]
        return Completion(
            content=str(message.get("content") or ""),
            tool_calls=[call for call in calls if call.name],
            finish_reason=str(body.get("done_reason") or ""),
        )

    def _parse_stream_line(self, line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except ValueError:
            return None

    async def chat_stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": self._options(),
        }
        async for chunk in self._stream("/api/chat", payload):
            piece = str((chunk.get("message") or {}).get("content") or "")
            if piece:
                yield piece
            if chunk.get("done"):
                return


class OpenAiProvider(BaseProvider):
    """Driver for an OpenAI-compatible server: /v1/models, /v1/chat/completions."""

    def _generation(self) -> dict[str, Any]:
        settings = self.settings
        payload: dict[str, Any] = {
            "temperature": settings.temperature,
            "top_p": settings.top_p,
            "max_tokens": settings.max_tokens,
        }
        if settings.stop:
            payload["stop"] = list(settings.stop)
        return payload

    def effective_parameters(self) -> dict[str, Any]:
        parameters = {"model": self.model, **self._generation()}
        if self.settings.context_tokens:
            # No OpenAI-compatible server takes the context window per request;
            # it is a property of how the model was loaded.
            parameters["context_tokens"] = (
                f"{self.settings.context_tokens} (set on the server, not sent)"
            )
        return parameters

    async def list_models(self) -> list[str]:
        result = await http_client.get(
            self._url("/v1/models"),
            headers=self._headers(),
            timeout=self.timeout,
            allow_private=True,
        )
        if not result.ok:
            raise ProviderError(self._error_message(result))
        data = (result.json_body or {}).get("data") or []
        return sorted(str(entry.get("id") or "") for entry in data if entry.get("id"))

    async def chat(
        self, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]] | None = None
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            **self._generation(),
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        body = await self._post("/v1/chat/completions", payload)
        choices = body.get("choices") or []
        if not choices:
            raise ProviderError("the inference server returned no choice")
        choice = choices[0]
        message = choice.get("message") or {}
        calls = [
            ToolCall(
                name=str((call.get("function") or {}).get("name") or ""),
                arguments=_as_object((call.get("function") or {}).get("arguments")),
                call_id=str(call.get("id") or ""),
            )
            for call in (message.get("tool_calls") or [])
        ]
        return Completion(
            content=str(message.get("content") or ""),
            tool_calls=[call for call in calls if call.name],
            finish_reason=str(choice.get("finish_reason") or ""),
        )

    def _parse_stream_line(self, line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line.startswith("data:"):
            return None
        data = line[5:].strip()
        if not data or data == "[DONE]":
            return None
        try:
            return json.loads(data)
        except ValueError:
            return None

    async def chat_stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            **self._generation(),
        }
        async for chunk in self._stream("/v1/chat/completions", payload):
            for choice in chunk.get("choices") or []:
                piece = str((choice.get("delta") or {}).get("content") or "")
                if piece:
                    yield piece


def _as_object(raw: Any) -> dict[str, Any]:
    """Tool arguments arrive as an object from Ollama and as JSON text from OpenAI."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def build_provider(settings: Any) -> BaseProvider:
    """Pick the driver the section declares."""
    if settings.provider == "openai":
        return OpenAiProvider(settings)
    return OllamaProvider(settings)
