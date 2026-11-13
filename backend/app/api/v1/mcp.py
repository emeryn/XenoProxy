"""The two MCP servers: an AI agent drives XenoProxy through JSON-RPC over HTTP.

`POST /api/v1/mcp/user` — run and read analyses with the rights of the token.
`POST /api/v1/mcp` — configure the instance.

Both are off until an administrator turns them on, and both are reached with a
personal API token presented as `Authorization: Bearer xenoproxy_…`.

**Neither server elevates anything.** A tool is a request against this API,
issued in-process with the caller's own token, so the validation, the
authorization, the rate limits and the audit trail that apply to a browser
request apply unchanged. The administration server differs only in which tools
it offers and in whom it accepts: an account that is already an administrator
and that is named in the allow-list. An agent therefore cannot reach a right its
account does not have, which is a property an elevating server could not offer.

Transport is Streamable HTTP, stateless, answering JSON. There is no event
stream: every tool here returns a complete result, and a half-sent one would
only be a result an agent has to reassemble.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.core import provenance
from app.core.logging import get_logger
from app.models.job import JobOrigin
from app.models.user import User
from app.services import app_settings, mcp_tools
from app.services.mcp_tools import Tool

logger = get_logger(__name__)
router = APIRouter(tags=["mcp"])

VERSION = "0.1.0"
# Newest first: an older client asking for one of these gets what it asked for.
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# POST requests that only read. They exist because a query too long for a URL
# has to go in a body, which does not make it a change.
READ_POSTS = frozenset(
    {"/api/v1/jobs/preview", "/api/v1/reports/search", "/api/v1/admin/settings/export"}
)


def is_read_request(method: str, path: str) -> bool:
    if method.upper() in SAFE_METHODS:
        return True
    return method.upper() == "POST" and (
        path in READ_POSTS or path.endswith("/test") or path.endswith("/healthcheck")
    )


@dataclass(frozen=True)
class Profile:
    """One server: its name, its tools and what it tells an agent."""

    name: str
    title: str
    tools: tuple[Tool, ...]
    instructions: str


USER_PROFILE = Profile(
    "xenoproxy", "XenoProxy analysis", mcp_tools.USER_TOOLS, mcp_tools.USER_INSTRUCTIONS
)
ADMIN_PROFILE = Profile(
    "xenoproxy-admin",
    "XenoProxy administration",
    mcp_tools.ADMIN_TOOLS,
    mcp_tools.ADMIN_INSTRUCTIONS,
)


# --------------------------------------------------------------------------
# JSON-RPC envelopes
# --------------------------------------------------------------------------


def _error(identifier: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def _result(identifier: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "result": result}


def _as_text(data: Any, limit: int) -> str:
    """Render a tool answer, cut with a note rather than silently truncated."""
    text = (
        data
        if isinstance(data, str)
        else json.dumps(data, ensure_ascii=False, default=str, indent=1)
    )
    if len(text) > limit:
        return (
            text[:limit] + f"\n… cut here ({len(text):,} characters in total). Narrow the request: "
            "a path, a filter, or a smaller limit."
        )
    return text


def _tool_text(data: Any, limit: int, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": _as_text(data, limit)}], "isError": is_error}


# --------------------------------------------------------------------------
# The caller
# --------------------------------------------------------------------------


class McpCaller:
    """Issues each tool as a request against this API, with the caller's token."""

    def __init__(
        self,
        request: Request,
        *,
        token: str,
        profile: Profile,
        read_only: bool,
        max_result_chars: int,
        actor: str,
    ) -> None:
        self.request = request
        self.token = token
        self.profile = profile
        self.read_only = read_only
        self.max_result_chars = max_result_chars
        self.actor = actor
        self.tools = tuple(tool for tool in profile.tools if not (read_only and tool.writes))
        self.by_name = {tool.name: tool for tool in self.tools}

    async def call(self, tool: Tool, arguments: dict[str, Any]) -> dict[str, Any]:
        method, path, query, body = tool.call(arguments)

        # The path comes from a tool declaration, not from the model, but the
        # arguments interpolated into it do. Checking it here means a tool
        # cannot be talked into addressing something else.
        if not path.startswith("/api/v1/") or ".." in path:
            return _tool_text(
                f"this tool addressed a path that is not allowed: {path}", 400, is_error=True
            )
        if self.read_only and not is_read_request(method, path):
            return _tool_text(
                "this server is in read-only mode", self.max_result_chars, is_error=True
            )

        transport = httpx.ASGITransport(app=self.request.app)
        headers = {
            "Authorization": f"Bearer {self.token}",
            # The API's own CSRF check exempts a bearer token, but sending the
            # header keeps this request indistinguishable from a scripted one.
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }
        # The transport runs the application in this very task, so the mark
        # set here reaches the route handler. A job submitted through an agent
        # is then labelled as such in the history rather than looking like one
        # the analyst ran by hand.
        async with httpx.AsyncClient(
            transport=transport, base_url="http://mcp.internal", timeout=180.0
        ) as client:
            with provenance.entering(JobOrigin.MCP):
                response = await client.request(
                    method, path, params=query or None, json=body, headers=headers
                )

        logger.info(
            "mcp_tool_call",
            server=self.profile.name,
            tool=tool.name,
            actor=self.actor,
            status=response.status_code,
            writes=tool.writes,
        )

        try:
            payload: Any = response.json()
        except ValueError:
            # An export answers Markdown, which is the point of asking for it.
            payload = response.text

        if response.status_code >= 400:
            detail = payload
            if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
                error = payload["error"]
                detail = f"{error.get('code')}: {error.get('message')}"
            return _tool_text(
                f"the request was refused (HTTP {response.status_code}): {detail}",
                self.max_result_chars,
                is_error=True,
            )
        return _tool_text(payload, self.max_result_chars)


# --------------------------------------------------------------------------
# Admission
# --------------------------------------------------------------------------


async def _admit(request: Request, *, admin: bool) -> McpCaller:
    """Authenticate the token and decide whether this server accepts it."""
    from app.core.errors import ForbiddenError, UnauthorizedError
    from app.services import auth

    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("An API token is required: Authorization: Bearer xenoproxy_…")
    token = authorization[7:].strip()

    factory = request.app.state.session_factory
    async with factory() as session:
        user: User | None = await auth.resolve_api_key(session, token)
        if user is None:
            raise UnauthorizedError("The API token is not valid.")
        settings = await app_settings.reload(session, "mcp")
        groups = [group.name.strip().lower() for group in user.groups]

    if admin:
        if not settings.admin_enabled:
            raise ForbiddenError("The administration MCP server is turned off on this instance.")
        if not user.is_admin:
            raise ForbiddenError("This server accepts an administrator's token only.")
        if user.username.strip().lower() not in settings.admin_usernames:
            # Being an administrator is not enough: the account has to be named,
            # so turning the server on does not hand it to every administrator.
            raise ForbiddenError(
                "This account is not in the allow-list of the administration MCP server."
            )
        profile, read_only = ADMIN_PROFILE, bool(settings.read_only)
    else:
        if not settings.user_enabled:
            raise ForbiddenError("The MCP server is turned off on this instance.")
        if settings.user_groups and not (set(settings.user_groups) & set(groups)):
            raise ForbiddenError("The MCP server is not available to your groups.")
        profile, read_only = USER_PROFILE, False

    return McpCaller(
        request,
        token=token,
        profile=profile,
        read_only=read_only,
        max_result_chars=int(settings.max_result_chars),
        actor=user.username,
    )


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


async def _handle(caller: McpCaller, message: dict[str, Any]) -> dict[str, Any]:
    identifier = message["id"]
    method = message["method"]
    params = message.get("params") or {}

    if method == "initialize":
        asked = params.get("protocolVersion")
        return _result(
            identifier,
            {
                "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": caller.profile.name,
                    "title": caller.profile.title,
                    "version": VERSION,
                },
                "instructions": caller.profile.instructions
                + ("\n\nThis server is in read-only mode." if caller.read_only else ""),
            },
        )

    if method == "ping":
        return _result(identifier, {})

    if method == "tools/list":
        return _result(identifier, {"tools": [tool.schema() for tool in caller.tools]})

    if method == "tools/call":
        name = str(params.get("name") or "")
        tool = caller.by_name.get(name)
        if tool is None:
            # A tool that exists but is hidden by read-only mode is worth saying
            # so: the agent otherwise retries a name it can see in the docs.
            hidden = any(entry.name == name for entry in caller.profile.tools)
            reason = (
                f"'{name}' changes data and this server is in read-only mode"
                if hidden
                else f"unknown tool: {name}"
            )
            return _result(identifier, _tool_text(reason, caller.max_result_chars, is_error=True))

        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _result(
                identifier,
                _tool_text("arguments must be an object", caller.max_result_chars, is_error=True),
            )
        missing = [name for name in tool.required if arguments.get(name) in (None, "")]
        if missing:
            return _result(
                identifier,
                _tool_text(
                    f"missing argument(s): {', '.join(missing)}",
                    caller.max_result_chars,
                    is_error=True,
                ),
            )
        try:
            return _result(identifier, await caller.call(tool, arguments))
        except Exception as exc:
            logger.warning("mcp_tool_failed", tool=tool.name, error=str(exc))
            return _result(
                identifier,
                _tool_text(f"{type(exc).__name__}: {exc}", caller.max_result_chars, is_error=True),
            )

    if method in {"resources/list", "prompts/list"}:
        return _result(identifier, {method.split("/")[0]: []})

    return _error(identifier, -32601, f"method not found: {method}")


async def _serve(request: Request, caller: McpCaller) -> Response:
    try:
        payload = json.loads(await request.body())
    except ValueError:
        return JSONResponse(_error(None, -32700, "parse error"), status_code=400)

    batch = isinstance(payload, list)
    messages = payload if batch else [payload]
    answers: list[dict[str, Any]] = []

    for message in messages:
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or "method" not in message
        ):
            if isinstance(message, dict) and ("result" in message or "error" in message):
                continue  # the client answering the server: nothing is sent back
            answers.append(
                _error(
                    message.get("id") if isinstance(message, dict) else None,
                    -32600,
                    "invalid request",
                )
            )
            continue
        if "id" not in message:
            continue  # a notification expects no answer
        answers.append(await _handle(caller, message))

    if not answers:
        return Response(status_code=202)
    return JSONResponse(answers if batch else answers[0])


@router.post("/mcp/user", summary="MCP server: run and read analyses with your own rights")
async def mcp_user(request: Request) -> Response:
    return await _serve(request, await _admit(request, admin=False))


@router.post("/mcp", summary="MCP server: configure the instance")
async def mcp_admin(request: Request) -> Response:
    return await _serve(request, await _admit(request, admin=True))
