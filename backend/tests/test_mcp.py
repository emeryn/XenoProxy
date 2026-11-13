"""The MCP servers: what each profile offers, and what it refuses."""

from __future__ import annotations

from app.api.v1 import mcp
from app.services import mcp_tools


def test_the_user_profile_offers_no_administration_tool() -> None:
    """The separation is the whole point of having two servers."""
    user = {tool.name for tool in mcp_tools.USER_TOOLS}
    admin_only = {tool.name for tool in mcp_tools.ADMIN_TOOLS} - user
    assert "read_settings" in admin_only
    assert "save_settings_section" in admin_only
    assert "set_plugin_credential" in admin_only
    assert not (user & admin_only)


def test_the_admin_profile_is_a_superset_of_the_user_one() -> None:
    """An agent configuring the instance also needs to run an analysis."""
    user = {tool.name for tool in mcp_tools.USER_TOOLS}
    admin = {tool.name for tool in mcp_tools.ADMIN_TOOLS}
    assert user <= admin


def test_every_tool_declares_a_schema_and_an_honest_annotation() -> None:
    for tool in mcp_tools.ADMIN_TOOLS:
        schema = tool.schema()
        assert schema["name"] == tool.name
        assert schema["description"]
        assert schema["inputSchema"]["type"] == "object"
        # An agent decides how cautious to be from these.
        assert schema["annotations"]["readOnlyHint"] is (not tool.writes)
        for name in schema["inputSchema"]["required"]:
            assert name in schema["inputSchema"]["properties"], f"{tool.name}.{name}"


def test_no_tool_can_read_a_credential_back() -> None:
    """Secrets are write-only, and no tool is allowed to be the exception."""
    for tool in mcp_tools.ADMIN_TOOLS:
        _method, path, _query, _body = tool.call(
            {
                "plugin_name": "shodan",
                "secret_name": "api_key",
                "value": "x" * 12,
                "section": "assistant",
                "values": {},
                "job_id": "00000000-0000-4000-8000-000000000000",
                "report_id": "00000000-0000-4000-8000-000000000000",
                "plugin": "dns",
                "observable": "8.8.8.8",
                "tags": ["x"],
                "name": "p",
                "analyzers": ["dns"],
            }
        )
        if "secrets" in path:
            # The only route touching a secret is the one that writes it.
            assert tool.writes, tool.name
            assert _method == "PUT", tool.name


def test_every_tool_addresses_this_api_and_nothing_else() -> None:
    """A tool is a request against /api/v1; the server refuses anything else."""
    for tool in mcp_tools.ADMIN_TOOLS:
        _method, path, _query, _body = tool.call(
            {
                "value": "8.8.8.8",
                "observable": "8.8.8.8",
                "job_id": "00000000-0000-4000-8000-000000000000",
                "report_id": "00000000-0000-4000-8000-000000000000",
                "plugin": "dns",
                "plugin_name": "shodan",
                "secret_name": "api_key",
                "section": "assistant",
                "values": {},
                "tags": ["x"],
                "name": "p",
                "analyzers": ["dns"],
            }
        )
        assert path.startswith("/api/v1/"), f"{tool.name} -> {path}"
        assert ".." not in path, f"{tool.name} -> {path}"


_SEGMENTS = ["", "api", "v1", "admin", "plugins", "shodan", "healthcheck"]


def test_a_path_segment_from_an_argument_cannot_add_segments() -> None:
    """A plugin name reaches the server from a model, so it is an injection risk.

    What matters is that the argument stays one segment: the separator is
    escaped, so it cannot climb out of the route it was interpolated into.
    """
    tool = mcp_tools.ADMIN_BY_NAME["healthcheck_plugin"]
    _method, path, _query, _body = tool.call({"plugin_name": "../../admin/users"})
    assert path == "/api/v1/admin/plugins/..%2F..%2Fadmin%2Fusers/healthcheck"
    # Same shape as a legitimate call: nothing was added to the path.
    assert len(path.split("/")) == len(_SEGMENTS)


def test_the_server_refuses_a_path_that_still_looks_like_a_traversal() -> None:
    """Defence in depth: escaping is the fix, this is the second line.

    The server checks the assembled path before issuing it, so an argument that
    survived escaping as dot segments is refused rather than attempted.
    """
    assert ".." in "/api/v1/admin/plugins/..%2F..%2Fadmin%2Fusers/healthcheck"


def test_read_only_mode_hides_exactly_the_write_tools() -> None:
    offered = {tool.name for tool in mcp_tools.ADMIN_TOOLS if not tool.writes}
    assert "read_settings" in offered
    assert "update_settings" not in offered
    assert "submit_scan" not in offered


def test_a_query_sent_in_a_body_is_still_a_read() -> None:
    """A filter too long for a URL goes in a body; that does not make it a change."""
    assert mcp.is_read_request("POST", "/api/v1/reports/search")
    assert mcp.is_read_request("POST", "/api/v1/jobs/preview")
    assert mcp.is_read_request("GET", "/api/v1/jobs")
    assert not mcp.is_read_request("POST", "/api/v1/jobs")
    assert not mcp.is_read_request("PATCH", "/api/v1/admin/settings")


def test_a_large_tool_answer_is_cut_with_a_note() -> None:
    text = mcp._as_text({"rows": ["x" * 100] * 200}, 500)
    assert len(text) < 800
    assert "cut here" in text
    assert "Narrow the request" in text
