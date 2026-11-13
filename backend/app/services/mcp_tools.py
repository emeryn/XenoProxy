"""The tools each MCP server offers, declared as calls on this API.

A tool does not reimplement anything. It names a method and a path of the REST
API, and the server calls it in-process. That is the whole design: the
validation, the authorization, the rate limits and the audit trail that apply to
a browser request apply unchanged to an agent request, and a tool cannot drift
away from the endpoint it fronts.

Two profiles:

- **user** — run and read analyses, with the rights of the token presented. No
  elevation of any kind: an analyst's token sees an analyst's jobs.
- **admin** — configure the instance. The calls run as an administrator, which
  is why that server is off by default, limited to accounts an administrator
  names, and can be put in read-only mode.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

STRING = {"type": "string"}
INTEGER = {"type": "integer"}
BOOLEAN = {"type": "boolean"}
OBJECT = {"type": "object"}
ARRAY_OF_STRING = {"type": "array", "items": {"type": "string"}}


def _escape(value: Any) -> str:
    """A path segment, escaped: a plugin name reaches us from the model."""
    return quote(str(value), safe="")


@dataclass(frozen=True)
class Tool:
    """One callable, expressed as a request against this API."""

    name: str
    description: str
    properties: dict[str, Any]
    required: tuple[str, ...] = ()
    # args -> (method, path, query, body)
    call: Callable[[dict[str, Any]], tuple[str, str, dict[str, Any] | None, Any]] = field(
        default=lambda _args: ("GET", "/api/v1/jobs", None, None)
    )
    writes: bool = False
    destructive: bool = False

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.properties,
                "required": list(self.required),
            },
            "annotations": {
                "readOnlyHint": not self.writes,
                "destructiveHint": self.destructive,
                # These reach a third-party provider rather than only this
                # instance, so an agent should treat them as costly.
                "openWorldHint": self.name in {"submit_scan", "rerun_job", "healthcheck_plugin"},
            },
        }


# --------------------------------------------------------------------------
# User profile: run and read analyses
# --------------------------------------------------------------------------

USER_TOOLS: tuple[Tool, ...] = (
    Tool(
        name="classify_observable",
        description=(
            "Detect the type of an observable and refang it, and list the analyzers, "
            "connectors, pivots and playbooks that can run on it right now."
        ),
        properties={"value": STRING, "tlp": STRING},
        required=("value",),
        call=lambda a: (
            "POST",
            "/api/v1/jobs/preview",
            None,
            {"value": a["value"], **({"tlp": a["tlp"]} if a.get("tlp") else {})},
        ),
    ),
    Tool(
        name="submit_scan",
        description=(
            "Submit an observable for analysis. Leave the plugin lists empty to run every "
            "analyzer that can run. Connectors and pivots only run when named: one publishes "
            "outside the instance, the other creates further jobs. Spends provider quota."
        ),
        properties={
            "observable": STRING,
            "analyzers": ARRAY_OF_STRING,
            "connectors": ARRAY_OF_STRING,
            "pivots": ARRAY_OF_STRING,
            "playbook": STRING,
            "tags": ARRAY_OF_STRING,
            "tlp": STRING,
            "force_rescan": BOOLEAN,
        },
        required=("observable",),
        call=lambda a: (
            "POST",
            "/api/v1/jobs",
            None,
            {
                "observable": a["observable"],
                "analyzers": a.get("analyzers") or [],
                "connectors": a.get("connectors") or [],
                "pivots": a.get("pivots") or [],
                "playbook": a.get("playbook") or None,
                "tags": a.get("tags") or [],
                **({"tlp": a["tlp"]} if a.get("tlp") else {}),
                "force_rescan": bool(a.get("force_rescan")),
            },
        ),
        writes=True,
    ),
    Tool(
        name="list_jobs",
        description=(
            "The team history you may see, filtered. Use it to find a job before reading it."
        ),
        properties={
            "search": STRING,
            "status": STRING,
            "verdict": STRING,
            "observable_type": STRING,
            "tag": STRING,
            "requested_by": STRING,
            "derived": BOOLEAN,
            "page": INTEGER,
            "page_size": INTEGER,
        },
        call=lambda a: (
            "GET",
            "/api/v1/jobs",
            {
                key: a[key]
                for key in (
                    "search",
                    "status",
                    "verdict",
                    "observable_type",
                    "tag",
                    "requested_by",
                    "derived",
                    "page",
                    "page_size",
                )
                if a.get(key) not in (None, "")
            },
            None,
        ),
    ),
    Tool(
        name="get_job",
        description=(
            "One job: its verdict, its aggregated summary, and one entry per plugin that ran."
        ),
        properties={"job_id": STRING},
        required=("job_id",),
        call=lambda a: ("GET", f"/api/v1/jobs/{_escape(a['job_id'])}", None, None),
    ),
    Tool(
        name="list_job_payloads",
        description=(
            "What a job has to read and how large each provider payload is. Call this before "
            "reading a payload, so nothing large is fetched blindly."
        ),
        properties={"job_id": STRING},
        required=("job_id",),
        call=lambda a: ("GET", f"/api/v1/jobs/{_escape(a['job_id'])}/reports", None, None),
    ),
    Tool(
        name="get_payload",
        description=(
            "What a provider actually returned, kept whole. `shape` returns the structure "
            "instead of the content, which is how you find the path worth asking for; `path` "
            "then returns just that subtree, for example "
            "'data.attributes.last_analysis_stats'."
        ),
        properties={"job_id": STRING, "plugin": STRING, "path": STRING, "shape": BOOLEAN},
        required=("job_id", "plugin"),
        call=lambda a: (
            "GET",
            f"/api/v1/jobs/{_escape(a['job_id'])}/reports/{_escape(a['plugin'])}/raw",
            {
                **({"path": a["path"]} if a.get("path") else {}),
                **({"shape": True} if a.get("shape") else {}),
            },
            None,
        ),
    ),
    Tool(
        name="search_payloads",
        description=(
            "Search inside the provider payloads across every job you may see. `json_path` is "
            "a Postgres JSON path and is the indexed way to ask, for example "
            "'$.data.attributes.last_analysis_stats.malicious ? (@ > 5)'. `contains` is a "
            "plain substring when you do not know the provider's shape. `extract` returns one "
            "field beside each hit."
        ),
        properties={
            "json_path": STRING,
            "contains": STRING,
            "extract": STRING,
            "plugin_name": STRING,
            "observable_type": STRING,
            "verdict": STRING,
            "limit": INTEGER,
        },
        call=lambda a: (
            "POST",
            "/api/v1/reports/search",
            None,
            {
                key: a[key]
                for key in (
                    "json_path",
                    "contains",
                    "extract",
                    "plugin_name",
                    "observable_type",
                    "verdict",
                    "limit",
                )
                if a.get(key) not in (None, "")
            },
        ),
    ),
    Tool(
        name="list_job_children",
        description="The jobs a pivot derived from this one.",
        properties={"job_id": STRING},
        required=("job_id",),
        call=lambda a: ("GET", f"/api/v1/jobs/{_escape(a['job_id'])}/children", None, None),
    ),
    Tool(
        name="tag_job",
        description="Replace the tags of a job, so it can be found later.",
        properties={"job_id": STRING, "tags": ARRAY_OF_STRING},
        required=("job_id", "tags"),
        call=lambda a: (
            "PATCH",
            f"/api/v1/jobs/{_escape(a['job_id'])}/tags",
            None,
            {"tags": a["tags"]},
        ),
        writes=True,
    ),
    Tool(
        name="rerun_job",
        description="Run a job again, ignoring the cache. Spends provider quota.",
        properties={"job_id": STRING},
        required=("job_id",),
        call=lambda a: ("POST", f"/api/v1/jobs/{_escape(a['job_id'])}/rerun", None, None),
        writes=True,
    ),
    Tool(
        name="retry_report",
        description=(
            "Re-run one failed, killed or skipped plugin of a job, leaving the other reports "
            "and the quota they already spent untouched."
        ),
        properties={"job_id": STRING, "report_id": STRING},
        required=("job_id", "report_id"),
        call=lambda a: (
            "POST",
            f"/api/v1/jobs/{_escape(a['job_id'])}/reports/{_escape(a['report_id'])}/retry",
            None,
            None,
        ),
        writes=True,
    ),
    Tool(
        name="kill_job",
        description="Stop a running job at its next checkpoint. Finished reports are kept.",
        properties={"job_id": STRING},
        required=("job_id",),
        call=lambda a: ("POST", f"/api/v1/jobs/{_escape(a['job_id'])}/kill", None, None),
        writes=True,
    ),
    Tool(
        name="list_plugins",
        description=(
            "The analyzers, connectors and pivots this instance has, what they support and "
            "whether they are enabled and configured."
        ),
        properties={"plugin_type": STRING},
        call=lambda a: (
            "GET",
            "/api/v1/plugins",
            {"plugin_type": a["plugin_type"]} if a.get("plugin_type") else None,
            None,
        ),
    ),
    Tool(
        name="list_playbooks",
        description="The preset plugin pipelines, per observable type.",
        properties={},
        call=lambda _a: ("GET", "/api/v1/playbooks", None, None),
    ),
    Tool(
        name="service_statistics",
        description=(
            "What the team analysed over a window and what it found: totals, per analyst, "
            "per day, per observable type and per plugin."
        ),
        properties={"days": INTEGER},
        call=lambda a: ("GET", "/api/v1/stats/service", {"days": a.get("days") or 30}, None),
    ),
    Tool(
        name="export_job",
        description="A job as a Markdown incident write-up, or as complete JSON.",
        properties={"job_id": STRING, "format": {"type": "string", "enum": ["json", "markdown"]}},
        required=("job_id",),
        call=lambda a: (
            "GET",
            f"/api/v1/jobs/{_escape(a['job_id'])}/export",
            {"format": a.get("format") or "markdown"},
            None,
        ),
    ),
)


# --------------------------------------------------------------------------
# Admin profile: configure the instance
# --------------------------------------------------------------------------

ADMIN_TOOLS: tuple[Tool, ...] = (
    *USER_TOOLS,
    Tool(
        name="read_settings",
        description=(
            "Every instance setting and every configuration section, with the secrets masked. "
            "Start here to see what is configured before changing anything."
        ),
        properties={},
        call=lambda _a: ("GET", "/api/v1/admin/settings", None, None),
    ),
    Tool(
        name="update_settings",
        description=(
            "Change the scalar instance settings, as an object of key to value. Only the keys "
            "given are changed. A key pinned by the deployment is refused."
        ),
        properties={"values": OBJECT},
        required=("values",),
        call=lambda a: ("PATCH", "/api/v1/admin/settings", None, {"values": a["values"]}),
        writes=True,
    ),
    Tool(
        name="save_settings_section",
        description=(
            "Save one configuration section whole: network, assistant, oidc, ldap, smtp or "
            "notifications. A secret left empty keeps the stored value; '<field>_clear': true "
            "removes it. Read the section first: it is validated as a whole."
        ),
        properties={"section": STRING, "values": OBJECT},
        required=("section", "values"),
        call=lambda a: (
            "PUT",
            f"/api/v1/admin/settings/sections/{_escape(a['section'])}",
            None,
            {"values": a["values"]},
        ),
        writes=True,
    ),
    Tool(
        name="test_settings_section",
        description=(
            "Probe a section against its provider without saving it. `target` is the address "
            "to fetch for network, the account to look up for ldap, the recipient for smtp."
        ),
        properties={"section": STRING, "values": OBJECT, "target": STRING},
        required=("section",),
        call=lambda a: (
            "POST",
            f"/api/v1/admin/settings/sections/{_escape(a['section'])}/test",
            None,
            {
                **({"values": a["values"]} if a.get("values") else {}),
                **({"target": a["target"]} if a.get("target") else {}),
            },
        ),
    ),
    Tool(
        name="configure_plugin",
        description=(
            "Enable or disable a plugin, and set its timeout, cache lifetime and options. "
            "A plugin missing a required credential cannot be enabled."
        ),
        properties={
            "plugin_name": STRING,
            "enabled": BOOLEAN,
            "timeout_seconds": INTEGER,
            "cache_ttl_seconds": INTEGER,
            "options": OBJECT,
        },
        required=("plugin_name",),
        call=lambda a: (
            "PATCH",
            f"/api/v1/admin/plugins/{_escape(a['plugin_name'])}",
            None,
            {
                key: a[key]
                for key in ("enabled", "timeout_seconds", "cache_ttl_seconds", "options")
                if a.get(key) is not None
            },
        ),
        writes=True,
    ),
    Tool(
        name="set_plugin_credential",
        description=(
            "Store or replace a plugin credential. It is sealed immediately and never "
            "returned: no tool can read one back."
        ),
        properties={"plugin_name": STRING, "secret_name": STRING, "value": STRING},
        required=("plugin_name", "secret_name", "value"),
        call=lambda a: (
            "PUT",
            f"/api/v1/admin/plugins/{_escape(a['plugin_name'])}"
            f"/secrets/{_escape(a['secret_name'])}",
            None,
            {"value": a["value"]},
        ),
        writes=True,
    ),
    Tool(
        name="healthcheck_plugin",
        description="Probe whether a plugin's provider answers, and record the outcome.",
        properties={"plugin_name": STRING},
        required=("plugin_name",),
        call=lambda a: (
            "POST",
            f"/api/v1/admin/plugins/{_escape(a['plugin_name'])}/healthcheck",
            None,
            None,
        ),
    ),
    Tool(
        name="create_playbook",
        description=(
            "Create a playbook: a plugin pipeline for one or more observable types. The "
            "analyzer list is required; connectors publish the result and pivots create "
            "child jobs."
        ),
        properties={
            "name": STRING,
            "description": STRING,
            "observable_types": ARRAY_OF_STRING,
            "analyzers": ARRAY_OF_STRING,
            "connectors": ARRAY_OF_STRING,
            "pivots": ARRAY_OF_STRING,
            "enabled": BOOLEAN,
        },
        required=("name", "analyzers"),
        call=lambda a: (
            "POST",
            "/api/v1/admin/playbooks",
            None,
            {
                "name": a["name"],
                "description": a.get("description") or "",
                "observable_types": a.get("observable_types") or [],
                "analyzers": a["analyzers"],
                "connectors": a.get("connectors") or [],
                "pivots": a.get("pivots") or [],
                "enabled": a.get("enabled", True),
            },
        ),
        writes=True,
    ),
    Tool(
        name="list_users",
        description="The accounts of this instance, with their role and their groups.",
        properties={},
        call=lambda _a: ("GET", "/api/v1/admin/users", None, None),
    ),
    Tool(
        name="list_groups",
        description="The groups, their default flag and whether they demand two-factor.",
        properties={},
        call=lambda _a: ("GET", "/api/v1/admin/groups", None, None),
    ),
    Tool(
        name="read_audit",
        description=(
            "The audit trail, most recent first, optionally filtered to one action. Every "
            "configuration change made through this server appears here."
        ),
        properties={"action": STRING, "page": INTEGER, "page_size": INTEGER},
        call=lambda a: (
            "GET",
            "/api/v1/admin/audit",
            {
                key: a[key]
                for key in ("action", "page", "page_size")
                if a.get(key) not in (None, "")
            },
            None,
        ),
    ),
    Tool(
        name="verify_audit",
        description="Verify the audit hash chain, which detects a tampered trail.",
        properties={},
        call=lambda _a: ("GET", "/api/v1/admin/audit/verify", None, None),
    ),
    Tool(
        name="export_configuration",
        description=(
            "The whole instance configuration as a document, carrying no credential. Use it "
            "to replay a configuration on another instance."
        ),
        properties={},
        call=lambda _a: ("GET", "/api/v1/admin/settings/export", None, None),
    ),
)

USER_BY_NAME = {tool.name: tool for tool in USER_TOOLS}
ADMIN_BY_NAME = {tool.name: tool for tool in ADMIN_TOOLS}

USER_INSTRUCTIONS = (
    "XenoProxy orchestrates OSINT analysis. You submit an observable — an IP address, a domain, a "
    "URL, a file hash — it runs analyzers against it in parallel, aggregates a verdict and "
    "keeps the result as a job.\n\n"
    "Start with classify_observable: it detects the type, refangs the value and tells you which "
    "sources can actually run right now. Then submit_scan, which returns immediately; poll "
    "get_job until its status is SUCCESS, PARTIAL_FAILURE, FAILED or KILLED.\n\n"
    "To read a result: get_job gives the verdict and one line per source. When that is not "
    "enough, list_job_payloads says what each provider returned and how large it is, then "
    "get_payload with shape=true shows the structure and get_payload with a path returns one "
    "subtree. Never fetch a whole payload to look at one field.\n\n"
    "To ask a question of the history rather than of one job, use search_payloads.\n\n"
    "The aggregated verdict is the worst verdict any successful analyzer reported. 'No provider "
    "reported anything' is not 'clean'. You only see the jobs your token may see."
)

ADMIN_INSTRUCTIONS = (
    "This is the XenoProxy administration server: it configures the instance. Everything the user "
    "server does is available here too.\n\n"
    "Read before you write. read_settings shows every setting and every configuration section "
    "with the secrets masked; list_plugins shows what is enabled and what is missing a "
    "credential. A section is saved whole, so read it, change what you mean to change, and send "
    "it back: save_settings_section with a secret left empty keeps the stored value.\n\n"
    "test_settings_section probes a section without saving it. Use it before saving anything the "
    "instance authenticates against, such as the directory or single sign-on.\n\n"
    "No tool can read a credential back. Every call you make is written to the audit trail "
    "against the account whose token you hold."
)
