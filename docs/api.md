# REST API and MCP

[Documentation](README.md) · [Users, rights and authentication](users-and-rights.md)

Everything the interface does is a REST endpoint. The interface has no privileged path of
its own, so anything an analyst can do by hand, a script can do with their token.

## Authenticating a script

Create a personal token under **My access**. It acts as you, with exactly your
permissions, and it is shown once.

```bash
curl -s https://xenoproxy.example.org/api/v1/jobs \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Requested-With: XMLHttpRequest'
```

Writing calls also take an `Idempotency-Key` header: the same key with the same body
returns the stored response instead of submitting twice, which is what makes a retry safe.

## Endpoints

| Method | Path | Permission | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | public | Sign in with a local account |
| GET | `/api/v1/auth/oidc/start` | public | Begin single sign-on |
| POST | `/api/v1/jobs/preview` | `jobs:read` | Classify an observable and list what can run on it |
| POST | `/api/v1/jobs` | `jobs:write` | Submit a scan |
| GET | `/api/v1/jobs` | `jobs:read` | Team history, filtered and paginated |
| GET | `/api/v1/jobs/{id}` | `jobs:read` | One job with every report |
| GET | `/api/v1/jobs/{id}/events` | `jobs:read` | Live progress (server-sent events) |
| GET | `/api/v1/jobs/{id}/export?format=json\|markdown` | `jobs:export` | Export a report |
| GET | `/api/v1/jobs/{id}/children` | `jobs:read` | Jobs a pivot derived from this one |
| POST | `/api/v1/jobs/{id}/kill` | `jobs:write` | Stop a running job at its next checkpoint |
| POST | `/api/v1/jobs/{id}/reports/{report_id}/retry` | `jobs:write` | Re-run one failed, killed or skipped plugin |
| POST | `/api/v1/reports/search` | `jobs:read` | Query inside the raw payloads |
| GET | `/api/v1/stats/service?days=N` | `jobs:read` | Service statistics over a window |
| GET | `/api/v1/plugins?plugin_type=analyzer\|connector\|pivot` | `analyzers:read` | Plugin catalogue |
| PUT | `/api/v1/me/plugin-config/{name}/secrets/{secret}` | `analyzers:read` | Store your own credential for a plugin |
| PUT | `/api/v1/admin/plugins/{name}/secrets/{secret}` | `secrets:manage` | Store an instance credential (write-only) |
| PATCH | `/api/v1/admin/plugins/{name}` | `analyzers:manage` | Enable, timeout, cache window, options |
| POST | `/api/v1/admin/plugins/{name}/healthcheck` | `analyzers:manage` | Probe whether the provider answers |
| POST | `/api/v1/admin/plugin-packages` | `plugins:manage` | Install a plugin package from a zip |
| GET | `/api/v1/admin/settings` | `settings:manage` | Every scalar setting and every section |
| PUT | `/api/v1/admin/settings/sections/{name}` | `settings:manage` | Save one section |
| POST | `/api/v1/admin/settings/sections/{name}/test` | `settings:manage` | Probe a section, saved or not |
| GET | `/api/v1/admin/settings/export` | `settings:manage` | Export the configuration, without secrets |
| POST | `/api/v1/assistant/conversations/{id}/ask` | `jobs:read` | One assistant turn, tools included |
| GET | `/api/v1/admin/audit/verify` | `audit:read` | Verify the audit hash chain |

The full specification is at `/api/openapi.json`, served on a development instance only —
`BACKEND_ENVIRONMENT=development`.

## Searching inside the payloads

Every report keeps the provider's raw JSON alongside the normalised summary, and
`POST /api/v1/reports/search` queries inside it. That is how you answer a question the
interface does not have a field for — "which jobs saw this certificate fingerprint", "every
host that answered on port 8443" — without re-running a single source.

## MCP servers

Two Model Context Protocol servers, JSON-RPC 2.0 over Streamable HTTP, both off by default
and enabled under **Settings › MCP**.

| Endpoint | For | Tools |
|---|---|---|
| `/api/v1/mcp/user` | Analysis | Submit scans, read jobs and reports, search payloads |
| `/api/v1/mcp` | Administration | The analysis tools, plus plugins, settings, users, groups and audit |

Both authenticate with an API token and go through the same authorization as the REST API.
**Neither elevates.** The admin server additionally checks an allow-list of usernames and
honours a read-only mode, so you can expose administration to an agent without granting
it write access.

Every tool call is audited: the token, the tool, its arguments with secrets masked, the
status and the duration.
