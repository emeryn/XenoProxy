# Configuration

[Documentation](README.md) · [Getting started](install.md) · [Deployment](deployment.md)

XenoProxy is configured from two places, and which one owns a setting is deliberate.

**Environment variables** carry what must be settled before the application can run, or
what an operator must be able to change without signing in: the database, the secrets, the
session policy, the two-factor requirement.

**The interface** carries what an administrator tunes while the service runs: plugin
credentials, timeouts and cache windows, the outbound proxy, the identity providers, the
assistant, mail and notifications. These are stored in the database, encrypted where they
are secrets.

A setting defined in the environment wins and is shown read-only in the interface, marked
as managed by the environment. That is how you recover from a configuration that locks you
out — see [two-factor authentication](users-and-rights.md#two-factor-authentication).

**Plugin API keys are never environment variables.** They are entered in the interface
and sealed; see [Security](security.md#credentials).

## Common variables

| Variable | Default | Description |
|---|---|---|
| `BACKEND_ENVIRONMENT` | `production` | `development` enables the OpenAPI UI |
| `BACKEND_PUBLIC_URL` | `http://localhost:8099` | Public URL, used to build the OIDC redirect |
| `BACKEND_TRUSTED_PROXY_COUNT` | `1` | Proxy hops trusted for the client address |
| `BACKEND_PROXY_AUTH_ENABLED` | `false` | Accept an identity delegated by the proxy |
| `BACKEND_OIDC_ENABLED` | `false` | Enable the OIDC code flow with PKCE |
| `BACKEND_CACHE_DEFAULT_TTL_SECONDS` | `86400` | Default cache window for a new analyzer |
| `BACKEND_ANALYZER_MAX_CONCURRENCY` | `8` | Analyzers running at once per job |
| `BACKEND_REQUIRE_MFA_FOR_ADMINS` | `true` | Two-factor for administrators |
| `BACKEND_REQUIRE_MFA_FOR_ALL` | `false` | Two-factor for every local account |
| `BACKEND_ALLOW_PRIVATE_TARGETS` | `false` | Allow scanning loopback and RFC1918 targets |
| `BACKEND_OUTBOUND_PROXY_URL` | — | Egress proxy for every provider call |
| `BACKEND_CUSTOM_CA_FILE` | — | Internal certificate authority bundle |

## Identity

| Variable | Default | Description |
|---|---|---|
| `XENOPROXY_ADMIN_USERNAME` | `admin` | First administrator, read by the compose file |
| `XENOPROXY_ADMIN_PASSWORD` | generated | First administrator's password; generated into the secrets volume when unset |
| `BACKEND_BOOTSTRAP_ADMIN_PASSWORD_FILE` | — | Production alternative: read it from the secrets provider |
| `BACKEND_PROXY_AUTH_USER_HEADER` | `X-Remote-User` | Header carrying the delegated user |
| `BACKEND_PROXY_AUTH_EMAIL_HEADER` | `X-Remote-Email` | Header carrying the delegated email |
| `BACKEND_PROXY_AUTH_GROUPS_HEADER` | `X-Remote-Groups` | Header carrying the delegated groups |
| `BACKEND_OIDC_ISSUER` | — | Provider issuer URL |
| `BACKEND_OIDC_CLIENT_ID` | — | Client identifier |
| `BACKEND_OIDC_CLIENT_SECRET_FILE` | — | Client secret file |
| `BACKEND_OIDC_SCOPES` | `openid profile email` | Requested scopes |
| `BACKEND_OIDC_ADMIN_GROUP` | `xenoproxy-admins` | Group mapped to the admin role |

## Sessions and secrets

| Variable | Default | Description |
|---|---|---|
| `BACKEND_SECRET_KEY_FILE` | `/run/secrets/secret_key` | Signs cookies and sign-on state |
| `BACKEND_MASTER_KEY_FILE` | `/run/secrets/master_key` | Wraps every plugin credential |
| `BACKEND_SESSION_IDLE_MINUTES` | `60` | Idle session expiry |
| `BACKEND_SESSION_ABSOLUTE_HOURS` | `12` | Absolute session expiry |

The master key is what makes a stored credential readable. Losing it does not break the
database, but every sealed credential becomes unreadable and has to be entered again. Back
it up [separately from the database](operations.md#backups).

## Infrastructure

| Variable | Default | Description |
|---|---|---|
| `BACKEND_DB_HOST` / `_PORT` / `_NAME` / `_USER` | `database` / `5432` / `xenoproxy` / `xenoproxy_app` | Database connection |
| `BACKEND_DB_PASSWORD_FILE` | `/run/secrets/db_password` | Database password file |
| `BACKEND_REDIS_HOST` / `_PORT` / `_DB` | `queue` / `6379` / `0` | Queue connection |
| `BACKEND_REDIS_PASSWORD_FILE` | `/run/secrets/redis_password` | Queue password file |
| `BACKEND_LOG_LEVEL` | `INFO` | Structured JSON log level |
| `BACKEND_DOCS_ENABLED` | `false` | OpenAPI UI, ignored in production |

## Limits

| Variable | Default | Description |
|---|---|---|
| `BACKEND_ANALYZER_DEFAULT_TIMEOUT_SECONDS` | `60` | Default provider timeout |
| `BACKEND_MAX_BODY_BYTES` | `2097152` | Maximum request body |
| `BACKEND_MAX_UPLOAD_BYTES` | `33554432` | Maximum upload |
| `BACKEND_MAX_PAGE_SIZE` | `100` | Maximum page size |
| `BACKEND_CORS_ORIGINS` | — | Extra browser origins, comma separated |

Every variable is listed with a comment in `.env.example`, so a headless deployment never
needs the interface.

## Settings held in the interface

Under **Settings**, each section is validated as a whole and offers a connection test
before it is saved:

| Section | What it holds |
|---|---|
| Network | Outbound proxy, no-proxy list, internal certificate authority bundle |
| Assistant | Inference server, model, parameters, system prompt, agent mode |
| OIDC | Issuer, client, scopes, group mapping, auto-provisioning |
| LDAP | Server, bind, base DN, user and group filters, group mapping |
| SMTP | Server, credentials, sender, TLS |
| Notifications | What is sent, to whom, through which channel |
| MCP | Whether each MCP server answers, its allow-list and read-only mode |

A configuration export is available, and carries no credential — useful to move an
instance's shape to another one without moving its secrets.
