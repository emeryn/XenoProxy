# Threat model

Scope: XenoProxy 0.1.0, a multi-user OSINT orchestration platform for roughly twenty
analysts, deployed on a single host behind a reverse proxy.

## Assets

| Asset | Why it matters |
|---|---|
| Analyzer API credentials (Shodan, Censys, VirusTotal, Onyphe, Joe Sandbox…) | Paid quotas; a leak is a direct financial and attribution loss |
| Master key | Unwraps every stored credential |
| Job history | Shows what the team is investigating, which is sensitive by itself |
| Analyst identities and sessions | Impersonation would grant scan and export rights |
| Audit trail | Evidence; must stay provably unaltered |
| Plugins volume | Holds code the backend executes; writing to it is equivalent to code execution |
| API quotas | A denial of quota stops the team from working |

## Trust boundaries

1. Browser to reverse proxy (TLS, public).
2. Reverse proxy to API (the proxy injects the client address and, when enabled, the delegated identity).
3. API to worker through the queue (job identifiers only).
4. Worker to external OSINT providers (outbound, untrusted answers).
5. Backend to database and queue (internal network, no route off the host).
6. Administrator to the plugins volume: an installed plugin is code the backend runs.

## Actors

- **Analyst**: authenticated, may run scans, read the shared history and export reports.
- **Administrator**: additionally configures credentials, analyzers, playbooks and users.
- **Automation**: a script or n8n workflow holding a personal API token, with that user's rights.
- **External provider**: returns data XenoProxy parses; trusted to answer, never trusted in content.
- **Attacker**: unauthenticated on the network, or an analyst trying to exceed their rights.

## Risks and controls (STRIDE)

| # | Threat | STRIDE | Control |
|---|---|---|---|
| 1 | Credential stolen from the database | Information disclosure | AES-256-GCM envelope encryption, per-record data key wrapped by a master key held outside the database; only the last four characters are ever returned |
| 2 | Credential leaked through logs or an error | Information disclosure | Key-name redaction in the structured logger, a filter that scrubs credentials from URLs logged by libraries, generic API errors carrying only a request identifier |
| 3 | Credential leaked to the browser | Information disclosure | The vault is write-only over the API; no endpoint returns a plaintext credential |
| 4 | An analyzer URL is pointed at the internal network | Information disclosure, elevation | Every outbound call goes through one client that rejects loopback, link-local, RFC1918 and cloud-metadata destinations after DNS resolution; redirects are refused unless an analyzer opts in, and each hop is re-validated |
| 5 | Observable used to inject into a log, an export or a query | Tampering | Typed classification before execution, control characters refused, parameterised SQL only, spreadsheet formula characters neutralised in exports |
| 6 | Cross-site request from another origin | Spoofing | `SameSite=Lax` host-prefixed cookie, required `X-Requested-With` header, `Origin` and `Sec-Fetch-Site` checks; bearer-token calls carry no cookie |
| 7 | Analyst reads or changes what their role forbids | Elevation of privilege | Deny by default: each route declares a permission, and a test fails the build when one does not |
| 8 | Brute force against sign-in | Spoofing | Argon2id, identical answer and comparable timing for an unknown user, per-address rate limits at the proxy and in the API |
| 9 | Stolen bootstrap password | Spoofing | Single-use by design: the account is created with a forced password change, so the value in the compose file stops working at first sign-in. It is a known default, so an instance reachable by anyone but its operator must override it, and production should read it from the secrets provider through the `_FILE` variant |
| 10 | A duplicate submission spends a quota twice | Denial of quota | Idempotency key per user action, replayed response on retry, and the report cache |
| 11 | One provider failing takes the job down | Denial of service | Each analyzer runs isolated in its own session and transaction; a failure, timeout or HTTP 429 degrades the job to partial |
| 12 | Audit records altered to hide an action | Repudiation | Append-only table with each row chained to the previous hash, verified on demand from the admin interface |
| 13 | Code execution in a dependency spawns a process | Elevation of privilege | No shell, compiler or package manager in the runtime image; an in-process guard refuses process creation; a seccomp filter denies `execve` where libseccomp is present |
| 14 | Container escape | Elevation of privilege | Rootless numeric users, read-only filesystems, all capabilities dropped, `no-new-privileges`, memory and pid limits, no socket mounted |
| 15 | Compromised dependency enters the build | Tampering | Pinned versions, install scripts disabled, `npm audit` and `pip-audit` gates that fail the build, image and configuration scanning |
| 16 | Hostile plugin archive writes outside its folder | Tampering, elevation | Archive validated before extraction: path traversal, absolute paths and symbolic links refused, file types restricted to source and text, entry count, size and compression ratio capped, and the resolved path re-checked against the staging folder at write time |
| 17 | Plugin shadows a built-in analyzer to intercept credentials | Spoofing | A plugin may not register a name already held by a built-in analyzer |
| 18 | Plugin code abuses backend privileges | Elevation of privilege | Accepted and documented: a plugin is trusted code, like an installed package. Restricted to the `plugins:manage` permission, audited with the archive digest, disableable by configuration, and still bound by the container: no shell, read-only filesystem, dropped capabilities, and the in-process guard that refuses process creation |

## Accepted for this version

- Multi-factor authentication is not implemented. The platform is intended to sit
  behind single sign-on, where the identity provider enforces it. Local accounts
  are a fallback, so an internet-exposed deployment must use OIDC or proxy
  delegation.
- Rate limiting is per API process and in memory. With several API replicas the
  effective limit is multiplied; the proxy limits remain global.
- File upload for static analysis is modelled but not implemented, so the
  upload-specific controls are not yet exercised.

## Review triggers

Update this document when a new trust boundary appears: file upload, an LLM or
MCP endpoint, a second deployment host, or any analyzer that reaches an internal
service.
