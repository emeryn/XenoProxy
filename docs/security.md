# Security

[Documentation](README.md) · [Threat model](threat-model.md) · [Deployment](deployment.md)

What the product does, and what is left to you.

## Credentials

Plugin API keys are sealed with AES-256-GCM envelope encryption: a per-record data key,
itself wrapped by a master key that lives outside the database. Only the last four
characters are ever returned, so an administrator can tell which key is configured without
the value leaving the backend.

A key never reaches the browser, the logs, or an API error body. Plugins receive it from a
vault accessor, not from the request.

The master key is the one thing that must be backed up separately from the database. With
the database alone, the stored credentials cannot be read back.

## Egress

Every outbound call goes through one HTTP client. After DNS resolution — not before, which
is what makes it resistant to rebinding — it refuses loopback, link-local, RFC1918 and
cloud-metadata destinations unless `BACKEND_ALLOW_PRIVATE_TARGETS` is set for a deliberate
internal analyzer. Redirects are refused unless a plugin opts in, and each hop is
re-validated.

The same validation applies to the observables a pivot derives, so a pivot cannot be used
to reach an internal address through a crafted DNS record.

Certificate verification cannot be turned off. There is no setting for it: an internal
authority is injected instead, as a bundle held in memory and never written to disk.

## Authorization

Deny by default. Every route declares the permission it requires, and a test fails the
build when one does not — including the MCP routes, which are token-gated and covered by
two compensating tests proving they reject an unauthenticated call.

Object-level checks live in the repository layer, so an identifier belonging to someone
else returns 404 rather than 403.

## Sessions and sign-in

Argon2id passwords with a bundled breached-password list. Host-prefixed `HttpOnly`,
`Secure`, `SameSite=Lax` cookies, a CSRF header and an origin check. Session identifiers
rotate at sign-in and at any privilege change. Rate limits on sign-in, two-factor
verification and submission. Two-factor is required for administrators by default.

## Integrity

The audit trail is append-only, and each entry is chained to the hash of the previous one.
`GET /api/v1/admin/audit/verify` walks the chain and reports where it breaks, which is
what turns "we have logs" into "we can show the logs were not edited".

Writes are idempotent: the same `Idempotency-Key` with the same body returns the stored
response, so a retry cannot duplicate a job.

## Containment

Every container runs as a numeric non-root user, with a read-only filesystem, all
capabilities dropped, `no-new-privileges`, a pids limit, a memory limit and core dumps
disabled. Only the edge proxy publishes a port. The database network is internal and has
no route out. No container mounts the Docker socket.

The runtime images carry no shell, compiler or package manager, and an in-process seccomp
filter denies `execve` after startup — so a code-execution bug in a dependency has nothing
to execute.

## Supply chain

Two audit gates **fail the build** rather than warn: `pip-audit --strict` on the resolved
backend dependency set, and `npm audit --audit-level=high` on the frontend. Lockfiles are
committed, npm install scripts are disabled, and dependency versions are pinned exactly.

## Scans

| Tool | Version | Target | Result | Date |
|---|---|---|---|---|
| pip-audit | 2.10.1 | backend dependency set | 0 known vulnerabilities | 2026-11-11 |
| npm audit | npm 10.9.4 | frontend dependency set | 0 vulnerabilities | 2026-11-11 |
| Trivy image | — | `xenoproxy/backend`, `xenoproxy/frontend` | Not run yet | — |
| Trivy config | — | Dockerfiles and compose | Not run yet | — |
| OpenSCAP | — | base image, CIS profile | Not run yet | — |
| gitleaks | — | tree and history | Not run yet | — |

The commands for the remaining scans are in [Development](development.md#scanning).

## What is left to you

- **TLS.** The proxy ships its configuration commented out and ready; nothing forces you
  to enable it.
- **The master key.** Backing it up separately is a procedure, not a feature.
- **Who gets the admin role.** An administrator can install a plugin package, point an
  outbound webhook anywhere and load a certificate authority. That is the same trust as
  write access to a configuration file.
- **The providers you enable.** Querying a source tells that source what you are
  investigating. Joe Sandbox Cloud Basic goes further and *publishes* every submission,
  which is why it is capped at TLP:CLEAR.
