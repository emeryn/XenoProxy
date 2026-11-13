# Security policy

## Reporting a vulnerability

**Please do not open a public issue.**

Use GitHub's private reporting form: **Security › Advisories › Report a vulnerability** on
<https://github.com/emeryn/XenoProxy/security/advisories/new>. It is private between you and the
maintainers, and it is the only channel — no address is published here, so nothing to keep up to
date and nothing to scrape.

Helpful in a report:

- what an attacker gets out of it, and what they need to start (an account? which role? a token?);
- the smallest sequence of requests that shows it, and the version shown in the sidebar;
- anything about the deployment that matters (behind a proxy, OIDC or LDAP, the assistant, the MCP
  servers, a submitted sample).

You can expect an acknowledgement within a few days and, if the finding holds, a fix and a published
advisory crediting you unless you ask otherwise. This is a project maintained on spare time: there is
no paid support and no promised deadline, and saying so plainly seems better than a service level
nobody can hold to.

## Supported versions

The latest release is the one that gets fixes. There is no long-term support branch.

## Scope

In scope — anything that lets someone:

- read or change a job, a report or a configuration their account may not. The REST API, the two MCP
  servers and the assistant's tools all go through the same permission checks, and a way around any
  of them is a finding;
- recover a stored provider credential, the master key, a session or an API token;
- make the instance reach a host it was not pointed at. The outbound client refuses loopback,
  link-local, RFC1918 and metadata addresses **after** DNS resolution, re-checks every redirect, and
  applies the same rule to an observable a pivot derived — a way past any of those is a finding;
- read a submitted sample, or make one leave the instance when
  [`send_files_to_providers`](docs/configuration.md) is off;
- sign in as someone else, keep a session they should have lost, or gain a role they were not
  granted — including through a group mapping;
- escape the archive handling: write a file, execute one, or exhaust the host through a
  decompression bomb;
- break the audit chain without it being detectable by `GET /api/v1/admin/audit/verify`.

Out of scope:

- anything that needs an administrator account to begin with, where an administrator is *meant* to
  be able to do it. XenoProxy lets an administrator install a plugin package, point an outbound
  webhook anywhere and load a certificate authority: that is the job, not a vulnerability. The README
  says so in as many words.
- missing hardening the operator is responsible for and the documentation says so: TLS and HSTS at
  the reverse proxy, where the master key is kept, the trusted proxy count.
- a provider answering something unexpected. A source that fails, times out or returns nonsense
  degrades its own report and nothing else, by design.
- denial of service through sheer volume. There are timeouts, concurrency limits and page-size caps;
  raising them is a choice.
- reports from a scanner with no demonstrated impact.

## What the project does on its own

Two dependency audits **fail the build** rather than warn: `pip-audit --strict` on the resolved
backend set and `npm audit --audit-level=high` on the frontend. Versions are pinned exactly,
lockfiles are committed and npm install scripts are disabled. The images run as numeric non-root
users with read-only root filesystems, every capability dropped, and an in-process seccomp filter
that denies process creation — the runtime image carries no shell to execute anyway.

What is covered, what is hardened by design and what is left to the operator is written down in
[Security](docs/security.md) and [Threat model](docs/threat-model.md).
