# Users, rights and authentication

[Documentation](README.md) · [Security](security.md) · [Administrator guide](help/administrator.md)

## Roles

There are two roles. Permissions are derived from the role and checked per route; code
never tests the role directly, so adding a permission is a change in one table.

| | `analyst` | `admin` |
|---|---|---|
| Run scans, read the history, tag and export | yes | yes |
| Read the plugin catalogue and the playbooks | yes | yes |
| Manage their own API tokens and credentials | yes | yes |
| Configure plugin credentials, timeouts, cache | no | yes |
| Create playbooks, users, groups | no | yes |
| Instance settings, plugin packages, audit | no | yes |

An administrator sees every job. The history is shared inside the organisation by default,
so a team mutualises both the results and the cache.

Authorization denies by default: every route declares the permission it needs, and a test
fails the build if one does not. See [Security](security.md#authorization).

## Local accounts

Created under **Users**, with a password shown once. Passwords are hashed with Argon2id
and checked against a bundled list of common and breached passwords; the policy follows
NIST SP 800-63B — at least 12 characters, no composition rules.

An administrator can force a local user to change their password at first sign-in, reset
it, clear a lost two-factor enrolment, or deactivate the account. The interface refuses to
remove the last administrator.

## OpenID Connect

The authorization code flow with PKCE, with `state` and `nonce` validated and the ID
token's signature, audience and issuer checked.

Configure it under **Settings › OIDC**, or by environment for a headless deployment — the
variables are in [Configuration](configuration.md#identity). Whatever the source, the same
schema validates it, and the section offers a connection test that performs discovery and
fetches the JWKS before you save.

`BACKEND_PUBLIC_URL` builds the redirect URI, so it must match what the provider expects.

## LDAP and Active Directory

LDAPS or StartTLS with certificate verification, and filter values escaped against LDAP
injection. Configure it under **Settings › LDAP**; the connection test binds and runs a
sample group search, which is the quickest way to find a wrong base DN.

## Reverse-proxy delegation

When `BACKEND_PROXY_AUTH_ENABLED` is on, a trusted proxy can assert the identity through
headers. The edge proxy clears those headers on every request it forwards, so a client
cannot send them itself; if you add another proxy in front, set
`BACKEND_TRUSTED_PROXY_COUNT` accordingly.

## Groups and mapping

Groups carry external names, so a directory group or an OIDC claim maps onto a XenoProxy
group. A group may grant the admin role. Under **Groups**, a mapping probe shows what a
given set of external names would resolve to, which answers "why is this person not an
admin" without a round trip through the provider.

Accounts without a group join the default group, so a new arrival shares the team's
history immediately.

## Two-factor authentication

TOTP, with recovery codes hashed and shown once. Replaying the same code inside its window
is refused.

It is **required for administrators by default** (`BACKEND_REQUIRE_MFA_FOR_ADMINS`), and
can be required for every local account (`BACKEND_REQUIRE_MFA_FOR_ALL`). An account that
must enrol is held at an onboarding gate until it does.

Two ways out when an authenticator is lost:

- A recovery code, entered in the same field as the six-digit code.
- `docker compose run --rm api reset-admin`, which clears the enrolment from the host.

A user whose identity comes from a directory is normally covered by that directory's own
second factor, so the requirement applies to local accounts.

## API tokens

Personal tokens let a script or an n8n workflow act as the analyst who created them, with
exactly that analyst's permissions. A token is at least 32 random bytes, shown once,
stored as a SHA-256 hash with a visible prefix, scoped, expiring and revocable, and its
last use is displayed.

See [REST API and MCP](api.md) for using one.
