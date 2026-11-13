# Getting started

[Documentation](README.md) · [Configuration](configuration.md) · [Deployment](deployment.md)

## Requirements

- Docker Engine 24+ with Compose v2, or rootless Podman with `podman compose`.
- About 2 GB of RAM and a few GB of disk.
- Outbound HTTPS to the providers you intend to query. Behind a corporate proxy, see
  [Deployment](deployment.md#egress-proxy-and-internal-certificate-authorities).

Nothing else. There is no `.env` to prepare and no `make`: the stack generates its own
secrets into a named volume on first boot.

## First start

```bash
git clone <repository url> xenoproxy
cd xenoproxy
docker compose up -d
docker compose ps        # six services, all healthy
```

The first start builds the two images, creates the database, applies the migrations and
provisions the plugin catalogue and the built-in playbooks.

## Signing in

Read the generated administrator password:

```bash
docker compose run --rm api admin-password
```

Open <http://localhost:8099> and sign in as `admin`.

Use `localhost`, not a LAN address. The session cookie is host-prefixed and `Secure`,
which browsers accept over plain HTTP on `localhost` only. Any other host needs TLS in
front — see [Deployment](deployment.md).

### Choosing your own password instead

Put it in a `.env` file beside the compose file **before the first start**:

```bash
XENOPROXY_ADMIN_PASSWORD=a-long-passphrase-you-chose
```

An explicit value always wins over the generated one.

### When the password is refused

The credential is applied when the account is **created**. If the password has since been
changed, or you set `XENOPROXY_ADMIN_PASSWORD` after the first start, it is not applied
retroactively. Reapply it:

```bash
docker compose run --rm api reset-admin
```

That resets the password to the configured value, clears two-factor enrolment, revokes
every open session and re-arms the forced change at next sign-in. Pass a password as an
argument to use a different one. The command reports exactly what it changed.

This is also the way back in when an administrator loses their authenticator.

### Two-factor authentication

Two-factor is required for administrators by default. At first sign-in you are asked to
enrol an authenticator: the page shows the secret to type into your application, and a
set of recovery codes shown once.

To change the requirement without being able to sign in, pin it in `.env` and restart:

```bash
BACKEND_REQUIRE_MFA_FOR_ADMINS=false
```

A setting pinned by environment is shown read-only in the interface, marked as managed by
the environment. Details in [Users, rights and authentication](users-and-rights.md#two-factor-authentication).

## The first source

XenoProxy starts with ten keyless analyzers already enabled — DNS, RDAP, IPinfo, crt.sh,
RIPEstat, Shodan InternetDB, the Tor exit list, DNS blocklists, URLScan and the abuse.ch
Feodo tracker. You can run a real analysis before configuring anything.

To add a source that needs a key, go to **Plugins & keys**. Each plugin states who serves
it, the endpoint XenoProxy calls, where to create the key, what the free tier allows and
the rate limit to expect. Paste the key and enable the plugin; the credential is sealed
and never returned to a browser afterwards.

Use **Test** on a configured plugin to confirm the provider answers with your key before
an analyst depends on it.

The catalogue, and what each provider expects, is in [Plugins and playbooks](plugins.md).

## A first analysis

Go to **New scan**, paste an observable and let the type be detected. Pick a playbook — the
`Free sources only` one needs no key — and run it. The job page updates live as each
source answers.

The analyst's view of all this is in the [Analyst guide](help/analyst.md). A condensed
version is served in the application itself, under the `?` button.

## What to do next

- Put [TLS and a reverse proxy](deployment.md#tls-and-the-reverse-proxy) in front before
  anyone else uses it.
- Connect your [directory or identity provider](users-and-rights.md) so analysts sign in
  with their own accounts.
- Set up [backups](operations.md#backups), and read what must be kept beside the database.
