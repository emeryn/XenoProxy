# Administering XenoProxy

## First sign-in

The first administrator's password is generated on first boot into the secrets
volume, so no credential is written in `docker-compose.yml` and none travels in
an environment variable that `docker inspect` would show. Read it once with:

```bash
docker compose run --rm api admin-password
```

To choose your own instead, set `XENOPROXY_ADMIN_PASSWORD` in a `.env` file beside
the compose file before the first start; an explicit value wins over the
generated one. In production, point `BACKEND_BOOTSTRAP_ADMIN_PASSWORD_FILE` at
your secrets provider.

Whether that first sign-in also demands a password change is the setting
**Force a password change at first sign-in**, under Admin, Settings, Security.
It is off by default, because the generated password is already private to
whoever can read the secrets volume. Turn it on where passwords are handed out
by a person — it then covers accounts an administrator creates and the
administrator's password reset as well.

### Lost password, or the configured credential is refused

The credential is applied when the account is **created**, never on later boots,
so an existing administrator password is never silently overwritten. If it was
already changed, or you edited the compose value afterwards, the configured
credential will be refused. Reapply it from the host:

```bash
docker compose run --rm api reset-admin
```

It resets the password to the configured value, revokes every open session and
requires a change at the next sign-in. `docker compose run --rm api reset-admin
"another password"` uses a different one. The command is deliberately not
exposed over the API: running it requires access to the host, and it is written
to the audit trail.

It also clears the account's two-factor enrolment and its recovery codes, and
revokes every open session, so it recovers an administrator who lost their
authenticator as well as one who lost their password. Where the instance
requires two-factor for administrators, the next sign-in enrols a fresh one.

## Configuring an API key

1. Open **Admin > Plugins & keys** and expand the plugin's **Settings**.
2. Paste the credential and save. It is sealed in the backend vault immediately;
   afterwards only its last four characters are ever displayed. It is never sent
   to the browser, written to a log or included in an API error.
3. Tick **Enabled**. A plugin cannot be enabled while a required credential is
   missing.
4. Press **Probe** to check the provider actually answers. The outcome is kept
   and shown in the list, so an unreachable provider is visible without opening
   every row.

Deleting a required credential disables the plugin. Every change is written to
the audit trail with the administrator's name.

Some credentials are marked **Analysts may override**. An analyst can then store
their own account for that provider under **Settings**, and it applies to their
own jobs only; the shared subscription still covers everyone else and every
other credential.

## Timeouts, cache and options

Each source has its own timeout, cache lifetime and options. The cache lifetime
is what protects a paid quota: with the default of 24 hours, the same observable
queried twice in a day costs one call. Setting it to 0 disables reuse for that
source.

Only an analyzer has a cache lifetime. A connector records that an export
happened, so serving one from cache would claim an export that did not occur,
and a pivot's decision belongs to one parent job; neither is reusable.

Plugins that call an internal service (n8n, OpenCTI) have a base URL option and
an "allow a target on the internal network" switch. Leave that switch off for
anything reachable from the internet. Neither option can be overridden per
analyst: that would make the personal configuration layer a way around the
instance's outbound policy.

## The three plugin types

A plugin declares which phase of a job runs it, and the Admin list states it on
every row:

- an **analyzer** reads the observable and reports on it. These decide the
  verdict;
- a **connector** runs once a verdict exists and publishes the finished job
  somewhere else. **Enabling one allows job data to leave this instance**;
- a **pivot** runs last, derives the next observable from the finished job and
  creates a child job for it. **Enabling one allows a job to create further
  jobs.**

Connectors and pivots are off on a fresh deployment and are never selected
automatically: an analyst who submits a scan without naming anything gets
analyzers only. Both have to be chosen, in the scan form or in a playbook.

### Bounding what pivots can do

Three settings under **Admin > Settings**, section Scanning, bound the fan-out:

- **Maximum pivot depth** — how far a chain may go from the job an analyst
  submitted. This is what makes a pivot loop terminate.
- **Maximum child jobs one job may create** — summed across every pivot of a
  job.
- **Let pivots create child jobs** — turning this off keeps pivots selectable
  but makes them report what they would have done, creating nothing. Use it to
  try a pivot playbook before trusting it.

Each pivot also has its own `max_children`. A derived observable that the
instance's SSRF policy refuses, such as a non-routable address, is recorded and
skipped rather than scanned.

## Playbooks

A playbook is a plugin pipeline scoped to observable types, with one list per
phase: analyzers, then connectors, then pivots. A playbook whose pivot list is
not empty is flagged **Creates child jobs**; one with connectors is flagged
**Exports results**.

Built-in playbooks can be disabled but not deleted, so a known-good baseline
always remains. The two investigation playbooks that include pivots ship
**disabled**: a stock playbook must not create extra jobs until an administrator
has chosen that. No built-in playbook names a connector, for the same reason
applied to data leaving the instance.

## Users and roles

Identities come from local accounts, OIDC, or headers delegated by a trusted
reverse proxy. `analyst` runs scans and exports; `admin` additionally manages
credentials, plugins, playbooks and users. You cannot remove your own
administrator role or disable your own account.

If single sign-on is configured by environment variable, those settings win and
are shown read-only in the interface.

## Adding a plugin package

**Admin, Plugin packages** installs an analyzer, a connector or a pivot without
rebuilding the image, in either of two ways:

- upload a zip holding a `plugin.json` manifest, or
- copy the plugin folder into the plugins volume and press **Rescan the
  volume**:
  `docker compose cp ./my_plugin api:/app/plugins/`

The archive is checked before anything is written: path traversal, absolute
paths, symbolic links, oversized or over-compressed archives and unexpected file
types are refused, and a package cannot take the name of a built-in plugin. The
declared class must also satisfy the rules for its type — an analyzer declares
the observables it reads, a pivot declares the playbook its children run — so a
bad package fails at load with a readable reason instead of inside a job. A
package that fails to load is listed with its error rather than breaking the
service.

A plugin runs inside the backend with its privileges, so treat installing one
like installing a Python package: read the code, and accept plugins only from a
source you trust. The archive digest is recorded in the audit trail. Set
`BACKEND_PLUGINS_UPLOAD_ENABLED=false` to allow only the volume route, or
`BACKEND_PLUGINS_ENABLED=false` to forbid plugins entirely.

Once installed, configure its credentials and enable it in **Plugins & keys**
as for any other plugin. The format is documented in `docs/plugin-example/`,
with a working example.

A new plugin is picked up immediately. Replacing one already loaded needs a
backend restart: `docker compose restart api worker`.

## Audit

**Admin > Audit** lists every sign-in, credential change, configuration change
and export. Each entry carries the hash of the previous one; **Verify the chain**
recomputes it and names the first altered entry if the trail was tampered with.

## Backups

`python scripts/backup.py` writes a dump into `./backups`. Encrypt it before
storing it, and keep the encryption key separate from the backup. Plugin
credentials in a restored dump are unreadable without the master key, so back
the master key up separately too. `python scripts/restore_test.py` proves the
newest dump can be read back.

## Two-factor authentication

Three things can make it mandatory: **Require two-factor for everyone**,
**Require two-factor for administrators** (on by default), or a group whose
*Require two-factor* flag is set.

An account that owes an enrolment can reach almost nothing, including the
settings page, so those two instance settings can also be pinned by the
deployment:

```
BACKEND_REQUIRE_MFA_FOR_ADMINS=false
```

in a `.env` beside the compose file, or in the compose file itself. A pinned
setting is shown read-only in the interface with a *Managed by the environment*
badge, and the endpoint refuses a change to it as well.

Enrolment happens in **My access**: the secret is shown once, as text and as an
`otpauth://` link, with ten recovery codes that each work once. Turning
two-factor off needs both the password and a current code, so losing either one
cannot be used to remove the second factor.

## Instance settings

**Admin, Settings** holds what applies to the whole deployment. The scalar
switches — sessions, two-factor, scanning defaults, pivot limits, retention —
are changed one at a time. The other groups are **sections**: a subsystem saved
as a whole, because its fields only make sense together, each with a **Test
connection** button that probes the values *before* they are saved.

A field pinned by an environment variable is shown read-only with a *Managed by
the environment* badge, and the endpoint refuses it too: hiding an input is a
courtesy, not a control.

### Network and certificates

The proxy every outbound call goes through, and the certificate authorities it
trusts. Paste your internal root CA in PEM form to reach a service with a
private PKI, or to work behind a TLS-inspecting proxy. There is deliberately no
switch to disable verification: trusting your own authority is the supported
answer, and the bundle is held in memory rather than written to disk.

The route applies to analyzers, connectors and the assistant at once. The worker
re-reads it at the start of each job, so a change reaches analyzer traffic
without a restart.

### Assistant

The chatbot talks to an inference server **you** run: Ollama, or anything
speaking the OpenAI API (vLLM, llama.cpp, LocalAI, TGI). Never publish that
server's port — most have no authentication at all. The browser never calls it;
the backend does, through the network settings above.

**Test connection** lists the models the server actually serves, so a typo in
the model name is caught before an analyst meets it.

**Agent mode** lets the model call the XenoProxy API. Three things bound it:

- it uses the session of the analyst who is chatting, so it can never read a job
  they could not read or do what they could not do;
- write tools (submit a scan, tag a job) exist only when **Allow writes** is on,
  and the check is enforced on the call, not only on the catalogue;
- the loop stops at **Maximum steps**.

Every tool call is logged, and the analyst sees the full trace under each
answer. The system prompt is editable, and an empty one falls back to the
shipped default shown beside it.

### Configuration transfer

**Export** downloads every setting and section as JSON. It carries **no
credential**: moving an API key between instances through a browser download is
how a key ends up in a ticket. **Import** validates the whole document before
applying anything, keeps this instance's own secrets, and skips what the
environment pins here.
