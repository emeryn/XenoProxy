# Operations

[Documentation](README.md) · [Deployment](deployment.md) · [Administrator guide](help/administrator.md)

## Everyday commands

| Command | Purpose |
|---|---|
| `docker compose up -d --build` | Build and start the stack |
| `docker compose down` | Stop it, keeping the data |
| `docker compose logs -f` | Follow the logs |
| `docker compose ps` | Service health |
| `docker compose run --rm api migrate` | Apply the database migrations |
| `docker compose run --rm api admin-password` | Read the generated administrator password |
| `docker compose run --rm api reset-admin` | Reset the first administrator: password, two-factor enrolment, open sessions |
| `docker compose run --rm api prune-plugins` | Delete configuration and credentials of plugins that no longer exist |
| `python scripts/backup.py` | Dump the database into `./backups` |
| `python scripts/restore_test.py` | Prove the newest dump restores |
| `python scripts/clean_prod.py` | Pre-production cleanup and secret scan |

The scripts are plain Python and need no `make`, so they behave the same on Windows and
Linux.

## Stopping and retrying work

A job that is taking too long can be stopped from its page: running plugins finish their
current step and the rest are marked as stopped.

A single failed plugin can be retried on its own, without re-running the ones that
succeeded — which matters when the others cost quota. A report is retryable when it
failed, was stopped or was skipped.

## Failure is partial, not total

A source that fails, times out or hits HTTP 429 marks **that report** as failed, with the
reason, and the job finishes as partially failed. The other sources still complete. A job
never fails as a whole because one provider had a bad day.

A quota error is distinguished from a failure, so you can tell "the key is exhausted" from
"the provider is down" on the job page.

## Audit

Every sign-in, failure, role change, configuration change, credential write, export and
MCP tool call is recorded with the user, the address, the user agent, the UTC time and the
before-and-after values. Secrets are redacted, and header values are redacted too.

Entries are append-only and chained to the previous entry's hash. **Verify** on the audit
page walks the chain and reports where it breaks.

## Backups

```bash
python scripts/backup.py          # dump into ./backups
python scripts/restore_test.py    # restore the newest dump into a scratch database
```

Back up three things, and not all in the same place:

1. **The database** — jobs, reports, users, settings, sealed credentials.
2. **The master key** — without it the sealed credentials in that dump are unreadable.
   Keep it somewhere the database backup is not.
3. **The plugins volume**, if you installed plugin packages.

A restore drill that has never been run is not a backup. `restore_test.py` exists so the
drill is one command.

## Upgrading

```bash
docker compose build
docker compose up -d
```

Migrations run at API startup. If a release drops a plugin, its configuration row stays —
it may hold a credential — and startup logs a warning naming it. Remove them deliberately
with `prune-plugins`.

## Statistics

The dashboard shows what the team has been doing: jobs over a window, how many came back
malicious, who is submitting, and the share of reports served from the cache. Every figure
links to the filtered list behind it.

The cache ratio is the one to watch: it is the quota you did not spend.
