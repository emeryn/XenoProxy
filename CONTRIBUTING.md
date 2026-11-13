# Contributing to XenoProxy

Thanks for taking the time. This file is short on purpose: it says what you need to run the project,
what a change is expected to look like, and how it gets reviewed.

## Before you write code

- **A bug**: open an issue with what you did, what happened and what you expected. The version in the
  sidebar and the relevant log lines help more than anything else. Logs are structured JSON and carry
  a `request_id`; include it.
- **A feature**: open an issue first and say what problem it solves. XenoProxy has a lot of surface
  already, and the cheapest change is the one that turns out to be unnecessary.
- **A security issue**: do not open an issue. See [SECURITY.md](SECURITY.md).

Small, obvious fixes (a typo, a wrong link, an off-by-one in a message) need no issue — send the pull
request.

## Running it

Docker is the only prerequisite; nothing is installed on the host, and there is no `make`.

```bash
docker compose up -d                              # http://localhost:8099
docker compose run --rm api admin-password        # the first administrator's password
```

The checks run in containers too, because the runtime image deliberately carries no development
tooling. The exact commands are in [Development](docs/development.md).

```bash
docker build --target test -t xenoproxy-tests ./backend
docker run --rm -v "$PWD:/repo" -w /repo/backend xenoproxy-tests pytest -q
docker run --rm -v "$PWD:/repo" -w /repo/backend xenoproxy-tests ruff check app tests
```

## What a change should look like

- **Tests.** A behaviour that matters has a test, and a bug fix comes with the test that was failing.
  The suite is fast and runs offline — no database, no network.
- **Keep the diff about one thing.** Reformatting, renaming and fixing in one pull request makes the
  change impossible to review.
- **Match the surrounding code.** Same naming, same comment density, same idiom. Comments explain
  *why*, never what the line below already says, and never what changed — that is what the history is
  for.
- **English** in the code, the comments, the commit messages and the interface.
- **Type hints** on the Python side, **TypeScript** with no `any` on the frontend. `ruff check`
  and `tsc --noEmit` must pass, and CI enforces both.
- **`mypy app` is not a gate yet.** It reports 41 findings, nearly all of them SQLAlchemy's
  generic types rather than defects. Do not add to them, and a patch that clears a file is
  welcome on its own.
- **Authorization goes through the existing choke point.** Every route declares the permission it
  needs, and a test fails the build when one does not. A new endpoint, a new MCP tool or a new
  assistant tool declares one too; none of them bypasses `app/api/deps.py`.
- **Outbound calls go through `app/core/http_client.py`.** It is what refuses private addresses after
  DNS resolution, re-validates redirects and applies the proxy and the certificate authorities. A
  plugin that calls `httpx` directly is a finding waiting to happen.
- **A migration** for every change to a model, in `backend/migrations/versions/`. Every revision after
  the baseline is written with the introspection guards in `app/core/schema_guards.py`, because the
  baseline uses `create_all` and a later revision may meet a table it already created.
- **Dependencies** are pinned exactly, in `backend/pyproject.toml` and `frontend/package.json`, with
  the lock file in the commit. Both audits fail the build, so a dependency with a known advisory does
  not merge.

## A new analyzer

Most contributions are one. A plugin declares what it supports, what it needs and what it may be
trusted with, and the registry refuses it at import time if the declaration is inconsistent:

- `supported_types` is mandatory for an analyzer;
- `max_tlp` is the most sensitive observable the source may see. A source that **publishes** what it
  receives is `Tlp.CLEAR`, and that is not a formality — it is the difference between a lookup and a
  disclosure;
- `ProviderInfo` says who serves it, which endpoint is called, where to get a key, what the free tier
  allows. An administrator configuring it reads that and nothing else;
- the result carries both the provider's raw payload and a normalised `PluginSummary`.

A complete worked example is in [docs/plugin-example/](docs/plugin-example/README.md).

## Documentation

A feature that is not documented does not exist for the person who has to operate it. A change that
adds or alters behaviour updates, as needed:

- [`docs/`](docs/README.md) — one page per subject, written for whoever runs the instance;
- the in-application help (`frontend/src/app/HelpPage.tsx`) — for whoever uses it;
- the docstring at the top of the module, when the change is about *how* something works.

## Pull requests

- Branch off `main`, one subject per branch.
- Say in the description what the change does and why, and how you checked it.
- CI runs the backend tests, the frontend build, both images and the migrations on PostgreSQL on
  every push. Keep it green.
- By opening a pull request you agree that your contribution is licensed under the
  [Apache License 2.0](LICENSE), like the rest of the project. There is no CLA.

Source files carry no licence header: `LICENSE` covers the whole repository.

## Code of conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
