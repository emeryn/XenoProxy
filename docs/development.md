# Development

[Documentation](README.md) · [Architecture](architecture.md) · [Writing a plugin](plugin-example/README.md)

## Running the checks

The runtime images carry no development tooling on purpose — no shell, no compiler, no
pytest — and they are read-only. So the checks run in their own containers.

**Frontend**, against the working tree:

```bash
docker run --rm -v "$PWD/frontend:/w" -w /w node:22.21.0-alpine3.22 \
  sh -c "npm ci && npx tsc --noEmit && npx eslint src && npm run build"
```

**Backend**: build a throwaway image with the development extras on top of the runtime
one, then run it against the source.

```bash
docker build -t xenoproxy/backend-test:local - <<'EOF'
FROM xenoproxy/backend:0.1.0
USER root
RUN /opt/venv/bin/pip install --no-cache-dir pytest pytest-asyncio ruff mypy respx aiosqlite
EOF

docker run --rm -v "$PWD/backend:/src" -w /src -e PYTHONPATH=/src \
  --entrypoint /opt/venv/bin/python xenoproxy/backend-test:local -m pytest -q

docker run --rm -v "$PWD/backend:/src" -w /src \
  --entrypoint /opt/venv/bin/ruff xenoproxy/backend-test:local check app tests
```

Use `sh -c`, not `sh -lc`: a login shell resets `PATH` from `/etc/profile` and the
application's virtual environment at `/opt/venv` disappears from it.

## Conventions

- **Python**: `ruff` for lint and format, `mypy --strict`, `pytest`. Lines at 100 columns.
- **TypeScript**: `tsc --strict` with `noUncheckedIndexedAccess`, `eslint`, `prettier`.
- **Naming**: `snake_case` modules and functions, `PascalCase` classes and React
  components, `kebab-case.ts` for other TypeScript files, kebab-case plural API paths.
- **Comments explain why, never what.** No commented-out code, and no comment describing a
  change — the code reads as if it had always been written that way, and the history lives
  in the commit message.
- **Dependencies are pinned exactly** and lockfiles are committed.

A component that merges a caller's `className` with its own uses `cn()` from
`src/lib/cn.ts`, not `clsx`. Tailwind resolves a conflict by the order of the rules in the
stylesheet, not by the order in the attribute, so a primitive's `w-full` silently beats a
caller's `w-auto`; `cn()` merges them properly.

## Tests

The backend suite covers authorization (including a test that fails the build when a route
declares no permission), the plugin registry, the orchestrator's failure handling, the
crypto, identity and the settings sections.

```bash
# one file
docker run --rm -v "$PWD/backend:/src" -w /src -e PYTHONPATH=/src \
  --entrypoint /opt/venv/bin/python xenoproxy/backend-test:local -m pytest -q tests/test_plugins.py
```

## Screenshots

The README screenshots are captured from the running application, never mocked up. The
suite signs in, seeds a few fictitious jobs through the API, waits for them to finish and
photographs the views.

```bash
docker compose up -d
docker run --rm --network host -v "$PWD:/repo" -w /repo/frontend \
  -e XENOPROXY_BASE_URL=http://localhost:8099 \
  -e XENOPROXY_DEMO_PASSWORD=<the admin password> \
  mcr.microsoft.com/playwright:v1.56.0-noble npx playwright test
```

Captures are 1440×900, dark theme, with fictitious data only. Regenerate them when the
interface changes visibly.

## Scanning

```bash
trivy image xenoproxy/backend:0.1.0                                      # CVEs, secrets, misconfiguration
trivy config .                                                            # Dockerfiles and compose
trivy image --format cyclonedx -o sbom.json xenoproxy/backend:0.1.0      # CycloneDX SBOM
python scripts/clean_prod.py                                              # pre-production cleanup and secret scan
```

The dependency audits are not a separate step: `pip-audit --strict` and
`npm audit --audit-level=high` run inside the image builds and **fail** them.

## Adding a plugin

Start from [Writing a plugin](plugin-example/README.md). A plugin can be developed against
a running stack without rebuilding an image, by dropping it into the plugins volume.

## Project conventions worth knowing

- **No Makefile.** Tasks are `docker compose` invocations and plain Python scripts in
  `scripts/`, so they behave identically on Windows and Linux.
- **The baseline migration uses `create_all`.** Every revision after it is written with
  introspection guards (`app/core/schema_guards.py`) so it is idempotent against a
  database the baseline already shaped. Freezing the baseline as explicit DDL is the real
  fix and has not been done.
- **Two constants in `app/core/crypto.py` still read `argus`.** They are HKDF `info`
  parameters from before the rename: changing them derives different keys and every stored
  credential stops decrypting. The file says so.

## Continuous integration

`.github/workflows/ci.yml` runs on a pull request, on a push to `main`, and is *called* by the
publish workflow so a release is gated by the same tests rather than a copy of them.

| Job | What it proves |
|---|---|
| Backend tests | The suite and `ruff`, in the image's `test` stage — the same dependency set as production |
| Frontend build | `eslint`, then `tsc -b && vite build` |
| Images build | Both runtime images, including the two dependency audits that fail the build |
| Migrations | Every revision applies to PostgreSQL, then applies again over the schema it just made |

The migration job checks **idempotency**, not a down-cycle: the baseline shapes the schema with
`create_all` over the current models, so `downgrade base` drops tables in an order that does not
match the revision it claims to undo. Idempotency is what the guards in `app/core/schema_guards.py`
promise, and that is what is gated.

`mypy app` is not in the gate. It reports 41 findings, nearly all of them SQLAlchemy's generic
types rather than defects, and a gate that is red from the first push teaches people to ignore it.

`.github/workflows/publish.yml` turns a push to `dev` into images tagged `dev` and `dev-<sha>`, and
a `v*` tag into the release tags plus `latest`. Each image is built once and pushed to Docker Hub
and GitHub Packages, so both registries carry the same digest.

```bash
docker pull skouedlabs/xenoproxy-backend:dev
docker pull ghcr.io/skouedlabs/xenoproxy-backend:dev
```

GitHub Packages needs no secret: the run's own token pushes there, under the repository owner.
Docker Hub needs `DOCKERHUB_USERNAME` (a repository variable or a secret) and `DOCKERHUB_TOKEN`.
Set `DOCKERHUB_NAMESPACE` as well when the images live under an organisation rather than under the
account that signs in — pushing to an organisation means authenticating as a member of it, so the
two names are not necessarily the same. Left unset, the namespace is the login name.
