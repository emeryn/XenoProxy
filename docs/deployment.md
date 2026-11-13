# Deployment

[Documentation](README.md) · [Configuration](configuration.md) · [Operations](operations.md)

Docker and rootless Podman are the two supported targets. There is no Kubernetes manifest.

| Target | Commands |
|---|---|
| Docker | `docker compose build`<br>`docker compose up -d` |
| Podman (rootless) | `podman compose build`<br>`podman compose up -d` |

The compose file uses only features both engines support: no host paths outside the
repository, no published port below 1024, and no CPU limits, which many rootless cgroup
setups do not provide.

## What runs

Six long-lived services, plus a one-shot `secrets-init` that generates the secrets into a
named volume and exits.

| Service | Role |
|---|---|
| `proxy` | The only service publishing a port. Terminates TLS, owns the security headers and the rate limits. |
| `frontend` | Unprivileged nginx serving the built single-page application. |
| `api` | FastAPI: authentication, authorization, job submission, administration. |
| `worker` | arq worker: runs the plugins. Never reachable from outside. |
| `database` | PostgreSQL, on an internal network with no route out. |
| `queue` | Redis, password-protected, holding the job queue. |

Every container runs as a numeric non-root user with a read-only filesystem, all
capabilities dropped and `no-new-privileges`. See [Security](security.md#containment).

## TLS and the reverse proxy

The edge proxy is the only component that publishes a port to the network, and the session cookie is
`Secure`, so anything other than `localhost` needs TLS.

`deploy/nginx/nginx.conf` ships with the TLS block commented out and ready: TLS 1.3,
hybrid post-quantum key exchange (`X25519MLKEM768`) first in the curve list, HSTS, a
content security policy, and rate limits on the sensitive routes. Uncomment it, mount your
certificate and set `BACKEND_PUBLIC_URL` to the public URL — the OIDC redirect is built
from it.

The `X-Remote-*` headers are cleared on every proxied request, so a client cannot forge a
delegated identity by sending them itself. If you put another proxy in front, set
`BACKEND_TRUSTED_PROXY_COUNT` to the number of hops, or the client address in the audit
trail will be your own proxy's.

### Using the Nginx you already run

The bundled proxy is a convenience, not a requirement. On a host that already terminates
TLS for everything else, two things get in each other's way — the certificates, the ACME
renewal, the logs, the fail2ban jails — so it is cleaner to let the host own the edge.

The frontend and the API each publish a port on the loopback interface for exactly this:

| Service | Address | What answers |
|---|---|---|
| `frontend` | `127.0.0.1:8098` | the static assets |
| `api` | `127.0.0.1:8097` | `/api/...` |

Nothing outside the machine can reach either one: the binding is `127.0.0.1`, not `0.0.0.0`.

Take the bundled proxy out of the way first, so one thing owns port 443 and one set of
logs tells the whole story:

```bash
docker compose up -d --scale proxy=0
```

Then install [`deploy/nginx/xenoproxy-host.conf`](../deploy/nginx/xenoproxy-host.conf) as a
site — `/etc/nginx/sites-available/` with a symlink on Debian and Ubuntu,
`/etc/nginx/conf.d/` on RHEL and AlmaLinux — set the server name and the certificate paths,
and reload:

```bash
nginx -t && systemctl reload nginx
```

It mirrors the container configuration: the same security headers, the same rate-limit
zones, the same cleared `X-Remote-*` headers, and the same unbuffered location for the job
event stream — without it the interface looks frozen until a job ends. TLS is on rather
than commented out, because a host proxy is the public edge and the session cookie is
`Secure`.

Two settings have to follow:

- `BACKEND_PUBLIC_URL` is the public URL, since the OIDC redirect is built from it;
- `BACKEND_TRUSTED_PROXY_COUNT` counts the proxies in front of the application, this one
  included. Get it wrong and the audit trail records the proxy's address instead of the
  analyst's.

For hardening the host Nginx itself — jails, WAF, blocklists, systemd sandboxing — see the
`reverse-proxy-hardening` material; this file stops at what XenoProxy needs.

With SELinux enforcing, a host Nginx is refused outbound connections until
`setsebool -P httpd_can_network_connect on`.

## Egress proxy and internal certificate authorities

Every outbound call a plugin makes goes through one HTTP client. It takes an egress proxy
and an internal certificate authority bundle, either from the environment
(`BACKEND_OUTBOUND_PROXY_URL`, `BACKEND_CUSTOM_CA_FILE`) or from **Settings › Network**,
where a connection test tells you whether the route works before you save it.

The bundle is held in memory and loaded into the TLS context directly; it is never written
to disk. Certificate verification cannot be disabled — there is no setting for it. If your
proxy intercepts TLS, give XenoProxy its authority.

The worker re-reads the network settings at the start of every job, so a change applies to
the next job without a restart.

## Secrets in production

By default `secrets-init` generates the secrets into a named volume, which is right for an
evaluation and acceptable for a single host. For anything larger, point the `*_FILE`
variables at files your secrets provider delivers, and keep the volume out of it.

The master key deserves its own handling: it wraps every plugin credential, and a database
backup without it restores an instance whose stored keys cannot be read.

## Backups

See [Operations](operations.md#backups) for the procedure and the restore drill. The short
version: `python scripts/backup.py` dumps the database, `python scripts/restore_test.py`
proves the newest dump restores, and the master key is backed up **separately**.

## Upgrading

```bash
docker compose pull            # or: docker compose build
docker compose up -d
```

Migrations run at API startup. A plugin dropped from a release leaves its configuration
behind on purpose — the row may hold a credential — and startup logs a warning naming it.
Remove them deliberately with `docker compose run --rm api prune-plugins`.
