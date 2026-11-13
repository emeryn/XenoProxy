# XenoProxy functional specification

XenoProxy centralises the OSINT and threat-intelligence sources a team of analysts
uses, behind one authenticated interface. Credentials stay in the backend, scans
run in parallel, and results are shared and cached so the team does not spend the
same API quota twice.

## 1. Observables

Input is refanged, normalised and classified before anything runs.

| Type | Accepted forms |
|---|---|
| `ip` | IPv4 and IPv6, including `1.1.1[.]1` |
| `domain` | FQDN, trailing dot and case tolerated |
| `url` | `http`, `https`, `ftp`, including `hxxps://` |
| `hash` | MD5, SHA1, SHA256, SHA512 |
| `file` | Modelled; submission is not implemented in 0.1.0 |
| `generic` | Email address, ASN, other short free text |

Loopback, link-local and RFC1918 targets are refused unless
`BACKEND_ALLOW_PRIVATE_TARGETS` is enabled for internal analyzers.

## 2. Plugins

Every integration is a **plugin**: a class registered declaratively with the
observable types it supports, the credentials it needs, its options, timeout and
cache lifetime. A plugin declares its **type**, which is what decides when in a
job it runs. The type comes from the class, never from the file it lives in, so
moving a module cannot silently change how it is scheduled.

| Type | Base class | When it runs | What it does |
|---|---|---|---|
| Analyzer | `BaseAnalyzer` | Analysis phase, concurrently | Reads one observable and reports on it |
| Connector | `BaseConnector` | After a verdict exists | Publishes the finished job to another platform |
| Pivot | `BasePivot` | After the connectors | Derives the next observable and creates a child job |

An analyzer returns the provider payload (`raw_output`) and a normalised
`summary_data`: verdict, score, tags, open ports, CVEs, geolocation, detection
ratio and provider links. A connector and a pivot report in the same shape, so
the interface renders every phase the same way.

A plugin never raises for a provider-side problem: it reports it. That is what
keeps one failing integration from failing the job around it.

### Analyzers

| Analyzer | Types | Credential | Notes |
|---|---|---|---|
| `shodan` | ip | API key | Ports, banners, CVEs, ASN |
| `censys` | ip, domain, url | API ID + secret | Services and TLS fingerprints |
| `virustotal` | ip, domain, url, hash | API key | Detection ratio and reputation |
| `abuseipdb` | ip | API key | Abuse confidence and categories |
| `urlscan` | url, domain, ip | API key (submission only) | Indexed scans, optional live scan |
| `onyphe` | ip, domain, url | API key | Aggregated exposure and threat lists |
| `ipinfo` | ip | Token (optional) | Geolocation, ASN, privacy flags |
| `threatfox` | ip, domain, url, hash | Auth-Key | Known IOC matches |
| `malwarebazaar` | hash | Auth-Key | Sample metadata |
| `feodotracker` | ip | — | Botnet C2 blocklist |
| `urlhaus` | url, domain, ip | Auth-Key | Malware distribution URLs |
| `circl_hashlookup` | hash | — | Known-good file filtering |
| `joesandbox_cloud` | hash, url, file | API key | Behavioural verdicts from the free cloud; submissions are published, so TLP:CLEAR only |
| `joesandbox_enterprise` | hash, url, file | API key + appliance URL | Same, on your own appliance; submissions stay private, so up to TLP:RED |
| `dns` | domain, url, ip | — | A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR |
| `rdap` | domain, url, ip | — | Registration, expiry, abuse contact |
| `n8n` | all | Webhook URL | Asks an existing workflow about the observable, signed with HMAC-SHA256 |

### Connectors

A connector is selected by intent, never by observable type: it is offered
because the operator wants results exported, not because the observable happens
to be an IP. It runs only once the analysis phase has aggregated a verdict —
running it alongside the analyzers would publish an empty verdict.

| Connector | Credential | Notes |
|---|---|---|
| `opencti_export` | Platform URL + token | Creates the STIX observable, with the verdict as its confidence score and the job's tags as labels |
| `n8n_webhook` | Webhook URL | Posts the finished job so a workflow can open a ticket, notify a channel or file a report |

A connector may decline a job, and says why: a verdict below its configured
floor, an analysis that failed outright, or an observable type it cannot export.
A declined export is recorded as `SKIPPED` with the reason, never omitted.

### Pivots

A pivot turns a single enrichment into an investigation. It reads the finished
job, decides whether the result warrants going further, and names the
observables worth analysing next; the orchestrator creates one child job per
derived observable, linked to its parent by `parent_job_id`, `pivot_name` and
`depth`.

| Pivot | From | Children run | Derives |
|---|---|---|---|
| `url_to_domain` | url | Domain reconnaissance | The host of the flagged URL |
| `url_to_ip` | url | Fast IP triage | The address URLScan observed serving it |
| `domain_to_ip` | domain, url | Fast IP triage | The A and AAAA records the DNS analyzer already resolved |

Three guards bound the fan-out, and they are enforced by the framework rather
than by each pivot: `max_children` per pivot, `max_pivot_children_per_job`
across a whole job, and `max_pivot_depth` on the chain from the job an analyst
submitted. `pivots_enabled` turns child creation off instance-wide while leaving
pivots selectable, so they report what they would have done.

A pivot acts only on a suspicious or malicious verdict by default, which is what
makes automatic pivoting affordable. A derived observable that the SSRF policy
refuses — a non-routable address, say — is recorded and skipped; it is a normal
outcome, not a pivot failure.

### Installed plugin packages

A plugin of any type can be supplied as a package, so a team can add one without
rebuilding the image. A package is a folder holding a `plugin.json` manifest and
the module its entrypoint names; it is installed by dropping the folder into the
plugins volume or by uploading a zip from the administration interface. The
format is documented in `docs/plugin-example/`.

An uploaded archive is validated before anything is written: path traversal,
absolute paths, symbolic links, over-compressed or oversized archives and file
types other than `.py`, `.json`, `.txt`, `.md`, `.cfg`, `.ini` and `.toml` are
refused, and a package may not take the name of a built-in plugin. The declared
class must satisfy the same rules the built-in registry applies — an analyzer
declares its supported types, a pivot declares its child playbook — so a bad
package fails at load with a readable reason rather than inside a job. A package
that fails to load is reported with its error and does not affect the service.

Plugin code runs with the backend's privileges. Installation needs the
`plugins:manage` permission and is recorded in the audit trail with the archive
digest. `BACKEND_PLUGINS_UPLOAD_ENABLED=false` restricts installation to the
volume; `BACKEND_PLUGINS_ENABLED=false` disables packages entirely.

## 3. Playbooks

A playbook is a named plugin pipeline scoped to observable types: one list per
phase, so the orchestrator schedules each without re-deriving a plugin's kind.
Eight are provisioned on first boot — fast IP triage, IP deep dive, domain
reconnaissance, URL triage, hash triage, free sources only, and two
investigation playbooks that include pivots. The two pivot playbooks ship
**disabled**, because a stock playbook must never create extra jobs without an
administrator having chosen that. No built-in playbook names a connector, for
the same reason applied to data leaving the instance. Administrators create
their own; built-in ones can be disabled but not deleted.

## 4. Configuration precedence

A plugin's effective configuration resolves over four layers, lowest priority
first:

1. the class declaration — `options_schema` defaults and `default_timeout`;
2. the instance configuration an administrator sets;
3. the analyst's own preferences, under Settings;
4. the `runtime_configuration` carried by a single job.

Layer 3 exists so an analyst can use a personal provider account without
touching the team's shared subscription. Only an option or credential the plugin
marks `user_overridable` may be set there. Nothing that points a plugin at a
different endpoint or relaxes a network restriction is overridable per user — a
personal `base_url` or `allow_private_target` would turn that layer into a way
around the instance's outbound policy, and a test asserts no built-in plugin
exposes one.

## 5. Cache

Before an analyzer runs, the engine looks for a successful report for the same
`(observable, analyzer)` inside that analyzer's cache window, 24 hours by
default. A hit is copied into the new job and flagged `from_cache`, with no
external call. `force_rescan` bypasses the lookup. A cache lifetime of zero
disables reuse for that analyzer.

Only analyzer reports are cacheable, and the lookup enforces it. Serving a
connector report from cache would claim an export took place when it did not,
and a pivot's decision is specific to one parent job, so neither is reusable.

## 6. Execution and failure

A job is created with one `PENDING` report per selected plugin, then queued. The
worker runs three phases in order:

1. **Analysis** — every analyzer runs concurrently, each in its own database
   session, under a configurable concurrency limit, consulting the cache first.
2. **Connectors** — the verdict and summary are aggregated, then every selected
   connector publishes the finished result.
3. **Pivots** — every selected pivot inspects the finished job and creates its
   child jobs.

A failure, timeout or HTTP 429 marks only that report `FAILED` with an explicit
reason. The job becomes:

- `SUCCESS` when every report succeeded,
- `PARTIAL_FAILURE` when some succeeded and some failed or were stopped,
- `FAILED` only when none succeeded,
- `KILLED` when it was stopped before anything succeeded.

The job verdict is the worst verdict any successful **analyzer** reported. A
connector reporting "exported successfully" says nothing about whether the
address is malicious, and a pivot reporting "two observables to analyse next"
says nothing either, so neither votes. A failed export still degrades the job to
`PARTIAL_FAILURE`, because the analyst needs to see it.

### Stopping and retrying

`POST /jobs/{id}/kill` stops a running job. The cancellation is cooperative: the
orchestrator checks before it starts each plugin and between phases, so nothing
further starts and reports already finished are kept. A provider call already in
flight is left to finish — aborting it would leave a half-written report and, for
a submission-style provider, lose the scan identifier needed to collect the
result.

`POST /jobs/{id}/reports/{report_id}/retry` re-arms one failed, killed or
skipped plugin instead of re-running the whole job, so a transient provider
failure is cheap to recover from and the other reports' quota is untouched.

`POST /admin/plugins/{name}/healthcheck` probes whether a plugin's provider
answers and records the outcome, which is what the Admin list's reachability
column shows.

## 7. Access

Authentication is local accounts, OIDC with PKCE, or identity delegated by a
trusted reverse proxy. All users share one organisation so history and cache are
pooled; every job records `requested_by`.

| Permission | analyst | admin |
|---|---|---|
| Run scans, read history, tag, export | yes | yes |
| Manage personal API tokens | yes | yes |
| Set own plugin options and credentials | yes | yes |
| Configure credentials and plugins | no | yes |
| Manage playbooks, plugin packages and users | no | yes |
| Read the audit trail | no | yes |

## 8. Interface

- **New scan**: live type detection, defang, filtering to analyzers that can
  actually run, playbook presets, tags, force-refresh switch. Connectors and
  pivots sit behind a separate section and are never pre-selected: one sends the
  result to a third party and the other creates further jobs, so both have to be
  a deliberate choice.
- **Jobs**: shared history with filters and pagination held in the URL.
- **Job detail**: aggregated verdict banner, live progress, reports grouped by
  phase, one tab per plugin with the normalised view and a collapsible raw
  payload, a stop button while it runs, a per-plugin retry, the derived
  observables with links to the child jobs, and JSON and Markdown export.
- **Dashboard**: counters linking to the filtered list, cache hit ratio.
- **Admin**: credentials, plugin activation, limits and health probes, playbooks,
  plugin packages, users, audit.

## 9. API

Every interface action maps to a documented REST endpoint under `/api/v1`.
Scripts and n8n authenticate with a personal token as `Authorization: Bearer`.
Mutating calls accept an `Idempotency-Key` so a retry cannot create a second job.

## 10. Not in this version

File submission for static analysis, LDAP binding (OIDC and proxy delegation
are implemented), PDF export, and an MCP endpoint. Of the IntelOwl plugin model,
visualizers and ingestors are not implemented, and neither are the analyzable
and investigation entities: a job carries its observable directly, and an
investigation is reconstructed from the pivot lineage rather than stored as its
own record.
