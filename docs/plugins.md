# Plugins and playbooks

[Documentation](README.md) · [Functional specification](specification.md) · [Writing a plugin](plugin-example/README.md)

A plugin's type is declared on its class and decides which phase of a job runs it.

| Type | When it runs | What it does |
|---|---|---|
| **Analyzer** | The analysis phase, in parallel | Enriches the observable from one source |
| **Connector** | After the analysis, on the finished job | Publishes the result, or judges it |
| **Pivot** | Last, on a suspicious or malicious verdict | Derives the next observable and creates a child job |

Connectors and pivots are never selected automatically: one sends data to a third party,
the other creates more jobs. Both have to be chosen.

## Analyzers

Twenty-two, of which ten need no credential and are enabled from the start.

### Keyless, and enabled from the start

| Plugin | Observables | What it adds |
|---|---|---|
| `dns` | domain, url, ip | A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR |
| `rdap` | domain, url, ip | Registration, expiry, abuse contact |
| `ipinfo` | ip | Geolocation, ASN, privacy flags (a token raises the quota) |
| `crtsh` | domain, url | Certificate transparency: every name ever certified, and when |
| `ripestat` | ip, ASN | The announcing prefix, its autonomous system, the abuse contact |
| `shodan_internetdb` | ip | Open ports, hostnames and CVEs, from Shodan's free endpoint |
| `dnsbl` | ip | Spamhaus, SpamCop, Barracuda, SORBS — malicious only at two or more listings |
| `tor_exit` | ip | Whether the address is a Tor exit node |
| `urlscan` | url, domain | Submission and retrieval, screenshot, DOM, associated addresses (a key raises the quota) |
| `feodotracker` | ip | The abuse.ch botnet command-and-control blocklist |

### Keyless, but off until you enable it

| Plugin | Observables | What it adds |
|---|---|---|
| `circl_hashlookup` | hash | CIRCL's known-good set: filters out files that ship with an operating system |

### Key required

| Plugin | Observables | Credential |
|---|---|---|
| `shodan` | ip | API key |
| `censys` | ip, domain | API ID and secret |
| `virustotal` | ip, domain, url, hash | API key (v3) |
| `abuseipdb` | ip | API key |
| `onyphe` | ip, domain, url | API key |
| `threatfox` | ip, domain, url, hash | Auth-Key |
| `malwarebazaar` | hash | Auth-Key |
| `urlhaus` | url, domain, ip | Auth-Key |
| `joesandbox_cloud` | hash, url, file | API key — **submissions are published**, so TLP:CLEAR only |
| `joesandbox_enterprise` | hash, url, file | API key and your appliance URL — submissions stay private, up to TLP:RED |
| `n8n` | all | Your own webhook URL |

Every plugin states, in the interface, who serves it, the endpoint XenoProxy calls, where
to create the key, what the free tier allows and the rate limit to expect. That is the
answer to "what do I paste here".

### Sources that answer for an address

`shodan`, `shodan_internetdb`, `ipinfo` and `abuseipdb` index *hosts*, not names.
Given a domain or a URL they resolve it first and report on the address, saying
which one in the headline — so scanning a URL tells you where it is hosted and
what is open there, without pivoting by hand. The resolved address goes through
the same check the submitted observable passed, so a name resolving into a
private range cannot be used to reach the internal network.

## Connectors

| Plugin | What it does |
|---|---|
| `opencti_export` | Creates or updates the observable in OpenCTI, verdict as confidence score, tags as labels |
| `n8n_webhook` | Posts the finished job to an n8n workflow, signed with HMAC-SHA256 |
| `ai_assessment` | A model you host reads every source's report and gives its own verdict, with its reasoning and any disagreement it finds |

`ai_assessment` records an opinion beside the aggregate. It does **not** override the
job's verdict: a model's judgement is evidence for the analyst, not the answer.

Outbound webhooks carry `X-XenoProxy-Signature` (HMAC-SHA256) and
`X-XenoProxy-Timestamp` when a signing key is configured, so the receiving workflow can
verify them.

## Pivots

| Plugin | Derives |
|---|---|
| `url_to_domain` | The host of the URL |
| `url_to_ip` | The addresses the URL resolves to |
| `domain_to_ip` | The addresses the domain resolves to |

A pivot only acts on a suspicious or malicious verdict, and is bounded three ways: how
many children one pivot may create, how many a job may create in total, and how deep the
chain may go. Each derived observable is validated like any other input, so a pivot cannot
be used to reach an internal address.

## Playbooks

A playbook is a preset pipeline for one or more observable types: the analyzers to run,
and optionally the connectors and pivots. Eight ship with the product, two of them using
pivots and shipped disabled.

| Playbook | For | Runs |
|---|---|---|
| Fast IP triage | ip | Reputation, exposure and geolocation |
| IP deep dive | ip | Everything available, threat feeds included |
| Domain reconnaissance | domain, url | Registration, DNS, certificates, reputation |
| URL triage | url | Reputation and page analysis |
| Hash triage | hash | Known-good filtering first, then malware intelligence |
| Free sources only | all | Every source that needs no paid quota |
| Domain investigation with pivots | domain | Reconnaissance, then down to the hosting addresses |
| URL investigation with pivots | url | Triage, then to the domain and the hosting address |

Administrators can create their own under **Playbooks**.

## The cache

Before calling a paid provider, the orchestrator looks for a valid report for the same
`(observable, plugin)` pair inside that plugin's window. A hit costs no external call and
is marked as served from cache on the report.

The window is per plugin, defaulting to `BACKEND_CACHE_DEFAULT_TTL_SECONDS` (24 hours).
Set it to zero to disable caching for a source whose answers change by the minute.

An analyst can tick **force a refresh** on a scan to bypass it, which spends the quota of
every selected source.

The cache is shared across the team: that is the point. A lookup one analyst made this
morning costs nothing when a colleague repeats it this afternoon.

## Configuration layers

Four layers, each overriding the one before:

1. **The class** — what the plugin's author declared: supported types, default timeout,
   default cache window, maximum TLP.
2. **The instance** — what an administrator set under Plugins & keys.
3. **The analyst** — their own options, and their own credential where the plugin allows
   one, so a team can share an instance without sharing a personal quota.
4. **The job** — what was chosen when the scan was submitted.

## Adding a plugin

Drop a folder into the plugins volume, or upload a zip under **Plugin packages**. No image
rebuild. A complete worked example, with its manifest, is in
[Writing a plugin](plugin-example/README.md).
