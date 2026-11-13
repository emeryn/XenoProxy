# Writing an XenoProxy plugin

A plugin adds an analyzer, a connector or a pivot to XenoProxy without rebuilding
the image. It is a folder with a manifest and at least one Python module,
installed either by dropping it into the plugins volume or by uploading a zip
from **Admin, Plugin packages**.

Which of the three you are writing is decided by the base class you inherit,
not by the manifest:

| Base class | Module | Implement | Runs |
|---|---|---|---|
| `BaseAnalyzer` | `app.plugins.base.analyzer` | `run(observable)` | During the analysis phase |
| `BaseConnector` | `app.plugins.base.connector` | `run(context)` | After a verdict exists |
| `BasePivot` | `app.plugins.base.pivot` | `run(context)` | After the connectors |

## Structure

```
greynoise_community/          folder named exactly like "name" in the manifest
├── plugin.json               the manifest, required, at the folder root
└── analyzer.py               the module the entrypoint names
```

Extra modules, a `README.md` and data files are allowed. Only `.py`, `.json`,
`.txt`, `.md`, `.cfg`, `.ini` and `.toml` files are accepted.

## plugin.json

```json
{
  "api_version": 1,
  "name": "greynoise_community",
  "version": "1.0.0",
  "label": "GreyNoise Community",
  "description": "What the source answers, in one sentence.",
  "author": "Your team",
  "homepage": "https://provider.example/api-docs",
  "entrypoint": "analyzer:GreyNoiseCommunityAnalyzer"
}
```

| Field | Required | Rule |
|---|---|---|
| `api_version` | yes | `1` for this XenoProxy release |
| `name` | yes | lowercase letters, digits and underscores, 3 to 48 characters; must equal the folder name **and** the class's `name` attribute |
| `version` | yes | `1.0.0` style |
| `entrypoint` | yes | `module:ClassName`, the module path relative to the folder |
| `label`, `description`, `author`, `homepage` | no | shown in the interface |

## The plugin class

Inherit the base class for your type, declare the metadata, implement `run`. The
`analyzer.py` beside this file is a complete working analyzer. The rules that
matter for every type:

- `name` must match the manifest.
- Declare each credential with `SecretSpec`. The administrator fills them in the
  interface and they are stored encrypted; read them with `self.secret("api_key")`.
  Pass `user_overridable=True` only for a personal provider account, never for
  something that redirects the plugin.
- Declare options in `options_schema` with a `default` and a `label`, and read
  them with `self.option("key", default)`.
- Perform HTTP calls through `app.core.http_client`. It applies the egress
  proxy, the internal certificate authority, timeouts and the SSRF guard. A
  plugin that opens its own socket bypasses all of that.
- Return `self.ok(raw, summary)`, `self.not_found(...)`, `self.skipped(...)` or
  `self.provider_http_error(...)`, and raise `PluginQuotaError` on HTTP 429.
- Set `max_tlp` to the highest handling level the plugin tolerates. Anything
  that sends the observable to a third party caps at `Tlp.AMBER`; a source that
  publishes or indexes the query caps at `Tlp.CLEAR`.
- Do not catch broad exceptions. The engine turns any failure into a `FAILED`
  report for your plugin alone, without affecting the rest of the job.

Per type:

- an **analyzer** must declare a non-empty `supported_types`;
- a **connector** receives a `JobContext` — the observable, the aggregated
  verdict, the tags, the summary and every analyzer report — and may decline a
  job by overriding `refusal_reason`. Leave `supported_types` empty to export
  whatever the job produced;
- a **pivot** must declare `child_playbook`, the playbook its child jobs run,
  and returns observables with `self.pivot_to([...], reason=...)` or declines
  with `self.no_pivot(...)`. `max_children` bounds its fan-out, and the
  instance's depth and per-job limits apply on top. A derived observable the
  SSRF policy refuses is skipped, not scanned.

## Installing

Zip the folder and upload it in **Admin, Plugin packages**:

```bash
cd docs/plugin-example
zip -r greynoise_community.zip greynoise_community
```

An archive wrapped in a single top-level folder is accepted too, so a GitHub
"Download ZIP" works as is.

Alternatively, copy the folder into the plugins volume and press **Rescan** on
the same page:

```bash
docker compose cp docs/plugin-example/greynoise_community api:/app/plugins/
```

Then configure the credential and enable it in **Admin, Plugins & keys**,
exactly as for a built-in plugin.

## What a plugin can and cannot do

A plugin runs inside the backend with the backend's privileges. Installing one
is as consequential as installing a Python package: read the code first, and
accept plugins only from a source you trust. The archive digest is recorded in
the audit trail.

The container still constrains it: no shell, no compiler, a read-only
filesystem, dropped capabilities, and an in-process guard that refuses process
creation.

Installing a new plugin takes effect without a restart. **Updating** one that is
already loaded needs a backend restart, because the previous module stays
imported; the interface says so after an upgrade.
