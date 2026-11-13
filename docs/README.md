# XenoProxy documentation

[XenoProxy](../README.md) · [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md) · [Licence](../LICENSE)

Everything about running XenoProxy, connecting your sources and opening it to your
analysts. Start with [Getting started](install.md); the rest is read when you need it.

## Run it

| Page | What is in it |
|---|---|
| [Getting started](install.md) | First start, the administrator password and what to do when it is refused, the first source, two-factor enrolment. |
| [Configuration](configuration.md) | Every environment variable, with its default and what it changes, and which settings are edited in the interface instead. |
| [Deployment](deployment.md) | TLS and the reverse proxy, rootless Podman, egress proxies and internal certificate authorities, backups and what to keep where. |
| [Operations](operations.md) | Day-to-day commands, stopping and retrying work, the audit trail, backups and restore drills, upgrading. |

## Use it

| Page | What is in it |
|---|---|
| [Analyst guide](help/analyst.md) | Submitting an observable, reading a verdict, the cache, exporting a report. A condensed version is served in the application under the `?` button. |
| [Plugins and playbooks](plugins.md) | The three plugin types, the analyzer catalogue with what each provider needs, playbooks, the cache, and how configuration layers resolve. |
| [REST API and MCP](api.md) | Authenticating a script, the endpoints, personal tokens, and the two MCP servers. |
| [Assistant](assistant.md) | The chatbot on a model you host, what it can read, and agent mode with its limits. |

## Open it to your team

| Page | What is in it |
|---|---|
| [Users, rights and authentication](users-and-rights.md) | Roles and permissions, local accounts, OpenID Connect, LDAP, group mapping, two-factor authentication, API tokens. |
| [Administrator guide](help/administrator.md) | The same ground from the interface's point of view, step by step. A condensed version is served in the application under the `?` button. |
| [Security](security.md) | What the product does for credentials, egress, authorization, integrity and containment — and what is left to you. |
| [Threat model](threat-model.md) | Assets, trust boundaries, the risks considered and the control answering each. |

## Work on it

| Page | What is in it |
|---|---|
| [Architecture](architecture.md) | The components, what happens from submission to verdict, the data model, and the repository layout. |
| [Writing a plugin](plugin-example/README.md) | A complete worked analyzer, the manifest, and how to install it without rebuilding the image. |
| [Development](development.md) | Running the checks, the test suites, the conventions, and regenerating the screenshots. |
| [Functional specification](specification.md) | The reference for behaviour: observables, plugin phases, precedence, cache, failure handling, access. |
