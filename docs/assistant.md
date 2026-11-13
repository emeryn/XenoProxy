# Assistant

[Documentation](README.md) · [Configuration](configuration.md) · [REST API and MCP](api.md)

A chatbot inside the application, backed by **a model you host**. There is no external AI
service: the inference server is yours, the backend is its only client, and the browser
never calls it.

## Connecting a model

Under **Settings › Assistant**, a *connection* holds where the model is and how
it answers — the server, the model, the generation parameters and the
credentials. The settings beneath it hold the policy: whether the assistant is
on, who may use it, whether it may write. Keeping the two apart means switching
from a local Ollama to a hosted gateway changes nothing about who is allowed to
do what.

Several connections can be saved and one is active. Each offers a **Test** that
lists the models the server returns, which proves the address and the key before
anything depends on them.

| API shape | Endpoints used |
|---|---|
| Ollama | `/api/tags`, `/api/chat` |
| OpenAI-compatible | `/v1/models`, `/v1/chat/completions` — vLLM, llama.cpp server, LocalAI, TGI, and hosted gateways such as OpenRouter |

A gateway often wants its own headers rather than only `Authorization`. A
connection takes any number of them, as `Name: value` lines. Their **values are
sealed** with the API key and never returned; only the names come back, which
is enough to show the shape of a connection without holding its secrets.

For OpenRouter, the base URL is `https://openrouter.ai/api`, the key goes in the
API key field, and the model is the identifier as listed — a `:free` suffix
marks the models that cost nothing.

Models are discovered from the server rather than hardcoded. Temperature, top-p, maximum
tokens and the context window are set per endpoint, and the interface shows the parameters
that are actually in effect — some servers silently ignore what they do not support.

The section has a connection test that lists the models before you save.

The endpoint URL is an administrator-only setting and is validated like any other outbound
address: private ranges need the explicit allowance. See [Security](security.md#egress).

## What it can read

The assistant answers about the jobs **the analyst asking may see**. Its tools go through
the same authorization as the REST API, so it can never show someone a job they could not
open themselves.

The system prompt is visible and editable in the same section, with a reset to the
shipped default that does not delete conversations.

## Agent mode

Off by default. When enabled, the assistant may chain tool calls — looking up a job,
searching payloads, submitting a scan — within bounds:

- A maximum number of steps and a timeout per turn.
- Every tool call checked against the asking analyst's permissions, re-checked at call
  time rather than trusted from the catalogue.
- Write actions require the permission the equivalent REST call would.
- The step trace is visible, so the analyst sees what it did rather than only the answer.

Model output is untrusted: it is rendered through a sanitiser, with no raw HTML and no
automatically loaded remote images — an image URL is an exfiltration channel.

## The judgement connector

Separately from the chatbot, the `ai_assessment` connector can run at the end of a job: the
model reads every source's report and gives its own verdict, confidence, reasoning, the
findings it considered decisive, and any disagreement between sources it noticed.

It records an opinion **beside** the aggregated verdict and never overrides it. A model's
judgement is evidence for the analyst, not the answer.

## Exposing it to your own agent

The two [MCP servers](api.md#mcp-servers) let an agent outside XenoProxy do the same
work. Both are off by default, both authenticate with an API token, and neither elevates
beyond the permissions of the token's owner.
