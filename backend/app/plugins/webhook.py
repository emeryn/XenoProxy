"""Signed outbound webhook helper, shared by the webhook-shaped plugins.

The n8n integration exists in two shapes — an analyzer that asks a workflow
about an observable, and a connector that tells a workflow a job finished — and
both must authenticate the same way. The signing scheme lives here so the two
cannot drift apart, which would silently break whichever side the workflow was
written against.

The signature covers `"{timestamp}.{body}"` with HMAC-SHA256, so a receiver can
reject a replayed payload by checking the timestamp window as well as the
digest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from app.core import http_client

SIGNATURE_HEADER = "X-XenoProxy-Signature"
TIMESTAMP_HEADER = "X-XenoProxy-Timestamp"


def canonical_body(payload: dict[str, Any]) -> str:
    """Serialise a payload deterministically, so the digest is reproducible."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)


def signature_headers(body: str, signing_key: str) -> dict[str, str]:
    """Build the timestamp and signature headers for a body."""
    timestamp = str(int(time.time()))
    digest = hmac.new(
        signing_key.encode("utf-8"),
        f"{timestamp}.{body}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return {TIMESTAMP_HEADER: timestamp, SIGNATURE_HEADER: f"sha256={digest}"}


async def post_signed(
    url: str,
    payload: dict[str, Any],
    *,
    # The provider deadline the plugin was configured with, handed to the HTTP
    # client; this is not a cancellation scope, so asyncio.timeout does not apply.
    timeout: int,  # noqa: ASYNC109
    allow_private: bool,
    signing_key: str | None = None,
    auth_header: str | None = None,
    auth_token: str | None = None,
) -> http_client.HttpResult:
    """POST a JSON payload, signed and authenticated as configured."""
    body = canonical_body(payload)
    headers = {"Content-Type": "application/json"}
    if auth_token and auth_header:
        headers[auth_header] = auth_token
    if signing_key:
        headers.update(signature_headers(body, signing_key))

    return await http_client.post(
        url,
        content=body,
        headers=headers,
        timeout=timeout,
        allow_private=allow_private,
    )


def coerce_json_object(raw: Any) -> dict[str, Any]:
    """Normalise whatever a workflow returned into a JSON object.

    n8n returns a bare list when the workflow ends on a node with several
    items, and a scalar when it ends on a Set node, so neither shape is an
    error worth failing the report over.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        return {"items": raw}
    return {"value": raw}
