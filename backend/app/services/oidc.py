"""OIDC authorization code flow with PKCE.

Discovery, JWKS and the token endpoint are reached through the shared HTTP
client, so the proxy and internal certificate authority apply here too. The
`state`, `nonce` and PKCE verifier live in a short-lived signed cookie rather
than in server memory, so the flow survives a restart and several API replicas.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from joserfc import jwt
from joserfc.jwk import KeySet

from app.core.config import get_settings
from app.core.errors import AppError, UnauthorizedError
from app.core.http_client import get, post
from app.core.logging import get_logger

logger = get_logger(__name__)

STATE_COOKIE = "__Host-oidc-state"
STATE_TTL_SECONDS = 600
_DISCOVERY_PATH = "/.well-known/openid-configuration"

_metadata_cache: tuple[float, dict[str, Any]] | None = None
_jwks_cache: tuple[float, Any] | None = None
_CACHE_TTL_SECONDS = 3600


class OidcNotConfiguredError(AppError):
    status_code = 503
    code = "OIDC_NOT_CONFIGURED"


@dataclass(frozen=True)
class OidcIdentity:
    """The claims XenoProxy maps onto a user account."""

    subject: str
    username: str
    email: str | None
    display_name: str | None
    groups: list[str]


def _require_config() -> tuple[str, str, str]:
    settings = get_settings()
    if not settings.oidc_enabled:
        raise OidcNotConfiguredError("Single sign-on is not enabled on this instance.")
    if not (settings.oidc_issuer and settings.oidc_client_id and settings.oidc_client_secret):
        raise OidcNotConfiguredError(
            "Single sign-on is enabled but the issuer, client id or client secret is missing."
        )
    return (
        settings.oidc_issuer.rstrip("/"),
        settings.oidc_client_id,
        settings.oidc_client_secret,
    )


async def _metadata() -> dict[str, Any]:
    """Fetch and cache the provider discovery document."""
    global _metadata_cache
    issuer, _, _ = _require_config()
    now = time.monotonic()
    if _metadata_cache and now - _metadata_cache[0] < _CACHE_TTL_SECONDS:
        return _metadata_cache[1]

    response = await get(f"{issuer}{_DISCOVERY_PATH}", timeout=15)
    if not response.ok or not isinstance(response.json_body, dict):
        raise OidcNotConfiguredError("The provider discovery document could not be read.")
    _metadata_cache = (now, response.json_body)
    return response.json_body


async def _jwks() -> Any:
    global _jwks_cache
    now = time.monotonic()
    if _jwks_cache and now - _jwks_cache[0] < _CACHE_TTL_SECONDS:
        return _jwks_cache[1]

    metadata = await _metadata()
    jwks_uri = str(metadata.get("jwks_uri") or "")
    if not jwks_uri:
        raise OidcNotConfiguredError("The provider advertises no JWKS endpoint.")
    response = await get(jwks_uri, timeout=15)
    if not response.ok or not isinstance(response.json_body, dict):
        raise OidcNotConfiguredError("The provider signing keys could not be read.")
    key_set = KeySet.import_key_set(response.json_body)
    _jwks_cache = (now, key_set)
    return key_set


def _sign(payload: bytes) -> str:
    key = get_settings().secret_key.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def seal_state(data: dict[str, str]) -> str:
    """Sign the flow state so the callback can trust what the browser returns."""
    payload = json.dumps({**data, "ts": int(time.time())}, separators=(",", ":")).encode()
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{body}.{_sign(payload)}"


def open_state(token: str) -> dict[str, str]:
    try:
        body, signature = token.split(".", 1)
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError) as exc:
        raise UnauthorizedError("The sign-on state is malformed.") from exc

    if not hmac.compare_digest(signature, _sign(payload)):
        raise UnauthorizedError("The sign-on state could not be verified.")

    data: dict[str, Any] = json.loads(payload)
    if int(time.time()) - int(data.get("ts", 0)) > STATE_TTL_SECONDS:
        raise UnauthorizedError("The sign-on attempt expired; start again.")
    return {key: str(value) for key, value in data.items()}


async def build_authorization_url(redirect_uri: str) -> tuple[str, str]:
    """Return the provider URL to redirect to, and the state to store in a cookie."""
    _, client_id, _ = _require_config()
    settings = get_settings()
    metadata = await _metadata()
    endpoint = str(metadata.get("authorization_endpoint") or "")
    if not endpoint:
        raise OidcNotConfiguredError("The provider advertises no authorization endpoint.")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode("ascii")
        .rstrip("=")
    )

    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    sealed = seal_state({"state": state, "nonce": nonce, "verifier": verifier})
    return f"{endpoint}?{query}", sealed


async def exchange_code(
    *, code: str, redirect_uri: str, state_token: str, returned_state: str
) -> OidcIdentity:
    """Validate the callback, exchange the code and verify the identity token."""
    _, client_id, client_secret = _require_config()
    stored = open_state(state_token)
    if not hmac.compare_digest(stored.get("state", ""), returned_state):
        raise UnauthorizedError("The sign-on state does not match.")

    metadata = await _metadata()
    token_endpoint = str(metadata.get("token_endpoint") or "")
    if not token_endpoint:
        raise OidcNotConfiguredError("The provider advertises no token endpoint.")

    response = await post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": stored.get("verifier", ""),
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    if not response.ok or not isinstance(response.json_body, dict):
        logger.warning("oidc_token_exchange_failed", status_code=response.status_code)
        raise UnauthorizedError("The identity provider refused the sign-on.")

    id_token = str(response.json_body.get("id_token") or "")
    if not id_token:
        raise UnauthorizedError("The identity provider returned no identity token.")

    issuer, _, _ = _require_config()
    algorithms = [
        str(algorithm)
        for algorithm in metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
        if str(algorithm) != "none"
    ]
    try:
        token = jwt.decode(id_token, await _jwks(), algorithms=algorithms)
        claims = token.claims
    except Exception as exc:
        logger.warning("oidc_id_token_invalid", error=str(exc))
        raise UnauthorizedError("The identity token could not be verified.") from exc

    if str(claims.get("iss", "")).rstrip("/") != issuer:
        raise UnauthorizedError("The identity token was issued by another provider.")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in [str(entry) for entry in audiences]:
        raise UnauthorizedError("The identity token was issued for another client.")
    if str(claims.get("nonce", "")) != stored.get("nonce", ""):
        raise UnauthorizedError("The identity token nonce does not match.")
    expiry = claims.get("exp")
    if not isinstance(expiry, int) or expiry < int(time.time()):
        raise UnauthorizedError("The identity token has expired.")

    groups_claim = claims.get("groups") or claims.get("roles") or []
    groups = [str(group) for group in groups_claim] if isinstance(groups_claim, list) else []

    username = str(
        claims.get("preferred_username") or claims.get("email") or claims.get("sub") or ""
    )
    return OidcIdentity(
        subject=str(claims.get("sub") or ""),
        username=username,
        email=str(claims["email"]) if claims.get("email") else None,
        display_name=str(claims["name"]) if claims.get("name") else None,
        groups=groups,
    )


def safe_next_path(candidate: str | None) -> str:
    """Accept only a relative path, which closes the open-redirect hole."""
    if not candidate:
        return "/"
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/"
    return candidate[:512]
