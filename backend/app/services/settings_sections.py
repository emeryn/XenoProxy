"""Declaration of every settings section an administrator edits.

Each section is a Pydantic model: its fields, their bounds and the reason they
exist. `app_settings` stores, seals and serves them; this module only says what
they are, so adding a subsystem is one model and two dictionary entries.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
# Each part can match in exactly one way: with the dot excluded from the
# character classes the engine has nothing to backtrack over, so a crafted
# address cannot make this quadratic.
EMAIL_RE = re.compile(r"^[^@\s<>,;]{1,64}@[^@\s<>,;.]{1,63}(\.[^@\s<>,;.]{1,63}){1,8}$")
_PROXY_URL = re.compile(r"^(https?|socks5h?)://[^\s]+$")
_SERVER_URL = re.compile(r"^https?://[^\s/]+(/[^\s]*)?$")
LDAP_URL_PATTERN = r"^ldaps?://[^\s/]+(:\d{1,5})?/?$"


class NetworkSettings(BaseModel):
    """Outbound access: the proxy to go through, and the authorities to trust.

    Every call an analyzer, a connector or the assistant makes goes through the
    central HTTP client, so what is set here applies to all of them at once.

    The certificate bundle exists because an inspecting TLS proxy, or an
    internal service with a private PKI, presents a certificate no public store
    knows. The alternative an operator reaches for is disabling verification,
    which is why there is no switch for that: trusting your own authority is the
    supported answer.
    """

    http_proxy: str = Field("", max_length=1024)
    https_proxy: str = Field("", max_length=1024)
    no_proxy: str = Field("localhost,127.0.0.1", max_length=2048)
    proxy_username: str = Field("", max_length=256)
    proxy_password: str = Field("", max_length=1024)
    # Additional authorities in PEM form, for an internal root CA or a company
    # TLS-inspecting proxy. Appended to the system store, never replacing it.
    ca_bundle: str = Field("", max_length=1_048_576)

    @field_validator("http_proxy", "https_proxy")
    @classmethod
    def _proxy(cls, value: str) -> str:
        value = value.strip()
        if value and not _PROXY_URL.match(value):
            raise ValueError("a proxy URL is expected, for example http://proxy.internal:3128")
        return value

    @field_validator("ca_bundle")
    @classmethod
    def _pem(cls, value: str) -> str:
        value = value.strip()
        if value and PEM_HEADER not in value:
            raise ValueError("one or more PEM certificates are expected")
        return value

    @property
    def configured(self) -> bool:
        return bool(self.http_proxy or self.https_proxy or self.ca_bundle)


class AssistantSettings(BaseModel):
    """The in-application assistant: a chatbot answering about the jobs.

    The model runs on a server of your own — Ollama, or anything speaking the
    OpenAI API (vLLM, llama.cpp, LocalAI, TGI). XenoProxy is its only client: the
    browser never calls it, and the connection uses the proxy and the
    certificate authorities of the Network section.
    """

    enabled: bool = False
    # ollama: /api/tags, /api/chat · openai: /v1/models, /v1/chat/completions
    provider: Literal["ollama", "openai"] = "ollama"
    base_url: str = Field("", max_length=1024)
    # Most local inference servers have no authentication at all.
    api_key: str = Field("", max_length=1024)
    # Extra headers for a gateway that wants its own routing or tenant key.
    headers: dict[str, str] = Field(default_factory=dict)
    model: str = Field("", max_length=256)
    timeout: int = Field(120, ge=5, le=900)

    # Generation. A server silently ignores what it does not support, so the
    # interface shows what the chosen API would actually receive.
    temperature: float = Field(0.2, ge=0, le=2)
    top_p: float = Field(0.95, ge=0, le=1)
    # Ollama: num_predict · OpenAI: max_tokens
    max_tokens: int = Field(2048, ge=64, le=32768)
    # Ollama: num_ctx. 0 leaves it to the server, which often means a small
    # window; raise it when the agent reads large tool results.
    context_tokens: int = Field(0, ge=0, le=1_048_576)
    stop: list[str] = Field(default_factory=list)
    history_messages: int = Field(20, ge=2, le=200)

    # Agent mode: the model calls the XenoProxy API through the session of the
    # analyst who is chatting, so it can never do what that analyst could not.
    agent_enabled: bool = False
    max_steps: int = Field(8, ge=1, le=30)
    # Tools that change something: submit a scan, tag a job. They still obey the
    # analyst's permissions, and a write is confirmed before it runs.
    allow_writes: bool = False

    # Who may use the assistant: these groups and these accounts. Everyone when
    # both are empty; administrators always.
    groups: list[str] = Field(default_factory=list, max_length=50)
    # Empty uses the prompt shipped with the application.
    system_prompt: str = Field("", max_length=32_768)
    # Conversations older than this are purged; 0 keeps them.
    retention_days: int = Field(30, ge=0, le=3650)
    rate_per_minute: int = Field(20, ge=1, le=600)

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if value and not _SERVER_URL.match(value):
            raise ValueError(
                "the address of the inference server is expected, for example "
                "http://ollama.internal:11434"
            )
        return value

    @field_validator("stop")
    @classmethod
    def _stop(cls, value: list[str]) -> list[str]:
        kept = [entry for entry in (str(item) for item in value) if entry]
        if len(kept) > 8:
            raise ValueError("at most 8 stop sequences")
        if any(len(entry) > 200 for entry in kept):
            raise ValueError("a stop sequence is at most 200 characters")
        return kept

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 20:
            raise ValueError("at most 20 headers")
        for name, content in value.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
                raise ValueError(f"'{name}' is not a valid header name")
            if len(str(content)) > 1024:
                raise ValueError(f"the value of '{name}' is too long")
            # A header XenoProxy sets itself must not be overridable from settings.
            if name.lower() in {"host", "content-length", "authorization"}:
                raise ValueError(f"'{name}' is set by XenoProxy and cannot be overridden")
        return {name: str(content) for name, content in value.items()}

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.model)


class OidcSettings(BaseModel):
    """Single sign-on with OpenID Connect, authorization code flow with PKCE.

    Every field can also be pinned by an environment variable. A value coming
    from the environment wins and is shown read-only in the interface, so a
    headless deployment stays authoritative and nobody can widen it from a
    browser.
    """

    enabled: bool = False
    label: str = Field("Single sign-on", max_length=64)
    issuer: str = Field("", max_length=1024)
    client_id: str = Field("", max_length=256)
    client_secret: str = Field("", max_length=1024)
    scopes: str = Field("openid profile email", max_length=512)
    groups_claim: str = Field("groups", max_length=128)
    admin_group: str = Field("xenoproxy-admins", max_length=256)
    # Create an account on the first successful sign-in.
    auto_provision: bool = True

    @field_validator("issuer")
    @classmethod
    def _issuer(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if value and not value.startswith("https://"):
            # The discovery document and the signing keys are what authenticate
            # the provider; fetching them over plain HTTP authenticates nothing.
            raise ValueError("the issuer must be an https:// address")
        return value

    @property
    def configured(self) -> bool:
        return bool(self.issuer and self.client_id)


class LdapSettings(BaseModel):
    """Authentication against a directory, over LDAPS or StartTLS.

    The filters take `{username}` and `{user_dn}`. The value substituted into
    them is escaped before the query is built, so a user name cannot alter the
    filter it appears in.
    """

    enabled: bool = False
    label: str = Field("Company directory", max_length=64)
    server_url: str = Field("", max_length=1024)
    start_tls: bool = False
    timeout: int = Field(10, ge=1, le=120)
    bind_dn: str = Field("", max_length=1024)
    bind_password: str = Field("", max_length=1024)
    user_base_dn: str = Field("", max_length=1024)
    user_filter: str = Field("(&(objectClass=person)(uid={username}))", max_length=1024)
    username_attr: str = Field("uid", max_length=64)
    display_name_attr: str = Field("cn", max_length=64)
    email_attr: str = Field("mail", max_length=64)
    group_mode: Literal["memberof", "search", "none"] = "memberof"
    group_base_dn: str = Field("", max_length=1024)
    group_filter: str = Field("(&(objectClass=groupOfNames)(member={user_dn}))", max_length=1024)
    group_name_attr: str = Field("cn", max_length=64)
    admin_group: str = Field("", max_length=256)

    @field_validator("server_url")
    @classmethod
    def _server(cls, value: str) -> str:
        value = value.strip()
        if value and not re.match(LDAP_URL_PATTERN, value):
            raise ValueError("an ldaps:// or ldap:// address is expected")
        return value

    @field_validator("user_filter", "group_filter")
    @classmethod
    def _filter(cls, value: str) -> str:
        value = value.strip()
        if value and value.count("(") != value.count(")"):
            raise ValueError("unbalanced parentheses in the filter")
        return value

    @property
    def configured(self) -> bool:
        return bool(self.server_url and self.user_base_dn)


class SmtpSettings(BaseModel):
    """Outgoing mail server, used by the notification channels of type e-mail."""

    host: str = Field("", max_length=256)
    port: int = Field(587, ge=1, le=65535)
    # starttls: upgraded in place (587) · tls: TLS from the start (465) ·
    # none: a relay on the local network that offers no encryption.
    security: Literal["starttls", "tls", "none"] = "starttls"
    username: str = Field("", max_length=256)
    password: str = Field("", max_length=1024)
    sender: str = Field("", max_length=320)
    timeout: int = Field(20, ge=1, le=120)

    @field_validator("sender")
    @classmethod
    def _sender(cls, value: str) -> str:
        value = value.strip()
        if value and not EMAIL_RE.match(value):
            raise ValueError("an e-mail address is expected")
        return value

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender)


class NotificationsSettings(BaseModel):
    """When XenoProxy tells someone that a job finished badly.

    A notification goes out for a finished job whose verdict reaches the floor,
    which is what keeps a quiet instance quiet. The webhook is signed the way
    the n8n connector signs its payload, so a receiver can verify it came from
    here.
    """

    enabled: bool = False
    minimum_verdict: Literal["clean", "unknown", "suspicious", "malicious"] = "malicious"
    email_enabled: bool = False
    recipients: list[str] = Field(default_factory=list, max_length=50)
    webhook_enabled: bool = False
    webhook_url: str = Field("", max_length=1024)
    webhook_signing_key: str = Field("", max_length=1024)
    # A burst of malicious verdicts must not become a burst of mail.
    max_per_hour: int = Field(20, ge=1, le=1000)

    @field_validator("recipients")
    @classmethod
    def _recipients(cls, value: list[str]) -> list[str]:
        kept: list[str] = []
        for entry in value:
            address = str(entry).strip()
            if not address:
                continue
            if not EMAIL_RE.match(address):
                raise ValueError(f"'{address}' is not an e-mail address")
            kept.append(address)
        return kept

    @field_validator("webhook_url")
    @classmethod
    def _webhook(cls, value: str) -> str:
        value = value.strip()
        if value and not _SERVER_URL.match(value):
            raise ValueError("an http:// or https:// address is expected")
        return value

    @property
    def configured(self) -> bool:
        return bool(
            (self.email_enabled and self.recipients) or (self.webhook_enabled and self.webhook_url)
        )


class McpSettings(BaseModel):
    """The two MCP servers an AI agent drives XenoProxy through.

    Both are off by default. They are reached with a personal API token, and the
    token is what carries the rights: the user server applies exactly the
    permissions of the account that owns it.

    The administration server does **not** elevate anything. It offers the
    administration tools, and it only accepts a token belonging to an account
    that is already an administrator and is named in `admin_usernames`. An agent
    therefore never gains a right its account does not have, which removes the
    escalation path an elevating server would create.
    """

    user_enabled: bool = False
    admin_enabled: bool = False
    # The administration server offers only the tools that read. Use it to let
    # an agent inspect a configuration without being able to change it.
    read_only: bool = False
    # Accounts allowed on the administration server. Empty means nobody, so
    # enabling the server is not on its own enough to reach it.
    admin_usernames: list[str] = Field(default_factory=list, max_length=20)
    # Groups allowed on the user server. Empty means every account may use it.
    user_groups: list[str] = Field(default_factory=list, max_length=50)
    # Characters of one tool answer. Past this it is cut with a note, because a
    # provider payload is large enough to fill a context window on its own.
    max_result_chars: int = Field(60_000, ge=2_000, le=400_000)

    @field_validator("admin_usernames", "user_groups")
    @classmethod
    def _names(cls, value: list[str]) -> list[str]:
        kept = [str(entry).strip().lower() for entry in value if str(entry).strip()]
        return list(dict.fromkeys(kept))


SECTIONS: dict[str, type[BaseModel]] = {
    "network": NetworkSettings,
    "assistant": AssistantSettings,
    "oidc": OidcSettings,
    "ldap": LdapSettings,
    "smtp": SmtpSettings,
    "notifications": NotificationsSettings,
    "mcp": McpSettings,
}

# *Names* of the sealed fields of each section, never their values, so this
# mapping is safe to log.
SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "network": ("proxy_password",),
    "assistant": ("api_key",),
    "oidc": ("client_secret",),
    "ldap": ("bind_password",),
    "smtp": ("password",),
    "notifications": ("webhook_signing_key",),
    "mcp": (),
}


def describe(name: str) -> dict[str, Any]:
    """The JSON schema of a section, so the interface can render it generically."""
    return SECTIONS[name].model_json_schema()
