"""Outgoing mail, used by the notification channels.

Two things matter here beyond sending a message. Header values are stripped of
carriage returns, because a newline in a subject or a recipient injects
additional headers and turns a notification into an open relay for whoever
controlled that value. And TLS is verified against the authorities the Network
section trusts, so a mail password never goes to whoever answered on port 587.
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_RECIPIENTS = 50


class MailError(RuntimeError):
    """The mail server refused, failed or could not be reached."""


def _header_safe(value: str, *, limit: int = 512) -> str:
    """A header value cannot carry a line break, so it never carries a header."""
    cleaned = value.replace("\r", " ").replace("\n", " ").strip()
    return cleaned[:limit]


def _context(ca_bundle: str) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if ca_bundle:
        context.load_verify_locations(cadata=ca_bundle)
    return context


def _build(settings: Any, recipients: list[str], subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = _header_safe(settings.sender)
    message["To"] = ", ".join(_header_safe(address, limit=320) for address in recipients)
    message["Subject"] = _header_safe(subject)
    message.set_content(body)
    return message


def _send(settings: Any, ca_bundle: str, message: EmailMessage) -> None:
    context = _context(ca_bundle)
    try:
        if settings.security == "tls":
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                settings.host, settings.port, timeout=settings.timeout, context=context
            )
        else:
            server = smtplib.SMTP(settings.host, settings.port, timeout=settings.timeout)
        with server:
            server.ehlo()
            if settings.security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if settings.username:
                server.login(settings.username, settings.password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise MailError(f"{type(exc).__name__}: {exc}") from exc


async def send(
    settings: Any,
    recipients: list[str],
    subject: str,
    body: str,
    *,
    ca_bundle: str = "",
) -> None:
    """Send one message. smtplib is synchronous, so it runs in a thread."""
    if not settings.host or not settings.sender:
        raise MailError("the mail server is not configured")
    kept = [address for address in recipients if address][:MAX_RECIPIENTS]
    if not kept:
        raise MailError("no recipient")

    message = _build(settings, kept, subject, body)
    await asyncio.to_thread(_send, settings, ca_bundle, message)
    logger.info("mail_sent", recipients=len(kept), subject=_header_safe(subject, limit=120))


async def send_test(settings: Any, recipient: str, *, ca_bundle: str = "") -> None:
    """Send the message the settings page's test button sends."""
    await send(
        settings,
        [recipient],
        "[XenoProxy] Test message",
        "This message was sent from Admin, Settings, E-mail.\n\n"
        "The job notifications of this instance use this server.\n",
        ca_bundle=ca_bundle,
    )
