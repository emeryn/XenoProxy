"""Turning what a source reports about software into names an analyst reads.

Every exposure source answers this question in its own shape — Shodan a
`product` and a `version` per service, Shodan InternetDB a list of CPEs, Censys
a `software` array, urlscan the raw HTTP `Server` header. None of those belong
in the interface as they come, and leaving them in the raw payload means the
one fact an analyst wants from an exposure scan — *what is running there* — is
the one they have to dig for.
"""

from __future__ import annotations

# A version is useful; a build string is not, and it is what makes two readings
# of the same host look like two different hosts.
_MAX_LENGTH = 48


def clean(name: str | None, version: str | None = None) -> str | None:
    """One technology, as "product version", or None when there is nothing to say."""
    product = (name or "").strip()
    if not product or product.lower() in {"unknown", "none", "null"}:
        return None
    release = (version or "").strip()
    label = f"{product} {release}".strip() if release else product
    return label[:_MAX_LENGTH]


def from_cpe(cpe: str) -> str | None:
    """The software named by a CPE 2.3 or 2.2 string.

    The product alone is often not the name anyone uses: Apache httpd is
    `apache:http_server`, and "http server 2.4.7" tells an analyst nothing. So
    the vendor is kept in front of it — unless one already contains the other,
    which is the common `nginx:nginx` case, and then it would only stutter.
    """
    parts = cpe.split(":")
    if len(parts) < 5 or not parts[0].lower().startswith("cpe"):
        return None
    # cpe:2.3:part:vendor:product:version -> vendor at 3, product at 4
    # cpe:/part:vendor:product:version    -> vendor at 2, product at 3
    offset = 4 if parts[1] == "2.3" else 3
    if len(parts) <= offset:
        return None
    vendor = parts[offset - 1].replace("_", " ").strip()
    product = parts[offset].replace("_", " ").strip()
    version = parts[offset + 1] if len(parts) > offset + 1 else ""
    if version in {"*", "-", ""}:
        version = ""
    if vendor and vendor not in product and product not in vendor:
        product = f"{vendor} {product}"
    return clean(product, version)
