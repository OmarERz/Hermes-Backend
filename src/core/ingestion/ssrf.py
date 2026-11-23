"""SSRF guard for every outbound fetch of a feed or an article (SEG-15, docs/14 §10).

A target is accepted only when it is HTTPS on the default port, has no credentials in the URL and every address
its host resolves to is a global (public) one. Redirect targets go through the same check (see `fetcher`).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

Resolver = Callable[[str], list[str]]


class UnsafeUrlError(ValueError):
    """The URL must not be fetched (scheme, credentials, port or a non-public address)."""


def system_resolver(host: str) -> list[str]:
    """Every IP address of `host` according to the system resolver."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeUrlError("The host does not resolve") from exc
    except ValueError as exc:  # UnicodeError (IDNA) or an embedded NUL: not a host name at all
        raise UnsafeUrlError("The host is not a valid name") from exc
    return sorted({str(info[4][0]) for info in infos})


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_public_url(url: str, resolver: Resolver = system_resolver) -> str:
    """Return the host of `url` when it is safe to fetch; raise `UnsafeUrlError` otherwise."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeUrlError("Malformed URL") from exc
    if parts.scheme != "https":
        raise UnsafeUrlError("Only HTTPS URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise UnsafeUrlError("Credentials in the URL are not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeUrlError("The URL has no host")
    if port not in (None, 443):
        raise UnsafeUrlError("Only the default HTTPS port is allowed")
    resolve_public_address(host, resolver)
    return host


def resolve_public_address(host: str, resolver: Resolver = system_resolver) -> str:
    """The address to connect to for `host`; every address the host resolves to must be public."""
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        addresses = resolver(host)
    if not addresses:
        raise UnsafeUrlError("The host does not resolve")
    if not all(_is_public(address) for address in addresses):
        raise UnsafeUrlError("The host resolves to a non-public address")
    return addresses[0]
