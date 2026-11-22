"""Canonical article URL (ING-05 layer 1): no utm_* parameters, no AMP, no trailing slash."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_TRACKING_PARAMS = frozenset({"fbclid", "gclid", "mc_cid", "mc_eid", "igshid"})
_AMP_QUERY = {("amp", "1"), ("amp", "true"), ("outputtype", "amp")}
_AMP_SUFFIX = re.compile(r"(?:/amp|\.amp)$", re.IGNORECASE)
_AMP_PREFIX = re.compile(r"^/amp(?=/)", re.IGNORECASE)


class InvalidUrlError(ValueError):
    """The value is not an absolute http(s) URL."""


def canonicalize_url(url: str) -> str:
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise InvalidUrlError("Malformed URL") from exc
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise InvalidUrlError("Not an absolute http(s) URL")
    host = parts.hostname.lower().rstrip(".")
    if host.startswith("amp.") and host.count(".") > 1:
        host = host.removeprefix("amp.")
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    if ":" in host:  # IPv6 literal
        netloc = f"[{host}]" + ("" if port in (None, 80, 443) else f":{port}")
    path = _AMP_PREFIX.sub("", parts.path)
    path = _AMP_SUFFIX.sub("", path).rstrip("/")
    query = sorted(
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith("utm_")
        and key.lower() not in _TRACKING_PARAMS
        and (key.lower(), value.lower()) not in _AMP_QUERY
    )
    return urlunsplit(("https", netloc, path or "/", urlencode(query), ""))
