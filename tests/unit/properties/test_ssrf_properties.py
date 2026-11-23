"""Properties of the SSRF guard (SEG-15): no private, loopback, link-local or mapped target is ever accepted."""

from __future__ import annotations

import contextlib
import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.ingestion.ssrf import UnsafeUrlError, resolve_public_address, system_resolver, validate_public_url

NON_PUBLIC_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
]  # fmt: skip
NON_PUBLIC_V6 = ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "64:ff9b:1::/48"]


def address_in(network: str) -> st.SearchStrategy[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    net = ipaddress.ip_network(network)
    start, size = int(net.network_address), net.num_addresses
    make = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
    return st.integers(min_value=0, max_value=size - 1).map(lambda offset: make(start + offset))


v4 = st.sampled_from(NON_PUBLIC_V4).flatmap(address_in)
v6 = st.sampled_from(NON_PUBLIC_V6).flatmap(address_in)
mapped = v4.map(lambda address: ipaddress.IPv6Address(f"::ffff:{address}"))
any_private = st.one_of(v4, v6, mapped)
public_v4 = (
    st.integers(min_value=1, max_value=2**32 - 1)
    .map(ipaddress.IPv4Address)
    .filter(lambda a: a.is_global and not a.is_multicast)
)


def literal(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return f"[{address}]" if address.version == 6 else str(address)


@given(any_private)
def test_a_private_address_literal_is_never_accepted(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_url(f"https://{literal(address)}/feed", resolver=lambda _host: ["93.184.216.34"])


@given(any_private, public_v4)
def test_one_private_answer_among_public_ones_rejects_the_host(
    bad: ipaddress.IPv4Address | ipaddress.IPv6Address, good: ipaddress.IPv4Address
) -> None:
    for answers in ([str(bad), str(good)], [str(good), str(bad)]):
        with pytest.raises(UnsafeUrlError):
            validate_public_url("https://feeds.example.test/feed", resolver=lambda _host, a=answers: a)


@given(public_v4)
def test_a_public_address_is_accepted_and_returned(address: ipaddress.IPv4Address) -> None:
    assert resolve_public_address("feeds.example.test", resolver=lambda _host: [str(address)]) == str(address)
    assert validate_public_url(f"https://{address}/x", resolver=lambda _host: []) == str(address)


@given(any_private)
def test_a_rebinding_host_never_returns_a_private_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> None:
    with pytest.raises(UnsafeUrlError):
        resolve_public_address("rebind.example.test", resolver=lambda _host: [str(address)])


@given(st.sampled_from(["http", "ftp", "file", "gopher", "ws", ""]), st.sampled_from(["example.test", "93.184.216.34"]))
def test_only_https_is_accepted(scheme: str, host: str) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_url(f"{scheme}://{host}/x", resolver=lambda _host: ["93.184.216.34"])


@given(st.sampled_from(["user", "a:b", "x:"]), st.integers(min_value=0, max_value=65535).filter(lambda p: p != 443))
def test_credentials_and_odd_ports_are_refused(user: str, port: int) -> None:
    def ok(_host: str) -> list[str]:
        return ["93.184.216.34"]

    with pytest.raises(UnsafeUrlError):
        validate_public_url(f"https://{user}@example.test/x", resolver=ok)
    with pytest.raises(UnsafeUrlError):
        validate_public_url(f"https://example.test:{port}/x", resolver=ok)


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "017700000001", "127.1", "0", "localhost", "[::1]"])
def test_alternative_notations_of_loopback_are_refused_by_the_real_resolver(host: str) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_url(f"https://{host}/x", resolver=system_resolver)


@given(st.text(max_size=80))
def test_arbitrary_urls_never_raise_anything_but_unsafe_url_error(url: str) -> None:
    with contextlib.suppress(UnsafeUrlError):
        validate_public_url(url, resolver=lambda _host: ["93.184.216.34"])
