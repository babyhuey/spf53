"""Tests for spf53.resolver — DNS mocked entirely at the module seams, no live DNS."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

import pytest

from spf53 import resolver
from spf53.resolver import MAX_DEPTH, ResolutionError, flatten

RESOLVER_IPS = ["1.1.1.1", "8.8.8.8"]


class DNSFailure(Exception):
    """Stand-in for a DNS-layer failure (NXDOMAIN, timeout, ...) in tests."""


@dataclass
class FakeDNS:
    """In-memory DNS fixture installed over the resolver's `_query_*` seams."""

    txt: dict[str, list[str]] = field(default_factory=dict)
    a: dict[str, list[str]] = field(default_factory=dict)
    aaaa: dict[str, list[str]] = field(default_factory=dict)
    mx: dict[str, list[str]] = field(default_factory=dict)
    seen_resolver_ips: list[list[str]] = field(default_factory=list)

    def query_txt(self, name: str, resolver_ips: list[str]) -> list[str]:
        self.seen_resolver_ips.append(list(resolver_ips))
        if name not in self.txt:
            raise DNSFailure(f"NXDOMAIN: {name}")
        return self.txt[name]

    def query_a(self, name: str, resolver_ips: list[str]) -> list[str]:
        return self.a.get(name, [])

    def query_aaaa(self, name: str, resolver_ips: list[str]) -> list[str]:
        return self.aaaa.get(name, [])

    def query_mx(self, name: str, resolver_ips: list[str]) -> list[str]:
        return self.mx.get(name, [])


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> FakeDNS:
    fake = FakeDNS()
    monkeypatch.setattr(resolver, "_query_txt", fake.query_txt)
    monkeypatch.setattr(resolver, "_query_a", fake.query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", fake.query_aaaa)
    monkeypatch.setattr(resolver, "_query_mx", fake.query_mx)
    return fake


def net(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr)


def test_flattens_ip4_and_ip6_mechanisms(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:198.51.100.1/32 ip6:2001:db8::/32 ~all"]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.1/32"), net("2001:db8::/32")]


def test_nested_includes_are_resolved(fake_dns: FakeDNS) -> None:
    fake_dns.txt["top.example.com"] = ["v=spf1 include:mid.example.com ~all"]
    fake_dns.txt["mid.example.com"] = ["v=spf1 ip4:203.0.113.5/32 include:leaf.example.com ~all"]
    fake_dns.txt["leaf.example.com"] = ["v=spf1 ip4:203.0.113.9/32 ~all"]

    result = flatten(["top.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.5/32"), net("203.0.113.9/32")]


def test_cycle_is_safe_and_does_not_duplicate(fake_dns: FakeDNS) -> None:
    fake_dns.txt["a.example.com"] = ["v=spf1 ip4:198.51.100.10/32 include:b.example.com ~all"]
    fake_dns.txt["b.example.com"] = ["v=spf1 ip4:198.51.100.20/32 include:a.example.com ~all"]

    result = flatten(["a.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.10/32"), net("198.51.100.20/32")]


def _install_chain(fake_dns: FakeDNS, length: int) -> str:
    """Install a straight-line chain of `length` distinct domains, each including the next."""
    for i in range(1, length + 1):
        name = f"chain{i}.example.com"
        if i < length:
            fake_dns.txt[name] = [f"v=spf1 include:chain{i + 1}.example.com ~all"]
        else:
            fake_dns.txt[name] = ["v=spf1 ip4:203.0.113.100/32 ~all"]
    return "chain1.example.com"


def test_depth_exactly_max_depth_succeeds(fake_dns: FakeDNS) -> None:
    top = _install_chain(fake_dns, MAX_DEPTH)

    result = flatten([top], RESOLVER_IPS)

    assert result == [net("203.0.113.100/32")]


def test_depth_beyond_max_depth_raises(fake_dns: FakeDNS) -> None:
    top = _install_chain(fake_dns, MAX_DEPTH + 1)

    with pytest.raises(ResolutionError, match=f"chain{MAX_DEPTH + 1}.example.com"):
        flatten([top], RESOLVER_IPS)


def test_a_mechanism_bare_resolves_own_domain(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a ~all"]
    fake_dns.a["own.example.com"] = ["198.51.100.7"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.7/32")]


def test_a_mechanism_bare_with_prefix_len(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a/24 ~all"]
    fake_dns.a["own.example.com"] = ["198.51.100.7"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.0/24")]


def test_a_mechanism_with_host_and_prefix_len(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a:other.example.com/28 ~all"]
    fake_dns.a["other.example.com"] = ["203.0.113.16"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.16/28")]


def test_a_mechanism_with_host_no_len_and_ipv6(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a:other.example.com ~all"]
    fake_dns.a["other.example.com"] = ["203.0.113.16"]
    fake_dns.aaaa["other.example.com"] = ["2001:db8::16"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.16/32"), net("2001:db8::16/128")]


def test_mx_mechanism_bare_resolves_own_domain_exchanges(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 mx ~all"]
    fake_dns.mx["own.example.com"] = ["mail1.example.com", "mail2.example.com"]
    fake_dns.a["mail1.example.com"] = ["198.51.100.30"]
    fake_dns.a["mail2.example.com"] = ["198.51.100.90"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.30/32"), net("198.51.100.90/32")]


def test_mx_mechanism_with_host_and_prefix_len(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 mx:relay.example.com/24 ~all"]
    fake_dns.mx["relay.example.com"] = ["mail.example.com"]
    fake_dns.a["mail.example.com"] = ["198.51.100.99"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.0/24")]


def test_redirect_modifier_is_followed_like_an_include(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 redirect=provider.example.com"]
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:203.0.113.50/32 ~all"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.50/32")]


def test_nested_include_failure_raises_naming_it(fake_dns: FakeDNS) -> None:
    fake_dns.txt["top.example.com"] = ["v=spf1 include:missing.example.com ~all"]
    # "missing.example.com" is intentionally absent from fake_dns.txt -> DNSFailure

    with pytest.raises(ResolutionError, match="missing.example.com"):
        flatten(["top.example.com"], RESOLVER_IPS)


def test_no_spf_record_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["noSPF.example.com"] = ["some-other-verification-record"]

    with pytest.raises(ResolutionError, match="noSPF.example.com"):
        flatten(["noSPF.example.com"], RESOLVER_IPS)


def test_no_txt_records_at_all_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["empty.example.com"] = []

    with pytest.raises(ResolutionError, match="empty.example.com"):
        flatten(["empty.example.com"], RESOLVER_IPS)


def test_multiple_spf_records_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["dup.example.com"] = [
        "v=spf1 ip4:198.51.100.1/32 ~all",
        "v=SPF1 ip4:198.51.100.2/32 ~all",
    ]

    with pytest.raises(ResolutionError, match="dup.example.com"):
        flatten(["dup.example.com"], RESOLVER_IPS)


def test_overlapping_cidrs_collapse(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:10.0.0.0/24 ip4:10.0.1.0/24 ~all"]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("10.0.0.0/23")]


def test_duplicate_networks_across_includes_dedup(fake_dns: FakeDNS) -> None:
    fake_dns.txt["a.example.com"] = ["v=spf1 ip4:198.51.100.5/32 ~all"]
    fake_dns.txt["b.example.com"] = ["v=spf1 ip4:198.51.100.5/32 ~all"]

    result = flatten(["a.example.com", "b.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.5/32")]


def test_deterministic_ordering_v4_before_v6_and_sorted(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = [
        "v=spf1 ip6:2001:db8:2::/48 ip4:203.0.113.9/32 ip6:2001:db8:1::/48 ip4:198.51.100.5/32 ~all"
    ]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [
        net("198.51.100.5/32"),
        net("203.0.113.9/32"),
        net("2001:db8:1::/48"),
        net("2001:db8:2::/48"),
    ]


def test_all_mechanism_is_ignored(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:198.51.100.1/32 -all"]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.1/32")]


def test_ptr_and_exists_are_ignored_with_logged_warning(
    fake_dns: FakeDNS, caplog: pytest.LogCaptureFixture
) -> None:
    fake_dns.txt["provider.example.com"] = [
        "v=spf1 ptr:example.com exists:%{i}._spf.example.com ip4:198.51.100.1/32 ~all"
    ]

    with caplog.at_level(logging.WARNING, logger="spf53.resolver"):
        result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.1/32")]
    messages = "\n".join(caplog.messages)
    assert "ptr" in messages
    assert "exists" in messages


def test_resolver_ips_are_forwarded_to_seams(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:198.51.100.1/32 ~all"]

    flatten(["provider.example.com"], RESOLVER_IPS)

    assert fake_dns.seen_resolver_ips == [RESOLVER_IPS]


def test_multi_string_txt_concatenation_bytes() -> None:
    joined = resolver._join_txt_strings(
        (b"v=spf1 ip4:198.51.100.1/32 ", b"ip4:198.51.100.2/32 ~all")
    )

    assert joined == "v=spf1 ip4:198.51.100.1/32 ip4:198.51.100.2/32 ~all"


def test_multi_string_txt_concatenation_mixed_str_and_bytes() -> None:
    joined = resolver._join_txt_strings(("v=spf1 ip4:198.51.100.1/32 ", b"~all"))

    assert joined == "v=spf1 ip4:198.51.100.1/32 ~all"
