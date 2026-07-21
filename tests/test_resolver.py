"""Tests for spf53.resolver — DNS mocked entirely at the module seams, no live DNS."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

import dns.rdatatype
import dns.resolver
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


def test_revisit_of_already_seen_domain_beyond_max_depth_is_free(fake_dns: FakeDNS) -> None:
    """A domain already resolved via a shallow include is free to revisit later,
    even through a branch deep enough that a first visit there would exceed
    MAX_DEPTH — the revisit costs no further lookups and must not raise.
    """
    chain_top = _install_chain(fake_dns, MAX_DEPTH)
    fake_dns.txt[f"chain{MAX_DEPTH}.example.com"] = ["v=spf1 include:shared.example.com ~all"]
    fake_dns.txt["shared.example.com"] = ["v=spf1 ip4:203.0.113.200/32 ~all"]

    result = flatten(["shared.example.com", chain_top], RESOLVER_IPS)

    assert result == [net("203.0.113.200/32")]


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


def test_a_single_slash_prefix_len_applies_only_to_ipv4(fake_dns: FakeDNS) -> None:
    """A `/LEN` single-slash form is the ip4-cidr-length only (RFC 7208 5.3) —

    it must not be applied to AAAA results, which should default to /128.
    """
    fake_dns.txt["provider.example.com"] = ["v=spf1 a:mail.provider.com/24 ~all"]
    fake_dns.a["mail.provider.com"] = ["192.0.2.10"]
    fake_dns.aaaa["mail.provider.com"] = ["2001:db8:1234::1"]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("192.0.2.0/24"), net("2001:db8:1234::1/128")]


def test_a_dual_cidr_with_host_applies_len_per_family(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 a:mail.provider.com/24//64 ~all"]
    fake_dns.a["mail.provider.com"] = ["192.0.2.10"]
    fake_dns.aaaa["mail.provider.com"] = ["2001:db8:1234::1"]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("192.0.2.0/24"), net("2001:db8:1234::/64")]


def test_a_bare_ip6_only_dual_cidr(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a//64 ~all"]
    fake_dns.a["own.example.com"] = ["198.51.100.7"]
    fake_dns.aaaa["own.example.com"] = ["2001:db8::7"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.7/32"), net("2001:db8::/64")]


def test_a_host_ip6_only_dual_cidr(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a:other.example.com//64 ~all"]
    fake_dns.a["other.example.com"] = ["203.0.113.16"]
    fake_dns.aaaa["other.example.com"] = ["2001:db8:cafe::16"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.16/32"), net("2001:db8:cafe::/64")]


def test_mx_bare_dual_cidr_applies_len_per_family(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 mx/16//48 ~all"]
    fake_dns.mx["own.example.com"] = ["mail.example.com"]
    fake_dns.a["mail.example.com"] = ["198.51.100.30"]
    fake_dns.aaaa["mail.example.com"] = ["2001:db8:abcd::30"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.0.0/16"), net("2001:db8:abcd::/48")]


def test_invalid_ip4_literal_raises_resolution_error(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:999.1.2.3/24 ~all"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["provider.example.com"], RESOLVER_IPS)

    message = str(exc_info.value)
    assert "provider.example.com" in message
    assert "999.1.2.3/24" in message


def test_out_of_range_prefix_len_raises_resolution_error(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 a:other.example.com/33 ~all"]
    fake_dns.a["other.example.com"] = ["203.0.113.16"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["own.example.com"], RESOLVER_IPS)

    message = str(exc_info.value)
    assert "own.example.com" in message
    assert "a:other.example.com/33" in message


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


# --- Concurrency tests ------------------------------------------------------


def test_a_and_aaaa_queries_run_concurrently(monkeypatch: pytest.MonkeyPatch) -> None:
    """If A/AAAA ran sequentially, only one thread would ever reach the barrier
    at a time and `barrier.wait()` would time out (BrokenBarrierError).
    """
    barrier = threading.Barrier(2, timeout=2)

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        barrier.wait()
        return ["198.51.100.7"]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        barrier.wait()
        return ["2001:db8::7"]

    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    with ThreadPoolExecutor(max_workers=resolver._MAX_WORKERS) as pool:
        addresses = resolver._resolve_addresses(
            "host.example.com", RESOLVER_IPS, "host.example.com", pool
        )

    assert sorted(addresses) == sorted(["198.51.100.7", "2001:db8::7"])


def test_mx_exchanges_resolve_concurrently(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same proof as above, but for 3 concurrent MX-exchange address lookups."""
    barrier = threading.Barrier(3, timeout=2)
    # Spaced-out last octets so no two networks are adjacent /32s that
    # collapse_addresses would merge into a wider CIDR.
    a_answers = {
        "mail1.example.com": "198.51.100.10",
        "mail2.example.com": "198.51.100.20",
        "mail3.example.com": "198.51.100.30",
    }

    def query_txt(name: str, resolver_ips: list[str]) -> list[str]:
        return ["v=spf1 mx ~all"]

    def query_mx(name: str, resolver_ips: list[str]) -> list[str]:
        return list(a_answers)

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        barrier.wait()
        return [a_answers[name]]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        return []

    monkeypatch.setattr(resolver, "_query_txt", query_txt)
    monkeypatch.setattr(resolver, "_query_mx", query_mx)
    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    result = flatten(["own.example.com"], RESOLVER_IPS)

    expected = sorted(net(f"{ip}/32") for ip in a_answers.values())
    assert result == expected


def test_exception_in_one_of_concurrent_a_aaaa_lookups_raises_resolution_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        return ["203.0.113.16"]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        raise DNSFailure("boom")

    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    with (
        ThreadPoolExecutor(max_workers=resolver._MAX_WORKERS) as pool,
        pytest.raises(ResolutionError, match="other.example.com"),
    ):
        resolver._resolve_addresses("other.example.com", RESOLVER_IPS, "own.example.com", pool)


def test_one_of_several_concurrent_mx_exchange_lookups_raising_surfaces_resolution_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def query_txt(name: str, resolver_ips: list[str]) -> list[str]:
        return ["v=spf1 mx ~all"]

    def query_mx(name: str, resolver_ips: list[str]) -> list[str]:
        return ["mail1.example.com", "mail2.example.com", "mail3.example.com"]

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        if name == "mail2.example.com":
            raise DNSFailure("boom")
        return ["198.51.100.1"]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        return []

    monkeypatch.setattr(resolver, "_query_txt", query_txt)
    monkeypatch.setattr(resolver, "_query_mx", query_mx)
    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    with pytest.raises(ResolutionError, match="mail2.example.com"):
        flatten(["own.example.com"], RESOLVER_IPS)


def test_mx_exchange_results_are_collected_in_submission_order_not_completion_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserts the network-building step runs in submission order even when
    staggered sleeps make the underlying per-exchange lookups finish out of
    order — flatten()'s final output is always fully sorted, so asserting on
    that output can't distinguish a submission-order collector from a
    completion-order one; asserting on call order here can.
    """
    a_answers = {
        "mail1.example.com": "198.51.100.10",
        "mail2.example.com": "198.51.100.20",
        "mail3.example.com": "198.51.100.30",
    }
    sleep_seconds = {
        "mail1.example.com": 0.03,
        "mail2.example.com": 0.0,
        "mail3.example.com": 0.015,
    }

    def query_txt(name: str, resolver_ips: list[str]) -> list[str]:
        return ["v=spf1 mx ~all"]

    def query_mx(name: str, resolver_ips: list[str]) -> list[str]:
        return ["mail1.example.com", "mail2.example.com", "mail3.example.com"]

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        time.sleep(sleep_seconds[name])
        return [a_answers[name]]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        return []

    monkeypatch.setattr(resolver, "_query_txt", query_txt)
    monkeypatch.setattr(resolver, "_query_mx", query_mx)
    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    call_order: list[str] = []
    real_addresses_to_networks = resolver._addresses_to_networks

    def spy(
        addresses: list[str], v4_len: int | None, v6_len: int | None, term: str, name: str
    ) -> list[resolver._Network]:
        call_order.append(addresses[0])
        return real_addresses_to_networks(addresses, v4_len, v6_len, term, name)

    monkeypatch.setattr(resolver, "_addresses_to_networks", spy)

    flatten(["own.example.com"], RESOLVER_IPS)

    assert call_order == ["198.51.100.10", "198.51.100.20", "198.51.100.30"]


def test_flatten_is_deterministic_across_repeated_runs_with_concurrent_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies output stability and correctness when a single record combines
    an `a:` mechanism and a bare `mx` mechanism, each resolving both A and
    AAAA answers under staggered timing that makes lookups finish in a
    different relative order than they were submitted.

    This does NOT prove submission-order-safety — flatten()'s final output is
    always fully sorted, so identical output across repeated runs can't
    distinguish a submission-order collector from a completion-order one
    (that's what test_mx_exchange_results_are_collected_in_submission_order_
    not_completion_order proves above, via call-order spying). What this test
    proves is the broader "nothing races or corrupts under realistic combined
    load" property: concurrent A/AAAA lookups for both an `a:` mechanism and
    multiple `mx` exchanges, sharing one bounded thread pool, must not lose,
    duplicate, or garble results no matter which lookup finishes first — and
    must produce byte-identical output across repeated calls.
    """
    a_v4 = {
        "hosta.example.com": "192.0.2.50",
        "mail1.example.com": "198.51.100.10",
        "mail2.example.com": "198.51.100.20",
    }
    a_v6 = {
        "hosta.example.com": "2001:db8::50",
        "mail1.example.com": "2001:db8::10",
        "mail2.example.com": "2001:db8::20",
    }
    sleep_a = {
        "hosta.example.com": 0.02,
        "mail1.example.com": 0.005,
        "mail2.example.com": 0.015,
    }
    sleep_aaaa = {
        "hosta.example.com": 0.0,
        "mail1.example.com": 0.02,
        "mail2.example.com": 0.005,
    }

    def query_txt(name: str, resolver_ips: list[str]) -> list[str]:
        return ["v=spf1 a:hosta.example.com mx ~all"]

    def query_mx(name: str, resolver_ips: list[str]) -> list[str]:
        return ["mail1.example.com", "mail2.example.com"]

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        time.sleep(sleep_a[name])
        return [a_v4[name]]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        time.sleep(sleep_aaaa[name])
        return [a_v6[name]]

    monkeypatch.setattr(resolver, "_query_txt", query_txt)
    monkeypatch.setattr(resolver, "_query_mx", query_mx)
    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    expected = [
        net("192.0.2.50/32"),
        net("198.51.100.10/32"),
        net("198.51.100.20/32"),
        net("2001:db8::10/128"),
        net("2001:db8::20/128"),
        net("2001:db8::50/128"),
    ]

    first_run = flatten(["own.example.com"], RESOLVER_IPS)
    second_run = flatten(["own.example.com"], RESOLVER_IPS)

    assert first_run == expected
    assert second_run == expected
    assert first_run == second_run


def test_mx_exchange_failure_does_not_wait_for_slow_sibling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing exchange must surface its ResolutionError without blocking
    on a sibling exchange that is still resolving. The slow sibling blocks on
    an Event that this test never sets, with a 2s timeout as an upper bound;
    if flatten() waited for it, this test would take close to 2s instead of
    returning almost immediately.
    """
    slow_may_proceed = threading.Event()

    def query_txt(name: str, resolver_ips: list[str]) -> list[str]:
        return ["v=spf1 mx ~all"]

    def query_mx(name: str, resolver_ips: list[str]) -> list[str]:
        return ["fast.example.com", "slow.example.com"]

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        if name == "fast.example.com":
            raise DNSFailure("boom")
        slow_may_proceed.wait(timeout=2)
        return ["198.51.100.1"]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        return []

    monkeypatch.setattr(resolver, "_query_txt", query_txt)
    monkeypatch.setattr(resolver, "_query_mx", query_mx)
    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    start = time.monotonic()
    with pytest.raises(ResolutionError, match="fast.example.com"):
        flatten(["own.example.com"], RESOLVER_IPS)
    elapsed = time.monotonic() - start

    slow_may_proceed.set()  # release the still-running background lookup
    assert elapsed < 0.5


def test_a_mechanism_aaaa_failure_does_not_wait_for_slow_sibling_a_lookup(
    fake_dns: FakeDNS, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mirrors test_mx_exchange_failure_does_not_wait_for_slow_sibling above,
    but for the bare `a` mechanism's own A/AAAA pair in _resolve_addresses.
    Before this fix, _resolve_addresses called a_future.result() then
    aaaa_future.result() strictly in that order, so a fast AAAA failure would
    sit unreported until the slow A lookup also finished. The slow A lookup
    blocks on an Event this test never sets, with a 2s timeout as an upper
    bound; if flatten() waited for it, this test would take close to 2s
    instead of returning almost immediately.
    """
    fake_dns.txt["own.example.com"] = ["v=spf1 a ~all"]
    slow_may_proceed = threading.Event()

    def query_a(name: str, resolver_ips: list[str]) -> list[str]:
        slow_may_proceed.wait(timeout=2)
        return ["198.51.100.1"]

    def query_aaaa(name: str, resolver_ips: list[str]) -> list[str]:
        raise DNSFailure("boom")

    monkeypatch.setattr(resolver, "_query_a", query_a)
    monkeypatch.setattr(resolver, "_query_aaaa", query_aaaa)

    start = time.monotonic()
    with pytest.raises(ResolutionError, match="own.example.com"):
        flatten(["own.example.com"], RESOLVER_IPS)
    elapsed = time.monotonic() - start

    slow_may_proceed.set()  # release the still-running background lookup
    assert elapsed < 0.5


def test_single_shared_threadpool_executor_per_flatten_call(
    monkeypatch: pytest.MonkeyPatch, fake_dns: FakeDNS
) -> None:
    """A flatten() call with multiple mx exchanges and an a mechanism must
    construct exactly one ThreadPoolExecutor, not one per mx exchange or one
    per a/mx term.
    """
    fake_dns.txt["own.example.com"] = ["v=spf1 mx a:other.example.com ~all"]
    fake_dns.mx["own.example.com"] = ["mail1.example.com", "mail2.example.com"]
    fake_dns.a["mail1.example.com"] = ["198.51.100.10"]
    fake_dns.a["mail2.example.com"] = ["198.51.100.20"]
    fake_dns.a["other.example.com"] = ["203.0.113.5"]

    construct_count = 0
    real_executor_cls = resolver.ThreadPoolExecutor

    class CountingExecutor(real_executor_cls):
        def __init__(self, *args: object, **kwargs: object) -> None:
            nonlocal construct_count
            construct_count += 1
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(resolver, "ThreadPoolExecutor", CountingExecutor)

    flatten(["own.example.com"], RESOLVER_IPS)

    assert construct_count == 1


def test_mx_term_with_more_exchanges_than_max_workers_does_not_deadlock(
    fake_dns: FakeDNS,
) -> None:
    """An mx term with >= _MAX_WORKERS exchanges must not deadlock. If a
    worker thread ever submitted further work back onto this same bounded
    pool, enough concurrently-blocked outer tasks could consume every
    worker with none left free to run the inner submissions. Run flatten()
    on a background thread and assert it finishes well inside a timeout,
    since a real deadlock would otherwise hang the whole test run.
    """
    # Must stay <= _MAX_MX_EXCHANGES (the RFC 7208 4.6.4 mx-exchange cap) while
    # still exceeding _MAX_WORKERS, to exercise the deadlock scenario without
    # tripping that separate cap.
    exchange_count = resolver._MAX_MX_EXCHANGES
    assert exchange_count > resolver._MAX_WORKERS
    exchanges = [f"mail{i}.example.com" for i in range(exchange_count)]
    fake_dns.txt["own.example.com"] = ["v=spf1 mx ~all"]
    fake_dns.mx["own.example.com"] = exchanges
    for i, exchange in enumerate(exchanges):
        # Spaced-out last octets so no two /32s are adjacent and collapsed
        # by ipaddress.collapse_addresses into fewer, wider CIDRs.
        fake_dns.a[exchange] = [f"198.51.100.{i * 10}"]

    result: list[resolver._Network] = []

    def run() -> None:
        result.extend(flatten(["own.example.com"], RESOLVER_IPS))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive(), "flatten() deadlocked with many mx exchanges"
    assert len(result) == exchange_count


def test_no_worker_futures_remain_unjoined_after_flatten_returns_on_success(
    monkeypatch: pytest.MonkeyPatch, fake_dns: FakeDNS
) -> None:
    """flatten()'s finally block shuts its pool down with wait=False,
    cancel_futures=True. On the success path that must never abandon a
    still-running background lookup: every future submitted to the pool is
    expected to already be done() by the time flatten() returns, so
    cancel_futures=True has nothing live left to cancel. Wrap the pool's
    submit() so every future it hands out is recorded, then assert all of
    them are done() once flatten() has returned — a future can only reach
    done() after its worker thread has actually finished running it.
    """
    fake_dns.txt["own.example.com"] = ["v=spf1 mx a:other.example.com ~all"]
    fake_dns.mx["own.example.com"] = ["mail1.example.com", "mail2.example.com"]
    fake_dns.a["mail1.example.com"] = ["198.51.100.10"]
    fake_dns.a["mail2.example.com"] = ["198.51.100.20"]
    fake_dns.a["other.example.com"] = ["203.0.113.5"]

    submitted: list[Future] = []
    real_executor_cls = resolver.ThreadPoolExecutor

    class RecordingExecutor(real_executor_cls):
        def submit(self, fn: object, *args: object, **kwargs: object) -> Future:
            future = super().submit(fn, *args, **kwargs)
            submitted.append(future)
            return future

    monkeypatch.setattr(resolver, "ThreadPoolExecutor", RecordingExecutor)

    flatten(["own.example.com"], RESOLVER_IPS)

    assert submitted, "expected at least one future to have been submitted"
    assert all(f.done() for f in submitted)


# --- Fix 1: qualifier stripping must not invert deny to allow --------------


def test_fail_qualified_ip4_mechanism_raises_instead_of_flattening(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 -ip4:203.0.113.9/32 ~all"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["provider.example.com"], RESOLVER_IPS)

    message = str(exc_info.value)
    assert "provider.example.com" in message
    assert "-ip4:203.0.113.9/32" in message
    assert "fail" in message


def test_softfail_qualified_include_raises_instead_of_flattening(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 ~include:other.example.com ~all"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["own.example.com"], RESOLVER_IPS)

    message = str(exc_info.value)
    assert "own.example.com" in message
    assert "~include:other.example.com" in message
    assert "softfail" in message


def test_neutral_qualified_ip6_mechanism_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ?ip6:2001:db8::/32 ~all"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["provider.example.com"], RESOLVER_IPS)

    assert "neutral" in str(exc_info.value)


def test_negative_qualified_a_mechanism_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 -a ~all"]

    with pytest.raises(ResolutionError, match="fail"):
        flatten(["own.example.com"], RESOLVER_IPS)


def test_negative_qualified_mx_mechanism_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 -mx ~all"]

    with pytest.raises(ResolutionError, match="fail"):
        flatten(["own.example.com"], RESOLVER_IPS)


def test_qualified_redirect_raises_instead_of_being_followed(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 ~redirect=provider.example.com"]
    # provider.example.com is intentionally NOT registered -- if the
    # redirect were (incorrectly) followed despite its qualifier, this would
    # raise a "no SPF record found" error for it instead of a qualifier error.

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["own.example.com"], RESOLVER_IPS)

    message = str(exc_info.value)
    assert "own.example.com" in message
    assert "softfail" in message


def test_plus_qualified_and_unqualified_mechanisms_still_flatten(fake_dns: FakeDNS) -> None:
    """Both an explicit '+' qualifier and no qualifier at all (the RFC 7208
    default) must still flatten normally -- only non-'+' qualifiers refuse.
    """
    fake_dns.txt["provider.example.com"] = ["v=spf1 +ip4:203.0.113.1/32 ip4:203.0.113.2/32 ~all"]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.1/32"), net("203.0.113.2/32")]


# --- Fix 2: transitive lookup cost of include:/redirect= passthrough terms -


def test_count_transitive_lookup_cost_counts_nested_dns_querying_mechanisms(
    fake_dns: FakeDNS,
) -> None:
    fake_dns.txt["_spf.google.com"] = [
        "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com "
        "include:_netblocks3.google.com ~all"
    ]
    fake_dns.txt["_netblocks.google.com"] = ["v=spf1 ip4:172.217.0.0/19 ~all"]
    fake_dns.txt["_netblocks2.google.com"] = ["v=spf1 ip4:172.253.0.0/16 ~all"]
    fake_dns.txt["_netblocks3.google.com"] = ["v=spf1 ip4:108.177.0.0/17 ~all"]

    cost = resolver.count_transitive_lookup_cost("include:_spf.google.com", RESOLVER_IPS)

    assert cost == 3


def test_count_transitive_lookup_cost_recurses_multiple_levels(fake_dns: FakeDNS) -> None:
    fake_dns.txt["top.example.com"] = ["v=spf1 include:mid.example.com ~all"]
    fake_dns.txt["mid.example.com"] = ["v=spf1 a mx include:leaf.example.com ~all"]
    fake_dns.txt["leaf.example.com"] = ["v=spf1 ip4:203.0.113.0/24 ~all"]

    cost = resolver.count_transitive_lookup_cost("include:top.example.com", RESOLVER_IPS)

    # top.example.com's record: include:mid.example.com (+1, recurse)
    #   mid.example.com's record: a (+1), mx (+1), include:leaf.example.com (+1, recurse)
    #     leaf.example.com's record: ip4 only (+0)
    # total = 1 + 1 + 1 + 1 = 4
    assert cost == 4


def test_count_transitive_lookup_cost_recognizes_nested_redirect(fake_dns: FakeDNS) -> None:
    fake_dns.txt["_spf.example.com"] = ["v=spf1 redirect=other.example.com"]
    fake_dns.txt["other.example.com"] = ["v=spf1 ip4:203.0.113.0/24 ~all"]

    cost = resolver.count_transitive_lookup_cost("include:_spf.example.com", RESOLVER_IPS)

    assert cost == 1


def test_count_transitive_lookup_cost_accepts_redirect_as_the_passthrough_term(
    fake_dns: FakeDNS,
) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 a mx ~all"]

    cost = resolver.count_transitive_lookup_cost("redirect=provider.example.com", RESOLVER_IPS)

    assert cost == 2


def test_count_transitive_lookup_cost_is_safe_against_cycles(fake_dns: FakeDNS) -> None:
    fake_dns.txt["a.example.com"] = ["v=spf1 include:b.example.com ~all"]
    fake_dns.txt["b.example.com"] = ["v=spf1 include:a.example.com ~all"]

    cost = resolver.count_transitive_lookup_cost("include:a.example.com", RESOLVER_IPS)

    # a -> b (+1) -> a already seen, so the revisit costs 1 for its own
    # include: occurrence but recurses no further.
    assert cost == 2


def test_count_transitive_lookup_cost_exactly_max_depth_succeeds(fake_dns: FakeDNS) -> None:
    top = _install_chain(fake_dns, MAX_DEPTH)

    cost = resolver.count_transitive_lookup_cost(f"include:{top}", RESOLVER_IPS)

    assert cost == MAX_DEPTH - 1


def test_count_transitive_lookup_cost_beyond_max_depth_raises(fake_dns: FakeDNS) -> None:
    top = _install_chain(fake_dns, MAX_DEPTH + 1)

    with pytest.raises(ResolutionError, match=f"chain{MAX_DEPTH + 1}.example.com"):
        resolver.count_transitive_lookup_cost(f"include:{top}", RESOLVER_IPS)


def test_count_transitive_lookup_cost_dns_failure_raises_naming_it(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 include:missing.example.com ~all"]
    # missing.example.com is intentionally absent -> DNSFailure

    with pytest.raises(ResolutionError, match="missing.example.com"):
        resolver.count_transitive_lookup_cost("include:own.example.com", RESOLVER_IPS)


def test_count_transitive_lookup_cost_rejects_non_include_redirect_term() -> None:
    with pytest.raises(ValueError, match="not an include"):
        resolver.count_transitive_lookup_cost("exists:foo.example.com", RESOLVER_IPS)


def test_count_transitive_lookup_cost_exceeding_max_chain_names_raises(fake_dns: FakeDNS) -> None:
    """A passthrough include's own chain fanning out into more branches than
    _MAX_CHAIN_NAMES allows (mirrors test_chain_exceeding_max_chain_names_raises
    for _walk) must be refused rather than issuing that many serial DNS
    queries -- unlike flatten(), this counter has no thread pool, so each
    query pays its own timeout serially.
    """
    leaf_count = resolver._MAX_CHAIN_NAMES + 5
    leaves = [f"leaf{i}.example.com" for i in range(leaf_count)]
    fake_dns.txt["root.example.com"] = [
        "v=spf1 " + " ".join(f"include:{leaf}" for leaf in leaves) + " ~all"
    ]
    for leaf in leaves:
        fake_dns.txt[leaf] = ["v=spf1 ~all"]

    with pytest.raises(ResolutionError, match="SPF chain too large"):
        resolver.count_transitive_lookup_cost("include:root.example.com", RESOLVER_IPS)


# --- Fix 3: NXDOMAIN on an a:/mx: target must not hard-fail the domain -----


def _raise_nxdomain(
    name: str, rdtype: dns.rdatatype.RdataType, resolver_ips: list[str]
) -> dns.resolver.Answer:
    raise dns.resolver.NXDOMAIN()


def test_query_a_nxdomain_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver, "_resolve", _raise_nxdomain)

    assert resolver._query_a("gone.example.com", RESOLVER_IPS) == []


def test_query_aaaa_nxdomain_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver, "_resolve", _raise_nxdomain)

    assert resolver._query_aaaa("gone.example.com", RESOLVER_IPS) == []


def test_query_mx_nxdomain_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver, "_resolve", _raise_nxdomain)

    assert resolver._query_mx("gone.example.com", RESOLVER_IPS) == []


def test_query_txt_nxdomain_still_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unlike _query_a/_query_aaaa/_query_mx, _query_txt must NOT soften
    NXDOMAIN -- a missing include:/redirect= target is a genuine
    misconfiguration in the SPF chain worth surfacing, not a "no addresses"
    outcome.
    """
    monkeypatch.setattr(resolver, "_resolve", _raise_nxdomain)

    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver._query_txt("gone.example.com", RESOLVER_IPS)


def test_a_mechanism_target_nxdomain_does_not_fail_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    """A decommissioned a:/mx: target that NXDOMAINs must simply not match
    (RFC 7208), not abort the whole domain's flatten() call.
    """

    def fake_query_txt(name: str, resolver_ips: list[str]) -> list[str]:
        return ["v=spf1 a:gone.example.com ip4:203.0.113.1/32 ~all"]

    def fake_resolve(
        name: str, rdtype: dns.rdatatype.RdataType, resolver_ips: list[str]
    ) -> dns.resolver.Answer:
        if rdtype == dns.rdatatype.A:
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(resolver, "_query_txt", fake_query_txt)
    monkeypatch.setattr(resolver, "_resolve", fake_resolve)

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.1/32")]


# --- Macro-based a:/mx: mechanisms must be rejected, not silently dropped --


def test_a_mechanism_with_macro_host_raises(fake_dns: FakeDNS) -> None:
    """spf53 has no SPF macro support. Without this guard, a macro-based a:
    target would NXDOMAIN (its literal macro text isn't a real hostname) and,
    now that NXDOMAIN softens to "no addresses" instead of hard-failing,
    would silently drop an entire authorized sending path from the
    flattened output instead of raising.
    """
    fake_dns.txt["own.example.com"] = [
        "v=spf1 a:%{i}.allowed.provider.example ip4:198.51.100.7/32 -all"
    ]

    with pytest.raises(ResolutionError, match="own.example.com") as exc_info:
        flatten(["own.example.com"], RESOLVER_IPS)

    assert "a:%{i}.allowed.provider.example" in str(exc_info.value)


def test_mx_mechanism_with_macro_host_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = [
        "v=spf1 mx:%{i}.allowed.provider.example ip4:198.51.100.7/32 -all"
    ]

    with pytest.raises(ResolutionError, match="own.example.com") as exc_info:
        flatten(["own.example.com"], RESOLVER_IPS)

    assert "mx:%{i}.allowed.provider.example" in str(exc_info.value)


# --- Fix 4: redirect= must be ignored when the record has an `all` ---------


def test_redirect_ignored_when_record_has_all(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 ip4:203.0.113.1/32 -all redirect=other.example.com"]
    # other.example.com is intentionally NOT registered -- if redirect= were
    # (incorrectly) followed, this would raise ResolutionError for it.

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.1/32")]


def test_redirect_ignored_regardless_of_term_order_relative_to_all(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 redirect=other.example.com ip4:203.0.113.1/32 -all"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert result == [net("203.0.113.1/32")]


# --- v=spf1 prefix must be boundary-anchored --------------------------------


def test_v_spf100_lookalike_record_is_not_treated_as_spf(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = [
        "v=spf100 not-actually-spf",
        "v=spf1 ip4:198.51.100.1/32 ~all",
    ]

    result = flatten(["provider.example.com"], RESOLVER_IPS)

    assert result == [net("198.51.100.1/32")]


# --- ip4/ip6 family mismatch must raise, not be silently accepted ----------


def test_ip4_prefix_with_ipv6_literal_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip4:2001:db8::/32 ~all"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["provider.example.com"], RESOLVER_IPS)

    message = str(exc_info.value)
    assert "provider.example.com" in message
    assert "2001:db8::/32" in message


def test_ip6_prefix_with_ipv4_literal_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["provider.example.com"] = ["v=spf1 ip6:203.0.113.0/24 ~all"]

    with pytest.raises(ResolutionError) as exc_info:
        flatten(["provider.example.com"], RESOLVER_IPS)

    assert "provider.example.com" in str(exc_info.value)


# --- Self-DoS caps -----------------------------------------------------------


def test_mx_mechanism_with_more_than_ten_exchanges_raises(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 mx ~all"]
    fake_dns.mx["own.example.com"] = [f"mail{i}.example.com" for i in range(11)]

    with pytest.raises(ResolutionError, match="own.example.com"):
        flatten(["own.example.com"], RESOLVER_IPS)


def test_mx_mechanism_with_exactly_ten_exchanges_succeeds(fake_dns: FakeDNS) -> None:
    fake_dns.txt["own.example.com"] = ["v=spf1 mx ~all"]
    exchanges = [f"mail{i}.example.com" for i in range(10)]
    fake_dns.mx["own.example.com"] = exchanges
    for i, exchange in enumerate(exchanges):
        # Spaced-out last octets so no two /32s are adjacent and collapsed
        # by ipaddress.collapse_addresses into fewer, wider CIDRs.
        fake_dns.a[exchange] = [f"198.51.100.{i * 10}"]

    result = flatten(["own.example.com"], RESOLVER_IPS)

    assert len(result) == 10


def test_chain_exceeding_max_chain_names_raises(fake_dns: FakeDNS) -> None:
    """A root record fanning out into more branches than _MAX_CHAIN_NAMES
    allows (all well within MAX_DEPTH, so the depth cap can't be what stops
    it) must be refused rather than allowed to run unbounded.
    """
    leaf_count = resolver._MAX_CHAIN_NAMES + 5
    leaves = [f"leaf{i}.example.com" for i in range(leaf_count)]
    fake_dns.txt["root.example.com"] = [
        "v=spf1 " + " ".join(f"include:{leaf}" for leaf in leaves) + " ~all"
    ]
    for leaf in leaves:
        fake_dns.txt[leaf] = ["v=spf1 ~all"]

    with pytest.raises(ResolutionError, match="SPF chain too large"):
        flatten(["root.example.com"], RESOLVER_IPS)


def test_chain_at_exactly_max_chain_names_succeeds(fake_dns: FakeDNS) -> None:
    leaf_count = resolver._MAX_CHAIN_NAMES - 1  # + root itself = _MAX_CHAIN_NAMES
    leaves = [f"leaf{i}.example.com" for i in range(leaf_count)]
    fake_dns.txt["root.example.com"] = [
        "v=spf1 " + " ".join(f"include:{leaf}" for leaf in leaves) + " ~all"
    ]
    for leaf in leaves:
        fake_dns.txt[leaf] = ["v=spf1 ~all"]

    result = flatten(["root.example.com"], RESOLVER_IPS)

    assert result == []
