"""Tests for spf53.chunker."""

from ipaddress import IPv4Network, IPv6Network

from spf53 import chunker

DOMAIN = "example.com"


def _all_content(records: dict[str, list[str]]) -> dict[str, str]:
    """Concatenate each record's strings back into its full content line."""
    return {name: "".join(strings) for name, strings in records.items()}


def test_minimal_record_no_networks_no_passthrough() -> None:
    records = chunker.build_records(DOMAIN, [], [], "~all")
    assert records == {"_spf53-1.example.com": ["v=spf1 ~all"]}


def test_build_records_basic_layout() -> None:
    networks = [IPv4Network("192.0.2.1/32"), IPv4Network("198.51.100.0/24")]
    passthrough = ["exists:%{i}._spf.mta.salesforce.com"]
    records = chunker.build_records(DOMAIN, networks, passthrough, "~all")

    assert list(records) == ["_spf53-1.example.com"]
    content = "".join(records["_spf53-1.example.com"])
    assert content == (
        "v=spf1 exists:%{i}._spf.mta.salesforce.com ip4:192.0.2.1 ip4:198.51.100.0/24 ~all"
    )


def test_host_routes_omit_prefix() -> None:
    networks = [
        IPv4Network("192.0.2.1/32"),
        IPv6Network("2001:db8::1/128"),
        IPv6Network("2001:db8::/32"),
    ]
    records = chunker.build_records(DOMAIN, networks, [], "-all")
    content = "".join(records["_spf53-1.example.com"])
    assert "ip4:192.0.2.1 " in content
    assert "ip4:192.0.2.1/32" not in content
    assert "ip6:2001:db8::1 " in content
    assert "ip6:2001:db8::1/128" not in content
    assert "ip6:2001:db8::/32" in content


def test_ip4_before_ip6() -> None:
    networks = [IPv6Network("2001:db8::/32"), IPv4Network("192.0.2.0/24")]
    records = chunker.build_records(DOMAIN, networks, [], "~all")
    content = "".join(records["_spf53-1.example.com"])
    assert content.index("ip4:") < content.index("ip6:")


def test_many_networks_forces_at_least_three_chunks() -> None:
    networks = [IPv4Network(f"10.0.{i}.0/32") for i in range(200)]
    records = chunker.build_records(DOMAIN, networks, [], "~all")
    assert len(records) >= 3


def test_chain_integrity() -> None:
    networks = [IPv4Network(f"10.0.{i}.0/32") for i in range(200)]
    passthrough = ["include:_spf.example-provider.com"]
    records = chunker.build_records(DOMAIN, networks, passthrough, "~all")
    content = _all_content(records)
    n = len(records)
    assert n >= 3

    for i in range(1, n):
        this_name = f"_spf53-{i}.example.com"
        next_name = f"_spf53-{i + 1}.example.com"
        assert content[this_name].endswith(f"include:{next_name}")

    last_name = f"_spf53-{n}.example.com"
    assert content[last_name].endswith("~all")

    # passthrough is only ever placed in chunk 1
    first_name = "_spf53-1.example.com"
    assert "include:_spf.example-provider.com" in content[first_name]
    for i in range(2, n + 1):
        name = f"_spf53-{i}.example.com"
        assert "include:_spf.example-provider.com" not in content[name]

    for strings in records.values():
        assert 1 <= len(strings) <= chunker.MAX_STRINGS_PER_RECORD
        for s in strings:
            assert len(s) <= chunker.MAX_TXT_STRING


def test_mechanism_lands_exactly_at_255_boundary() -> None:
    # "v=spf1 " is 7 chars; pad the first passthrough token to 248 chars so
    # "v=spf1 " + token is exactly 255 chars -- forcing the split right there.
    token_a = "x" * 248
    assert len("v=spf1 " + token_a) == 255
    passthrough = [token_a, "exists:more"]
    records = chunker.build_records(DOMAIN, [], passthrough, "~all")

    strings = records["_spf53-1.example.com"]
    assert len(strings) == 2
    assert strings[0] == "v=spf1 " + token_a
    assert len(strings[0]) == 255
    assert strings[1].startswith(" ")
    for s in strings:
        assert len(s) <= chunker.MAX_TXT_STRING
    # no mechanism was split: concatenation reproduces the exact content
    assert "".join(strings) == "v=spf1 " + token_a + " exists:more ~all"


def test_round_trip_to_from_route53_value() -> None:
    networks = [IPv4Network(f"10.0.{i}.0/32") for i in range(60)]
    records = chunker.build_records(DOMAIN, networks, ["exists:foo"], "~all")

    for strings in records.values():
        value = chunker.to_route53_value(strings)
        parsed = chunker.from_route53_value(value)
        assert parsed == strings
        assert "".join(parsed) == "".join(strings)


def test_from_route53_value_handles_escaped_quotes_and_backslashes() -> None:
    value = r'"abc\"def" "back\\slash"'
    assert chunker.from_route53_value(value) == ['abc"def', "back\\slash"]


def test_to_route53_value_escapes_quotes_and_backslashes() -> None:
    strings = ['has "quotes"', "has\\backslash"]
    value = chunker.to_route53_value(strings)
    assert value == r'"has \"quotes\"" "has\\backslash"'
    assert chunker.from_route53_value(value) == strings


def test_lookup_cost_counts_chain_apex_and_dns_querying_passthrough() -> None:
    networks = [IPv4Network("192.0.2.0/24")]
    passthrough = [
        "exists:%{i}._spf.mta.salesforce.com",
        "include:_spf.other.com",
        "a:mail.example.com",
        "mx",
        "ptr:example.com",
        "ip4:203.0.113.0/24",  # not DNS-querying
    ]
    records = chunker.build_records(DOMAIN, networks, passthrough, "~all")
    cost = chunker.lookup_cost(records, passthrough)
    # chain length (already includes the apex include) + 5 dns-querying passthrough entries
    assert cost == len(records) + 5


def test_lookup_cost_excludes_all_and_negated_all_from_passthrough() -> None:
    # "all"/"-all" start with the letter "a" but are not the "a" mechanism.
    passthrough = ["all", "-all"]
    records = chunker.build_records(DOMAIN, [], passthrough, "~all")
    cost = chunker.lookup_cost(records, passthrough)
    assert cost == len(records)


def test_lookup_cost_counts_qualified_dns_querying_mechanisms() -> None:
    passthrough = [
        "a",
        "a:host.example.com",
        "mx",
        "mx:host.example.com",
        "ptr",
        "ptr:host.example.com",
        "include:x",
        "exists:x",
        "-a",
        "~mx:host",
    ]
    records = chunker.build_records(DOMAIN, [], passthrough, "~all")
    cost = chunker.lookup_cost(records, passthrough)
    assert cost == len(records) + len(passthrough)


def test_is_dns_querying_mechanism_rejects_all_and_negated_all() -> None:
    assert chunker._is_dns_querying_mechanism("all") is False
    assert chunker._is_dns_querying_mechanism("-all") is False


def test_is_dns_querying_mechanism_accepts_real_mechanisms_with_and_without_qualifiers() -> None:
    for term in [
        "a",
        "a:host.example.com",
        "mx",
        "mx:host.example.com",
        "ptr",
        "ptr:host.example.com",
        "include:x",
        "exists:x",
        "-a",
        "~mx:host",
    ]:
        assert chunker._is_dns_querying_mechanism(term) is True, term


def test_is_dns_querying_mechanism_recognizes_redirect_modifier() -> None:
    """redirect= is syntactically a modifier (`=`-separated), not a
    mechanism, but RFC 7208 4.6.4 counts it as one DNS-querying lookup.
    """
    assert chunker._is_dns_querying_mechanism("redirect=other.example.com") is True


def test_lookup_cost_counts_redirect_passthrough_as_dns_querying() -> None:
    passthrough = ["redirect=other.example.com"]
    records = chunker.build_records(DOMAIN, [], passthrough, "~all")
    cost = chunker.lookup_cost(records, passthrough)
    assert cost == len(records) + 1
