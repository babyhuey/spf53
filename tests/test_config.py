from pathlib import Path

import pytest

from spf53.config import ConfigError, DomainConfig, Spf53Config, load_config_file, parse_config

MINIMAL_YAML = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes:
      - _spf.google.com
"""

FULL_YAML = """
sns_topic_arn: arn:aws:sns:us-east-1:123456789012:spf53-alerts
resolver_ips: ["9.9.9.9", "8.8.4.4"]
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    policy: "-all"
    max_shrink_pct: 50
    passthrough:
      - "exists:%{i}._spf.mta.salesforce.com"
    includes:
      - _spf.google.com
      - amazonses.com
"""


def test_minimal_valid_yaml_applies_defaults() -> None:
    cfg = parse_config(MINIMAL_YAML)
    assert cfg == Spf53Config(
        domains=(
            DomainConfig(
                name="example.com",
                hosted_zone_id="Z123EXAMPLE",
                includes=("_spf.google.com",),
            ),
        ),
    )
    assert cfg.sns_topic_arn is None
    assert cfg.resolver_ips == ("1.1.1.1", "8.8.8.8")


def test_full_yaml_overrides_defaults() -> None:
    cfg = parse_config(FULL_YAML)
    assert cfg.sns_topic_arn == "arn:aws:sns:us-east-1:123456789012:spf53-alerts"
    assert cfg.resolver_ips == ("9.9.9.9", "8.8.4.4")
    assert len(cfg.domains) == 1
    domain = cfg.domains[0]
    assert domain.name == "example.com"
    assert domain.hosted_zone_id == "Z123EXAMPLE"
    assert domain.policy == "-all"
    assert domain.max_shrink_pct == 50
    assert domain.passthrough == ("exists:%{i}._spf.mta.salesforce.com",)
    assert domain.includes == ("_spf.google.com", "amazonses.com")


def test_multiple_domains() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z1
    includes: [_spf.google.com]
  - name: example.org
    hosted_zone_id: Z2
    includes: [amazonses.com]
"""
    cfg = parse_config(yaml_text)
    assert [d.name for d in cfg.domains] == ["example.com", "example.org"]


def test_invalid_yaml_syntax_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="invalid YAML"):
        parse_config("domains: [unterminated")


def test_empty_config_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="empty"):
        parse_config("")


def test_top_level_not_a_mapping_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="mapping"):
        parse_config("- just\n- a\n- list\n")


def test_unknown_top_level_key_raises_config_error() -> None:
    yaml_text = MINIMAL_YAML + "\nbogus_field: true\n"
    with pytest.raises(ConfigError, match="bogus_field"):
        parse_config(yaml_text)


def test_missing_domains_key_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="domains"):
        parse_config("sns_topic_arn: arn:aws:sns:us-east-1:123456789012:topic\n")


def test_empty_domains_list_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="domains"):
        parse_config("domains: []\n")


def test_missing_name_raises_config_error() -> None:
    yaml_text = """
domains:
  - hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    with pytest.raises(ConfigError, match="name"):
        parse_config(yaml_text)


def test_missing_hosted_zone_id_raises_config_error() -> None:
    yaml_text = """
domains:
  - name: example.com
    includes: [_spf.google.com]
"""
    with pytest.raises(ConfigError, match="hosted_zone_id"):
        parse_config(yaml_text)


def test_missing_includes_raises_config_error() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
"""
    with pytest.raises(ConfigError, match="includes"):
        parse_config(yaml_text)


def test_error_names_offending_domain() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
  - name: example.org
    includes: [amazonses.com]
"""
    with pytest.raises(ConfigError, match="example.org"):
        parse_config(yaml_text)


def test_unknown_domain_key_raises_config_error() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    bogus: true
"""
    with pytest.raises(ConfigError, match="bogus"):
        parse_config(yaml_text)


@pytest.mark.parametrize("policy", ["+all", "?all", "all", ""])
def test_bad_policy_raises_config_error(policy: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    policy: "{policy}"
    includes: [_spf.google.com]
"""
    with pytest.raises(ConfigError, match="policy"):
        parse_config(yaml_text)


@pytest.mark.parametrize("policy", ["~all", "-all"])
def test_valid_policies_accepted(policy: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    policy: "{policy}"
    includes: [_spf.google.com]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].policy == policy


@pytest.mark.parametrize("value", [-1, 101, 30.5, "30", True])
def test_bad_max_shrink_pct_raises_config_error(value: object) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    max_shrink_pct: {value!r}
    includes: [_spf.google.com]
"""
    with pytest.raises(ConfigError, match="max_shrink_pct"):
        parse_config(yaml_text)


@pytest.mark.parametrize("value", [0, 30, 100])
def test_valid_max_shrink_pct_boundaries_accepted(value: int) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    max_shrink_pct: {value}
    includes: [_spf.google.com]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].max_shrink_pct == value


def test_domain_name_lowercased() -> None:
    yaml_text = """
domains:
  - name: Example.COM
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].name == "example.com"


def test_domain_name_trailing_dot_stripped() -> None:
    yaml_text = """
domains:
  - name: example.com.
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].name == "example.com"


def test_domain_name_lowercased_and_trailing_dot_stripped() -> None:
    yaml_text = """
domains:
  - name: Example.COM.
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].name == "example.com"


def test_domain_name_with_double_trailing_dot_raises_config_error() -> None:
    """Only a single trailing dot is a legitimate FQDN root marker -- a
    second one means the input was already malformed. Silently normalizing
    "example.com.." to "example.com." (one dot left over) would never match
    Route53's dot-stripped names, causing a perpetual DELETE+UPSERT of the
    same rrset that Route53 rejects.
    """
    yaml_text = """
domains:
  - name: example.com..
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    with pytest.raises(ConfigError, match="name"):
        parse_config(yaml_text)


def test_domain_name_all_dots_raises_config_error() -> None:
    yaml_text = """
domains:
  - name: "."
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    with pytest.raises(ConfigError, match="name"):
        parse_config(yaml_text)


def test_duplicate_domain_raises_config_error() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z1
    includes: [_spf.google.com]
  - name: example.com
    hosted_zone_id: Z2
    includes: [amazonses.com]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_duplicate_domain_case_insensitive_raises_config_error() -> None:
    yaml_text = """
domains:
  - name: Example.COM
    hosted_zone_id: Z1
    includes: [_spf.google.com]
  - name: example.com.
    hosted_zone_id: Z2
    includes: [amazonses.com]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_three_distinct_domains_do_not_raise() -> None:
    yaml_text = """
domains:
  - name: a.example.com
    hosted_zone_id: Z1
    includes: [_spf.google.com]
  - name: b.example.com
    hosted_zone_id: Z2
    includes: [amazonses.com]
  - name: c.example.com
    hosted_zone_id: Z3
    includes: [amazonses.com]
"""
    cfg = parse_config(yaml_text)
    assert [d.name for d in cfg.domains] == ["a.example.com", "b.example.com", "c.example.com"]


@pytest.mark.parametrize("value", ["all", "+all", "-all", "~all", "?all", "ALL", "-ALL"])
def test_bare_all_passthrough_raises_config_error(value: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert value in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [
        "ip4:1.2.3.4 all",
        "include:a.com include:b.com",
        "ip4:1.2.3.4 ip4:5.6.7.8",
    ],
)
def test_passthrough_entry_with_whitespace_raises_config_error(value: str) -> None:
    """A whitespace-containing passthrough entry is spliced verbatim into the
    built record, so a multi-token entry like "ip4:1.2.3.4 all" would embed
    a bare `all` mid-record without matching the single-token bare-'all'
    check above, silently terminating SPF evaluation early.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert "whitespace" in str(exc_info.value)


@pytest.mark.parametrize("value", ["a", "mx", "ptr", "a/24", "mx//64"])
def test_bare_a_mx_ptr_passthrough_raises_config_error(value: str) -> None:
    """A bare a/mx/ptr mechanism implicitly refers to the domain it's
    evaluated in -- but passthrough entries are spliced into
    '_spf53-1.<domain>', not the real domain, so a bare entry would silently
    stop matching anything a user expects it to.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert value in str(exc_info.value)


def test_explicit_target_a_mx_passthrough_entries_accepted() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "a:example.com"
      - "mx:example.com"
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == ("a:example.com", "mx:example.com")


@pytest.mark.parametrize(
    "value",
    ["a:mail.example.com/33", "mx:example.com//129", "a:x.com/24//129", "ptr:example.com/24"],
)
def test_out_of_range_cidr_length_passthrough_raises_config_error(value: str) -> None:
    """An IPv4 CIDR length must be 0-32 and an IPv6 CIDR length must be 0-128
    -- an out-of-range length would publish a syntax error that PermErrors
    the whole domain. ptr: has no CIDR-length suffix at all.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_in_range_cidr_length_passthrough_entries_accepted() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "a:mail.example.com/32"
      - "a:mail.example.com/0"
      - "mx:example.com//128"
      - "a:x.com/24//64"
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == (
        "a:mail.example.com/32",
        "a:mail.example.com/0",
        "mx:example.com//128",
        "a:x.com/24//64",
    )


@pytest.mark.parametrize(
    "value",
    [
        "ip4:203.0.113.0/024",
        "ip6:2001:db8::/032",
        "a:mail.example.com/032",
        "a:mail.example.com/00",
        "mx:example.com//0128",
    ],
)
def test_leading_zero_cidr_length_passthrough_raises_config_error(value: str) -> None:
    """RFC 7208's ABNF forbids a leading zero in a CIDR length ("0" is the
    only valid single-digit form) -- a leading-zero length like /024 would
    publish verbatim and PermError the whole domain at strict receivers.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_zero_cidr_length_passthrough_entries_accepted() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "ip4:203.0.113.0/0"
      - "a:mail.example.com/0"
      - "mx:example.com//0"
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == (
        "ip4:203.0.113.0/0",
        "a:mail.example.com/0",
        "mx:example.com//0",
    )


@pytest.mark.parametrize(
    "value",
    [
        "a:host.example.com/2٤",  # Arabic-Indic digit 4 -- int() reads it as 24
        "a:h.com/2۴",  # Extended Arabic-Indic digit 4
        "a:h.com/3２",  # Fullwidth digit 2 -- int() reads it as 32
        "mx:host.example.com//12８",  # Fullwidth digit 8 -- int() reads it as 128
        "a:héllo.example.com",  # non-ASCII target, not just a non-ASCII length
        "include:_spf.exämple.com",
        "exists:☃.example.com",
    ],
)
def test_non_ascii_passthrough_entry_raises_config_error(value: str) -> None:
    """RFC 7208 only allows ASCII. Unicode decimal digits (which \\d matches
    and int() converts) could otherwise sail through a CIDR-length bounds
    check that assumes ASCII input -- e.g. '/2٤' parses as int 24 and
    passes a 0-32 range check, then publishes non-ASCII bytes as a CIDR
    length. A single ASCII check up front closes this and the equivalent
    non-ASCII-target gap at once.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_oversized_cidr_length_passthrough_raises_config_error() -> None:
    """A CIDR length longer than any valid value (max 3 digits, since 128 is
    the largest legal length) must be rejected by the shape match itself,
    not reach int() -- Python 3.11+ raises a bare ValueError, not
    ConfigError, past 4300 digits of int-string conversion.
    """
    value = "a:host.example.com/" + "1" * 4301
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


@pytest.mark.parametrize(
    "escaped_target",
    [
        r"foo\x00bar.example",  # NUL
        r"foo\x01bar.example",  # SOH
        r"foo\x7Fbar.example",  # DEL -- isascii() doesn't exclude it either
    ],
)
def test_control_char_passthrough_entry_raises_config_error(escaped_target: str) -> None:
    """isascii() alone admits C0 control characters and DEL -- none of them
    are in RFC 7208's visible-ASCII macro-literal grammar (%x21-24/%x26-7E),
    and none are caught by the separate whitespace check either. A YAML
    double-quoted escape (as used here, mirroring how a real config file
    could carry one) decodes to a real control character that reaches
    _validate_passthrough_shape intact -- unlike a raw control character in
    a plain YAML scalar, which PyYAML itself already rejects before
    validation ever runs.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["include:{escaped_target}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


@pytest.mark.parametrize(
    "value",
    [
        "exists:%q.example.com",  # bare '%' before an invalid escape char
        "exists:%{z}.example.com",  # invalid macro letter
        "exists:%{i.example.com",  # unterminated macro, otherwise-valid letter
        "include:50%.example.com",  # bare '%' inside a target
        "a:%.example.com",
        "exists:%{dfoo.example",  # unterminated %{d -- dodges _MACRO_D_RE's own check
    ],
)
def test_invalid_macro_sequence_passthrough_raises_config_error(value: str) -> None:
    """The visible-ASCII gate has to admit '%' since macros are a documented
    passthrough use case, but every '%' must actually introduce one of RFC
    7208's four legal macro-expand forms (%%, %_, %-, %{...}) -- anything
    else is a syntax error that permerrors the whole domain, same blast
    radius as an invalid character.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_valid_macro_sequence_passthrough_entries_accepted() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "exists:%{i}._spf.example.net"
      - "exists:%{ir}._spf.example.net"
      - "exists:%{s}._spf.example.net"
      - "exists:%%25.example.net"
      - "exists:%_.example.net"
      - "exists:%-.example.net"
      - "exists:%{l1r+}._spf.example.net"
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == (
        "exists:%{i}._spf.example.net",
        "exists:%{ir}._spf.example.net",
        "exists:%{s}._spf.example.net",
        "exists:%%25.example.net",
        "exists:%_.example.net",
        "exists:%-.example.net",
        "exists:%{l1r+}._spf.example.net",
    )


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_or_whitespace_only_passthrough_raises_config_error(value: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert "empty" in str(exc_info.value) or "whitespace" in str(exc_info.value)


def test_non_all_passthrough_entries_accepted() -> None:
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "exists:%{i}._spf.mta.salesforce.com"
      - "ip4:203.0.113.0/24"
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == (
        "exists:%{i}._spf.mta.salesforce.com",
        "ip4:203.0.113.0/24",
    )


@pytest.mark.parametrize(
    "value",
    [
        "a:%{d}.example.net",
        "exists:%{d2r}._spf.example.net",
        "include:%{D}.example.net",
        "mx:%{d1r-}.example.net",
    ],
)
def test_macro_d_passthrough_raises_config_error(value: str) -> None:
    """%{d} expands to the domain currently being evaluated -- but
    passthrough entries are spliced into '_spf53-1.<domain>', not the real
    domain, so after relocation %{d} would silently expand to the chunk
    record's own name instead of the domain the user meant, dropping the
    intended authorization.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert "%{d" in str(exc_info.value)


def test_macro_i_passthrough_entry_accepted() -> None:
    """%{i} (and other non-'%{d...}' macros) derive from the SMTP connection
    or sender address, not the evaluated domain, so they aren't relocation-
    sensitive and must remain accepted -- this is the documented Salesforce-
    style safe use case.
    """
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "exists:%{i}._spf.example.net"
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == ("exists:%{i}._spf.example.net",)


@pytest.mark.parametrize("value", ["a:", "mx:", "ptr:", "exists:", "include:", "redirect="])
def test_empty_target_passthrough_raises_config_error(value: str) -> None:
    """A colon/equals with nothing after it is spliced verbatim into the
    built record, publishing syntactically invalid SPF -- real receivers
    PermError the entire domain over this, not just skip the one mechanism.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert value in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [
        "a:example.com",
        "mx:example.com",
        "ptr:example.com",
        "exists:%{i}._spf.example.net",
        "include:_spf.example.net",
        "redirect=_spf.example.net",
    ],
)
def test_well_formed_target_passthrough_entries_accepted(value: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == (value,)


@pytest.mark.parametrize(
    "value",
    [
        "a:/24",
        "mx://64",
        "+",
        "-",
        "~",
        "ip4=1.2.3.0/24",
        "include=x.com",
    ],
)
def test_passthrough_shape_gaps_raise_config_error(value: str) -> None:
    """Round 5, verified against pyspf: these all slipped past the round 3/4
    blocklist checks despite being malformed or silently-wrong SPF --
    "a:/24"/"mx://64" have a colon followed by non-empty text so the old
    empty-target regex missed them; "+"/"-"/"~" reduce to "" after qualifier
    stripping and matched no blocklist check; "ip4=..."/"include=..." use
    the wrong separator and parse as an unknown, silently-ignored modifier
    per RFC 7208, dropping the intended authorization with zero error.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com") as exc_info:
        parse_config(yaml_text)
    assert value in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [
        "ip4:203.0.113.0/24",
        "ip6:2001:db8::/32",
        "a:mail.example.com",
        "exists:%{i}._spf.example.net",
    ],
)
def test_well_formed_passthrough_shapes_accepted(value: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == (value,)


@pytest.mark.parametrize(
    "value",
    [
        "ip4:not-a-cidr",
        "ip4:2001:db8::/32",  # ip6 literal under an ip4: prefix
        "ip6:203.0.113.0/24",  # ip4 literal under an ip6: prefix
    ],
)
def test_invalid_ip_literal_passthrough_raises_config_error(value: str) -> None:
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


@pytest.mark.parametrize(
    "value",
    [
        "exists:spfhosts",
        "exists:.",
        "mx:..",
        "ptr:foo",
        "exists:example.123",
        "exists:example.com-",
    ],
)
def test_malformed_domain_target_passthrough_raises_config_error(value: str) -> None:
    """Round 7, verified against pyspf: the mechanism *target* (the domain
    part after a:/mx:/ptr:/exists:/include:/redirect=) was never validated
    as an actual RFC 7208 domain-end -- a bare single-label target with no
    dot ("spfhosts"), an empty toplabel ("." or ".."), or a toplabel that's
    all-digits ("example.123") or ends in a hyphen ("example.com-") all
    published verbatim and PermErrored the whole domain at real receivers,
    even with the sender IP inside a legitimately-authorized range.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


@pytest.mark.parametrize("prefix", ["a:", "mx:", "ptr:", "exists:", "include:"])
def test_bare_single_label_target_rejected_for_every_mechanism(prefix: str) -> None:
    """The domain-spec check applies uniformly to every mechanism that takes
    a target -- not just exists:, which round 7's initial finding happened
    to use.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{prefix}spfhosts"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_redirect_bare_single_label_target_raises_config_error() -> None:
    """redirect= takes a domain-spec target too (RFC 7208 §6.1), so it needs
    the same domain-syntax validation as a:/mx:/ptr:/exists:/include:.
    """
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["redirect=spfhosts"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


@pytest.mark.parametrize(
    "value",
    [
        "exists:foo..example.com",
        "exists:" + "a" * 80 + ".example.com",
    ],
)
def test_tier2_grammar_valid_but_unresolvable_domain_target_raises_config_error(
    value: str,
) -> None:
    """These are syntactically legal per a strict RFC 7208 ABNF reading (it
    defers label-length limits to DNS itself), but can never resolve to
    anything -- an interior empty label ('foo..example.com') or a label
    over 63 octets never matches any real DNS name, so the authorization
    would silently do nothing. Same failure class as an earlier round's
    %{d} relocation bug.
    """
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["{value}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_domain_target_total_length_over_253_raises_config_error() -> None:
    long_target = ".".join(["a" * 50] * 5) + ".example.com"  # well over 253 octets
    yaml_text = f"""
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough: ["exists:{long_target}"]
"""
    with pytest.raises(ConfigError, match="example.com"):
        parse_config(yaml_text)


def test_trailing_dot_fqdn_domain_target_accepted() -> None:
    """A single trailing dot (the fully-qualified form) is legal per
    domain-end's optional '[ "." ]' and must not be rejected as an empty
    final label.
    """
    yaml_text = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
    passthrough:
      - "a:mail.example.com."
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].passthrough == ("a:mail.example.com.",)


def test_load_config_file(tmp_path: Path) -> None:
    config_path = tmp_path / "spf53.yaml"
    config_path.write_text(MINIMAL_YAML)
    cfg = load_config_file(config_path)
    assert cfg.domains[0].name == "example.com"


def test_load_config_file_accepts_str_path(tmp_path: Path) -> None:
    config_path = tmp_path / "spf53.yaml"
    config_path.write_text(MINIMAL_YAML)
    cfg = load_config_file(str(config_path))
    assert cfg.domains[0].name == "example.com"
