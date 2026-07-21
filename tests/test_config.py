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


def test_domain_name_only_strips_a_single_trailing_dot() -> None:
    yaml_text = """
domains:
  - name: example.com..
    hosted_zone_id: Z123EXAMPLE
    includes: [_spf.google.com]
"""
    cfg = parse_config(yaml_text)
    assert cfg.domains[0].name == "example.com."


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
