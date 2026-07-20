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
