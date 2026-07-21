"""Config schema and YAML parsing for spf53."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from spf53._spf import strip_qualifier

_ALLOWED_TOP_KEYS = {"sns_topic_arn", "resolver_ips", "domains"}
_ALLOWED_DOMAIN_KEYS = {
    "name",
    "hosted_zone_id",
    "includes",
    "passthrough",
    "policy",
    "max_shrink_pct",
}
_VALID_POLICIES = ("~all", "-all")


class ConfigError(Exception):
    """Raised when a config fails validation."""


@dataclass(frozen=True)
class DomainConfig:
    name: str
    hosted_zone_id: str
    includes: tuple[str, ...]
    passthrough: tuple[str, ...] = ()
    policy: str = "~all"
    max_shrink_pct: int = 30


@dataclass(frozen=True)
class Spf53Config:
    domains: tuple[DomainConfig, ...]
    sns_topic_arn: str | None = None
    resolver_ips: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")


def parse_config(yaml_text: str) -> Spf53Config:
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML: {e}") from e

    if raw is None:
        raise ConfigError("config is empty")
    if not isinstance(raw, dict):
        raise ConfigError(f"config must be a mapping, got {type(raw).__name__}")

    unknown = set(raw) - _ALLOWED_TOP_KEYS
    if unknown:
        raise ConfigError(f"unknown top-level field(s): {', '.join(sorted(unknown))}")

    if "domains" not in raw:
        raise ConfigError("missing required field 'domains'")
    domains_raw = raw["domains"]
    if not isinstance(domains_raw, list) or not domains_raw:
        raise ConfigError("'domains' must be a non-empty list")
    domains = tuple(_parse_domain(i, d) for i, d in enumerate(domains_raw))
    _check_duplicate_domains(domains)

    sns_topic_arn = raw.get("sns_topic_arn")
    if sns_topic_arn is not None and not isinstance(sns_topic_arn, str):
        raise ConfigError("'sns_topic_arn' must be a string")

    if "resolver_ips" in raw:
        resolver_ips_raw = raw["resolver_ips"]
        if not isinstance(resolver_ips_raw, list) or not all(
            isinstance(x, str) for x in resolver_ips_raw
        ):
            raise ConfigError("'resolver_ips' must be a list of strings")
        if not resolver_ips_raw:
            raise ConfigError("'resolver_ips' must not be empty")
        resolver_ips = tuple(resolver_ips_raw)
    else:
        resolver_ips = ("1.1.1.1", "8.8.8.8")

    return Spf53Config(domains=domains, sns_topic_arn=sns_topic_arn, resolver_ips=resolver_ips)


def _check_duplicate_domains(domains: Sequence[DomainConfig]) -> None:
    """Reject configs that list the same domain twice.

    Domain names are already lowercased by _parse_domain, so a plain
    equality check is case-insensitive. Two entries for the same domain
    would otherwise race concurrently over the same Route53 rrsets in
    core.py's domain pool.
    """
    seen: dict[str, int] = {}
    for i, d in enumerate(domains):
        if d.name in seen:
            raise ConfigError(
                f"duplicate domain {d.name!r}: domains[{seen[d.name]}] and domains[{i}] "
                "both configure the same domain"
            )
        seen[d.name] = i


def _parse_domain(index: int, raw: object) -> DomainConfig:
    label = f"domains[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{label}: must be a mapping, got {type(raw).__name__}")

    unknown = set(raw) - _ALLOWED_DOMAIN_KEYS
    if unknown:
        raise ConfigError(f"{label}: unknown field(s): {', '.join(sorted(unknown))}")

    if "name" not in raw:
        raise ConfigError(f"{label}: missing required field 'name'")
    name = raw["name"]
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{label}: 'name' must be a non-empty string")
    # Normalize so config names match what Route53 returns (always lowercase,
    # unqualified) — otherwise every diff looks like a change and the shrink
    # guard never sees a matching live record.
    name = name.lower()
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise ConfigError(f"{label}: 'name' must be a non-empty string")
    label = f"domain '{name}'"

    if "hosted_zone_id" not in raw:
        raise ConfigError(f"{label}: missing required field 'hosted_zone_id'")
    hosted_zone_id = raw["hosted_zone_id"]
    if not isinstance(hosted_zone_id, str) or not hosted_zone_id:
        raise ConfigError(f"{label}: 'hosted_zone_id' must be a non-empty string")

    if "includes" not in raw:
        raise ConfigError(f"{label}: missing required field 'includes'")
    includes_raw = raw["includes"]
    if not isinstance(includes_raw, list) or not all(isinstance(x, str) for x in includes_raw):
        raise ConfigError(f"{label}: 'includes' must be a list of strings")
    includes = tuple(includes_raw)

    passthrough_raw = raw.get("passthrough", [])
    if not isinstance(passthrough_raw, list) or not all(
        isinstance(x, str) for x in passthrough_raw
    ):
        raise ConfigError(f"{label}: 'passthrough' must be a list of strings")
    for entry in passthrough_raw:
        if strip_qualifier(entry).lower() == "all":
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} is a bare 'all' mechanism — "
                "passthrough is placed first in chunk 1, so this would terminate SPF "
                "evaluation immediately and make every mechanism after it (including "
                "the chunk chain and the final policy) unreachable"
            )
    passthrough = tuple(passthrough_raw)

    policy = raw.get("policy", "~all")
    if policy not in _VALID_POLICIES:
        raise ConfigError(f"{label}: 'policy' must be '~all' or '-all', got {policy!r}")

    max_shrink_pct = raw.get("max_shrink_pct", 30)
    if (
        isinstance(max_shrink_pct, bool)
        or not isinstance(max_shrink_pct, int)
        or not 0 <= max_shrink_pct <= 100
    ):
        raise ConfigError(
            f"{label}: 'max_shrink_pct' must be an int between 0 and 100, got {max_shrink_pct!r}"
        )

    return DomainConfig(
        name=name,
        hosted_zone_id=hosted_zone_id,
        includes=includes,
        passthrough=passthrough,
        policy=policy,
        max_shrink_pct=max_shrink_pct,
    )


def load_config_file(path: str | Path) -> Spf53Config:
    return parse_config(Path(path).read_text())
