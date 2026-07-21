"""Config schema and YAML parsing for spf53."""

from __future__ import annotations

import re
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

# Matches a bare (host-less) a/mx mechanism: "a", "mx", optionally followed by
# a "/<v4-len>" and/or "//<v6-len>" dual-cidr suffix, but with no ":<host>" --
# a colon anywhere makes the whole string not match, since there's no ":" in
# this pattern at all.
_BARE_A_MX_RE = re.compile(r"^(a|mx)(/\d+)?(//\d+)?$", re.IGNORECASE)

# Matches a/mx/ptr/exists/include: or redirect= with an empty (or
# whitespace-only) target after the colon/equals, e.g. "a:" or "include: ".
_EMPTY_TARGET_RE = re.compile(r"^(a|mx|ptr|exists|include):\s*$|^redirect=\s*$", re.IGNORECASE)

# Matches any %{d...} macro reference (%{d}, %{d1}, %{d2r}, %{D}, ...) --
# the macro letter is 'd'/'D' (case-insensitive), optionally followed by
# transformer digits/flags, closed by '}'.
_MACRO_D_RE = re.compile(r"%\{[dD][^}]*\}")


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


def _is_bare_a_mx_ptr(term: str) -> bool:
    """Whether `term` is a host-less a/mx/ptr mechanism (no explicit
    ":target"), which implicitly refers to "the domain this record is
    evaluated in" per RFC 7208 -- as opposed to e.g. "a:somehost.example",
    which explicitly names a target and carries no such ambiguity.
    """
    return term.lower() == "ptr" or bool(_BARE_A_MX_RE.match(term))


def _has_empty_target(term: str) -> bool:
    """Whether `term` is a a:/mx:/ptr:/exists:/include:/redirect= mechanism
    whose target (the part after the colon/equals) is empty or
    whitespace-only, e.g. "a:" -- as opposed to "a:example.com", which names
    a real target and is unambiguous.
    """
    return bool(_EMPTY_TARGET_RE.match(term))


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
        if not entry.strip():
            raise ConfigError(f"{label}: passthrough entry is empty or whitespace-only")
        if any(ch.isspace() for ch in entry):
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} contains whitespace — "
                "each passthrough entry is spliced verbatim into the built SPF record, "
                "so it must be exactly one mechanism"
            )
        if strip_qualifier(entry).lower() == "all":
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} is a bare 'all' mechanism — "
                "passthrough is placed first in chunk 1, so this would terminate SPF "
                "evaluation immediately and make every mechanism after it (including "
                "the chunk chain and the final policy) unreachable"
            )
        if _is_bare_a_mx_ptr(strip_qualifier(entry)):
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} is a bare 'a'/'mx'/'ptr' "
                "mechanism with no explicit target — a bare a/mx/ptr mechanism "
                "implicitly refers to the domain it's evaluated in, but passthrough "
                f"entries are spliced into '_spf53-1.{name}', not '{name}' itself — "
                f"write it explicitly instead, e.g. 'a:{name}' or 'mx:{name}'"
            )
        if _has_empty_target(strip_qualifier(entry)):
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} has an empty target — "
                "spliced verbatim into the built record, this would publish "
                "syntactically invalid SPF, which causes receivers to PermError "
                "the entire domain rather than just skip this one mechanism"
            )
        if _MACRO_D_RE.search(entry):
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} contains a '%{{d}}' macro — "
                "%{d} expands to the domain currently being evaluated, but "
                f"passthrough entries are spliced into '_spf53-1.{name}', not "
                f"'{name}' itself, so after relocation it would silently expand to "
                "the chunk record's own name instead of the domain you meant, "
                "dropping the intended authorization"
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
