"""Config schema and YAML parsing for spf53."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from spf53._spf import match_ip_mechanism, parse_ip_literal, strip_qualifier

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

# The mechanism/modifier shapes spf53 knows how to relocate verbatim into
# `_spf53-1.<domain>`. A passthrough entry is accepted only if it matches one
# of these -- requiring a real, non-empty target as part of the shape itself
# means a host-less "a"/"mx"/"ptr" and an empty "a:"/"include:"/etc. both
# simply fail to match, with no separate "bare" or "empty-target" check
# needed. ip4:/ip6: are handled separately via match_ip_mechanism +
# parse_ip_literal, since "a real CIDR" isn't expressible as a regex.
_A_MX_RE = re.compile(
    r"^(?:a|mx):(?P<host>[^/]+)(?:/(?P<len4>0|[1-9][0-9]{0,2}))?(?://(?P<len6>0|[1-9][0-9]{0,2}))?$",
    re.IGNORECASE,
)
_PTR_RE = re.compile(r"^ptr:(?P<host>[^/]+)$", re.IGNORECASE)
_EXISTS_INCLUDE_RE = re.compile(r"^(?:exists|include):(?P<target>.+)$", re.IGNORECASE)
# redirect= is a modifier, not a mechanism -- RFC 7208 gives it no qualifier
# prefix -- so this is matched against the raw entry rather than the
# qualifier-stripped one. A leading qualifier char (e.g. "+redirect=x.com")
# is itself invalid syntax and correctly falls through to the generic
# rejection instead of being treated as a valid redirect=.
_REDIRECT_RE = re.compile(r"^redirect=(?P<target>.+)$", re.IGNORECASE)

# Matches any %{d...} macro reference (%{d}, %{d1}, %{d2r}, %{D}, ...) --
# the macro letter is 'd'/'D' (case-insensitive), optionally followed by
# transformer digits/flags, closed by '}'.
_MACRO_D_RE = re.compile(r"%\{[dD][^}]*\}")

# RFC 7208 7.1's macro-expand grammar: %% / %_ / %- / %{macro-letter
# transformers *delimiter}. macro-letter is one of s/l/o/d/i/p/h/c/r/t/v
# (case-insensitive); transformers is optional digits with an optional
# trailing 'r'; delimiter is one of . - + , / _ =, and may repeat.
_MACRO_EXPAND_RE = re.compile(r"%(?:%|_|-|\{(?i:[slodiphcrtv])[0-9]*[rR]?[.\-+,/_=]*\})")

# RFC 7208 §5's DNS label limits -- the ABNF itself doesn't encode these
# (it defers to DNS's own rules), but a label/name past these bounds can
# never resolve, which is the same "publishes but authorizes nothing"
# failure mode as a grammar violation.
_MAX_LABEL_LEN = 63
_MAX_DOMAIN_LEN = 253

# Stand-in for a macro-expand when checking a passthrough target's domain
# structure (see _validate_domain_spec) -- never a real character, since
# the visible-ASCII gate in _validate_passthrough_shape already restricts
# every character reaching that function to 0x21-0x7E.
_MACRO_PLACEHOLDER = "\x00"


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


def _validate_domain_spec(target: str, label: str, entry: str) -> None:
    """Validate `target` -- the portion after a:/mx:/ptr:/exists:/include:/
    redirect=, with any CIDR-length suffix already stripped by the caller --
    as an RFC 7208 §7.1 domain-spec: `macro-string domain-end`, where
    `domain-end = ( "." toplabel [ "." ] ) / macro-expand`.

    A target that's entirely macro-expand(s), e.g. "%{ir}", legitimately
    stands in for the whole domain-end and needs no further check --
    `macro_free` (every macro-expand deleted) being empty is exactly that
    case. Otherwise, every macro-expand in `target` is replaced with a
    single placeholder character (`_MACRO_PLACEHOLDER`) rather than
    deleted, and the checks below run against that. Deleting outright
    would make a macro that legitimately stands for a whole label -- or
    sits right next to a literal dot -- look like an empty label after
    the fact: "foo.%{i}.example.com" would misread as
    "foo..example.com", and a leading macro would misread as a leading
    empty label the same way ".a" genuinely is. The placeholder can't
    collide with real content: the visible-ASCII gate earlier in
    `_validate_passthrough_shape` already restricts every character that
    reaches this function to 0x21-0x7E.

    What's left is checked in two tiers:

    Tier 1 (RFC-invalid, always rejected): the remainder must have a dot
    before its final label, and that final label must be a real toplabel
    -- non-empty, containing a letter, not starting or ending with a
    hyphen, and not all-digits. A remainder that's just "." or ends in
    ".." has no such label at all. This is the actual bug: entries like
    "exists:spfhosts" (no dot), "exists:example.123" (all-numeric
    toplabel), and "exists:example.com-" (hyphen-ending toplabel)
    currently sail through and publish a record that PermErrors the whole
    domain at real receivers.

    Tier 2 (RFC-grammar-valid but never resolves, also rejected): an empty
    label anywhere but the final position (already covered by Tier 1), a
    literal label over 63 octets, or a literal (non-macro) portion over
    253 octets. RFC 7208's ABNF doesn't encode DNS's own length limits, so
    these pass a strict grammar reading, but a name like this can never
    resolve -- the same "publishes but silently authorizes nothing"
    failure mode as the %{d} relocation bug from an earlier round.
    """
    macro_free = _MACRO_EXPAND_RE.sub("", target)
    if not macro_free:
        return

    literal = _MACRO_EXPAND_RE.sub(_MACRO_PLACEHOLDER, target)

    if literal == "." or literal.endswith(".."):
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} has a malformed domain target "
            f"{target!r} — RFC 7208's domain-end grammar requires a real toplabel, "
            "not an empty one"
        )

    # A single trailing dot is the FQDN form and is legal per domain-end's
    # optional "[ '.' ]" -- strip it before pulling out the final label.
    trimmed = literal[:-1] if literal.endswith(".") else literal

    if "." not in trimmed:
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} has target {target!r} with no "
            "dot at all — RFC 7208's domain-end grammar requires a literal '.' "
            "before the final label, unless the entire target is a macro-expand"
        )

    labels = trimmed.split(".")
    final_label = labels[-1]
    if (
        final_label[0] == "-"
        or final_label[-1] == "-"
        or not any(ch.isalpha() for ch in final_label)
    ):
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} has target {target!r} whose "
            f"final label {final_label!r} isn't a valid RFC 7208 toplabel — it "
            "must contain a letter and must not start or end with a hyphen or be "
            "all-digits"
        )

    # Tier 2: grammar-valid but can never resolve to anything. Every
    # non-final label (the final one was already validated above) must be
    # non-empty -- a placeholder-only label is never empty, so a macro
    # sitting at any position, including the very first label, correctly
    # doesn't trip this.
    if any(not lbl for lbl in labels[:-1]):
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} has target {target!r} with an "
            "empty label — this is syntactically legal SPF grammar but can never "
            "resolve to anything, so it would silently authorize nothing"
        )
    if any(_MACRO_PLACEHOLDER not in lbl and len(lbl) > _MAX_LABEL_LEN for lbl in labels):
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} has target {target!r} with a "
            f"label over {_MAX_LABEL_LEN} octets — this is syntactically legal "
            "SPF grammar but can never resolve to anything, so it would silently "
            "authorize nothing"
        )
    if len(macro_free) > _MAX_DOMAIN_LEN:
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} has target {target!r} whose "
            f"literal portion is over {_MAX_DOMAIN_LEN} octets — this is "
            "syntactically legal SPF grammar but can never resolve to anything, "
            "so it would silently authorize nothing"
        )


def _validate_passthrough_shape(entry: str, label: str, name: str) -> None:
    """Positively validate `entry` against the mechanism/modifier shapes
    spf53 actually knows how to relocate into `_spf53-1.<domain>`, rejecting
    anything that doesn't match one of them.

    This replaces blocklisting individual bad shapes one at a time -- three
    review rounds of that kept turning up the next unblocked variant (e.g.
    "a:/24", a lone "+", "ip4=..." with the wrong separator silently parsing
    as an ignored modifier). A positive match list has no such gap: anything
    not on it is rejected by default.
    """
    # RFC 7208's macro-literal grammar is exactly the visible-ASCII range
    # %x21-24 / %x26-7E (i.e. everything printable except '%' itself, which
    # is only legal as a macro-expand introducer) -- nothing outside
    # 0x21-0x7e is ever legal in an SPF record. isascii() alone isn't
    # enough: it admits C0 control characters (\x00-\x1f) and DEL (\x7f),
    # which aren't excluded by the separate whitespace check either
    # (isspace() only catches a handful of them) and can reach this
    # function via a YAML double-quoted escape like "a:host\x00.example".
    # Gating on the visible range closes that, plus every non-ASCII byte
    # (including Unicode digits in a CIDR length, e.g. '/2٤', which
    # Python's int() would otherwise silently accept as a valid-looking
    # '24') in one check.
    if not all(0x21 <= ord(ch) <= 0x7E for ch in entry):
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} contains a character outside "
            "RFC 7208's printable-ASCII SPF alphabet — this would publish invalid "
            "syntax"
        )

    # The visible-ASCII gate above admits '%' -- it has to, since macros are
    # the documented, common passthrough use case (e.g. '%{i}'). But every
    # '%' must actually introduce one of RFC 7208's four legal macro-expand
    # forms (%%, %_, %-, or %{<letter><transformers><delimiters>}); anything
    # else (a bare '%', an unknown macro letter, a missing closing brace) is
    # a syntax error that permerrors the whole domain, same blast radius as
    # an invalid character. Removing every valid macro-expand match and
    # checking no '%' remains catches all of those in one pass.
    if _MACRO_EXPAND_RE.sub("", entry).count("%"):
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} contains a '%' that isn't part "
            "of a valid SPF macro-expand sequence (%%, %_, %-, or "
            "%{<letter><transformers><delimiters>}) — this would publish invalid "
            "syntax"
        )

    stripped = strip_qualifier(entry)

    if stripped.lower() == "all":
        raise ConfigError(
            f"{label}: passthrough entry {entry!r} is a bare 'all' mechanism — "
            "passthrough is placed first in chunk 1, so this would terminate SPF "
            "evaluation immediately and make every mechanism after it (including "
            "the chunk chain and the final policy) unreachable"
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

    cidr = match_ip_mechanism(entry)
    if cidr is not None:
        # ipaddress.ip_network accepts a leading-zero prefix length (e.g.
        # "203.0.113.0/024"), but RFC 7208's ABNF forbids it
        # (ip4-cidr-length = "/" ("0" / %x31-39 0*1DIGIT)) -- parse_ip_literal
        # alone won't catch this, so check the raw text explicitly.
        if "/" in cidr:
            prefix_len = cidr.rsplit("/", 1)[1]
            if len(prefix_len) > 1 and prefix_len[0] == "0":
                raise ConfigError(
                    f"{label}: passthrough entry {entry!r} has a leading-zero "
                    f"CIDR length '/{prefix_len}' — RFC 7208 does not allow "
                    "leading zeros here"
                )
        expected_version = 4 if stripped.lower().startswith("ip4:") else 6
        try:
            parse_ip_literal(cidr, f"passthrough entry {entry!r}", expected_version)
        except ValueError as exc:
            raise ConfigError(f"{label}: {exc}") from exc
        return

    a_mx_match = _A_MX_RE.match(stripped)
    if a_mx_match is not None:
        len4 = a_mx_match.group("len4")
        if len4 is not None and not (0 <= int(len4) <= 32):
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} has an invalid IPv4 CIDR "
                f"length '/{len4}' — must be 0-32"
            )
        len6 = a_mx_match.group("len6")
        if len6 is not None and not (0 <= int(len6) <= 128):
            raise ConfigError(
                f"{label}: passthrough entry {entry!r} has an invalid IPv6 CIDR "
                f"length '//{len6}' — must be 0-128"
            )
        _validate_domain_spec(a_mx_match.group("host"), label, entry)
        return

    ptr_match = _PTR_RE.match(stripped)
    if ptr_match is not None:
        _validate_domain_spec(ptr_match.group("host"), label, entry)
        return

    exists_include_match = _EXISTS_INCLUDE_RE.match(stripped)
    if exists_include_match is not None:
        _validate_domain_spec(exists_include_match.group("target"), label, entry)
        return

    redirect_match = _REDIRECT_RE.match(entry)
    if redirect_match is not None:
        _validate_domain_spec(redirect_match.group("target"), label, entry)
        return

    raise ConfigError(
        f"{label}: passthrough entry {entry!r} is not a recognized SPF mechanism or "
        "modifier form — spf53 only accepts ip4:/ip6:/a:/mx:/ptr:/exists:/include:/"
        "redirect= with an explicit, non-empty target"
    )


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
        _validate_passthrough_shape(entry, label, name)
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
