"""Orchestration: resolve, chunk, diff against live DNS, guard-check, apply, notify."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from botocore.exceptions import BotoCoreError, ClientError

from spf53 import _spf, chunker, guards, notify, resolver, route53
from spf53.config import DomainConfig, Spf53Config
from spf53.guards import GuardResult
from spf53.resolver import ResolutionError

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_SUMMARY_LIST_CAP = 20
# Each domain worker here also runs its own 2-worker pair pool (flatten +
# get_txt_records, see _plan_one_domain), and one of that pair (flatten)
# runs its own internal ThreadPoolExecutor(max_workers=8) for DNS
# concurrency. Worst case per domain is therefore 1 (this pool) + 2 (pair
# pool) + 8 (flatten's internal pool) = 11 threads, so this must stay small
# enough that _MAX_DOMAIN_WORKERS * 11 stays a reasonable total thread count.
_MAX_DOMAIN_WORKERS = 4


@dataclass(frozen=True)
class DomainPlan:
    domain: str
    zone_id: str
    desired: dict[str, list[str]]
    live: dict[str, list[str]]
    upserts: dict[str, list[str]]
    deletes: dict[str, list[str]]
    guard: GuardResult
    lookup_cost: int
    apex_warning: str | None
    summary: str
    delete_ttls: dict[str, int] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.upserts or self.deletes)


@dataclass(frozen=True)
class RunResult:
    plans: tuple[DomainPlan, ...]
    errors: tuple[str, ...]
    failed_domains: tuple[str, ...] = ()


def plan(cfg: Spf53Config) -> RunResult:
    if not cfg.domains:
        return RunResult(plans=(), errors=())

    plans: list[DomainPlan] = []
    errors: list[str] = []

    # Submit in cfg.domains order and collect via .result() over that same
    # list (not as_completed()) so output order matches cfg.domains order
    # regardless of which domain's thread finishes first.
    with ThreadPoolExecutor(max_workers=min(_MAX_DOMAIN_WORKERS, len(cfg.domains))) as pool:
        futures = [pool.submit(_plan_one_domain, dc, cfg.resolver_ips) for dc in cfg.domains]
        for future in futures:
            outcome = future.result()
            if isinstance(outcome, DomainPlan):
                plans.append(outcome)
            else:
                errors.append(outcome)

    return RunResult(plans=tuple(plans), errors=tuple(errors))


def _plan_one_domain(dc: DomainConfig, resolver_ips: Sequence[str]) -> DomainPlan | str:
    """Resolve, chunk, diff, and guard-check a single domain.

    Returns a DomainPlan on success, or an error message string on any
    per-domain failure — never raises for the failure modes each try/except
    below handles, so one domain's failure can't affect any other domain.
    """
    # resolver.flatten (DNS) and route53.get_txt_records (AWS API) are
    # independent of each other's result, so run them concurrently rather
    # than paying their latency sequentially.
    with ThreadPoolExecutor(max_workers=2) as pair_pool:
        flatten_future = pair_pool.submit(resolver.flatten, dc.includes, resolver_ips)
        txt_future = pair_pool.submit(route53.get_txt_records, dc.hosted_zone_id, dc.name)

        try:
            networks = flatten_future.result()
        except ResolutionError as exc:
            return str(exc)

        try:
            live_all, live_ttls = txt_future.result()
        except (ClientError, BotoCoreError, ValueError) as exc:
            return f"{dc.name}: {exc}"

    try:
        desired = chunker.build_records(dc.name, networks, dc.passthrough, dc.policy)
    except ValueError as exc:
        return f"{dc.name}: {exc}"

    live = {name: strings for name, strings in live_all.items() if name != dc.name}
    apex_warning = _apex_warning(dc.name, live_all.get(dc.name))

    upserts = {name: strings for name, strings in desired.items() if live.get(name) != strings}
    deletes = {name: strings for name, strings in live.items() if name not in desired}
    delete_ttls = {name: live_ttls[name] for name in deletes if name in live_ttls}

    try:
        live_networks = _collapse(_networks_from_records(live))
    except ValueError as exc:
        return f"{dc.name}: {exc}"

    try:
        comparison_networks = _collapse(networks + _passthrough_networks(dc.passthrough))
    except ValueError as exc:
        return f"{dc.name}: {exc}"

    shrink_guard = guards.check_guards(live_networks, comparison_networks, dc.max_shrink_pct)
    try:
        lookup_cost = _total_lookup_cost(desired, dc.passthrough, resolver_ips)
    except ResolutionError as exc:
        return f"{dc.name}: {exc}"
    cost_guard = guards.check_lookup_cost(lookup_cost)
    guard = GuardResult(
        ok=shrink_guard.ok and cost_guard.ok,
        reasons=shrink_guard.reasons + cost_guard.reasons,
    )

    live_policy = extract_policy(live)
    desired_policy = extract_policy(desired)

    return DomainPlan(
        domain=dc.name,
        zone_id=dc.hosted_zone_id,
        desired=desired,
        live=live,
        upserts=upserts,
        deletes=deletes,
        guard=guard,
        lookup_cost=lookup_cost,
        apex_warning=apex_warning,
        summary=_build_summary(
            dc.name, live_networks, comparison_networks, live_policy, desired_policy
        ),
        delete_ttls=delete_ttls,
    )


def _total_lookup_cost(
    desired: dict[str, list[str]], passthrough: Sequence[str], resolver_ips: Sequence[str]
) -> int:
    """chunker.lookup_cost()'s flat "+1 per DNS-querying passthrough mechanism"
    undercounts include:/redirect= passthrough terms, whose real RFC 7208
    4.6.4 cost is transitive: they point at another domain's own SPF record,
    so on top of the 1 chunker.lookup_cost already counts for the term
    itself, add however many DNS-querying mechanisms that target's record
    (recursively) contains, via resolver.count_transitive_lookup_cost.
    """
    cost = chunker.lookup_cost(desired, passthrough)
    for term in passthrough:
        stripped = _spf.strip_qualifier(term)
        lower = stripped.lower()
        if lower.startswith("include:") or lower.startswith("redirect="):
            cost += resolver.count_transitive_lookup_cost(term, resolver_ips)
    return cost


def apply(cfg: Spf53Config, force: bool = False) -> RunResult:
    result = plan(cfg)
    errors = list(result.errors)
    failed_domains: list[str] = []

    if result.plans:
        # Submit in result.plans order and collect via .result() over that
        # same list (not as_completed()) so errors/failed_domains land in
        # result.plans order regardless of which domain's thread finishes
        # first -- mirrors plan()'s pool.submit/.result() pattern above.
        with ThreadPoolExecutor(max_workers=min(_MAX_DOMAIN_WORKERS, len(result.plans))) as pool:
            futures = [pool.submit(_apply_one_domain, p, cfg, force) for p in result.plans]
            for future in futures:
                outcome = future.result()
                if outcome is not None:
                    domain, msg = outcome
                    errors.append(msg)
                    failed_domains.append(domain)

    for err in result.errors:
        notify.publish(cfg.sns_topic_arn, "spf53: SPF resolution failed", err)

    return RunResult(plans=result.plans, errors=tuple(errors), failed_domains=tuple(failed_domains))


def _apply_one_domain(p: DomainPlan, cfg: Spf53Config, force: bool) -> tuple[str, str] | None:
    """Apply one domain's Route53 changes and notify, in isolation from other domains.

    Returns None on skip/refusal/success, or (p.domain, error message) on a
    Route53 apply failure -- never raises, so one domain's failure can't
    affect any other domain's concurrent apply.
    """
    if not p.has_changes:
        return None
    if not p.guard.ok and not force:
        _notify_refusal(cfg.sns_topic_arn, p)
        return None
    try:
        route53.apply_changes(p.zone_id, p.upserts, p.deletes, delete_ttls=p.delete_ttls)
    except (ClientError, BotoCoreError) as exc:
        msg = f"{p.domain}: failed to apply Route53 changes: {exc}"
        notify.publish(cfg.sns_topic_arn, f"spf53: failed to apply changes for {p.domain}", msg)
        return (p.domain, msg)
    _notify_success(cfg.sns_topic_arn, p)
    return None


def _apex_warning(domain: str, apex_record: list[str] | None) -> str | None:
    expected = f"include:_spf53-1.{domain}"
    if apex_record is None:
        return (
            f"no apex TXT record found for {domain} — create one: "
            f"v=spf1 include:_spf53-1.{domain} ~all"
        )
    if expected.lower() in "".join(apex_record).lower():
        return None
    return (
        f"live apex TXT record for {domain} does not contain '{expected}' — "
        f"the apex should read: v=spf1 include:_spf53-1.{domain} <policy>"
    )


def _parse_ip_token(raw_token: str, context: str) -> IPNetwork | None:
    """Strip qualifier and parse a single SPF term into a network.

    Returns None if `raw_token` isn't an ip4:/ip6: mechanism (e.g. an
    `exists:` macro, or any other term) — those aren't networks and
    contribute nothing to the caller's list.
    """
    token = _spf.strip_qualifier(raw_token)
    cidr = _spf.match_ip_mechanism(token)
    if cidr is None:
        return None
    # match_ip_mechanism only matches "ip4:"/"ip6:" (both 4 chars), so the
    # consumed prefix is always token's first 4 chars, lowercased to match
    # this module's existing (lowercase-only) error message convention.
    prefix = token[:4].lower()
    expected_version = 4 if prefix == "ip4:" else 6
    try:
        return _spf.parse_ip_literal(cidr, context, expected_version)
    except ValueError as exc:
        # exc is _spf.parse_ip_literal's own wrapped ValueError; __cause__
        # recovers the raw ipaddress error this message is built from (or,
        # for a family-mismatch error, is None -- fall back to exc itself,
        # which is already a complete message in that case).
        raise ValueError(
            f"invalid {prefix} token {token!r} in {context}: {exc.__cause__ or exc}"
        ) from exc


def _networks_from_records(records: dict[str, list[str]]) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for name, strings in records.items():
        for raw_token in "".join(strings).split():
            network = _parse_ip_token(raw_token, f"live record {name!r}")
            if network is not None:
                networks.append(network)
    return networks


def _passthrough_networks(passthrough: Sequence[str]) -> list[IPNetwork]:
    """Parse the ip4:/ip6: literal entries out of a domain's passthrough list.

    Mirrors _networks_from_records' token parsing, but over a passthrough
    list instead of live record strings: passthrough entries that aren't
    ip4:/ip6: mechanisms (e.g. a Salesforce `exists:` macro) simply aren't
    networks and contribute nothing.
    """
    networks: list[IPNetwork] = []
    for raw_token in passthrough:
        network = _parse_ip_token(raw_token, "passthrough entry")
        if network is not None:
            networks.append(network)
    return networks


def _collapse(networks: Sequence[IPNetwork]) -> list[IPNetwork]:
    """Collapse to the minimal non-overlapping CIDR set covering the same addresses.

    Without this, an exact-duplicate or partially-overlapping CIDR — e.g. a
    passthrough literal that also appears in the resolver-derived network
    list — gets double-counted in guards.check_guards' address totals, which
    can produce a false-positive or false-negative shrink result.
    """
    return _spf.collapse_networks(networks)


def _sort_key(network: IPNetwork) -> tuple[int, int, int]:
    return (network.version, int(network.network_address), network.prefixlen)


def _format_cidrs(networks: Iterable[IPNetwork]) -> str:
    ordered = sorted(networks, key=_sort_key)
    if not ordered:
        return "none"
    shown = [str(n) for n in ordered[:_SUMMARY_LIST_CAP]]
    if len(ordered) > _SUMMARY_LIST_CAP:
        shown.append(f"+{len(ordered) - _SUMMARY_LIST_CAP} more")
    return ", ".join(shown)


_CHUNK_NAME_RE = re.compile(r"^_spf53-(\d+)\.")


def extract_policy(records: dict[str, list[str]]) -> str | None:
    """Return the terminal policy token (e.g. '~all') from the
    highest-numbered `_spf53-N.<domain>` chunk record in `records`.

    Returns None if `records` contains no such chunk record, or if the
    matching record has no content to extract a token from.
    """
    numbered = [
        (int(match.group(1)), name) for name in records if (match := _CHUNK_NAME_RE.match(name))
    ]
    if not numbered:
        return None
    _, last_name = max(numbered)
    last_strings = records.get(last_name)
    if not last_strings:
        return None
    tokens = "".join(last_strings).split()
    return tokens[-1] if tokens else None


def _build_summary(
    domain: str,
    live_networks: Sequence[IPNetwork],
    new_networks: Sequence[IPNetwork],
    live_policy: str | None,
    desired_policy: str | None,
) -> str:
    live_set = set(live_networks)
    new_set = set(new_networks)
    added = new_set - live_set
    removed = live_set - new_set
    lines = [
        f"{domain}: {len(added)} CIDR(s) added, {len(removed)} CIDR(s) removed",
        f"  added:   {_format_cidrs(added)}",
        f"  removed: {_format_cidrs(removed)}",
    ]
    if live_policy is not None and desired_policy is not None and live_policy != desired_policy:
        lines.append(f"  policy changed: {live_policy!r} -> {desired_policy!r}")
    return "\n".join(lines)


def _notify_refusal(topic_arn: str | None, p: DomainPlan) -> None:
    reasons = "; ".join(p.guard.reasons)
    notify.publish(
        topic_arn,
        f"spf53: refused to apply changes for {p.domain}",
        f"spf53 refused to publish new SPF records for {p.domain} because the "
        f"safety guard failed: {reasons}\n\n{p.summary}",
    )


def _notify_success(topic_arn: str | None, p: DomainPlan) -> None:
    notify.publish(topic_arn, f"spf53: applied SPF changes for {p.domain}", p.summary)
