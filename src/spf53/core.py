"""Orchestration: resolve, chunk, diff against live DNS, guard-check, apply, notify."""

from __future__ import annotations

import ipaddress
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
        except (ClientError, BotoCoreError) as exc:
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

    guard = guards.check_guards(live_networks, comparison_networks, dc.max_shrink_pct)

    return DomainPlan(
        domain=dc.name,
        zone_id=dc.hosted_zone_id,
        desired=desired,
        live=live,
        upserts=upserts,
        deletes=deletes,
        guard=guard,
        lookup_cost=chunker.lookup_cost(desired, dc.passthrough),
        apex_warning=apex_warning,
        summary=_build_summary(dc.name, live_networks, comparison_networks),
        delete_ttls=delete_ttls,
    )


def apply(cfg: Spf53Config, force: bool = False) -> RunResult:
    result = plan(cfg)
    errors = list(result.errors)
    failed_domains: list[str] = []

    for p in result.plans:
        if not p.has_changes:
            continue
        if not p.guard.ok and not force:
            _notify_refusal(cfg.sns_topic_arn, p)
            continue
        try:
            route53.apply_changes(p.zone_id, p.upserts, p.deletes, delete_ttls=p.delete_ttls)
        except (ClientError, BotoCoreError) as exc:
            msg = f"{p.domain}: failed to apply Route53 changes: {exc}"
            errors.append(msg)
            failed_domains.append(p.domain)
            notify.publish(cfg.sns_topic_arn, f"spf53: failed to apply changes for {p.domain}", msg)
            continue
        _notify_success(cfg.sns_topic_arn, p)

    for err in result.errors:
        notify.publish(cfg.sns_topic_arn, "spf53: SPF resolution failed", err)

    return RunResult(plans=result.plans, errors=tuple(errors), failed_domains=tuple(failed_domains))


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
    lower = token.lower()
    for prefix in ("ip4:", "ip6:"):
        if lower.startswith(prefix):
            try:
                return ipaddress.ip_network(token[len(prefix) :], strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid {prefix} token {token!r} in {context}: {exc}") from exc
    return None


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

    Mirrors resolver.flatten()'s own end-of-pipeline collapsing: split by
    family (collapse_addresses requires same-version input), sort, and
    collapse each family separately. Without this, an exact-duplicate or
    partially-overlapping CIDR — e.g. a passthrough literal that also
    appears in the resolver-derived network list — gets double-counted in
    guards.check_guards' address totals, which can produce a false-positive
    or false-negative shrink result.
    """
    v4 = sorted(n for n in networks if isinstance(n, ipaddress.IPv4Network))
    v6 = sorted(n for n in networks if isinstance(n, ipaddress.IPv6Network))
    collapsed_v4 = sorted(ipaddress.collapse_addresses(v4))
    collapsed_v6 = sorted(ipaddress.collapse_addresses(v6))
    return [*collapsed_v4, *collapsed_v6]


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


def _build_summary(
    domain: str,
    live_networks: Sequence[IPNetwork],
    new_networks: Sequence[IPNetwork],
) -> str:
    live_set = set(live_networks)
    new_set = set(new_networks)
    added = new_set - live_set
    removed = live_set - new_set
    return (
        f"{domain}: {len(added)} CIDR(s) added, {len(removed)} CIDR(s) removed\n"
        f"  added:   {_format_cidrs(added)}\n"
        f"  removed: {_format_cidrs(removed)}"
    )


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
