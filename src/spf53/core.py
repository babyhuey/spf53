"""Orchestration: resolve, chunk, diff against live DNS, guard-check, apply, notify."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from spf53 import chunker, guards, notify, resolver, route53
from spf53.config import Spf53Config
from spf53.guards import GuardResult
from spf53.resolver import ResolutionError

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_SUMMARY_LIST_CAP = 20


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

    @property
    def has_changes(self) -> bool:
        return bool(self.upserts or self.deletes)


@dataclass(frozen=True)
class RunResult:
    plans: tuple[DomainPlan, ...]
    errors: tuple[str, ...]


def plan(cfg: Spf53Config) -> RunResult:
    plans: list[DomainPlan] = []
    errors: list[str] = []

    for dc in cfg.domains:
        try:
            networks = resolver.flatten(dc.includes, cfg.resolver_ips)
        except ResolutionError as exc:
            errors.append(str(exc))
            continue

        desired = chunker.build_records(dc.name, networks, dc.passthrough, dc.policy)
        live_all = route53.get_txt_records(dc.hosted_zone_id, dc.name)
        live = {name: strings for name, strings in live_all.items() if name != dc.name}
        apex_warning = _apex_warning(dc.name, live_all.get(dc.name))

        upserts = {name: strings for name, strings in desired.items() if live.get(name) != strings}
        deletes = {name: strings for name, strings in live.items() if name not in desired}

        live_networks = _networks_from_records(live)
        guard = guards.check_guards(live_networks, networks, dc.max_shrink_pct)

        plans.append(
            DomainPlan(
                domain=dc.name,
                zone_id=dc.hosted_zone_id,
                desired=desired,
                live=live,
                upserts=upserts,
                deletes=deletes,
                guard=guard,
                lookup_cost=chunker.lookup_cost(desired, dc.passthrough),
                apex_warning=apex_warning,
                summary=_build_summary(dc.name, live_networks, networks),
            )
        )

    return RunResult(plans=tuple(plans), errors=tuple(errors))


def apply(cfg: Spf53Config, force: bool = False) -> RunResult:
    result = plan(cfg)

    for p in result.plans:
        if not p.has_changes:
            continue
        if not p.guard.ok and not force:
            _notify_refusal(cfg.sns_topic_arn, p)
            continue
        route53.apply_changes(p.zone_id, p.upserts, p.deletes)
        _notify_success(cfg.sns_topic_arn, p)

    for err in result.errors:
        notify.publish(cfg.sns_topic_arn, "spf53: SPF resolution failed", err)

    return result


def _apex_warning(domain: str, apex_record: list[str] | None) -> str | None:
    if not apex_record:
        return None
    expected = f"include:_spf53-1.{domain}"
    if expected in "".join(apex_record):
        return None
    return (
        f"live apex TXT record for {domain} does not contain '{expected}' — "
        f"the apex should read: v=spf1 include:_spf53-1.{domain} <policy>"
    )


def _networks_from_records(records: dict[str, list[str]]) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for strings in records.values():
        for token in "".join(strings).split():
            for prefix in ("ip4:", "ip6:"):
                if token.startswith(prefix):
                    networks.append(ipaddress.ip_network(token[len(prefix) :], strict=False))
                    break
    return networks


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
