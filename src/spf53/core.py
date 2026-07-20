"""Orchestration: resolve, chunk, diff against live DNS, guard-check, apply, notify."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

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
    delete_ttls: dict[str, int] = field(default_factory=dict)

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
        live_all, live_ttls = route53.get_txt_records(dc.hosted_zone_id, dc.name)
        live = {name: strings for name, strings in live_all.items() if name != dc.name}
        apex_warning = _apex_warning(dc.name, live_all.get(dc.name))

        upserts = {name: strings for name, strings in desired.items() if live.get(name) != strings}
        deletes = {name: strings for name, strings in live.items() if name not in desired}
        delete_ttls = {name: live_ttls[name] for name in deletes if name in live_ttls}

        try:
            live_networks = _networks_from_records(live)
        except ValueError as exc:
            errors.append(f"{dc.name}: {exc}")
            continue
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
                delete_ttls=delete_ttls,
            )
        )

    return RunResult(plans=tuple(plans), errors=tuple(errors))


def apply(cfg: Spf53Config, force: bool = False) -> RunResult:
    result = plan(cfg)
    errors = list(result.errors)

    for p in result.plans:
        if not p.has_changes:
            continue
        if not p.guard.ok and not force:
            _notify_refusal(cfg.sns_topic_arn, p)
            continue
        try:
            route53.apply_changes(p.zone_id, p.upserts, p.deletes, delete_ttls=p.delete_ttls)
        except ClientError as exc:
            msg = f"{p.domain}: failed to apply Route53 changes: {exc}"
            errors.append(msg)
            notify.publish(cfg.sns_topic_arn, f"spf53: failed to apply changes for {p.domain}", msg)
            continue
        _notify_success(cfg.sns_topic_arn, p)

    for err in result.errors:
        notify.publish(cfg.sns_topic_arn, "spf53: SPF resolution failed", err)

    return RunResult(plans=result.plans, errors=tuple(errors))


def _apex_warning(domain: str, apex_record: list[str] | None) -> str | None:
    expected = f"include:_spf53-1.{domain}"
    if apex_record is None:
        return (
            f"no apex TXT record found for {domain} — create one: "
            f"v=spf1 include:_spf53-1.{domain} ~all"
        )
    if expected in "".join(apex_record):
        return None
    return (
        f"live apex TXT record for {domain} does not contain '{expected}' — "
        f"the apex should read: v=spf1 include:_spf53-1.{domain} <policy>"
    )


def _networks_from_records(records: dict[str, list[str]]) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for name, strings in records.items():
        for token in "".join(strings).split():
            for prefix in ("ip4:", "ip6:"):
                if token.startswith(prefix):
                    try:
                        networks.append(ipaddress.ip_network(token[len(prefix) :], strict=False))
                    except ValueError as exc:
                        raise ValueError(
                            f"invalid {prefix} token {token!r} in live record {name!r}: {exc}"
                        ) from exc
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
