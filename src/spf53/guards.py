"""Refusal guards that block an unsafe SPF apply."""

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reasons: tuple[str, ...]  # human-readable refusal reasons, empty when ok


MAX_LOOKUP_COST = 10  # RFC 7208 hard limit: exceeding this causes PermError for the whole domain
LOOKUP_COST_WARN_THRESHOLD = 9  # heads-up threshold: zero headroom left, but not yet a violation


def check_lookup_cost(lookup_cost: int) -> GuardResult:
    """Refuse an apply whose lookup_cost exceeds the RFC 7208 hard limit.

    A cost of exactly MAX_LOOKUP_COST is still valid (at capacity, zero
    headroom) — only exceeding it is the actual RFC 7208 violation that
    causes SPF evaluation to PermError for the whole domain.
    """
    if lookup_cost > MAX_LOOKUP_COST:
        return GuardResult(
            ok=False,
            reasons=(
                f"lookup cost {lookup_cost} exceeds the RFC 7208 hard limit of "
                f"{MAX_LOOKUP_COST} — SPF evaluation would PermError for the whole domain",
            ),
        )
    return GuardResult(ok=True, reasons=())


def check_guards(
    live_networks: Sequence[IPv4Network | IPv6Network],
    new_networks: Sequence[IPv4Network | IPv6Network],
    max_shrink_pct: int,
) -> GuardResult:
    """Refuse an apply when the new set is empty or has shrunk too far.

    First run (no live records) passes as long as the new set is non-empty.

    Shrink is evaluated independently per address family (IPv4 vs IPv6)
    rather than as one combined address count. IPv6 networks routinely
    dwarf IPv4 ones in address count, so a combined total lets a stable or
    growing IPv6 block completely mask a total loss of IPv4 addresses (or
    vice versa). A family that had no live addresses is skipped, since
    there's no baseline to shrink from.
    """
    if not new_networks:
        return GuardResult(ok=False, reasons=("new network set is empty",))

    if not live_networks:
        return GuardResult(ok=True, reasons=())

    reasons: list[str] = []
    for family_cls, label in ((IPv4Network, "IPv4"), (IPv6Network, "IPv6")):
        live_family = [n for n in live_networks if isinstance(n, family_cls)]
        if not live_family:
            continue
        new_family = [n for n in new_networks if isinstance(n, family_cls)]
        live_count = sum(n.num_addresses for n in live_family)
        new_count = sum(n.num_addresses for n in new_family)
        shrink_pct = (live_count - new_count) / live_count * 100
        if shrink_pct > max_shrink_pct:
            reasons.append(
                f"{label} address count shrank {shrink_pct:.1f}% "
                f"(from {live_count} to {new_count}), exceeding max_shrink_pct={max_shrink_pct}%"
            )

    if reasons:
        return GuardResult(ok=False, reasons=tuple(reasons))

    return GuardResult(ok=True, reasons=())
