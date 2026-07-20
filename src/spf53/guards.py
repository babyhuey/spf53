"""Refusal guards that block an unsafe SPF apply."""

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reasons: tuple[str, ...]  # human-readable refusal reasons, empty when ok


def check_guards(
    live_networks: Sequence[IPv4Network | IPv6Network],
    new_networks: Sequence[IPv4Network | IPv6Network],
    max_shrink_pct: int,
) -> GuardResult:
    """Refuse an apply when the new set is empty or has shrunk too far.

    First run (no live records) passes as long as the new set is non-empty.
    """
    if not new_networks:
        return GuardResult(ok=False, reasons=("new network set is empty",))

    if not live_networks:
        return GuardResult(ok=True, reasons=())

    live_count = sum(n.num_addresses for n in live_networks)
    new_count = sum(n.num_addresses for n in new_networks)
    shrink_pct = (live_count - new_count) / live_count * 100
    if shrink_pct > max_shrink_pct:
        reason = (
            f"address count shrank {shrink_pct:.1f}% (from {live_count} to {new_count}), "
            f"exceeding max_shrink_pct={max_shrink_pct}%"
        )
        return GuardResult(ok=False, reasons=(reason,))

    return GuardResult(ok=True, reasons=())
