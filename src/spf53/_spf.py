"""Shared low-level SPF helpers used by both resolver.py and core.py.

Covers SPF-qualifier stripping, CIDR-network collapsing, and bare-CIDR-literal
parsing — the pieces of network handling that are identical on both the
resolver (DNS-derived) and core (Route53-diffing) sides.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

QUALIFIERS = "+-~?"

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def strip_qualifier(term: str) -> str:
    return term[1:] if term and term[0] in QUALIFIERS else term


def collapse_networks(networks: Sequence[_Network]) -> list[_Network]:
    """Collapse to the minimal non-overlapping CIDR set covering the same addresses.

    Splits by address family (ipaddress.collapse_addresses requires
    same-version input), sorts, and collapses each family separately.
    """
    v4 = sorted(n for n in networks if isinstance(n, ipaddress.IPv4Network))
    v6 = sorted(n for n in networks if isinstance(n, ipaddress.IPv6Network))
    collapsed_v4 = sorted(ipaddress.collapse_addresses(v4))
    collapsed_v6 = sorted(ipaddress.collapse_addresses(v6))
    return [*collapsed_v4, *collapsed_v6]


def parse_ip_literal(cidr: str, context: str) -> _Network:
    """Parse a bare CIDR string (without any ip4:/ip6: prefix) into a network.

    Raises ValueError naming `context` on a malformed literal.
    """
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR literal {cidr!r} in {context}: {exc}") from exc
