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


def get_qualifier(term: str) -> str:
    """Return `term`'s qualifier char, defaulting to '+' (the RFC 7208 default)
    when none is present.
    """
    return term[0] if term and term[0] in QUALIFIERS else "+"


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


def match_ip_mechanism(term: str) -> str | None:
    """Strip a qualifier and check if `term` is an ip4:/ip6: mechanism.

    Returns the bare CIDR portion (e.g. "203.0.113.0/24") if `term` matches,
    or None if it's not an ip4:/ip6: mechanism at all.
    """
    token = strip_qualifier(term)
    lower = token.lower()
    for prefix in ("ip4:", "ip6:"):
        if lower.startswith(prefix):
            return token[len(prefix) :]
    return None


def parse_ip_literal(cidr: str, context: str, expected_version: int | None = None) -> _Network:
    """Parse a bare CIDR string (without any ip4:/ip6: prefix) into a network.

    Raises ValueError naming `context` on a malformed literal. If
    `expected_version` (4 or 6) is given and disagrees with the parsed
    literal's actual IP version -- e.g. `ip4:2001:db8::/32`, an ip6 literal
    under an ip4: prefix -- that's a permerror in the source record and also
    raises, rather than silently emitting it under the wrong family.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR literal {cidr!r} in {context}: {exc}") from exc
    if expected_version is not None and network.version != expected_version:
        raise ValueError(
            f"CIDR literal {cidr!r} in {context} is IPv{network.version} but "
            f"was declared as an ip{expected_version} mechanism"
        )
    return network
