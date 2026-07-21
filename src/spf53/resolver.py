"""DNS resolution and recursive SPF flattening.

The only module that touches dnspython. All DNS access goes through the
module-level `_query_*` seams so tests can monkeypatch them without any
live DNS or mocking of dnspython internals.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait

import dns.exception
import dns.rdatatype
import dns.resolver

from spf53 import _spf

logger = logging.getLogger(__name__)

MAX_DEPTH = 10

_TIMEOUT_SECONDS = 5.0
_TRIES = 2
# Shared across a whole flatten() call. Tasks submitted to this pool must
# never submit further tasks to it from within a worker thread — nested
# submission can exhaust all workers on blocked outer tasks and deadlock.
_MAX_WORKERS = 8

_A_TERM_RE = re.compile(r"^a(:(?P<host>[^/]+))?(/(?P<len4>\d+))?(//(?P<len6>\d+))?$", re.IGNORECASE)
_MX_TERM_RE = re.compile(
    r"^mx(:(?P<host>[^/]+))?(/(?P<len4>\d+))?(//(?P<len6>\d+))?$", re.IGNORECASE
)

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ResolutionError(Exception):
    """Raised when SPF resolution fails for an include/domain."""


def flatten(
    includes: Sequence[str],
    resolver_ips: Sequence[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Recursively resolve `includes` into a deduped, collapsed list of networks.

    Raises ResolutionError naming the failing include on any failure — never
    returns partial data.
    """
    networks: list[_Network] = []
    seen: set[str] = set()
    pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS)
    try:
        for include in includes:
            _walk(include, resolver_ips, seen, 1, networks, pool)
    finally:
        # wait=False + cancel_futures=True: on the fail-fast path (see
        # _process_record's mx branch), a sibling exchange lookup may still
        # be running in a worker thread when an exception propagates here.
        # Blocking shutdown here would wait for it to finish, reintroducing
        # the latency this fail-fast logic exists to avoid.
        #
        # On the success path this is safe: every future ever submitted to
        # `pool` (in _resolve_addresses and the mx branch of _process_record)
        # is joined via a direct `.result()` call or via _wait_fail_fast's
        # `wait(..., return_when=FIRST_EXCEPTION)` — which behaves like
        # ALL_COMPLETED when nothing raises — before _walk/_process_record
        # return control up the call stack. So by the time this finally
        # block runs without an active exception, no submitted future is
        # still running or un-started; cancel_futures=True has nothing left
        # to cancel and wait=False only skips redundant bookkeeping.
        pool.shutdown(wait=False, cancel_futures=True)

    v4 = sorted(n for n in networks if isinstance(n, ipaddress.IPv4Network))
    v6 = sorted(n for n in networks if isinstance(n, ipaddress.IPv6Network))
    collapsed_v4 = sorted(ipaddress.collapse_addresses(v4))
    collapsed_v6 = sorted(ipaddress.collapse_addresses(v6))
    return [*collapsed_v4, *collapsed_v6]


def _walk(
    name: str,
    resolver_ips: Sequence[str],
    seen: set[str],
    depth: int,
    networks: list[_Network],
    pool: ThreadPoolExecutor,
) -> None:
    key = name.lower()
    if key in seen:
        return

    if depth > MAX_DEPTH:
        raise ResolutionError(f"include depth exceeded {MAX_DEPTH} at {name!r}")

    seen.add(key)

    record = _get_spf_record(name, resolver_ips)
    _process_record(name, record, resolver_ips, seen, depth, networks, pool)


def _get_spf_record(name: str, resolver_ips: Sequence[str]) -> str:
    """Fetch and validate the single SPF TXT record for `name`."""
    txt_strings = _call_seam(_query_txt, name, resolver_ips, name)
    spf_records = [s for s in txt_strings if s.strip().lower().startswith("v=spf1")]
    if not spf_records:
        raise ResolutionError(f"no SPF record found for {name!r}")
    if len(spf_records) > 1:
        raise ResolutionError(f"multiple SPF records found for {name!r}")
    return spf_records[0]


def _process_record(
    name: str,
    record: str,
    resolver_ips: Sequence[str],
    seen: set[str],
    depth: int,
    networks: list[_Network],
    pool: ThreadPoolExecutor,
) -> None:
    for raw_term in record.split()[1:]:  # [0] is "v=spf1"
        term = _spf.strip_qualifier(raw_term)
        lower = term.lower()

        if lower == "all":
            continue
        if lower.startswith("ip4:") or lower.startswith("ip6:"):
            try:
                networks.append(ipaddress.ip_network(term[4:], strict=False))
            except ValueError as exc:
                raise ResolutionError(
                    f"invalid CIDR literal {term!r} in {name!r} SPF record: {exc}"
                ) from exc
            continue
        if lower.startswith("include:"):
            _walk(term[8:], resolver_ips, seen, depth + 1, networks, pool)
            continue
        if lower.startswith("redirect="):
            _walk(term[9:], resolver_ips, seen, depth + 1, networks, pool)
            continue
        if lower.startswith("exists:"):
            logger.warning("ignoring exists mechanism in %s SPF record: %s", name, term)
            continue
        if lower == "ptr" or lower.startswith("ptr:"):
            logger.warning("ignoring ptr mechanism in %s SPF record: %s", name, term)
            continue

        a_match = _A_TERM_RE.match(term)
        if a_match:
            host = a_match.group("host") or name
            v4_len = _parse_len(a_match.group("len4"))
            v6_len = _parse_len(a_match.group("len6"))
            addresses = _resolve_addresses(host, resolver_ips, name, pool)
            networks.extend(_addresses_to_networks(addresses, v4_len, v6_len, term, name))
            continue

        mx_match = _MX_TERM_RE.match(term)
        if mx_match:
            host = mx_match.group("host") or name
            v4_len = _parse_len(mx_match.group("len4"))
            v6_len = _parse_len(mx_match.group("len6"))
            exchanges = _call_seam(_query_mx, host, resolver_ips, name)
            # Submit each exchange's A/AAAA lookups directly rather than via
            # _resolve_addresses, so no worker ends up submitting further
            # work back onto this same pool (see _MAX_WORKERS above).
            per_exchange = [
                (
                    pool.submit(_call_seam, _query_a, exchange, resolver_ips, name),
                    pool.submit(_call_seam, _query_aaaa, exchange, resolver_ips, name),
                )
                for exchange in exchanges
            ]
            _wait_fail_fast([future for pair in per_exchange for future in pair])
            for a_future, aaaa_future in per_exchange:
                addresses = a_future.result() + aaaa_future.result()
                networks.extend(_addresses_to_networks(addresses, v4_len, v6_len, term, name))
            continue

        if "=" in term:
            continue  # unhandled modifier (e.g. exp=); nothing to flatten
        logger.warning("ignoring unrecognized SPF term in %s record: %s", name, term)


def _wait_fail_fast(futures: Sequence[Future]) -> None:
    """Wait for all futures; on the first exception, cancel not-yet-started
    siblings and re-raise immediately rather than waiting for the rest.
    """
    done, not_done = wait(futures, return_when=FIRST_EXCEPTION)
    for future in futures:
        if future in done and future.exception() is not None:
            for pending in not_done:
                pending.cancel()
            raise future.exception()


def _parse_len(len_str: str | None) -> int | None:
    return int(len_str) if len_str else None


def _resolve_addresses(
    host: str, resolver_ips: Sequence[str], context: str, pool: ThreadPoolExecutor
) -> list[str]:
    a_future = pool.submit(_call_seam, _query_a, host, resolver_ips, context)
    aaaa_future = pool.submit(_call_seam, _query_aaaa, host, resolver_ips, context)
    _wait_fail_fast([a_future, aaaa_future])
    return a_future.result() + aaaa_future.result()


def _addresses_to_networks(
    addresses: Sequence[str],
    v4_len: int | None,
    v6_len: int | None,
    term: str,
    name: str,
) -> list[_Network]:
    """Build networks from resolved addresses, applying each family's own prefix length.

    Per RFC 7208 5.3, a single `/len` is the ip4-cidr-length only; ip6 addresses use
    `v6_len` (from the `//len` dual-cidr form) and otherwise default to /128.
    """
    networks: list[_Network] = []
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
            is_v4 = isinstance(ip, ipaddress.IPv4Address)
            length = v4_len if is_v4 else v6_len
            if length is None:
                length = ip.max_prefixlen
            networks.append(ipaddress.ip_network(f"{ip}/{length}", strict=False))
        except ValueError as exc:
            raise ResolutionError(
                f"invalid address/prefix from {term!r} in {name!r} SPF record: {exc}"
            ) from exc
    return networks


def _call_seam(
    fn: Callable[[str, Sequence[str]], list[str]],
    name: str,
    resolver_ips: Sequence[str],
    context: str,
) -> list[str]:
    try:
        return fn(name, resolver_ips)
    except ResolutionError:
        raise
    except Exception as exc:
        raise ResolutionError(f"failed to resolve {name!r} for {context!r}: {exc}") from exc


# --- DNS seams -------------------------------------------------------------
# All actual dnspython access is confined to these four functions plus
# `_resolve` below. Tests monkeypatch these directly; no live DNS.


def _query_txt(name: str, resolver_ips: Sequence[str]) -> list[str]:
    try:
        answer = _resolve(name, dns.rdatatype.TXT, resolver_ips)
    except dns.resolver.NoAnswer:
        return []
    return [_join_txt_strings(rdata.strings) for rdata in answer]


def _query_a(name: str, resolver_ips: Sequence[str]) -> list[str]:
    try:
        answer = _resolve(name, dns.rdatatype.A, resolver_ips)
    except dns.resolver.NoAnswer:
        return []
    return [rdata.address for rdata in answer]


def _query_aaaa(name: str, resolver_ips: Sequence[str]) -> list[str]:
    try:
        answer = _resolve(name, dns.rdatatype.AAAA, resolver_ips)
    except dns.resolver.NoAnswer:
        return []
    return [rdata.address for rdata in answer]


def _query_mx(name: str, resolver_ips: Sequence[str]) -> list[str]:
    try:
        answer = _resolve(name, dns.rdatatype.MX, resolver_ips)
    except dns.resolver.NoAnswer:
        return []
    return [str(rdata.exchange).rstrip(".") for rdata in answer]


def _join_txt_strings(chunks: Sequence[bytes | str]) -> str:
    """Concatenate a TXT record's character-string chunks with no separator."""
    return "".join(chunk.decode() if isinstance(chunk, bytes) else chunk for chunk in chunks)


def _resolve(
    name: str,
    rdtype: dns.rdatatype.RdataType,
    resolver_ips: Sequence[str],
) -> dns.resolver.Answer:
    """Query `name`/`rdtype`, trying up to `_TRIES` times, alternating resolvers."""
    ips = list(resolver_ips)
    last_exc: dns.exception.DNSException | None = None
    for attempt in range(_TRIES):
        nameserver = ips[attempt % len(ips)]
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = _TIMEOUT_SECONDS
        resolver.lifetime = _TIMEOUT_SECONDS
        try:
            return resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except dns.exception.DNSException as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc
