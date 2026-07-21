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

from spf53 import _spf, guards

logger = logging.getLogger(__name__)

MAX_DEPTH = 10

_TIMEOUT_SECONDS = 5.0
_TRIES = 2
# Shared across a whole flatten() call. Tasks submitted to this pool must
# never submit further tasks to it from within a worker thread — nested
# submission can exhaust all workers on blocked outer tasks and deadlock.
_MAX_WORKERS = 8
# RFC 7208 4.6.4: more than 10 MX records for a single "mx" mechanism is a
# permerror condition.
_MAX_MX_EXCHANGES = 10
# Upper bound on unique names visited across one flatten() call, to bound
# worst-case runtime against a hostile/misconfigured, deeply-branching
# include chain.
_MAX_CHAIN_NAMES = 200

_QUALIFIER_NAMES = {"-": "fail", "~": "softfail", "?": "neutral"}

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

    return _spf.collapse_networks(networks)


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

    if len(seen) >= _MAX_CHAIN_NAMES:
        raise ResolutionError(
            f"SPF chain too large: exceeded {_MAX_CHAIN_NAMES} unique names "
            f"while resolving {name!r}"
        )

    seen.add(key)

    record = _get_spf_record(name, resolver_ips)
    _process_record(name, record, resolver_ips, seen, depth, networks, pool)


def _get_spf_record(name: str, resolver_ips: Sequence[str]) -> str:
    """Fetch and validate the single SPF TXT record for `name`."""
    txt_strings = _call_seam(_query_txt, name, resolver_ips, name)
    spf_records = [s for s in txt_strings if _is_spf_record(s)]
    if not spf_records:
        raise ResolutionError(f"no SPF record found for {name!r}")
    if len(spf_records) > 1:
        raise ResolutionError(f"multiple SPF records found for {name!r}")
    return spf_records[0]


def _is_spf_record(txt_string: str) -> bool:
    """Whether a TXT string is an SPF record: exactly "v=spf1", or "v=spf1"
    followed by a space (RFC 7208 4.5). A plain prefix match would wrongly
    accept an unrelated record like "v=spf100 ..." as SPF.
    """
    stripped = txt_string.strip().lower()
    return stripped == "v=spf1" or stripped.startswith("v=spf1 ")


def _process_record(
    name: str,
    record: str,
    resolver_ips: Sequence[str],
    seen: set[str],
    depth: int,
    networks: list[_Network],
    pool: ThreadPoolExecutor,
) -> None:
    raw_terms = record.split()[1:]  # [0] is "v=spf1"
    # RFC 7208 6.1: redirect= is only used when the record has no `all`
    # mechanism; if `all` is present it already terminates evaluation, so
    # redirect= must be ignored below rather than followed.
    has_all = _has_all_mechanism(raw_terms)

    for raw_term in raw_terms:
        qualifier = _spf.get_qualifier(raw_term)
        term = _spf.strip_qualifier(raw_term)
        lower = term.lower()

        if lower == "all":
            continue
        cidr = _spf.match_ip_mechanism(term)
        if cidr is not None:
            _require_default_qualifier(qualifier, raw_term, name)
            expected_version = 4 if lower.startswith("ip4:") else 6
            try:
                networks.append(
                    _spf.parse_ip_literal(cidr, f"{name!r} SPF record", expected_version)
                )
            except ValueError as exc:
                # exc is _spf.parse_ip_literal's own wrapped ValueError; __cause__
                # recovers the raw ipaddress error this message is built from
                # (or, for a family-mismatch error, is None -- fall back to exc
                # itself, which is already a complete message in that case).
                raise ResolutionError(
                    f"invalid CIDR literal {term!r} in {name!r} SPF record: {exc.__cause__ or exc}"
                ) from exc
            continue
        if lower.startswith("include:"):
            _require_default_qualifier(qualifier, raw_term, name)
            _walk(term[8:], resolver_ips, seen, depth + 1, networks, pool)
            continue
        if lower.startswith("redirect="):
            if has_all:
                continue
            _require_default_qualifier(qualifier, raw_term, name)
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
            _require_default_qualifier(qualifier, raw_term, name)
            host = a_match.group("host") or name
            _require_no_macro(host, term, name)
            v4_len = _parse_len(a_match.group("len4"))
            v6_len = _parse_len(a_match.group("len6"))
            addresses = _resolve_addresses(host, resolver_ips, name, pool)
            networks.extend(_addresses_to_networks(addresses, v4_len, v6_len, term, name))
            continue

        mx_match = _MX_TERM_RE.match(term)
        if mx_match:
            _require_default_qualifier(qualifier, raw_term, name)
            host = mx_match.group("host") or name
            _require_no_macro(host, term, name)
            v4_len = _parse_len(mx_match.group("len4"))
            v6_len = _parse_len(mx_match.group("len6"))
            exchanges = _call_seam(_query_mx, host, resolver_ips, name)
            if len(exchanges) > _MAX_MX_EXCHANGES:
                raise ResolutionError(
                    f"mx mechanism {term!r} in {name!r} SPF record has {len(exchanges)} "
                    f"MX exchanges, exceeding the RFC 7208 4.6.4 limit of "
                    f"{_MAX_MX_EXCHANGES} for a single mx mechanism"
                )
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


def _has_all_mechanism(raw_terms: Sequence[str]) -> bool:
    """Whether a record's raw term list (post "v=spf1") contains an `all`
    mechanism.

    RFC 7208 6.1: redirect= is only used when the record has no `all`
    mechanism -- `all` already terminates evaluation, so redirect= must be
    ignored rather than followed when both are present. Shared by
    `_process_record` (the flattening walk) and `_count_dns_querying_mechanisms`
    (the cost-counting walk) so both apply this pre-scan identically.
    """
    return any(_spf.strip_qualifier(t).lower() == "all" for t in raw_terms)


def _require_default_qualifier(qualifier: str, raw_term: str, name: str) -> None:
    """Refuse to flatten a mechanism qualified anything but '+' (the default).

    Flattening e.g. `-ip4:203.0.113.9` or `~include:other.example.com` into
    the output as a plain ip4:/include: mechanism would silently turn the
    domain owner's explicit fail/softfail/neutral into an unconditional
    pass. This is a deliberate, safe-by-default refusal rather than a silent
    semantic corruption of the domain's policy.
    """
    if qualifier != "+":
        raise ResolutionError(
            f"cannot flatten {_QUALIFIER_NAMES[qualifier]}-qualified mechanism {raw_term!r} "
            f"in {name!r} SPF record -- flattening it would silently turn its "
            f"{_QUALIFIER_NAMES[qualifier]} into an unconditional pass"
        )


def _require_no_macro(host: str, term: str, name: str) -> None:
    """Refuse to flatten an a:/mx: mechanism whose target host contains SPF
    macro syntax ('%').

    spf53 implements no macro expansion, so a macro like `a:%{i}.example`
    would be resolved against its literal, unexpandable macro text -- which
    is never a real hostname and always NXDOMAINs. Since NXDOMAIN on an
    a:/mx: target now softens to "no addresses" instead of hard-failing,
    that would silently drop the mechanism from the flattened output rather
    than surfacing the unsupported macro.
    """
    if "%" in host:
        raise ResolutionError(
            f"cannot flatten macro-based mechanism {term!r} in {name!r} SPF record -- "
            "spf53 does not support SPF macros; move this mechanism to 'passthrough' instead"
        )


def count_transitive_lookup_cost(term: str, resolver_ips: Sequence[str]) -> int:
    """Count the RFC 7208 4.6.4 lookup cost hidden inside an include:/redirect=
    term's own target SPF record -- i.e. everything beyond the 1 lookup
    chunker.lookup_cost already counts for the term itself.

    Fetches the target's SPF TXT record and counts each DNS-querying
    mechanism/modifier it contains: 1 each for a/mx/ptr/exists, and 1 each
    for a nested include:/redirect= (which is then recursed into). Only
    fetches TXT records -- RFC 7208 lookup cost counts mechanism/modifier
    occurrences, not resolved A/AAAA/MX addresses -- so unlike flatten() this
    needs no address resolution and no thread pool.

    Deliberately does NOT dedup by name the way `_walk` does for flattening:
    real SPF evaluators re-evaluate a repeated include target every time
    it's referenced, so a name reached via two different passthrough
    branches (or a cycle) counts every time, not once. What IS memoized is
    the DNS fetch itself -- each unique name's SPF record is looked up at
    most once and its text reused on every revisit, so a hostile or cyclic
    chain can't multiply real DNS queries just because the counting logic
    revisits the same name many times.

    Raises ResolutionError naming the failing name on any DNS failure, or if
    the chain depth exceeds MAX_DEPTH on a name whose record hasn't been
    fetched yet, mirroring flatten()'s own guards -- a revisit of an
    already-fetched name is exempt from the depth check, since it costs no
    further DNS query; it's bounded by the cost short-circuit below instead.
    """
    stripped = _spf.strip_qualifier(term)
    lower = stripped.lower()
    if lower.startswith("include:"):
        target = stripped[8:]
    elif lower.startswith("redirect="):
        target = stripped[9:]
    else:
        raise ValueError(f"not an include:/redirect= term: {term!r}")

    cache: dict[str, str] = {}
    return _count_dns_querying_mechanisms(target, resolver_ips, cache, 1, 0)


def _count_dns_querying_mechanisms(
    name: str,
    resolver_ips: Sequence[str],
    cache: dict[str, str],
    depth: int,
    running_total: int,
) -> int:
    """Return the DNS-querying-mechanism cost of `name`'s own record plus
    everything transitively reachable through its include:/redirect= chain.

    `running_total` is the cost already accumulated by the caller before
    this call -- everything counted so far along the whole walk, not just
    this branch -- mirroring how a real evaluator keeps a single running
    total across the whole evaluation rather than a per-branch one. Once
    `running_total` plus this call's own accumulated cost would exceed
    `guards.MAX_LOOKUP_COST`, recursion into further include:/redirect=
    targets stops (their own occurrence still counts -- a real evaluator
    tallies the lookup before it PermErrors -- but nothing beneath them is
    queried or counted). This is what actually bounds a cyclic chain: it
    keeps "recursing" (revisiting cached names) exactly like a real
    evaluator would, until the shared budget runs out, rather than looping
    forever.
    """
    key = name.lower()
    record = cache.get(key)
    if record is None:
        if depth > MAX_DEPTH:
            raise ResolutionError(f"include depth exceeded {MAX_DEPTH} at {name!r}")
        if len(cache) >= _MAX_CHAIN_NAMES:
            raise ResolutionError(
                f"SPF chain too large: exceeded {_MAX_CHAIN_NAMES} unique names "
                f"while resolving {name!r}"
            )
        record = _get_spf_record(name, resolver_ips)
        cache[key] = record

    raw_terms = record.split()[1:]  # [0] is "v=spf1"
    has_all = _has_all_mechanism(raw_terms)

    cost = 0
    for raw_term in raw_terms:
        term = _spf.strip_qualifier(raw_term)
        lower = term.lower()
        if lower.startswith("include:"):
            nested = term[8:]
        elif lower.startswith("redirect="):
            if has_all:
                continue
            nested = term[9:]
        elif (
            _A_TERM_RE.match(term)
            or _MX_TERM_RE.match(term)
            or lower == "ptr"
            or lower.startswith("ptr:")
            or lower.startswith("exists:")
        ):
            cost += 1
            continue
        else:
            continue

        cost += 1
        if running_total + cost <= guards.MAX_LOOKUP_COST:
            cost += _count_dns_querying_mechanisms(
                nested, resolver_ips, cache, depth + 1, running_total + cost
            )

    return cost


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
    # NXDOMAIN and NoAnswer are equivalent "no addresses" outcomes for an
    # a:/mx: mechanism's target per RFC 7208 -- it simply doesn't match,
    # rather than failing the whole domain's plan.
    try:
        answer = _resolve(name, dns.rdatatype.A, resolver_ips)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return [rdata.address for rdata in answer]


def _query_aaaa(name: str, resolver_ips: Sequence[str]) -> list[str]:
    try:
        answer = _resolve(name, dns.rdatatype.AAAA, resolver_ips)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return [rdata.address for rdata in answer]


def _query_mx(name: str, resolver_ips: Sequence[str]) -> list[str]:
    try:
        answer = _resolve(name, dns.rdatatype.MX, resolver_ips)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
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
