"""Pack flattened SPF mechanisms into chained ``_spf53-N.<domain>`` TXT records.

Split convention (RFC 7208 3.3): a DNS TXT record's character-strings are
concatenated by resolvers with NO separator between them, so a multi-string
record must carry its own separating space. When a record's content needs a
second string, the split always falls exactly between two mechanisms (never
mid-token): the first string carries no trailing space, and the second
string carries a single LEADING space. Concatenating the two strings then
reproduces the original "mech1 mech2 ..." content byte-for-byte.
"""

from collections.abc import Sequence
from ipaddress import IPv4Network, IPv6Network

from spf53 import _spf

MAX_TXT_STRING = 255
MAX_STRINGS_PER_RECORD = 2
DNS_QUERYING_MECHANISMS = frozenset({"include", "exists", "a", "mx", "ptr"})

_MAX_RECORD_CHARS = MAX_TXT_STRING * MAX_STRINGS_PER_RECORD


def build_records(
    domain: str,
    networks: Sequence[IPv4Network | IPv6Network],
    passthrough: Sequence[str],
    policy: str,
) -> dict[str, list[str]]:
    """Pack passthrough mechanisms and networks into chained TXT records.

    Chunk 1 carries passthrough mechanisms first, then ip4:, then ip6:
    mechanisms. Every chunk but the last ends with an ``include:`` link to
    the next chunk; the last ends with ``policy``. Room for that trailing
    link (or the policy) is reserved before packing each chunk's body.
    """
    v4 = sorted(n for n in networks if isinstance(n, IPv4Network))
    v6 = sorted(n for n in networks if isinstance(n, IPv6Network))
    tokens = [*passthrough, *(_render(n) for n in v4), *(_render(n) for n in v6)]

    records: dict[str, list[str]] = {}
    chunk_num = 1
    start = 0
    while True:
        name = f"_spf53-{chunk_num}.{domain}"
        remaining = tokens[start:]

        if _fits(["v=spf1", *remaining, policy]):
            content = " ".join(["v=spf1", *remaining, policy])
            records[name] = _split(content)
            return records

        next_link = f"include:_spf53-{chunk_num + 1}.{domain}"
        n = _max_fit(remaining, next_link)
        if n == 0:
            raise ValueError(f"mechanism too large to fit in chunk {name!r}")
        content = " ".join(["v=spf1", *remaining[:n], next_link])
        records[name] = _split(content)
        start += n
        chunk_num += 1


def lookup_cost(records: dict[str, list[str]], passthrough: Sequence[str]) -> int:
    """Total include-chain lookups (apex through the last chunk) + DNS-querying
    passthrough mechanisms.

    `records` has one entry per chunk (`_spf53-1.<domain>` through
    `_spf53-N.<domain>`), so `len(records) == N`. The include chain is: apex
    -> chunk 1 (1 lookup), then chunk 1 -> chunk 2 -> ... -> chunk N (N-1
    more lookups) -- that's exactly N lookups total, so `len(records)` alone
    already covers the whole chain including the apex's own include. Do NOT
    add a separate "+1 for the apex" on top of this; that double-counts it.
    """
    dns_querying = sum(1 for p in passthrough if _is_dns_querying_mechanism(p))
    return len(records) + dns_querying


def to_route53_value(strings: list[str]) -> str:
    """Render as Route53's space-separated, double-quoted TXT value form."""
    return " ".join(f'"{_escape(s)}"' for s in strings)


def from_route53_value(value: str) -> list[str]:
    """Parse a Route53 TXT value back into its component strings.

    Defensively unescapes ``\\"`` and ``\\\\`` inside each quoted string.
    """
    strings: list[str] = []
    i, n = 0, len(value)
    while i < n:
        if value[i].isspace():
            i += 1
            continue
        if value[i] != '"':
            raise ValueError(f"malformed Route53 TXT value: {value!r}")
        i += 1
        chars: list[str] = []
        while i < n and value[i] != '"':
            if value[i] == "\\" and i + 1 < n:
                chars.append(value[i + 1])
                i += 2
            else:
                chars.append(value[i])
                i += 1
        if i >= n:
            raise ValueError(f"unterminated quoted string in Route53 TXT value: {value!r}")
        i += 1  # skip closing quote
        strings.append("".join(chars))
    return strings


def _is_dns_querying_mechanism(term: str) -> bool:
    """Whether `term` is an a/mx/ptr/include/exists mechanism (exact keyword,
    not a prefix), or a `redirect=` modifier.

    `redirect=` is syntactically a modifier (`=`-separated) rather than a
    mechanism (`:`-separated) like the others, but RFC 7208 4.6.4 counts it
    as one DNS-querying lookup at its own level, same as `include`.
    """
    body = _spf.strip_qualifier(term)
    if body.lower().startswith("redirect="):
        return True
    cut = len(body)
    for sep in (":", "/"):
        idx = body.find(sep)
        if idx != -1:
            cut = min(cut, idx)
    return body[:cut].lower() in DNS_QUERYING_MECHANISMS


def _render(network: IPv4Network | IPv6Network) -> str:
    """Render a network as an ip4:/ip6: mechanism; host routes drop the prefix."""
    is_v6 = isinstance(network, IPv6Network)
    label = "ip6" if is_v6 else "ip4"
    host_prefixlen = 128 if is_v6 else 32
    if network.prefixlen == host_prefixlen:
        return f"{label}:{network.network_address}"
    return f"{label}:{network}"


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _split(content: str) -> list[str]:
    result = _try_split(content)
    if result is None:
        raise ValueError(f"content does not fit in {MAX_STRINGS_PER_RECORD} strings: {content!r}")
    return result


def _try_split(content: str) -> list[str] | None:
    """Split content into <= MAX_STRINGS_PER_RECORD strings, or None if it can't."""
    if len(content) <= MAX_TXT_STRING:
        return [content]
    if len(content) > _MAX_RECORD_CHARS:
        return None
    split_at = None
    for i, ch in enumerate(content):
        if i > MAX_TXT_STRING:
            break
        if ch == " " and (len(content) - i) <= MAX_TXT_STRING:
            split_at = i
    if split_at is None:
        return None
    return [content[:split_at], content[split_at:]]


def _fits(tokens: list[str]) -> bool:
    return _try_split(" ".join(tokens)) is not None


def _max_fit(remaining: list[str], suffix: str) -> int:
    """Largest prefix of `remaining` that still fits alongside `suffix`."""
    best = 0
    for i in range(len(remaining) + 1):
        if _fits(["v=spf1", *remaining[:i], suffix]):
            best = i
        else:
            break
    return best
