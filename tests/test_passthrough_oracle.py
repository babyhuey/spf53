"""Property-based oracle tests for spf53's passthrough validation.

`_validate_passthrough_shape` (spf53.config) has been through 7 review
rounds of hand-found RFC 7208 grammar gaps. Rather than rely on an 8th
adversarial pass to find the next one, this file fuzzes a wide range of
passthrough-entry-shaped strings and, for every one config.py ACCEPTS,
builds a minimal real SPF record via chunker.build_records and checks it
against pyspf -- an independent, DNS-hermetic SPF implementation -- as a
syntax oracle. If pyspf permerrors on something spf53 accepted, that's a
real gap, the same class of bug this round's domain-target fix closed.

This is a backstop for *future unknown* gaps, not a replacement for the
explicit per-bug unit tests in test_config.py.
"""

from __future__ import annotations

from ipaddress import ip_network

import pytest
import spf as pyspf
from hypothesis import given, settings
from hypothesis import strategies as st

from spf53 import chunker, config

_TEST_DOMAIN = "example.com"
_TEST_NETWORK = ip_network("203.0.113.0/24")
_TEST_IP = "203.0.113.1"  # inside _TEST_NETWORK, so a trailing ip4: match is
# always available once a mechanism's own target syntax has been ruled out
# as the cause of any permerror.


def _fake_dns_lookup(name: str, qtype: str, *args: object, **kwargs: object) -> list:
    """Hermetic stand-in for pyspf's DNSLookup -- no real network calls.

    TXT queries get a synthetic minimal SPF record so include:/redirect=
    targets resolve to *something*; otherwise every include:/redirect=
    would permerror on "no valid SPF record for included domain" purely
    because our stub answers nothing, a DNS-resolution artifact unrelated
    to the syntax question this oracle checks. Every other qtype (A/AAAA/
    MX/PTR) stays empty -- pyspf degrades those to a graceful non-match
    rather than an error, so leaving them empty is safe and keeps the
    harness testing syntax, not live resolvability.
    """
    if qtype == "TXT":
        return [((name, "TXT"), (b"v=spf1 -all",))]
    return []


pyspf.DNSLookup = _fake_dns_lookup


def _evaluate(record_text: str) -> tuple[str, int, str]:
    q = pyspf.query(
        i=_TEST_IP,
        s="postmaster@" + _TEST_DOMAIN,
        h="mail." + _TEST_DOMAIN,
        receiver=_TEST_DOMAIN,
    )
    return q.check(spf=record_text)


def _build_content(passthrough_entry: str) -> str | None:
    """Build the chunk-1 record content for a single passthrough entry.

    Returns None if the entry is too large to fit in a single chunk --
    chunker's own capacity limit, orthogonal to what this file tests.
    """
    try:
        records = chunker.build_records(_TEST_DOMAIN, [_TEST_NETWORK], [passthrough_entry], "~all")
    except ValueError:
        return None
    return "".join(records[f"_spf53-1.{_TEST_DOMAIN}"])


def _assert_accepted_entry_is_oracle_clean(entry: str) -> None:
    try:
        config._validate_passthrough_shape(entry, f"domain {_TEST_DOMAIN!r}", _TEST_DOMAIN)
    except config.ConfigError:
        return  # rejected by our own validator -- nothing to check here

    content = _build_content(entry)
    if content is None:
        return

    result, _code, explanation = _evaluate(content)
    assert result != "permerror", (
        f"config.py accepted passthrough entry {entry!r}, but pyspf permerrors "
        f"on the built record: {explanation!r}"
    )


# --- Hypothesis strategies ---------------------------------------------

_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
# %{i} and %{ir} are the documented, realistic passthrough macro use case
# (Salesforce-style "exists:%{i}._spf...") and expand to plain dotted
# text, so they can't produce a runtime-only false permerror the way a
# macro like %{s} (raw "local@domain", "@" and all) could. Sticking to
# these keeps the oracle testing spf53's own target-syntax validation
# rather than pyspf's macro-expansion semantics, which is out of scope.
#
# "%%" is deliberately excluded here: pyspf's own invalid-macro regex
# (`%$` matches a bare trailing '%') misfires on "%%" specifically when
# it's the last two characters of the expanded string -- a pyspf quirk,
# not an spf53 bug (RFC 7208 unconditionally allows "%%" regardless of
# position). "%%" is still covered, in a realistic non-trailing position,
# by the fixed historical corpus below ("exists:%%25.example.net").
_MACRO_EXPANDS = ["%{i}", "%{ir}", "%_", "%-"]
_QUALIFIERS = ["", "+", "-", "~", "?"]
_COLON_PREFIXES = ["a:", "mx:", "ptr:", "exists:", "include:"]


@st.composite
def _label(draw: st.DrawFn) -> str:
    return draw(st.text(alphabet=_LABEL_ALPHABET, min_size=0, max_size=8))


@st.composite
def _domain_target(draw: st.DrawFn) -> str:
    """A domain-spec-shaped target: a mix of literal labels and
    macro-expands, with optional leading/trailing dots -- covers both
    well-formed domains and the malformed shapes this fix rejects (no
    dot, empty labels, all-digit/hyphen-ending final label, ...).
    """
    n = draw(st.integers(min_value=0, max_value=3))
    pieces = [draw(st.one_of(_label(), st.sampled_from(_MACRO_EXPANDS))) for _ in range(n)]
    target = ".".join(pieces)
    if draw(st.booleans()):
        target = "." + target
    if draw(st.booleans()):
        target = target + "."
    return target


@st.composite
def _mechanism_entry(draw: st.DrawFn) -> str:
    qualifier = draw(st.sampled_from(_QUALIFIERS))
    kind = draw(st.sampled_from(["ip4", "ip6", "colon", "redirect"]))

    if kind == "ip4":
        octets = draw(st.lists(st.integers(0, 255), min_size=4, max_size=4))
        prefix = draw(st.integers(min_value=-1, max_value=40))
        body = f"ip4:{'.'.join(map(str, octets))}"
        if prefix >= 0:
            body += f"/{prefix}"
        return qualifier + body

    if kind == "ip6":
        literal = draw(st.sampled_from(["2001:db8::1", "::1", "2001:db8::/32", "::", "not-an-ip"]))
        return qualifier + f"ip6:{literal}"

    if kind == "redirect":
        return f"redirect={draw(_domain_target())}"

    prefix = draw(st.sampled_from(_COLON_PREFIXES))
    target = draw(_domain_target())
    suffix = ""
    if prefix in ("a:", "mx:") and draw(st.booleans()):
        len4 = draw(st.integers(min_value=-1, max_value=200))
        if len4 >= 0:
            suffix += f"/{len4}"
        if draw(st.booleans()):
            len6 = draw(st.integers(min_value=-1, max_value=300))
            if len6 >= 0:
                suffix += f"//{len6}"
    return qualifier + prefix + target + suffix


_KNOWN_GOOD_SEEDS = [
    "ip4:203.0.113.0/24",
    "ip6:2001:db8::/32",
    "a:example.com",
    "mx:example.com",
    "ptr:example.com",
    "exists:%{i}._spf.example.net",
    "include:_spf.example.net",
    "a:mail.example.com/32",
    "exists:%{ir}._spf.example.net",
]

_KNOWN_BAD_SEEDS = [
    "exists:spfhosts",
    "exists:.",
    "mx:..",
    "ptr:foo",
    "exists:example.123",
    "exists:example.com-",
    "exists:foo..example.com",
    "a:/24",
    "+",
    "all",
    "ip4=1.2.3.0/24",
    "redirect=vendor.example",
]

_passthrough_entries = st.one_of(
    _mechanism_entry(),
    st.sampled_from(_KNOWN_GOOD_SEEDS),
    st.sampled_from(_KNOWN_BAD_SEEDS),
)


@given(entry=_passthrough_entries)
@settings(max_examples=300, deadline=None)
def test_accepted_passthrough_entries_are_oracle_clean(entry: str) -> None:
    _assert_accepted_entry_is_oracle_clean(entry)


# --- Fixed historical regression corpus ---------------------------------

# Every passthrough entry test_config.py has explicitly asserted as
# well-formed across this session's fix history, run through the oracle as
# a fixed sanity check that doesn't depend on hypothesis's random search
# landing on them.
_HISTORICAL_ACCEPTED_ENTRIES = [
    "exists:%{i}._spf.mta.salesforce.com",
    "a:example.com",
    "mx:example.com",
    "ptr:example.com",
    "a:mail.example.com/32",
    "a:mail.example.com/0",
    "mx:example.com//128",
    "a:x.com/24//64",
    "ip4:203.0.113.0/0",
    "mx:example.com//0",
    "exists:%{i}._spf.example.net",
    "exists:%{ir}._spf.example.net",
    "exists:%{s}._spf.example.net",
    "exists:%%25.example.net",
    "exists:%_.example.net",
    "exists:%-.example.net",
    "exists:%{l1r+}._spf.example.net",
    "ip4:203.0.113.0/24",
    "include:_spf.example.net",
    "ip6:2001:db8::/32",
    "a:mail.example.com.",
]


@pytest.mark.parametrize("entry", _HISTORICAL_ACCEPTED_ENTRIES)
def test_historical_accepted_entries_are_oracle_clean(entry: str) -> None:
    config._validate_passthrough_shape(entry, f"domain {_TEST_DOMAIN!r}", _TEST_DOMAIN)
    content = _build_content(entry)
    assert content is not None
    result, _code, explanation = _evaluate(content)
    assert result != "permerror", f"{entry!r}: {explanation!r}"


# A curated subset of already-rejected bad entries that pyspf's OWN grammar
# also independently flags -- proof the oracle harness can actually detect
# a real bug (i.e. isn't a no-op), not just that it stays quiet on good
# input. Bypasses config.py's own validator entirely.
_HISTORICAL_REJECTED_ENTRIES_PYSPF_ALSO_CATCHES = [
    "exists:spfhosts",  # round 7: no dot at all
    "exists:.",  # round 7: empty toplabel
    "mx:..",  # round 7: empty toplabel
    "ptr:foo",  # round 7: no dot at all
    "exists:example.123",  # round 7: all-digit toplabel
    "exists:example.com-",  # round 7: hyphen-ending toplabel
    "a:mail.example.com/33",  # round 6: out-of-range IPv4 CIDR length
    "mx:example.com//129",  # round 6: out-of-range IPv6 CIDR length
    "exists:%q.example.com",  # round 10: invalid macro escape
    "exists:%{z}.example.com",  # round 10: unknown macro letter
    "a:/24",  # round 5: empty target
]


@pytest.mark.parametrize("entry", _HISTORICAL_REJECTED_ENTRIES_PYSPF_ALSO_CATCHES)
def test_rejected_entries_would_have_failed_the_oracle(entry: str) -> None:
    """Confirms the harness isn't a no-op: build the record straight from
    the raw entry (skipping config.py's own validator) and check that
    pyspf independently flags each of these as a permerror.
    """
    content = _build_content(entry)
    assert content is not None
    result, _code, explanation = _evaluate(content)
    assert result == "permerror", (
        f"expected pyspf to flag {entry!r} as a permerror, got {result!r}: "
        f"{explanation!r} -- if pyspf no longer flags this, replace it with "
        "an entry it does, so this test keeps proving the harness works"
    )
