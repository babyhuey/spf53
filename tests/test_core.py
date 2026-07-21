"""Unit tests for spf53.core orchestration."""

from __future__ import annotations

import ipaddress
import threading
import time

import pytest

from spf53 import chunker, core, notify, resolver, route53
from spf53.config import DomainConfig, Spf53Config
from spf53.resolver import ResolutionError

NET_A = ipaddress.ip_network("192.0.2.0/24")


def _domain(**overrides: object) -> DomainConfig:
    defaults: dict[str, object] = dict(
        name="example.com",
        hosted_zone_id="Z123",
        includes=("_spf.google.com",),
        passthrough=(),
        policy="~all",
        max_shrink_pct=30,
    )
    defaults.update(overrides)
    return DomainConfig(**defaults)  # type: ignore[arg-type]


def _cfg(domains: list[DomainConfig], sns_topic_arn: str | None = None) -> Spf53Config:
    return Spf53Config(domains=tuple(domains), sns_topic_arn=sns_topic_arn)


def test_plan_no_op_when_live_equals_desired(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain()
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (dict(desired), {}))

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    assert len(result.plans) == 1
    p = result.plans[0]
    assert p.upserts == {}
    assert p.deletes == {}
    assert p.has_changes is False


def test_apply_no_op_does_not_call_route53_or_notify(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain()
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (dict(desired), {}))

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([dc]))

    assert apply_calls == []
    assert notify_calls == []
    assert result.errors == ()


def test_plan_first_run_creates_all_records(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain()
    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([dc]))
    p = result.plans[0]

    assert p.live == {}
    assert p.deletes == {}
    assert set(p.upserts) == set(p.desired)
    assert p.has_changes is True
    assert p.guard.ok is True


def test_apply_first_run_calls_apply_changes_and_notifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dc = _domain()
    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([dc], sns_topic_arn="arn:aws:sns:us-east-1:1:spf53"))

    assert len(apply_calls) == 1
    args, _kwargs = apply_calls[0]
    zone_id, upserts, deletes = args[:3]
    assert zone_id == dc.hosted_zone_id
    assert upserts
    assert deletes == {}
    assert len(notify_calls) == 1
    assert "applied" in notify_calls[0][0][1].lower()
    assert result.errors == ()


def test_plan_chain_shrink_produces_deletes(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain(max_shrink_pct=100)
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)
    stale_key = "_spf53-2.example.com"
    live = dict(desired)
    live[stale_key] = ["v=spf1 ip4:203.0.113.0/24 ~all"]

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (live, {}))

    result = core.plan(_cfg([dc]))
    p = result.plans[0]

    assert p.deletes == {stale_key: live[stale_key]}
    assert p.has_changes is True


def test_apply_chain_shrink_sends_deletes_to_route53(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain(max_shrink_pct=100)
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)
    stale_key = "_spf53-2.example.com"
    live = dict(desired)
    live[stale_key] = ["v=spf1 ip4:203.0.113.0/24 ~all"]

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (live, {}))

    apply_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: None)

    core.apply(_cfg([dc]))

    assert len(apply_calls) == 1
    args, _kwargs = apply_calls[0]
    deletes = args[2]
    assert deletes == {stale_key: live[stale_key]}


def test_apply_guard_refusal_blocks_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain()  # default max_shrink_pct=30
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)
    live = dict(desired)
    live["_spf53-2.example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]  # huge stale block

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (live, {}))

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([dc]))

    p = result.plans[0]
    assert p.guard.ok is False
    assert apply_calls == []
    assert len(notify_calls) == 1
    assert "refus" in notify_calls[0][0][1].lower()


def test_apply_force_overrides_guard_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    dc = _domain()
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)
    live = dict(desired)
    live["_spf53-2.example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (live, {}))

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([dc]), force=True)

    assert result.plans[0].guard.ok is False  # guard still reports the real refusal
    assert len(apply_calls) == 1  # but force applied anyway
    assert len(notify_calls) == 1
    assert "applied" in notify_calls[0][0][1].lower()


def test_plan_resolution_error_does_not_block_other_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = _domain(name="bad.example", includes=("broken.include",))
    good = _domain(name="good.example", includes=("_spf.google.com",))

    def fake_flatten(includes: tuple[str, ...], ips: tuple[str, ...]) -> list:
        if "broken.include" in includes:
            raise ResolutionError("bad.example: broken.include failed to resolve")
        return [NET_A]

    monkeypatch.setattr(resolver, "flatten", fake_flatten)
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([bad, good]))

    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    assert len(result.plans) == 1
    assert result.plans[0].domain == "good.example"


def test_apply_resolution_error_notifies_and_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = _domain(name="bad.example", includes=("broken.include",))
    good = _domain(name="good.example", includes=("_spf.google.com",))

    def fake_flatten(includes: tuple[str, ...], ips: tuple[str, ...]) -> list:
        if "broken.include" in includes:
            raise ResolutionError("bad.example: broken.include failed to resolve")
        return [NET_A]

    monkeypatch.setattr(resolver, "flatten", fake_flatten)
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    core.apply(_cfg([bad, good]))

    assert len(apply_calls) == 1  # good.example still applied
    subjects = [c[0][1] for c in notify_calls]
    assert any("resolution failed" in s.lower() for s in subjects)
    assert any("applied" in s.lower() for s in subjects)


def test_plan_corrupt_live_token_isolated_to_its_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = _domain(name="bad.example")
    good = _domain(name="good.example")
    bad_live = {"_spf53-1.bad.example": ["v=spf1 ip4:not-an-address ~all"]}

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])

    def fake_get_txt_records(zone_id: str, domain: str) -> tuple[dict, dict]:
        if domain == "bad.example":
            return bad_live, {}
        return {}, {}

    monkeypatch.setattr(route53, "get_txt_records", fake_get_txt_records)

    result = core.plan(_cfg([bad, good]))

    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    assert "not-an-address" in result.errors[0]
    assert "_spf53-1.bad.example" in result.errors[0]
    assert len(result.plans) == 1
    assert result.plans[0].domain == "good.example"


def test_networks_from_records_strips_spf_qualifiers() -> None:
    """A qualified ip4/ip6 mechanism (e.g. from a passthrough entry placed
    verbatim into a live record) must still be recognized, or the guard's
    live_networks baseline silently undercounts.
    """
    records = {
        "_spf53-1.example.com": ["v=spf1 +ip4:203.0.113.0/24 -ip4:198.51.100.0/24 ~all"],
        "_spf53-2.example.com": ["v=spf1 ip6:2001:db8::/32 ~all"],
    }

    networks = core._networks_from_records(records)

    assert ipaddress.ip_network("203.0.113.0/24") in networks
    assert ipaddress.ip_network("198.51.100.0/24") in networks
    assert ipaddress.ip_network("2001:db8::/32") in networks
    assert len(networks) == 3


def test_parse_ip_token_uppercase_prefix_and_mixed_case_hex() -> None:
    """SPF mechanism keywords are case-insensitive per RFC 7208 — an
    uppercase IP4:/IP6: prefix (e.g. copy-pasted from vendor SPF docs, which
    often uses uppercase) must parse the same as lowercase, and uppercase
    IPv6 hex digits must round-trip correctly too.
    """
    assert core._parse_ip_token("IP4:203.0.113.0/24", "test") == ipaddress.ip_network(
        "203.0.113.0/24"
    )
    assert core._parse_ip_token("IP6:2001:DB8::/32", "test") == ipaddress.ip_network(
        "2001:db8::/32"
    )


def test_passthrough_networks_uppercase_prefix_is_recognized() -> None:
    networks = core._passthrough_networks(["IP4:203.0.113.0/24"])

    assert networks == [ipaddress.ip_network("203.0.113.0/24")]


def test_networks_from_records_uppercase_prefix_is_recognized() -> None:
    records = {"_spf53-1.example.com": ["v=spf1 IP4:203.0.113.0/24 ~all"]}

    networks = core._networks_from_records(records)

    assert networks == [ipaddress.ip_network("203.0.113.0/24")]


def test_collapse_merges_passthrough_subset_of_resolved_supernet() -> None:
    """A passthrough /25 fully contained in a resolved /24 must collapse
    into just the /24 rather than double-counting the overlapping addresses
    — partial overlaps need the same collapsing as exact duplicates.
    """
    supernet = ipaddress.ip_network("203.0.113.0/24")
    subnet = ipaddress.ip_network("203.0.113.0/25")  # first half of supernet

    collapsed = core._collapse([supernet, subnet])

    assert collapsed == [supernet]
    assert sum(n.num_addresses for n in collapsed) == supernet.num_addresses


def test_plan_passthrough_duplicate_removed_from_resolved_side_no_false_positive_shrink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: comparison_networks = networks + _passthrough_networks(...)
    was a plain list concatenation with no collapsing. When a passthrough
    literal CIDR exactly duplicates a resolver-derived CIDR, both the live
    baseline and the new comparison set counted that CIDR's addresses
    twice. If the resolver side later drops it (e.g. a normal upstream
    vendor SPF change) while the passthrough entry still covers it, the
    address count appeared to shrink by the full duplicated CIDR even
    though the domain's true SPF-covered address space hadn't changed —
    a false-positive guard refusal.
    """
    stable_cidr = "198.51.100.0/24"
    dup_cidr = "203.0.113.0/24"
    dc = _domain(passthrough=(f"ip4:{dup_cidr}",))

    # Prior apply: the vendor's SPF resolved to both blocks, and the
    # passthrough entry for dup_cidr duplicates one of them — this is what
    # got published and is now live.
    resolved_before = [ipaddress.ip_network(stable_cidr), ipaddress.ip_network(dup_cidr)]
    live = chunker.build_records(dc.name, resolved_before, dc.passthrough, dc.policy)

    # Now the vendor's SPF record no longer includes dup_cidr (a normal,
    # safe upstream change) — the passthrough entry alone still covers it.
    resolved_after = [ipaddress.ip_network(stable_cidr)]

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: resolved_after)
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (dict(live), {}))

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    p = result.plans[0]
    assert p.guard.ok is True
    assert p.guard.reasons == ()


def test_plan_steady_state_passthrough_cidr_matching_resolved_cidr_is_no_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a literal ip4:/ip6: passthrough entry gets rendered
    verbatim into the live TXT records (chunker.build_records writes both
    `networks` and `dc.passthrough` into the chunk), so live_networks (parsed
    back from live) picks it up — but raw `networks` (resolver-only) never
    does, since resolver.flatten() never walks dc.passthrough. Comparing
    live_networks against raw `networks` therefore showed this CIDR as
    "removed" on every run, even in a steady state where an include resolves
    to that exact same CIDR and nothing has actually changed.
    """
    passthrough_cidr = "198.51.100.0/24"
    dc = _domain(passthrough=(f"ip4:{passthrough_cidr}",))
    resolved = ipaddress.ip_network(passthrough_cidr)

    # The live records already reflect a prior apply of this exact steady
    # state: build_records renders both the passthrough token and the
    # resolved network verbatim into the same chunk.
    live = chunker.build_records(dc.name, [resolved], dc.passthrough, dc.policy)

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [resolved])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (dict(live), {}))

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    p = result.plans[0]
    assert p.guard.ok is True
    assert p.has_changes is False
    assert "0 CIDR(s) added, 0 CIDR(s) removed" in p.summary


def test_plan_malformed_passthrough_cidr_isolated_to_its_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = _domain(name="bad.example", passthrough=("ip4:not-an-ip",))
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([bad, good]))

    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    assert "not-an-ip" in result.errors[0]
    assert len(result.plans) == 1
    assert result.plans[0].domain == "good.example"


def test_apex_warning_absent_apex_still_a_warning_not_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dc = _domain()

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    # No apex key at all in the live records (key absent, not just empty).
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    p = result.plans[0]
    assert p.apex_warning is not None
    assert "_spf53-1.example.com" in p.apex_warning
    assert "v=spf1 include:_spf53-1.example.com ~all" in p.apex_warning


def test_apex_warning_case_insensitive_match_produces_no_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SPF mechanism names are case-insensitive per RFC 7208 — a manually set
    apex record using 'Include:' (or any other casing) instead of lowercase
    'include:' is functionally identical and must not trigger a false
    "apex record incorrect" warning.
    """
    dc = _domain()
    apex_live = {dc.name: ["v=spf1 Include:_spf53-1.example.com ~all"]}

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (dict(apex_live), {}))

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    assert result.plans[0].apex_warning is None


def test_apply_route53_client_error_recorded_and_next_domain_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from botocore.exceptions import ClientError

    bad = _domain(name="bad.example")
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    apply_calls: list[tuple] = []

    def fake_apply_changes(zone_id: str, upserts: dict, deletes: dict, **kw: object) -> None:
        apply_calls.append((zone_id, upserts, deletes))
        # Keyed off which domain's own upserts this call carries (not call
        # count) so the failure lands on bad.example deterministically even
        # though apply() now runs both domains concurrently -- thread
        # scheduling doesn't guarantee bad.example's call happens first.
        if any("bad.example" in name for name in upserts):
            raise ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ChangeResourceRecordSets",
            )

    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", fake_apply_changes)
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([bad, good], sns_topic_arn="arn:aws:sns:us-east-1:1:spf53"))

    assert len(apply_calls) == 2  # both domains attempted despite bad.example failing
    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    subjects = [c[0][1] for c in notify_calls]
    assert any("failed to apply" in s.lower() for s in subjects)
    assert any("applied" in s.lower() for s in subjects)


def test_apply_botocore_connection_error_isolated_to_one_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connection-level BotoCoreError (not a ClientError API response) from
    apply_changes must be caught and isolated the same way a ClientError is.
    """
    from botocore.exceptions import EndpointConnectionError

    bad = _domain(name="bad.example")
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    apply_calls: list[tuple] = []

    def fake_apply_changes(zone_id: str, upserts: dict, deletes: dict, **kw: object) -> None:
        apply_calls.append((zone_id, upserts, deletes))
        # Keyed off which domain's own upserts this call carries (not call
        # count) so the failure lands on bad.example deterministically even
        # though apply() now runs both domains concurrently -- thread
        # scheduling doesn't guarantee bad.example's call happens first.
        if any("bad.example" in name for name in upserts):
            raise EndpointConnectionError(endpoint_url="https://route53.amazonaws.com/")

    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", fake_apply_changes)
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([bad, good], sns_topic_arn="arn:aws:sns:us-east-1:1:spf53"))

    assert len(apply_calls) == 2  # good.example still attempted despite bad.example's error
    assert result.failed_domains == ("bad.example",)
    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    subjects = [c[0][1] for c in notify_calls]
    assert any("failed to apply" in s.lower() for s in subjects)
    assert any("applied" in s.lower() for s in subjects)


def test_plan_chunk_build_error_isolated_to_its_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = _domain(name="bad.example")
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    real_build_records = chunker.build_records

    def fake_build_records(
        name: str, networks: list, passthrough: tuple, policy: str
    ) -> dict[str, list[str]]:
        if name == "bad.example":
            raise ValueError(f"mechanism too large to fit in chunk '_spf53-1.{name}'")
        return real_build_records(name, networks, passthrough, policy)

    monkeypatch.setattr(chunker, "build_records", fake_build_records)

    result = core.plan(_cfg([bad, good]))

    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    assert len(result.plans) == 1
    assert result.plans[0].domain == "good.example"


def test_apply_chunk_build_error_notifies_and_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = _domain(name="bad.example")
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    real_build_records = chunker.build_records

    def fake_build_records(
        name: str, networks: list, passthrough: tuple, policy: str
    ) -> dict[str, list[str]]:
        if name == "bad.example":
            raise ValueError(f"mechanism too large to fit in chunk '_spf53-1.{name}'")
        return real_build_records(name, networks, passthrough, policy)

    monkeypatch.setattr(chunker, "build_records", fake_build_records)

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([bad, good], sns_topic_arn="arn:aws:sns:us-east-1:1:spf53"))

    assert len(apply_calls) == 1  # good.example still applied despite bad.example's chunk error
    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    subjects = [c[0][1] for c in notify_calls]
    assert any("resolution failed" in s.lower() for s in subjects)  # SNS fired for the run error
    assert any("applied" in s.lower() for s in subjects)


def test_plan_route53_read_error_isolated_to_its_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from botocore.exceptions import ClientError

    bad = _domain(name="bad.example")
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])

    def fake_get_txt_records(zone_id: str, domain: str) -> tuple[dict, dict]:
        if domain == "bad.example":
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
                "ListResourceRecordSets",
            )
        return {}, {}

    monkeypatch.setattr(route53, "get_txt_records", fake_get_txt_records)

    result = core.plan(_cfg([bad, good]))

    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    assert len(result.plans) == 1
    assert result.plans[0].domain == "good.example"


def test_plan_preserves_cfg_domains_order_despite_out_of_order_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """flatten()'s output order can't distinguish a submission-order collector
    from a completion-order one on its own, so stagger sleeps such that the
    domain submitted FIRST finishes LAST — a completion-order collector would
    then produce plans in the reverse of cfg.domains order.
    """
    domains = [
        _domain(name=f"d{i}.example", includes=(f"_spf.d{i}.example.com",)) for i in range(4)
    ]
    sleep_seconds = {d.includes[0]: (len(domains) - i) * 0.02 for i, d in enumerate(domains)}

    def fake_flatten(includes: tuple[str, ...], ips: tuple[str, ...]) -> list:
        time.sleep(sleep_seconds[includes[0]])
        return [NET_A]

    monkeypatch.setattr(resolver, "flatten", fake_flatten)
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg(domains))

    assert result.errors == ()
    assert [p.domain for p in result.plans] == [d.name for d in domains]


def test_plan_runs_domains_concurrently(monkeypatch: pytest.MonkeyPatch) -> None:
    """If domains were processed sequentially, only one thread would ever
    reach the barrier at a time and `barrier.wait()` would time out
    (BrokenBarrierError), failing this test.
    """
    n = 3
    domains = [
        _domain(name=f"d{i}.example", includes=(f"_spf.d{i}.example.com",)) for i in range(n)
    ]
    barrier = threading.Barrier(n, timeout=2)

    def fake_flatten(includes: tuple[str, ...], ips: tuple[str, ...]) -> list:
        barrier.wait()
        return [NET_A]

    monkeypatch.setattr(resolver, "flatten", fake_flatten)
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg(domains))

    assert result.errors == ()
    assert len(result.plans) == n


def test_apply_runs_domains_concurrently(monkeypatch: pytest.MonkeyPatch) -> None:
    """If apply() processed domains sequentially, only one thread would ever
    reach the barrier at a time and `barrier.wait()` would time out
    (BrokenBarrierError), failing this test.
    """
    n = 3
    domains = [
        _domain(name=f"d{i}.example", includes=(f"_spf.d{i}.example.com",)) for i in range(n)
    ]
    barrier = threading.Barrier(n, timeout=2)

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    def fake_apply_changes(zone_id: str, upserts: dict, deletes: dict, **kw: object) -> None:
        barrier.wait()

    monkeypatch.setattr(route53, "apply_changes", fake_apply_changes)
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: None)

    result = core.apply(_cfg(domains))

    assert result.errors == ()
    assert len(result.plans) == n


def test_apply_preserves_plan_order_in_failed_domains_despite_out_of_order_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """apply_changes()'s call order can't distinguish a submission-order
    collector from a completion-order one on its own, so stagger sleeps such
    that the domain submitted FIRST finishes LAST — a completion-order
    collector would then produce failed_domains/errors in the reverse of
    result.plans order.
    """
    from botocore.exceptions import ClientError

    n = 4
    domains = [
        _domain(name=f"d{i}.example", hosted_zone_id=f"Z{i}", includes=(f"_spf.d{i}.example.com",))
        for i in range(n)
    ]
    sleep_seconds = {d.hosted_zone_id: (n - i) * 0.02 for i, d in enumerate(domains)}

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    def fake_apply_changes(zone_id: str, upserts: dict, deletes: dict, **kw: object) -> None:
        time.sleep(sleep_seconds[zone_id])
        raise ClientError(
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
            "ChangeResourceRecordSets",
        )

    monkeypatch.setattr(route53, "apply_changes", fake_apply_changes)
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: None)

    result = core.apply(_cfg(domains))

    assert result.failed_domains == tuple(d.name for d in domains)


def test_plan_one_domain_flatten_and_get_txt_records_run_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resolver.flatten() and route53.get_txt_records() are independent of
    each other's result within a single domain's plan, so they must run
    concurrently. If they ran sequentially, only one thread would ever reach
    the barrier at a time and `barrier.wait()` would time out
    (BrokenBarrierError), failing this test.
    """
    dc = _domain()
    barrier = threading.Barrier(2, timeout=2)

    def fake_flatten(includes: tuple[str, ...], ips: tuple[str, ...]) -> list:
        barrier.wait()
        return [NET_A]

    def fake_get_txt_records(zone_id: str, domain: str) -> tuple[dict, dict]:
        barrier.wait()
        return {}, {}

    monkeypatch.setattr(resolver, "flatten", fake_flatten)
    monkeypatch.setattr(route53, "get_txt_records", fake_get_txt_records)

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    assert len(result.plans) == 1


def test_plan_empty_domains_returns_empty_result_without_pool() -> None:
    result = core.plan(_cfg([]))

    assert result.plans == ()
    assert result.errors == ()


# --- Finding 1: malformed live TXT decoding must be isolated per-domain ----


def test_plan_route53_malformed_txt_value_isolated_to_its_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare ValueError from decoding a live TXT record (e.g.
    chunker.from_route53_value choking on a hand-authored, non-spf53 apex
    record) must be isolated to that one domain — not propagate out of
    _plan_one_domain and crash the whole plan()/apply() run for every domain.
    """
    bad = _domain(name="bad.example")
    good = _domain(name="good.example")

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])

    def fake_get_txt_records(zone_id: str, domain: str) -> tuple[dict, dict]:
        if domain == "bad.example":
            raise ValueError("malformed Route53 TXT value: 'not-a-quoted-string'")
        return {}, {}

    monkeypatch.setattr(route53, "get_txt_records", fake_get_txt_records)

    result = core.plan(_cfg([bad, good]))

    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    assert len(result.plans) == 1
    assert result.plans[0].domain == "good.example"


# --- Finding 2: RFC 7208 hard lookup-cost limit must refuse an apply -------


def test_plan_lookup_cost_exactly_ten_not_refused_by_cost_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # lookup_cost = len(records) (already includes the apex include) +
    #               dns-querying passthrough count = 1 + 9 = 10, exactly at
    #               the RFC 7208 hard limit.
    passthrough = tuple(f"exists:{i}.example.com" for i in range(9))
    dc = _domain(passthrough=passthrough)

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([dc]))

    p = result.plans[0]
    assert p.lookup_cost == 10
    assert p.guard.ok is True
    assert p.guard.reasons == ()


def test_plan_lookup_cost_over_rfc7208_limit_refused_despite_no_shrink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lookup_cost of 11+ must refuse the apply with a reason naming the
    RFC 7208 limit, even when the address set is stable (first run, no live
    records to shrink from) -- this is a distinct refusal reason from the
    shrink guard.
    """
    # lookup_cost = len(records) (already includes the apex include) +
    #               dns-querying passthrough count = 1 + 10 = 11, one over
    #               the RFC 7208 hard limit.
    passthrough = tuple(f"exists:{i}.example.com" for i in range(10))
    dc = _domain(passthrough=passthrough)

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([dc]))

    p = result.plans[0]
    assert p.lookup_cost == 11
    assert p.guard.ok is False
    assert any("RFC 7208" in reason for reason in p.guard.reasons)


# --- Finding 3: a policy-only change must show up in the summary -----------


def test_plan_policy_change_with_identical_cidrs_reported_in_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: _build_summary was computed purely from CIDR-set diffs, so
    tightening a domain's policy (~all -> -all) with zero IP changes still
    performs a real Route53 upsert (the last chunk's terminal token differs)
    but the summary claimed "0 added, 0 removed", masking the enforcement
    change entirely.
    """
    old_dc = _domain(policy="~all")
    live = chunker.build_records(old_dc.name, [NET_A], old_dc.passthrough, "~all")

    dc = _domain(policy="-all")  # tightened policy, same resolved CIDRs

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (dict(live), {}))

    result = core.plan(_cfg([dc]))

    assert result.errors == ()
    p = result.plans[0]
    assert p.has_changes is True
    assert "0 CIDR(s) added, 0 CIDR(s) removed" in p.summary
    assert "policy changed" in p.summary
    assert "'~all'" in p.summary
    assert "'-all'" in p.summary


def test_plan_first_run_no_live_baseline_does_not_report_spurious_policy_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dc = _domain()

    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: ({}, {}))

    result = core.plan(_cfg([dc]))

    p = result.plans[0]
    assert "policy changed" not in p.summary


def test_extract_policy_returns_none_for_empty_records() -> None:
    assert core.extract_policy({}) is None


def test_extract_policy_picks_highest_numbered_chunk() -> None:
    records = {
        "_spf53-1.example.com": ["v=spf1 include:_spf53-2.example.com"],
        "_spf53-2.example.com": ["v=spf1 ip4:192.0.2.0/24 -all"],
    }
    assert core.extract_policy(records) == "-all"
