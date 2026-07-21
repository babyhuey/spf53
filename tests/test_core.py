"""Unit tests for spf53.core orchestration."""

from __future__ import annotations

import ipaddress

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
        if len(apply_calls) == 1:
            raise ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ChangeResourceRecordSets",
            )

    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", fake_apply_changes)
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    result = core.apply(_cfg([bad, good], sns_topic_arn="arn:aws:sns:us-east-1:1:spf53"))

    assert len(apply_calls) == 2  # both domains attempted despite the first failing
    assert len(result.errors) == 1
    assert "bad.example" in result.errors[0]
    subjects = [c[0][1] for c in notify_calls]
    assert any("failed to apply" in s.lower() for s in subjects)
    assert any("applied" in s.lower() for s in subjects)
