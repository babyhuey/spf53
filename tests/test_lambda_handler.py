"""Tests for spf53.lambda_handler."""

from __future__ import annotations

import ipaddress

import pytest

from spf53 import chunker, core, lambda_handler, notify, resolver, route53, ssm
from spf53.config import DomainConfig, Spf53Config

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


def test_lambda_handler_guard_refusal_sends_sns_notification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scheduled (EventBridge async) invocation discards the handler's return
    value, so a guard refusal is only observable via SNS -- this confirms
    core.apply's existing refusal notification actually fires on the Lambda
    path, not just when called directly."""
    dc = _domain()  # default max_shrink_pct=30
    desired = chunker.build_records(dc.name, [NET_A], dc.passthrough, dc.policy)
    live = dict(desired)
    live["_spf53-2.example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]  # huge stale block

    cfg = _cfg([dc], sns_topic_arn="arn:aws:sns:us-east-1:1:spf53-alerts")
    monkeypatch.setattr(ssm, "load_config_ssm", lambda param_name: cfg)
    monkeypatch.setattr(resolver, "flatten", lambda includes, ips: [NET_A])
    monkeypatch.setattr(route53, "get_txt_records", lambda zone_id, domain: (live, {}))

    apply_calls: list[tuple] = []
    notify_calls: list[tuple] = []
    monkeypatch.setattr(route53, "apply_changes", lambda *a, **kw: apply_calls.append((a, kw)))
    monkeypatch.setattr(notify, "publish", lambda *a, **kw: notify_calls.append((a, kw)))

    response = lambda_handler.lambda_handler({}, None)

    assert response["refused"] == ["example.com"]
    assert response["changed"] == []
    assert apply_calls == []

    assert len(notify_calls) == 1
    args, _kwargs = notify_calls[0]
    topic_arn, subject, message = args
    assert topic_arn == cfg.sns_topic_arn
    assert "refus" in subject.lower()
    assert "example.com" in subject
    assert "example.com" in message
    assert "safety guard failed" in message.lower()


def test_lambda_handler_raises_on_domain_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """A domain-level error must surface as a raised exception, not just a
    quiet entry in the return value -- EventBridge discards the return
    value on a scheduled (async) invocation, so raising is the ONLY
    mechanism that turns a failed run into a visible Lambda error
    (CloudWatch Errors metric, EventBridge retry). A regression here would
    make failed scheduled runs silently look successful.
    """
    cfg = _cfg([_domain()])
    monkeypatch.setattr(ssm, "load_config_ssm", lambda param_name: cfg)
    monkeypatch.setattr(
        core,
        "apply",
        lambda cfg, force=False: core.RunResult(
            plans=(), errors=("example.com: resolution failed",)
        ),
    )

    with pytest.raises(RuntimeError, match="example.com: resolution failed"):
        lambda_handler.lambda_handler({}, None)


def test_lambda_handler_uses_spf53_param_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every non-default --function-name deployment sets SPF53_PARAM in the
    Lambda's environment so it reads its own SSM parameter instead of the
    default -- this confirms the handler actually honors that override
    rather than always reading ssm.DEFAULT_PARAM.
    """
    cfg = _cfg([_domain()])
    seen_param_names: list[str] = []

    def fake_load(param_name: str) -> Spf53Config:
        seen_param_names.append(param_name)
        return cfg

    monkeypatch.setattr(ssm, "load_config_ssm", fake_load)
    monkeypatch.setattr(core, "apply", lambda cfg, force=False: core.RunResult(plans=(), errors=()))
    monkeypatch.setenv("SPF53_PARAM", "/spf53/spf53-a/config")

    lambda_handler.lambda_handler({}, None)

    assert seen_param_names == ["/spf53/spf53-a/config"]
