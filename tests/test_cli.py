"""Unit tests for spf53.cli argument parsing and exit codes."""

from __future__ import annotations

import argparse

import pytest

from spf53 import cli
from spf53.config import ConfigError
from spf53.core import DomainPlan, RunResult
from spf53.guards import GuardResult


def _plan(
    domain: str = "example.com",
    has_upserts: bool = False,
    has_deletes: bool = False,
    guard_ok: bool = True,
    reasons: tuple[str, ...] = (),
) -> DomainPlan:
    desired = {f"_spf53-1.{domain}": ["v=spf1 ip4:192.0.2.0/24 ~all"]}
    upserts = dict(desired) if has_upserts else {}
    deletes = {f"_spf53-2.{domain}": ["v=spf1 ~all"]} if has_deletes else {}
    return DomainPlan(
        domain=domain,
        zone_id="Z123",
        desired=desired,
        live={},
        upserts=upserts,
        deletes=deletes,
        guard=GuardResult(ok=guard_ok, reasons=reasons),
        lookup_cost=2,
        apex_warning=None,
        summary=f"{domain}: 1 CIDR(s) added, 0 CIDR(s) removed",
    )


def _stub_load_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda args: object())


def test_plan_exit_0_when_no_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_config(monkeypatch)
    monkeypatch.setattr(cli.core, "plan", lambda cfg: RunResult(plans=(_plan(),), errors=()))

    assert cli.main(["plan", "-c", "dummy.yaml"]) == 0


def test_plan_exit_2_when_changes_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_config(monkeypatch)
    monkeypatch.setattr(
        cli.core,
        "plan",
        lambda cfg: RunResult(plans=(_plan(has_upserts=True),), errors=()),
    )

    assert cli.main(["plan", "-c", "dummy.yaml"]) == 2


def test_plan_exit_1_on_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_config(monkeypatch)
    monkeypatch.setattr(
        cli.core,
        "plan",
        lambda cfg: RunResult(plans=(), errors=("example.com: NXDOMAIN",)),
    )

    assert cli.main(["plan", "-c", "dummy.yaml"]) == 1


def test_apply_exit_0_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_config(monkeypatch)
    monkeypatch.setattr(
        cli.core,
        "apply",
        lambda cfg, force=False: RunResult(plans=(_plan(has_upserts=True),), errors=()),
    )

    assert cli.main(["apply", "-c", "dummy.yaml"]) == 0


def test_apply_exit_1_on_refusal_without_force(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_config(monkeypatch)
    refused = _plan(has_deletes=True, guard_ok=False, reasons=("new set is empty",))
    monkeypatch.setattr(
        cli.core, "apply", lambda cfg, force=False: RunResult(plans=(refused,), errors=())
    )

    assert cli.main(["apply", "-c", "dummy.yaml"]) == 1


def test_apply_prints_failed_not_applied_for_failed_domain(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_load_config(monkeypatch)
    p = _plan(has_upserts=True)
    monkeypatch.setattr(
        cli.core,
        "apply",
        lambda cfg, force=False: RunResult(
            plans=(p,),
            errors=(f"{p.domain}: failed to apply Route53 changes: boom",),
            failed_domains=(p.domain,),
        ),
    )

    exit_code = cli.main(["apply", "-c", "dummy.yaml"])
    out = capsys.readouterr().out

    assert exit_code == 1
    assert f"{p.domain}: applied" not in out
    assert f"{p.domain}: failed" in out


def test_apply_force_overrides_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_config(monkeypatch)
    refused = _plan(has_deletes=True, guard_ok=False, reasons=("new set is empty",))
    monkeypatch.setattr(
        cli.core, "apply", lambda cfg, force=False: RunResult(plans=(refused,), errors=())
    )

    assert cli.main(["apply", "-c", "dummy.yaml", "--force"]) == 0


def test_plan_config_load_error_prints_error_and_returns_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_load_config(args: argparse.Namespace) -> None:
        raise ConfigError("invalid YAML: bad indentation")

    monkeypatch.setattr(cli, "_load_config", fake_load_config)

    exit_code = cli.main(["plan", "-c", "dummy.yaml"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "spf53 plan:" in err
    assert "invalid YAML" in err


def test_apply_config_load_error_prints_error_and_returns_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_load_config(args: argparse.Namespace) -> None:
        raise ConfigError("invalid YAML: bad indentation")

    monkeypatch.setattr(cli, "_load_config", fake_load_config)

    exit_code = cli.main(["apply", "-c", "dummy.yaml"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "spf53 apply:" in err
    assert "invalid YAML" in err


def test_config_and_ssm_param_are_mutually_exclusive() -> None:
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["plan", "-c", "dummy.yaml", "--ssm-param", "/spf53/config"])


def test_deploy_delegates_to_run_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    from spf53 import deploy

    calls: list[argparse.Namespace] = []

    def fake_run_deploy(args: argparse.Namespace) -> int:
        calls.append(args)
        return 0

    monkeypatch.setattr(deploy, "run_deploy", fake_run_deploy)

    assert cli.main(["deploy", "-c", "dummy.yaml"]) == 0
    assert len(calls) == 1
