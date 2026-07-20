"""Tests for spf53.deploy.

spf53.config and spf53.ssm are owned by a different work stream and may not
exist yet when this suite runs. If either is missing, minimal stand-ins that
match the contracts in docs/superpowers/specs/2026-07-20-spf53-design.md are
installed into sys.modules so spf53.deploy (and these tests) can still import
and run. Once the real modules land, this stub is skipped entirely.
"""

from __future__ import annotations

import argparse
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import boto3
import pytest
import yaml
from moto import mock_aws


def _install_config_ssm_stubs() -> None:
    try:
        import spf53.config  # noqa: F401
        import spf53.ssm  # noqa: F401

        return
    except ImportError:
        pass

    config_module = types.ModuleType("spf53.config")

    @dataclass(frozen=True)
    class DomainConfig:
        name: str
        hosted_zone_id: str
        includes: tuple[str, ...]
        passthrough: tuple[str, ...] = ()
        policy: str = "~all"
        max_shrink_pct: int = 30

    @dataclass(frozen=True)
    class Spf53Config:
        domains: tuple[DomainConfig, ...]
        sns_topic_arn: str | None = None
        resolver_ips: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")

    class ConfigError(Exception):
        pass

    def parse_config(yaml_text: str) -> Spf53Config:
        data = yaml.safe_load(yaml_text) or {}
        try:
            domains = tuple(
                DomainConfig(
                    name=d["name"],
                    hosted_zone_id=d["hosted_zone_id"],
                    includes=tuple(d.get("includes", ())),
                    passthrough=tuple(d.get("passthrough", ())),
                    policy=d.get("policy", "~all"),
                    max_shrink_pct=d.get("max_shrink_pct", 30),
                )
                for d in data["domains"]
            )
        except KeyError as exc:
            raise ConfigError(f"missing required field: {exc}") from exc
        return Spf53Config(
            domains=domains,
            sns_topic_arn=data.get("sns_topic_arn"),
            resolver_ips=tuple(data.get("resolver_ips", ("1.1.1.1", "8.8.8.8"))),
        )

    def load_config_file(path: str | Path) -> Spf53Config:
        return parse_config(Path(path).read_text())

    config_module.DomainConfig = DomainConfig
    config_module.Spf53Config = Spf53Config
    config_module.ConfigError = ConfigError
    config_module.parse_config = parse_config
    config_module.load_config_file = load_config_file
    sys.modules["spf53.config"] = config_module

    ssm_module = types.ModuleType("spf53.ssm")
    ssm_module.DEFAULT_PARAM = "/spf53/config"

    def put_config_ssm(yaml_text: str, param_name: str = "/spf53/config") -> None:
        parse_config(yaml_text)  # validate before pushing, per contract
        client = boto3.client("ssm")
        client.put_parameter(Name=param_name, Value=yaml_text, Type="String", Overwrite=True)

    def load_config_ssm(param_name: str = "/spf53/config") -> Spf53Config:
        client = boto3.client("ssm")
        value = client.get_parameter(Name=param_name)["Parameter"]["Value"]
        return parse_config(value)

    ssm_module.put_config_ssm = put_config_ssm
    ssm_module.load_config_ssm = load_config_ssm
    sys.modules["spf53.ssm"] = ssm_module


_install_config_ssm_stubs()

from spf53 import deploy  # noqa: E402

SAMPLE_CONFIG = """\
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes:
      - _spf.google.com
"""


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(autouse=True)
def stub_zip_build(monkeypatch: pytest.MonkeyPatch) -> None:
    # Real dep installation is slow and needs network access; tests only
    # care that the returned bytes get handed to the Lambda API.
    monkeypatch.setattr(deploy, "build_lambda_zip", lambda: b"PK\x03\x04stub-zip-contents")


def _write_config(tmp_path: Path, text: str = SAMPLE_CONFIG) -> Path:
    path = tmp_path / "spf53.yaml"
    path.write_text(text)
    return path


def _make_args(config_path: Path, **overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "config": str(config_path),
        "schedule": "rate(6 hours)",
        "create_topic": None,
        "param_name": "/spf53/config",
        "function_name": "spf53",
        "region": "us-east-1",
        "dry_run": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@mock_aws
def test_dry_run_makes_zero_aws_calls(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts", dry_run=True)

    result = deploy.run_deploy(args)

    assert result == 0
    assert boto3.client("iam", region_name="us-east-1").list_roles()["Roles"] == []
    assert boto3.client("lambda", region_name="us-east-1").list_functions()["Functions"] == []
    assert boto3.client("sns", region_name="us-east-1").list_topics()["Topics"] == []
    assert boto3.client("ssm", region_name="us-east-1").describe_parameters()["Parameters"] == []
    assert boto3.client("events", region_name="us-east-1").list_rules()["Rules"] == []


@mock_aws
def test_deploy_idempotent_second_run(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts")

    assert deploy.run_deploy(args) == 0
    assert deploy.run_deploy(args) == 0

    assert len(boto3.client("iam", region_name="us-east-1").list_roles()["Roles"]) == 1
    assert len(boto3.client("lambda", region_name="us-east-1").list_functions()["Functions"]) == 1
    assert len(boto3.client("sns", region_name="us-east-1").list_topics()["Topics"]) == 1
    assert len(boto3.client("events", region_name="us-east-1").list_rules()["Rules"]) == 1


@mock_aws
def test_policy_scoped_to_config_arns(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts")

    assert deploy.run_deploy(args) == 0

    iam = boto3.client("iam", region_name="us-east-1")
    doc = iam.get_role_policy(RoleName=deploy.ROLE_NAME, PolicyName=deploy.POLICY_NAME)[
        "PolicyDocument"
    ]
    resources = {stmt["Sid"]: stmt["Resource"] for stmt in doc["Statement"]}

    account_id = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    topic_arn = boto3.client("sns", region_name="us-east-1").list_topics()["Topics"][0]["TopicArn"]

    assert resources["Route53Flatten"] == ["arn:aws:route53:::hostedzone/Z123EXAMPLE"]
    assert resources["SsmConfig"] == f"arn:aws:ssm:us-east-1:{account_id}:parameter/spf53/config"
    assert resources["SnsAlerts"] == topic_arn
    assert (
        resources["CloudWatchLogs"]
        == f"arn:aws:logs:us-east-1:{account_id}:log-group:/aws/lambda/spf53:*"
    )


@mock_aws
def test_create_topic_injects_arn_into_pushed_config(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)  # no sns_topic_arn in the file
    args = _make_args(config_path, create_topic="spf53-alerts")

    assert deploy.run_deploy(args) == 0

    pushed_text = boto3.client("ssm", region_name="us-east-1").get_parameter(Name="/spf53/config")[
        "Parameter"
    ]["Value"]
    pushed_data = yaml.safe_load(pushed_text)
    topic_arn = boto3.client("sns", region_name="us-east-1").list_topics()["Topics"][0]["TopicArn"]

    assert pushed_data["sns_topic_arn"] == topic_arn


@mock_aws
def test_existing_sns_topic_arn_in_config_is_not_overwritten(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        SAMPLE_CONFIG + "sns_topic_arn: arn:aws:sns:us-east-1:123456789012:existing-topic\n",
    )
    args = _make_args(config_path)  # no --create-topic

    assert deploy.run_deploy(args) == 0

    pushed_text = boto3.client("ssm", region_name="us-east-1").get_parameter(Name="/spf53/config")[
        "Parameter"
    ]["Value"]
    pushed_data = yaml.safe_load(pushed_text)

    assert pushed_data["sns_topic_arn"] == "arn:aws:sns:us-east-1:123456789012:existing-topic"
    assert boto3.client("sns", region_name="us-east-1").list_topics()["Topics"] == []


def test_missing_config_file_returns_error(tmp_path: Path) -> None:
    args = _make_args(tmp_path / "does-not-exist.yaml")

    assert deploy.run_deploy(args) == 1
