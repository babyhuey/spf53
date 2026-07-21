"""Unit tests for spf53.deploy."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import boto3
import pytest
import yaml
from moto import mock_aws

from spf53 import deploy

_REAL_BUILD_LAMBDA_ZIP = deploy.build_lambda_zip

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
        "schedule": "rate(1 hour)",
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
def test_create_topic_injection_does_not_reparse_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injecting the freshly-created topic ARN into yaml_text must not trigger
    an extra parse_config call: only the initial parse at the top of
    run_deploy and the validating parse inside put_config_ssm should occur."""
    from spf53 import config, ssm

    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts")

    real_parse_config = config.parse_config
    calls: list[str] = []

    def counting_parse_config(yaml_text: str) -> config.Spf53Config:
        calls.append(yaml_text)
        return real_parse_config(yaml_text)

    monkeypatch.setattr(deploy, "parse_config", counting_parse_config)
    monkeypatch.setattr(ssm, "parse_config", counting_parse_config)

    assert deploy.run_deploy(args) == 0
    assert len(calls) == 2


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


@mock_aws
def test_update_path_waits_between_code_and_config_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from botocore.client import BaseClient

    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts")

    # First run creates the function; only the second run hits the update path.
    assert deploy.run_deploy(args) == 0

    calls: list[str] = []

    original_wait = deploy._wait_for_update

    def recording_wait(lam: object, function_name: str) -> None:
        calls.append("wait")
        original_wait(lam, function_name)

    monkeypatch.setattr(deploy, "_wait_for_update", recording_wait)

    original_make_api_call = BaseClient._make_api_call

    def recording_make_api_call(
        self: BaseClient, operation_name: str, api_params: object
    ) -> object:
        if operation_name in ("UpdateFunctionCode", "UpdateFunctionConfiguration"):
            calls.append(operation_name)
        return original_make_api_call(self, operation_name, api_params)

    monkeypatch.setattr(BaseClient, "_make_api_call", recording_make_api_call)

    assert deploy.run_deploy(args) == 0

    assert calls == ["UpdateFunctionCode", "wait", "UpdateFunctionConfiguration"]


@mock_aws
def test_wait_for_update_swallows_waiter_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from botocore.exceptions import WaiterError

    lam = boto3.client("lambda", region_name="us-east-1")

    class ExplodingWaiter:
        def wait(self, **kwargs: object) -> None:
            raise WaiterError(name="function_updated_v2", reason="boom", last_response={})

    monkeypatch.setattr(lam, "get_waiter", lambda name: ExplodingWaiter())

    deploy._wait_for_update(lam, "some-function")  # must not raise


@mock_aws
def test_pip_failure_during_zip_build_returns_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts")

    def failing_pip_install(*cmd: object, **kwargs: object) -> None:
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["pip", "install"],
            output="",
            stderr="ERROR: Could not find a version satisfying dnspython==9.9.9\n",
        )

    # stub_zip_build (autouse) replaces build_lambda_zip wholesale; put the
    # real implementation back so its internal subprocess.run call is exercised.
    monkeypatch.setattr(deploy, "build_lambda_zip", _REAL_BUILD_LAMBDA_ZIP)
    monkeypatch.setattr(deploy.subprocess, "run", failing_pip_install)

    result = deploy.run_deploy(args)

    assert result == 1
    err = capsys.readouterr().err
    assert "spf53 deploy: failed to build Lambda package:" in err
    assert "dnspython==9.9.9" in err
    assert "Traceback" not in err
