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

SAMPLE_CONFIG_B = """\
domains:
  - name: example.org
    hosted_zone_id: Z456OTHER
    includes:
      - amazonses.com
"""


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
    doc = iam.get_role_policy(
        RoleName=deploy._role_name("spf53"), PolicyName=deploy._policy_name("spf53")
    )["PolicyDocument"]
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
def test_ssm_arn_normalized_for_param_name_without_leading_slash(tmp_path: Path) -> None:
    """SSM allows parameter names without a leading slash; the built ARN must
    still get a "parameter/" separator, or it names no real resource and the
    Lambda gets AccessDenied on ssm:GetParameter at runtime."""
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts", param_name="spf53config")

    assert deploy.run_deploy(args) == 0

    iam = boto3.client("iam", region_name="us-east-1")
    doc = iam.get_role_policy(
        RoleName=deploy._role_name("spf53"), PolicyName=deploy._policy_name("spf53")
    )["PolicyDocument"]
    resources = {stmt["Sid"]: stmt["Resource"] for stmt in doc["Statement"]}

    account_id = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    assert resources["SsmConfig"] == f"arn:aws:ssm:us-east-1:{account_id}:parameter/spf53config"


@mock_aws
def test_distinct_function_names_get_independent_iam_role_policies(tmp_path: Path) -> None:
    """A second `--function-name` deploy must not overwrite the first
    deployment's inline IAM policy: each function name gets its own role and
    policy name, so neither deploy's Route53/logs permissions are lost."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    config_a = _write_config(tmp_path / "a", SAMPLE_CONFIG)
    config_b = _write_config(tmp_path / "b", SAMPLE_CONFIG_B)
    args_a = _make_args(config_a, function_name="spf53-a", param_name="/spf53/config-a")
    args_b = _make_args(config_b, function_name="spf53-b", param_name="/spf53/config-b")

    assert deploy.run_deploy(args_a) == 0
    assert deploy.run_deploy(args_b) == 0

    iam = boto3.client("iam", region_name="us-east-1")
    account_id = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]

    doc_a = iam.get_role_policy(
        RoleName=deploy._role_name("spf53-a"), PolicyName=deploy._policy_name("spf53-a")
    )["PolicyDocument"]
    doc_b = iam.get_role_policy(
        RoleName=deploy._role_name("spf53-b"), PolicyName=deploy._policy_name("spf53-b")
    )["PolicyDocument"]
    resources_a = {stmt["Sid"]: stmt["Resource"] for stmt in doc_a["Statement"]}
    resources_b = {stmt["Sid"]: stmt["Resource"] for stmt in doc_b["Statement"]}

    assert resources_a["Route53Flatten"] == ["arn:aws:route53:::hostedzone/Z123EXAMPLE"]
    assert (
        resources_a["CloudWatchLogs"]
        == f"arn:aws:logs:us-east-1:{account_id}:log-group:/aws/lambda/spf53-a:*"
    )
    assert resources_b["Route53Flatten"] == ["arn:aws:route53:::hostedzone/Z456OTHER"]
    assert (
        resources_b["CloudWatchLogs"]
        == f"arn:aws:logs:us-east-1:{account_id}:log-group:/aws/lambda/spf53-b:*"
    )
    assert len(iam.list_roles()["Roles"]) == 2


@mock_aws
def test_distinct_function_names_get_independent_schedules(tmp_path: Path) -> None:
    """A second `--function-name` deploy must not retarget the first
    deployment's EventBridge rule: each function name gets its own rule and
    target ID, so neither schedule stops invoking its own function."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    config_a = _write_config(tmp_path / "a", SAMPLE_CONFIG)
    config_b = _write_config(tmp_path / "b", SAMPLE_CONFIG_B)
    args_a = _make_args(config_a, function_name="spf53-a", param_name="/spf53/config-a")
    args_b = _make_args(config_b, function_name="spf53-b", param_name="/spf53/config-b")

    assert deploy.run_deploy(args_a) == 0
    assert deploy.run_deploy(args_b) == 0

    lam = boto3.client("lambda", region_name="us-east-1")
    arn_a = lam.get_function(FunctionName="spf53-a")["Configuration"]["FunctionArn"]
    arn_b = lam.get_function(FunctionName="spf53-b")["Configuration"]["FunctionArn"]

    events = boto3.client("events", region_name="us-east-1")
    targets_a = events.list_targets_by_rule(Rule=deploy._rule_name("spf53-a"))["Targets"]
    targets_b = events.list_targets_by_rule(Rule=deploy._rule_name("spf53-b"))["Targets"]

    assert targets_a == [{"Id": deploy._target_id("spf53-a"), "Arn": arn_a}]
    assert targets_b == [{"Id": deploy._target_id("spf53-b"), "Arn": arn_b}]
    assert len(events.list_rules()["Rules"]) == 2


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


@mock_aws
def test_create_topic_overrides_existing_sns_topic_arn_in_config(tmp_path: Path) -> None:
    """--create-topic must win over a pre-existing (different) sns_topic_arn:
    the new topic is what the operator explicitly asked for, so it must be
    the one injected into the pushed config and the one the IAM role is
    scoped to publish to -- not silently orphaned in favor of the old ARN."""
    old_topic_arn = "arn:aws:sns:us-east-1:123456789012:old-topic"
    config_path = _write_config(
        tmp_path,
        SAMPLE_CONFIG + f"sns_topic_arn: {old_topic_arn}\n",
    )
    args = _make_args(config_path, create_topic="new-topic-name")

    assert deploy.run_deploy(args) == 0

    sns = boto3.client("sns", region_name="us-east-1")
    topics = sns.list_topics()["Topics"]
    assert len(topics) == 1
    new_topic_arn = topics[0]["TopicArn"]
    assert new_topic_arn != old_topic_arn
    assert new_topic_arn.endswith(":new-topic-name")

    pushed_text = boto3.client("ssm", region_name="us-east-1").get_parameter(Name="/spf53/config")[
        "Parameter"
    ]["Value"]
    pushed_data = yaml.safe_load(pushed_text)
    assert pushed_data["sns_topic_arn"] == new_topic_arn

    iam = boto3.client("iam", region_name="us-east-1")
    doc = iam.get_role_policy(
        RoleName=deploy._role_name("spf53"), PolicyName=deploy._policy_name("spf53")
    )["PolicyDocument"]
    resources = {stmt["Sid"]: stmt["Resource"] for stmt in doc["Statement"]}
    assert resources["SnsAlerts"] == new_topic_arn


@mock_aws
def test_put_config_ssm_called_with_deploy_region(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_deploy must forward --region into put_config_ssm: every other AWS
    call in run_deploy goes through the region-scoped boto3.Session, but the
    SSM push previously went through ssm.py's own region-blind client cache
    and silently landed in the ambient default region instead of --region.
    Uses eu-west-1 (not conftest.py's us-east-1 default) so a regression
    that drops the region argument can't coincidentally still pass."""
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, region="eu-west-1")

    calls: list[dict[str, object]] = []
    real_put_config_ssm = deploy.put_config_ssm

    def spy_put_config_ssm(yaml_text: str, *, param_name: str, region: str | None = None) -> None:
        calls.append({"param_name": param_name, "region": region})
        real_put_config_ssm(yaml_text, param_name=param_name, region=region)

    monkeypatch.setattr(deploy, "put_config_ssm", spy_put_config_ssm)

    assert deploy.run_deploy(args) == 0
    assert calls == [{"param_name": "/spf53/config", "region": "eu-west-1"}]


@mock_aws
def test_deploy_writes_ssm_param_in_requested_region(tmp_path: Path) -> None:
    """End-to-end companion to the spy test above: the pushed config must
    actually be readable back from eu-west-1, and absent from the ambient
    default region (us-east-1) it would have landed in before the fix."""
    from botocore.exceptions import ClientError

    config_path = _write_config(tmp_path)
    args = _make_args(config_path, region="eu-west-1")

    assert deploy.run_deploy(args) == 0

    eu_param = boto3.client("ssm", region_name="eu-west-1").get_parameter(Name="/spf53/config")[
        "Parameter"
    ]
    assert eu_param["Value"]

    with pytest.raises(ClientError):
        boto3.client("ssm", region_name="us-east-1").get_parameter(Name="/spf53/config")


@pytest.mark.parametrize("dry_run", [True, False])
def test_oversized_function_name_returns_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], dry_run: bool
) -> None:
    """An oversized --function-name must fail with a one-line stderr message
    and exit code 1 in both --dry-run and real-apply modes, not an unhandled
    ValueError traceback (_print_plan, called before the AWS-calls try
    block, also derives these names, so both paths need the upfront check)."""
    config_path = _write_config(tmp_path)
    oversized_name = "x" * 60  # "{name}-lambda" is 67 chars, over the 64-char IAM role limit
    args = _make_args(config_path, function_name=oversized_name, dry_run=dry_run)

    result = deploy.run_deploy(args)

    assert result == 1
    err = capsys.readouterr().err
    assert err.strip().startswith("spf53 deploy:")
    assert "IAM role" in err
    assert "Traceback" not in err


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


def test_build_lambda_zip_installs_dist_info_for_version_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """build_lambda_zip must bundle spf53's real .dist-info metadata
    (located via importlib.metadata, copied alongside the raw-copied source
    tree) so importlib.metadata.version("spf53") resolves inside the
    deployed Lambda instead of falling back to __init__.py's "0.0.0-dev".
    Also confirms the spf53/ package still lands at the path HANDLER needs
    to import it from."""
    import importlib.metadata
    import io
    import sys
    import zipfile

    import spf53

    monkeypatch.setattr(deploy, "build_lambda_zip", _REAL_BUILD_LAMBDA_ZIP)

    zip_bytes = deploy.build_lambda_zip()

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        assert "spf53/lambda_handler.py" in zf.namelist()
        extract_dir = tmp_path / "extracted"
        zf.extractall(extract_dir)

    sys.path.insert(0, str(extract_dir))
    importlib.invalidate_caches()
    try:
        assert importlib.metadata.version("spf53") == spf53.__version__
    finally:
        sys.path.remove(str(extract_dir))
        importlib.invalidate_caches()


def test_build_lambda_zip_pins_platform_and_python_version_for_pip_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pip install used to build the dependency bundle must pin
    --platform/--python-version/--only-binary=:all: to the Lambda runtime's
    target, not whatever platform and interpreter `spf53 deploy` happens to
    run under -- otherwise a compiled dependency wheel selected for the
    deploy machine could land in the zip in a form Lambda can't execute."""
    monkeypatch.setattr(deploy, "build_lambda_zip", _REAL_BUILD_LAMBDA_ZIP)

    captured_cmd: list[str] = []

    def recording_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_cmd.extend(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(deploy.subprocess, "run", recording_run)

    deploy.build_lambda_zip()

    assert "--platform" in captured_cmd
    assert captured_cmd[captured_cmd.index("--platform") + 1] == deploy.RUNTIME_PLATFORM
    assert "--python-version" in captured_cmd
    assert captured_cmd[captured_cmd.index("--python-version") + 1] == deploy.RUNTIME_PYTHON_VERSION
    assert "--only-binary=:all:" in captured_cmd


def test_missing_pip_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """`uv tool install spf53` ships an isolated tool venv with no pip module
    at all; build_lambda_zip must fail fast with an actionable MissingPipError
    instead of letting `python -m pip install` blow up with a confusing
    subprocess traceback."""
    monkeypatch.setattr(deploy, "build_lambda_zip", _REAL_BUILD_LAMBDA_ZIP)
    monkeypatch.setattr(deploy, "_pip_is_available", lambda: False)

    with pytest.raises(deploy.MissingPipError, match="pip"):
        deploy.build_lambda_zip()


@mock_aws
def test_missing_pip_during_zip_build_returns_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = _write_config(tmp_path)
    args = _make_args(config_path, create_topic="spf53-alerts")

    monkeypatch.setattr(deploy, "build_lambda_zip", _REAL_BUILD_LAMBDA_ZIP)
    monkeypatch.setattr(deploy, "_pip_is_available", lambda: False)

    result = deploy.run_deploy(args)

    assert result == 1
    err = capsys.readouterr().err
    assert err.strip().startswith("spf53 deploy:")
    assert "pip" in err
    assert "Traceback" not in err


def test_build_lambda_zip_locates_package_via_spf53_dunder_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """build_lambda_zip must locate spf53's source files via
    Path(spf53.__file__).resolve().parent -- which always points at wherever
    the currently-running spf53 package actually lives, editable install or
    wheel install alike -- rather than by counting parent directories up
    from deploy.py's own __file__ to guess a repo root containing
    pyproject.toml. That guess only happens to resolve correctly for an
    editable dev install of this exact repo layout; under a real `pip
    install spf53` wheel install, deploy.py's __file__ resolves under
    site-packages, which has no pyproject.toml, so the old approach fails
    for every real end user. Proven here by pointing spf53.__file__ at a
    throwaway fake package directory: if build_lambda_zip is still deriving
    the source location from spf53.__file__, the fake files show up in the
    zip and the real repo's files (e.g. config.py, never part of the fake
    package) do not. A regression back to the __file__-parent-chain
    repo_root approach would ignore spf53.__file__ entirely, keep bundling
    the real repo's files, and fail these assertions -- since CI always runs
    against an editable install, this is the only test that would catch
    that regression."""
    import io
    import zipfile

    import spf53

    fake_pkg_dir = tmp_path / "fake_site_packages" / "spf53"
    fake_pkg_dir.mkdir(parents=True)
    (fake_pkg_dir / "__init__.py").write_text("__version__ = 'fake-0.0.0'\n")
    (fake_pkg_dir / "lambda_handler.py").write_text("FAKE_MARKER = True\n")

    monkeypatch.setattr(deploy, "build_lambda_zip", _REAL_BUILD_LAMBDA_ZIP)
    monkeypatch.setattr(spf53, "__file__", str(fake_pkg_dir / "__init__.py"))

    zip_bytes = deploy.build_lambda_zip()

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        assert zf.read("spf53/__init__.py").decode() == "__version__ = 'fake-0.0.0'\n"
        assert zf.read("spf53/lambda_handler.py").decode() == "FAKE_MARKER = True\n"
        assert "spf53/config.py" not in zf.namelist()
