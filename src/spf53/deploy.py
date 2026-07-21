"""Idempotent bootstrap that deploys spf53 as a scheduled Lambda function.

Called from `spf53 deploy`. Every step is create-or-update and safe to
re-run: SNS topic (optional), SSM config push, IAM role + inline policy,
Lambda deployment package + function, EventBridge schedule.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import io
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import boto3
import yaml
from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError, WaiterError

from spf53.config import ConfigError, Spf53Config, parse_config
from spf53.ssm import put_config_ssm

logger = logging.getLogger(__name__)

INVOKE_STATEMENT_ID = "spf53-schedule-permission"
RUNTIME = "python3.13"
HANDLER = "spf53.lambda_handler.lambda_handler"
MEMORY_MB = 256
TIMEOUT_S = 60
CREATE_RETRY_ATTEMPTS = 6
CREATE_RETRY_DELAY_S = 5


def _sized_name(name: str, limit: int, resource: str) -> str:
    """Guard against a --function-name that pushes a derived AWS resource
    name past its length limit. Kept as a plain length check rather than
    truncating/hashing since function_name is user-supplied and expected to
    be a reasonable identifier."""
    if len(name) > limit:
        raise ValueError(
            f"--function-name produces {resource} name {name!r} ({len(name)} chars), "
            f"which exceeds the {limit}-char AWS limit"
        )
    return name


def _role_name(function_name: str) -> str:
    # Suffix matches the historical hardcoded ROLE_NAME ("spf53-lambda") so
    # the default function name "spf53" keeps deploying the same role.
    return _sized_name(f"{function_name}-lambda", 64, "IAM role")


def _policy_name(function_name: str) -> str:
    # Suffix matches the historical hardcoded POLICY_NAME.
    return _sized_name(f"{function_name}-lambda-policy", 128, "IAM inline policy")


def _rule_name(function_name: str) -> str:
    # Suffix matches the historical hardcoded RULE_NAME.
    return _sized_name(f"{function_name}-schedule", 64, "EventBridge rule")


def _target_id(function_name: str) -> str:
    # Suffix matches the historical hardcoded TARGET_ID.
    return _sized_name(f"{function_name}-lambda-target", 64, "EventBridge target")


def run_deploy(args: argparse.Namespace) -> int:
    """Run the deploy bootstrap. Returns a process exit code."""
    try:
        yaml_text = Path(args.config).read_text()
        cfg = parse_config(yaml_text)
    except (ConfigError, OSError) as exc:
        print(f"spf53 deploy: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        _print_plan(args, cfg)
        return 0

    try:
        session = boto3.Session(region_name=args.region)

        new_topic_arn = _ensure_sns_topic(session, args.create_topic)
        if new_topic_arn and not cfg.sns_topic_arn:
            yaml_text = _inject_topic_arn(yaml_text, new_topic_arn)
        topic_arn = cfg.sns_topic_arn or new_topic_arn

        put_config_ssm(yaml_text, param_name=args.param_name)
        print(f"pushed config to SSM parameter {args.param_name}")

        account_id = session.client("sts").get_caller_identity()["Account"]
        region = session.region_name

        role_arn = _ensure_iam_role(
            session, cfg, args.param_name, topic_arn, account_id, region, args.function_name
        )
        function_arn = _ensure_lambda_function(
            session, args.function_name, role_arn, args.param_name
        )
        _ensure_schedule(session, args.schedule, args.function_name, function_arn)
    except (ClientError, BotoCoreError) as exc:
        print(f"spf53 deploy: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        stderr_lines = (exc.stderr or "").strip().splitlines()
        detail = stderr_lines[-1] if stderr_lines else str(exc)
        print(f"spf53 deploy: failed to build Lambda package: {detail}", file=sys.stderr)
        return 1

    return 0


def _print_plan(args: argparse.Namespace, cfg: Spf53Config) -> None:
    print("[dry-run] planned actions (no AWS calls made):")
    if args.create_topic:
        print(f"  - create/verify SNS topic {args.create_topic!r}")
    elif cfg.sns_topic_arn:
        print(f"  - use existing SNS topic {cfg.sns_topic_arn}")
    else:
        print("  - no SNS topic configured; alerts disabled")
    print(f"  - push validated config to SSM parameter {args.param_name}")
    zone_ids = sorted({d.hosted_zone_id for d in cfg.domains})
    role_name = _role_name(args.function_name)
    print(f"  - create/update IAM role {role_name} scoped to zone(s): {', '.join(zone_ids)}")
    print(
        f"  - build deployment package (dnspython, pyyaml, spf53) "
        f"and create/update Lambda {args.function_name}"
    )
    rule_name = _rule_name(args.function_name)
    print(
        f"  - create/update EventBridge rule {rule_name} ({args.schedule}) -> {args.function_name}"
    )


def _inject_topic_arn(yaml_text: str, topic_arn: str) -> str:
    data = yaml.safe_load(yaml_text) or {}
    data["sns_topic_arn"] = topic_arn
    return yaml.safe_dump(data, sort_keys=False)


def _ensure_sns_topic(session: boto3.Session, topic_name: str | None) -> str | None:
    if not topic_name:
        return None
    sns = session.client("sns")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]  # create_topic is idempotent by name
    print(f"SNS topic {topic_name!r} ready: {topic_arn}")
    return topic_arn


def _trust_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _inline_policy(
    cfg: Spf53Config,
    param_name: str,
    topic_arn: str | None,
    account_id: str,
    region: str,
    function_name: str,
) -> dict[str, Any]:
    zone_arns = sorted({f"arn:aws:route53:::hostedzone/{d.hosted_zone_id}" for d in cfg.domains})
    param_arn = f"arn:aws:ssm:{region}:{account_id}:parameter{param_name}"
    log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:/aws/lambda/{function_name}:*"

    statements: list[dict[str, Any]] = [
        {
            "Sid": "Route53Flatten",
            "Effect": "Allow",
            "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
            "Resource": zone_arns,
        },
        {
            "Sid": "SsmConfig",
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": param_arn,
        },
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": log_group_arn,
        },
    ]
    if topic_arn:
        statements.append(
            {"Sid": "SnsAlerts", "Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}
        )
    return {"Version": "2012-10-17", "Statement": statements}


def _ensure_iam_role(
    session: boto3.Session,
    cfg: Spf53Config,
    param_name: str,
    topic_arn: str | None,
    account_id: str,
    region: str,
    function_name: str,
) -> str:
    role_name = _role_name(function_name)
    policy_name = _policy_name(function_name)
    iam = session.client("iam")
    trust_doc = json.dumps(_trust_policy())
    try:
        role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc)["Role"][
            "Arn"
        ]
        print(f"created IAM role {role_name}")
    except iam.exceptions.EntityAlreadyExistsException:
        iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=trust_doc)
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
        print(f"IAM role {role_name} already exists, trust policy refreshed")

    policy_doc = json.dumps(
        _inline_policy(cfg, param_name, topic_arn, account_id, region, function_name)
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    print(f"applied inline policy {policy_name}")
    return role_arn


def build_lambda_zip() -> bytes:
    """Build the Lambda deployment package.

    Bundles dnspython, pyyaml, and the spf53 package itself. boto3 is
    provided by the Lambda runtime and is intentionally excluded. Both deps
    are pinned to the versions installed in the current environment (rather
    than left to float to whatever's newest on PyPI) so the zip matches what
    was actually tested; both work without compiled extensions (pyyaml falls
    back to its pure-Python implementation), so this stays a plain
    pip install with no cross-platform build flags needed.
    """
    pkg_dir = Path(__file__).resolve().parent
    pinned_deps = [
        f"dnspython=={importlib.metadata.version('dnspython')}",
        f"pyyaml=={importlib.metadata.version('pyyaml')}",
    ]
    with tempfile.TemporaryDirectory() as build_dir:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--target", build_dir, *pinned_deps],
            check=True,
            capture_output=True,
            text=True,
        )
        shutil.copytree(
            pkg_dir, Path(build_dir) / "spf53", ignore=shutil.ignore_patterns("__pycache__")
        )

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(Path(build_dir).rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(build_dir))
        return buffer.getvalue()


def _create_function(
    lam: BaseClient, function_name: str, role_arn: str, zip_bytes: bytes, env: dict[str, Any]
) -> dict[str, Any]:
    # IAM role propagation can lag a few seconds behind create_role returning.
    for attempt in range(1, CREATE_RETRY_ATTEMPTS + 1):
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime=RUNTIME,
                Role=role_arn,
                Handler=HANDLER,
                Code={"ZipFile": zip_bytes},
                Timeout=TIMEOUT_S,
                MemorySize=MEMORY_MB,
                Environment=env,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterValueException" or attempt == CREATE_RETRY_ATTEMPTS:
                raise
            time.sleep(CREATE_RETRY_DELAY_S)
    raise AssertionError("unreachable")  # pragma: no cover


def _wait_for_update(lam: BaseClient, function_name: str) -> None:
    """Wait out an in-progress Lambda update before the next mutating call.

    On real AWS, create_function/update_function_code leave the function
    with LastUpdateStatus=InProgress for a few seconds; a mutating call made
    during that window raises ResourceConflictException. moto applies
    updates synchronously, so this waiter no-ops under test. If the waiter
    itself misbehaves (missing, or never observes a terminal status), that's
    logged and swallowed rather than failing the deploy.
    """
    try:
        lam.get_waiter("function_updated_v2").wait(FunctionName=function_name)
    except (WaiterError, ValueError, ClientError, BotoCoreError) as exc:
        logger.info("waiter for %s did not confirm update completion: %s", function_name, exc)


def _ensure_lambda_function(
    session: boto3.Session, function_name: str, role_arn: str, param_name: str
) -> str:
    lam = session.client("lambda")
    env = {"Variables": {"SPF53_PARAM": param_name}}

    try:
        lam.get_function(FunctionName=function_name)
        exists = True
    except lam.exceptions.ResourceNotFoundException:
        exists = False

    zip_bytes = build_lambda_zip()

    if exists:
        lam.update_function_code(FunctionName=function_name, ZipFile=zip_bytes)
        _wait_for_update(lam, function_name)
        response = lam.update_function_configuration(
            FunctionName=function_name,
            Runtime=RUNTIME,
            Role=role_arn,
            Handler=HANDLER,
            Timeout=TIMEOUT_S,
            MemorySize=MEMORY_MB,
            Environment=env,
        )
        print(f"updated Lambda function {function_name}")
    else:
        response = _create_function(lam, function_name, role_arn, zip_bytes, env)
        _wait_for_update(lam, function_name)
        print(f"created Lambda function {function_name}")

    return response["FunctionArn"]


def _ensure_schedule(
    session: boto3.Session, schedule: str, function_name: str, function_arn: str
) -> None:
    rule_name = _rule_name(function_name)
    target_id = _target_id(function_name)
    events = session.client("events")
    rule_arn = events.put_rule(Name=rule_name, ScheduleExpression=schedule, State="ENABLED")[
        "RuleArn"
    ]
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": function_arn}])
    print(f"scheduled rule {rule_name} ({schedule}) targets {function_name}")

    lam = session.client("lambda")
    try:
        lam.add_permission(
            FunctionName=function_name,
            StatementId=INVOKE_STATEMENT_ID,
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=rule_arn,
        )
        print(f"granted EventBridge invoke permission on {function_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise
        print(f"EventBridge invoke permission on {function_name} already present")
