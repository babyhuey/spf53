"""Idempotent bootstrap that deploys spf53 as a scheduled Lambda function.

Called from `spf53 deploy`. Every step is create-or-update and safe to
re-run: SNS topic (optional), SSM config push, IAM role + inline policy,
Lambda deployment package + function, EventBridge schedule.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
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

import spf53
from spf53.config import ConfigError, Spf53Config, parse_config
from spf53.ssm import DEFAULT_PARAM, put_config_ssm

logger = logging.getLogger(__name__)

INVOKE_STATEMENT_ID = "spf53-schedule-permission"
RUNTIME = "python3.13"
RUNTIME_PYTHON_VERSION = RUNTIME.removeprefix("python")
RUNTIME_PLATFORM = "manylinux2014_x86_64"
HANDLER = "spf53.lambda_handler.lambda_handler"
MEMORY_MB = 256
TIMEOUT_S = 60
CREATE_RETRY_ATTEMPTS = 6
CREATE_RETRY_DELAY_S = 5


class MissingPipError(RuntimeError):
    """Raised when the running interpreter has no importable pip module.

    Environments created by `uv tool install spf53` ship an isolated tool
    venv with no pip at all, so the `python -m pip install --target ...`
    call this module relies on to build the Lambda dependency bundle would
    otherwise fail with a confusing subprocess traceback.
    """


class PermissionVerificationError(RuntimeError):
    """Raised when _invoke_permission_present can't tell whether the
    EventBridge invoke permission is actually present, because get_policy
    itself was denied.

    add_permission raising ResourceConflictException is the expected,
    common path on every redeploy (see _ensure_schedule): it fires both for
    a harmless duplicate StatementId and for the permission never having
    been granted, and get_policy is how those are told apart. If get_policy
    is itself denied, that ambiguity can't be resolved at all -- this must
    surface as a clear, actionable failure naming the missing
    lambda:GetPolicy permission, rather than either a confusing raw
    botocore error or (worse) silently assuming success.
    """


def _pip_is_available() -> bool:
    return importlib.util.find_spec("pip") is not None


def _require_pip() -> None:
    if not _pip_is_available():
        raise MissingPipError(
            "no pip module found in this Python environment; spf53 deploy needs pip "
            "to build the Lambda dependency bundle. Run it from an environment with "
            "pip installed -- e.g. `pip install spf53` instead of `uv tool install "
            "spf53`, or `uv tool install spf53 --with pip`."
        )


def _validate_schedule_expression(schedule: str) -> None:
    """Fail fast on an obviously malformed --schedule value.

    This is a basic shape check (starts with rate(/cron( and has a closing
    paren), not a full EventBridge grammar validator -- events.put_rule
    still does the authoritative validation. Without even this much, a
    schedule that's missing entirely or clearly not an EventBridge
    expression only surfaces as a failure at the very last AWS mutation in
    the deploy sequence, after SSM, IAM, and the Lambda function/code have
    all already been created or updated.
    """
    if not (schedule.startswith(("rate(", "cron(")) and schedule.endswith(")")):
        raise ValueError(
            f"--schedule {schedule!r} doesn't look like a valid EventBridge schedule "
            "expression; expected rate(...) or cron(...)"
        )


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


def _default_param_name(function_name: str) -> str:
    # The default function name ("spf53") keeps the historical flat SSM
    # path so existing single-deployment users see no change. Any other
    # function name gets its own derived path instead -- without this, two
    # independently-named deployments left at the default --param-name
    # would silently share (and clobber) the same SSM parameter.
    if function_name == "spf53":
        return DEFAULT_PARAM
    return f"/spf53/{function_name}/config"


def run_deploy(args: argparse.Namespace) -> int:
    """Run the deploy bootstrap. Returns a process exit code."""
    try:
        yaml_text = Path(args.config).read_text()
        cfg = parse_config(yaml_text)
        _role_name(args.function_name)
        _policy_name(args.function_name)
        _rule_name(args.function_name)
        _target_id(args.function_name)
        _validate_schedule_expression(args.schedule)
        _require_pip()
    except (ConfigError, OSError, ValueError, MissingPipError) as exc:
        print(f"spf53 deploy: {exc}", file=sys.stderr)
        return 1

    if args.param_name is None:
        args.param_name = _default_param_name(args.function_name)

    if args.dry_run:
        _print_plan(args, cfg)
        return 0

    try:
        session = boto3.Session(region_name=args.region)

        new_topic_arn = _ensure_sns_topic(session, args.create_topic)
        if new_topic_arn:
            yaml_text = _inject_topic_arn(yaml_text, new_topic_arn)
            topic_arn = new_topic_arn
            # The injected ARN only lives in the config pushed to SSM this
            # run -- the user's local config file on disk is never touched.
            # Without this, the next `spf53 deploy` run without
            # --create-topic pushes a config with no sns_topic_arn, silently
            # dropping SNS alerting from the deployed Lambda's IAM policy.
            print(
                f"add `sns_topic_arn: {new_topic_arn}` to {args.config} so future "
                "deploys without --create-topic don't drop SNS alerting"
            )
        else:
            topic_arn = cfg.sns_topic_arn

        put_config_ssm(yaml_text, param_name=args.param_name, region=args.region)
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
    except MissingPipError as exc:
        print(f"spf53 deploy: {exc}", file=sys.stderr)
        return 1
    except PermissionVerificationError as exc:
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
    # SSM allows parameter names with or without a leading slash; normalize
    # so the ARN always gets the "parameter/" separator regardless of which
    # form param_name is in -- without this, a non-slash name like
    # "myconfig" glues onto "parameter" with no separator, matching no real
    # resource.
    param_arn = f"arn:aws:ssm:{region}:{account_id}:parameter/{param_name.lstrip('/')}"
    # logs:CreateLogGroup is evaluated against the log group's own ARN with
    # no trailing colon or stream wildcard, while CreateLogStream/PutLogEvents
    # need the ":*" stream-wildcard suffix. IAM resource matching requires
    # the pattern's literal characters (including that trailing colon) to
    # actually be present in the evaluated resource string, so a policy
    # scoped only to the ":*"-suffixed ARN never grants CreateLogGroup.
    log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:/aws/lambda/{function_name}"
    log_stream_arn = f"{log_group_arn}:*"

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
            "Sid": "CloudWatchLogsCreateGroup",
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": log_group_arn,
        },
        {
            "Sid": "CloudWatchLogsStream",
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": log_stream_arn,
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
    provided by the Lambda runtime and is intentionally excluded. The two
    runtime deps are pinned to the versions installed in the current
    environment (rather than left to float to whatever's newest on PyPI) so
    the zip matches what was actually tested. The pip install is further
    pinned to the Lambda runtime's actual target platform and Python
    version (--platform/--python-version/--only-binary=:all:) rather than
    whatever platform and interpreter `spf53 deploy` happens to run under:
    without that, a dependency with a compiled/platform-specific wheel
    built for the deploy machine (e.g. deploying from a Mac) could get
    bundled in a form Lambda can't execute -- this currently only "works"
    for pyyaml because it has a pure-Python fallback when its C extension
    fails to import. Raises MissingPipError up front if the running
    interpreter has no pip module at all (e.g. a `uv tool install` tool
    venv), rather than letting that surface as an opaque subprocess
    failure. spf53 itself is bundled by copying files directly rather than
    a `pip install <path>` of a reverse-engineered repo root: that only
    worked for editable dev installs, where __file__ happens to resolve
    under a checkout with a pyproject.toml three parents up; under a real
    `pip install spf53` wheel install, __file__ resolves under
    site-packages, which has no pyproject.toml, and pip install fails. The
    package's .py files are located via spf53.__file__ (always correct,
    editable or wheel), and its .dist-info directory is located via
    importlib.metadata (always physically present in site-packages) and
    copied alongside so importlib.metadata.version("spf53") still resolves
    correctly at runtime inside the deployed Lambda.
    """
    _require_pip()

    pinned_deps = [
        f"dnspython=={importlib.metadata.version('dnspython')}",
        f"pyyaml=={importlib.metadata.version('pyyaml')}",
    ]
    package_dir = Path(spf53.__file__).resolve().parent
    dist = importlib.metadata.distribution("spf53")

    with tempfile.TemporaryDirectory() as build_dir:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--target",
                build_dir,
                "--platform",
                RUNTIME_PLATFORM,
                "--python-version",
                RUNTIME_PYTHON_VERSION,
                "--only-binary=:all:",
                *pinned_deps,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        build_dir_path = Path(build_dir)
        dest_package_dir = build_dir_path / "spf53"
        for src_path in package_dir.rglob("*.py"):
            if "__pycache__" in src_path.parts:
                continue
            dest_path = dest_package_dir / src_path.relative_to(package_dir)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)

        for file in dist.files or []:
            if file.parts[0].endswith(".dist-info"):
                dest_path = build_dir_path / str(file)
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dist.locate_file(file), dest_path)

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(Path(build_dir).rglob("*")):
                if not path.is_file():
                    continue
                # zf.write() copies the source file's on-disk Unix mode into
                # the zip entry's external_attr. Files staged by `pip install
                # --target` and shutil.copy2 inherit whatever mode the deploy
                # machine's umask/source files happen to have -- under a
                # restrictive umask (e.g. 077, common on hardened
                # workstations) that can produce a zip Lambda's execution
                # environment can't read, failing every invocation with
                # Runtime.ImportModuleError. Build the ZipInfo explicitly and
                # normalize to 0o644 (nothing here needs to be executable) so
                # the zip's permissions never depend on the deploy machine.
                zip_info = zipfile.ZipInfo.from_file(path, path.relative_to(build_dir))
                zip_info.compress_type = zipfile.ZIP_DEFLATED
                zip_info.external_attr = 0o644 << 16
                zip_info.create_system = 3  # Unix, so external_attr's mode bits are honored
                zf.writestr(zip_info, path.read_bytes())
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


def _wait_for_lambda_state(lam: BaseClient, function_name: str, waiter_name: str) -> None:
    """Wait out an in-progress Lambda state transition before the next
    mutating call.

    On real AWS, create_function leaves Configuration.State=Pending, and
    update_function_code/update_function_configuration leave
    Configuration.LastUpdateStatus=InProgress, for a few seconds; a mutating
    call made during either window raises ResourceConflictException. Callers
    must pass the waiter matching what they just did: "function_active_v2"
    (polls Configuration.State, succeeds on Active) after _create_function,
    or "function_updated_v2" (polls Configuration.LastUpdateStatus, succeeds
    on Successful) after an update call -- per AWS's own waiter
    descriptions, each "should be used after" its respective operation, and
    using the wrong one only "works" by coincidence rather than by
    documented contract. moto applies changes synchronously, so this waiter
    no-ops under test. If the waiter itself misbehaves (missing, or never
    observes a terminal status), that's logged and swallowed rather than
    failing the deploy.
    """
    try:
        lam.get_waiter(waiter_name).wait(FunctionName=function_name)
    except (WaiterError, ValueError, ClientError, BotoCoreError) as exc:
        logger.info("waiter for %s did not confirm completion: %s", function_name, exc)


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
        _wait_for_lambda_state(lam, function_name, "function_updated_v2")
        response = lam.update_function_configuration(
            FunctionName=function_name,
            Runtime=RUNTIME,
            Role=role_arn,
            Handler=HANDLER,
            Timeout=TIMEOUT_S,
            MemorySize=MEMORY_MB,
            Environment=env,
        )
        # Like update_function_code above, this is itself async -- without
        # waiting here too, _ensure_schedule's add_permission call can land
        # while the function is still "Updating" and get a
        # ResourceConflictException for THAT reason, which the caller
        # currently (mis)treats as "permission already present" and silently
        # never grants it.
        _wait_for_lambda_state(lam, function_name, "function_updated_v2")
        print(f"updated Lambda function {function_name}")
    else:
        response = _create_function(lam, function_name, role_arn, zip_bytes, env)
        _wait_for_lambda_state(lam, function_name, "function_active_v2")
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
        # ResourceConflictException fires for two different reasons: a
        # genuine duplicate StatementId (expected on redeploy, harmless) or
        # the function still being Pending/Updating when add_permission was
        # called, in which case the permission was never actually granted.
        # Verify which one actually happened rather than trusting the error
        # code's likely-but-unproven meaning -- the alternative is a
        # schedule that's wired up but never actually invokes the function,
        # with no signal until someone notices missed runs.
        if not _invoke_permission_present(lam, function_name):
            raise
        print(f"EventBridge invoke permission on {function_name} already present")


def _invoke_permission_present(lam: BaseClient, function_name: str) -> bool:
    try:
        policy = json.loads(lam.get_policy(FunctionName=function_name)["Policy"])
    except lam.exceptions.ResourceNotFoundException:
        # No policy exists at all yet, so the permission definitely was
        # never granted.
        return False
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessDeniedException":
            raise
        raise PermissionVerificationError(
            "spf53 deploy couldn't verify the EventBridge invoke permission on "
            f"{function_name!r}: lambda:GetPolicy was denied. lambda:GetPolicy is "
            "now a required deploy permission -- see the IAM permissions section "
            "of the README -- add it to the deploy credentials and re-run."
        ) from exc
    return any(stmt.get("Sid") == INVOKE_STATEMENT_ID for stmt in policy.get("Statement", []))
