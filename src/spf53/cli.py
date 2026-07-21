"""Command-line interface for spf53: plan, apply, deploy."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from spf53 import core, ssm
from spf53.config import Spf53Config, load_config_file


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spf53")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="show pending SPF changes")
    _add_config_args(plan_parser)
    plan_parser.set_defaults(func=_cmd_plan)

    apply_parser = subparsers.add_parser("apply", help="apply pending SPF changes")
    _add_config_args(apply_parser)
    apply_parser.add_argument(
        "--force", action="store_true", help="apply changes even if a guard refuses"
    )
    apply_parser.set_defaults(func=_cmd_apply)

    deploy_parser = subparsers.add_parser("deploy", help="deploy the spf53 Lambda")
    deploy_parser.add_argument("-c", "--config", required=True, metavar="FILE")
    deploy_parser.add_argument("--schedule", default="rate(1 hour)")
    deploy_parser.add_argument("--create-topic", metavar="NAME")
    deploy_parser.add_argument("--param-name", default=ssm.DEFAULT_PARAM)
    deploy_parser.add_argument("--function-name", default="spf53")
    deploy_parser.add_argument("--region")
    deploy_parser.add_argument("--dry-run", action="store_true")
    deploy_parser.set_defaults(func=_cmd_deploy)

    return parser


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--config", metavar="FILE", help="local YAML config file")
    group.add_argument(
        "--ssm-param",
        metavar="NAME",
        help=f"SSM parameter name (default: {ssm.DEFAULT_PARAM})",
    )


def _load_config(args: argparse.Namespace) -> Spf53Config:
    if args.config:
        return load_config_file(args.config)
    return ssm.load_config_ssm(args.ssm_param or ssm.DEFAULT_PARAM)


def _expected_apex_line(p: core.DomainPlan) -> str | None:
    if not p.desired:
        return None
    last_name = f"_spf53-{len(p.desired)}.{p.domain}"
    last_strings = p.desired.get(last_name)
    if not last_strings:
        return None
    policy = "".join(last_strings).split()[-1]
    return f"v=spf1 include:_spf53-1.{p.domain} {policy}"


def _cmd_plan(args: argparse.Namespace) -> int:
    cfg = _load_config(args)
    result = core.plan(cfg)

    for p in result.plans:
        print(f"== {p.domain} ==")
        apex_line = _expected_apex_line(p)
        print(f"expected apex record: {apex_line if apex_line else 'n/a'}")
        cost_note = " (WARNING: exceeds 9-lookup limit)" if p.lookup_cost > 9 else ""
        print(f"lookup cost: {p.lookup_cost}{cost_note}")
        if p.apex_warning:
            print(f"WARNING: {p.apex_warning}")
        if not p.guard.ok:
            print(f"guard: REFUSED - {'; '.join(p.guard.reasons)}")
        if not p.has_changes:
            print("changes: none")
        else:
            print(f"changes: {len(p.upserts)} upsert(s), {len(p.deletes)} delete(s)")
        print(p.summary)
        print()

    for err in result.errors:
        print(f"ERROR: {err}", file=sys.stderr)

    if result.errors:
        return 1
    if any(p.has_changes for p in result.plans):
        return 2
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    cfg = _load_config(args)
    result = core.apply(cfg, force=args.force)

    refused: list[str] = []
    for p in result.plans:
        if not p.has_changes:
            continue
        if not p.guard.ok and not args.force:
            refused.append(p.domain)
            print(f"{p.domain}: refused - {'; '.join(p.guard.reasons)}")
        elif p.domain in result.failed_domains:
            print(f"{p.domain}: failed")
        else:
            print(f"{p.domain}: applied")

    for err in result.errors:
        print(f"ERROR: {err}", file=sys.stderr)

    if result.errors or refused:
        return 1
    return 0


def _cmd_deploy(args: argparse.Namespace) -> int:
    from spf53 import deploy

    result = deploy.run_deploy(args)
    return result if isinstance(result, int) else 0
