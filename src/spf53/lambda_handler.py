"""AWS Lambda entry point for the scheduled spf53 run."""

from __future__ import annotations

import os

from spf53 import core, ssm


def lambda_handler(event: dict, context: object) -> dict:
    param_name = os.environ.get("SPF53_PARAM", ssm.DEFAULT_PARAM)
    cfg = ssm.load_config_ssm(param_name)
    result = core.apply(cfg, force=False)

    changed = [p.domain for p in result.plans if p.has_changes and p.guard.ok]
    refused = [p.domain for p in result.plans if p.has_changes and not p.guard.ok]
    errors = list(result.errors)

    response = {"changed": changed, "refused": refused, "errors": errors}

    if errors:
        raise RuntimeError(f"spf53: {len(errors)} domain(s) failed to resolve: {'; '.join(errors)}")

    return response
