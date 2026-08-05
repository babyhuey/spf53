"""AWS Lambda entry point for the scheduled spf53 run."""

from __future__ import annotations

import logging
import os

from spf53 import core, ssm

logger = logging.getLogger(__name__)

# The Lambda runtime leaves the root logger at WARNING, so INFO records from
# this package are dropped unless the package logger opts in explicitly.
logging.getLogger("spf53").setLevel(logging.INFO)


def lambda_handler(event: dict, context: object) -> dict:
    param_name = os.environ.get("SPF53_PARAM", ssm.DEFAULT_PARAM)
    cfg = ssm.load_config_ssm(param_name)
    result = core.apply(cfg, force=False)

    changed = [p.domain for p in result.plans if p.has_changes and p.guard.ok]
    refused = [p.domain for p in result.plans if p.has_changes and not p.guard.ok]
    errors = list(result.errors)

    response = {"changed": changed, "refused": refused, "errors": errors}

    logger.info(
        "spf53 run: %d domain(s) planned, changed=%s, refused=%s, errors=%d",
        len(result.plans),
        ",".join(changed) or "none",
        ",".join(refused) or "none",
        len(errors),
    )
    if refused:
        logger.warning("spf53 refused to apply changes for: %s", ", ".join(refused))

    if errors:
        raise RuntimeError(f"spf53: {len(errors)} domain(s) had errors: {'; '.join(errors)}")

    return response
