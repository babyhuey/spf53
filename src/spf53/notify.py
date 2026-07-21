"""SNS notification helper for spf53."""

from __future__ import annotations

import logging
from typing import Any

from spf53 import _boto

logger = logging.getLogger(__name__)

MAX_SUBJECT_LEN = 100


def _client() -> Any:
    return _boto.get_client("sns")


def publish(topic_arn: str | None, subject: str, message: str) -> None:
    """Publish an SNS notification.

    No-op when `topic_arn` is None. Never raises — a failed notification
    must not fail a successful apply, so boto errors are logged and swallowed.
    """
    if topic_arn is None:
        return

    try:
        _client().publish(
            TopicArn=topic_arn,
            Subject=subject[:MAX_SUBJECT_LEN],
            Message=message,
        )
    except Exception:
        logger.exception("Failed to publish SNS notification to %s", topic_arn)
