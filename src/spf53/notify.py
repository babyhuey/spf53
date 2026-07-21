"""SNS notification helper for spf53."""

from __future__ import annotations

import logging

from spf53 import _boto

logger = logging.getLogger(__name__)

MAX_SUBJECT_LEN = 100


def _region_from_arn(arn: str) -> str | None:
    """Extract the region from an ARN (arn:PARTITION:SERVICE:REGION:ACCOUNT:RESOURCE).

    Returns None if `arn` doesn't parse as expected, so callers fall back to
    the ambient default region instead of raising.
    """
    parts = arn.split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    return parts[3]


def publish(topic_arn: str | None, subject: str, message: str) -> None:
    """Publish an SNS notification.

    No-op when `topic_arn` is None. Never raises — a failed notification
    must not fail a successful apply, so boto errors are logged and swallowed.
    """
    if topic_arn is None:
        return

    try:
        client = _boto.get_client("sns", region=_region_from_arn(topic_arn))
        client.publish(
            TopicArn=topic_arn,
            Subject=subject[:MAX_SUBJECT_LEN],
            Message=message,
        )
    except Exception:
        logger.exception("Failed to publish SNS notification to %s", topic_arn)
