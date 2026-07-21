"""Tests for spf53.notify."""

from __future__ import annotations

import json
import logging
from unittest import mock

import boto3
import pytest
from moto import mock_aws

from spf53 import notify


def test_publish_noop_on_none_topic() -> None:
    with mock.patch("boto3.client") as mock_client:
        notify.publish(None, "subject", "message")
    mock_client.assert_not_called()


@mock_aws
def test_publish_delivers_subject_and_message() -> None:
    sns = boto3.client("sns", region_name="us-east-1")
    sqs = boto3.client("sqs", region_name="us-east-1")

    topic_arn = sns.create_topic(Name="spf53-alerts")["TopicArn"]
    queue_url = sqs.create_queue(QueueName="spf53-alerts-queue")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    notify.publish(topic_arn, "spf53: changes applied", "example.com: 2 records updated")

    received = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    body = json.loads(received["Messages"][0]["Body"])
    assert body["Subject"] == "spf53: changes applied"
    assert body["Message"] == "example.com: 2 records updated"


@mock_aws
def test_publish_truncates_subject_to_100_chars() -> None:
    sns = boto3.client("sns", region_name="us-east-1")
    sqs = boto3.client("sqs", region_name="us-east-1")

    topic_arn = sns.create_topic(Name="spf53-alerts")["TopicArn"]
    queue_url = sqs.create_queue(QueueName="spf53-alerts-queue")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    long_subject = "x" * 150
    notify.publish(topic_arn, long_subject, "message")

    received = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    body = json.loads(received["Messages"][0]["Body"])
    assert body["Subject"] == "x" * 100
    assert len(body["Subject"]) == 100


@mock_aws
def test_publish_swallows_errors_on_bad_topic_arn(caplog: pytest.LogCaptureFixture) -> None:
    bad_arn = "arn:aws:sns:us-east-1:123456789012:does-not-exist"

    with caplog.at_level(logging.ERROR):
        notify.publish(bad_arn, "subject", "message")

    assert "Failed to publish" in caplog.text
