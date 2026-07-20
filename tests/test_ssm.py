import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from spf53.config import ConfigError, parse_config
from spf53.ssm import DEFAULT_PARAM, load_config_ssm, put_config_ssm

VALID_YAML = """
domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    includes:
      - _spf.google.com
"""

OTHER_VALID_YAML = """
domains:
  - name: example.org
    hosted_zone_id: Z456OTHER
    includes:
      - amazonses.com
"""

INVALID_YAML = """
domains:
  - name: example.com
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


@mock_aws
def test_put_then_load_round_trip() -> None:
    put_config_ssm(VALID_YAML)
    cfg = load_config_ssm()
    assert cfg == parse_config(VALID_YAML)


@mock_aws
def test_put_config_ssm_invalid_yaml_raises_and_does_not_write() -> None:
    with pytest.raises(ConfigError):
        put_config_ssm(INVALID_YAML)

    client = boto3.client("ssm", region_name="us-east-1")
    with pytest.raises(ClientError):
        client.get_parameter(Name=DEFAULT_PARAM)


@mock_aws
def test_custom_param_name() -> None:
    put_config_ssm(VALID_YAML, param_name="/custom/spf53")
    cfg = load_config_ssm(param_name="/custom/spf53")
    assert cfg.domains[0].name == "example.com"

    client = boto3.client("ssm", region_name="us-east-1")
    with pytest.raises(ClientError):
        client.get_parameter(Name=DEFAULT_PARAM)


@mock_aws
def test_put_config_ssm_overwrites_existing_param() -> None:
    put_config_ssm(VALID_YAML)
    put_config_ssm(OTHER_VALID_YAML)

    cfg = load_config_ssm()
    assert cfg.domains[0].name == "example.org"


@mock_aws
def test_put_config_ssm_stores_as_string_type() -> None:
    put_config_ssm(VALID_YAML)

    client = boto3.client("ssm", region_name="us-east-1")
    param = client.get_parameter(Name=DEFAULT_PARAM)["Parameter"]
    assert param["Type"] == "String"
    assert param["Value"] == VALID_YAML


@mock_aws
def test_load_config_ssm_missing_param_raises() -> None:
    with pytest.raises(ClientError):
        load_config_ssm()
