"""SSM Parameter Store backing for spf53 config."""

from __future__ import annotations

import boto3

from spf53.config import Spf53Config, parse_config

DEFAULT_PARAM = "/spf53/config"


def load_config_ssm(param_name: str = DEFAULT_PARAM) -> Spf53Config:
    client = boto3.client("ssm")
    response = client.get_parameter(Name=param_name)
    return parse_config(response["Parameter"]["Value"])


def put_config_ssm(yaml_text: str, param_name: str = DEFAULT_PARAM) -> None:
    parse_config(yaml_text)
    client = boto3.client("ssm")
    client.put_parameter(Name=param_name, Value=yaml_text, Type="String", Overwrite=True)
