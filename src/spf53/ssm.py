"""SSM Parameter Store backing for spf53 config."""

from __future__ import annotations

import functools
from typing import Any

import boto3

from spf53.config import Spf53Config, parse_config

DEFAULT_PARAM = "/spf53/config"


@functools.cache
def _client() -> Any:
    return boto3.client("ssm")


def load_config_ssm(param_name: str = DEFAULT_PARAM) -> Spf53Config:
    response = _client().get_parameter(Name=param_name)
    return parse_config(response["Parameter"]["Value"])


def put_config_ssm(yaml_text: str, param_name: str = DEFAULT_PARAM) -> None:
    parse_config(yaml_text)
    _client().put_parameter(Name=param_name, Value=yaml_text, Type="String", Overwrite=True)
