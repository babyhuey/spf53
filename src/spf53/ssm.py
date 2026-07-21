"""SSM Parameter Store backing for spf53 config."""

from __future__ import annotations

from typing import Any

from spf53 import _boto
from spf53.config import Spf53Config, parse_config

DEFAULT_PARAM = "/spf53/config"


def _client(region: str | None = None) -> Any:
    return _boto.get_client("ssm", region)


def load_config_ssm(param_name: str = DEFAULT_PARAM, region: str | None = None) -> Spf53Config:
    response = _client(region).get_parameter(Name=param_name)
    return parse_config(response["Parameter"]["Value"])


def put_config_ssm(
    yaml_text: str, param_name: str = DEFAULT_PARAM, region: str | None = None
) -> None:
    parse_config(yaml_text)
    _client(region).put_parameter(Name=param_name, Value=yaml_text, Type="String", Overwrite=True)
