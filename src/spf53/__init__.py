"""spf53 — self-hosted SPF flattener for Route53."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("spf53")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
