"""Tests for spf53's package version metadata."""

import tomllib
from pathlib import Path

import spf53


def test_version_is_non_empty_string() -> None:
    assert isinstance(spf53.__version__, str)
    assert spf53.__version__


def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert spf53.__version__ == data["project"]["version"]
