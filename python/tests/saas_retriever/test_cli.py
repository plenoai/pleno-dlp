"""CLI smoke + helper tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from saas_retriever import __version__
from saas_retriever.cli import _parse_since, app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_list_shows_github() -> None:
    """v0.1.x ships only the GitHub connector. Sibling providers come back
    in later releases as standalone API-based connectors."""
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "github" in result.stdout


def test_fetch_unknown_connector_exits_2() -> None:
    result = runner.invoke(app, ["fetch", "does-not-exist"])
    assert result.exit_code == 2
    out = result.stdout + (result.stderr or "")
    assert "unknown connector" in out


def test_parse_since_relative_units() -> None:
    now = datetime.now(UTC)
    parsed = _parse_since("7d")
    assert parsed is not None
    assert abs((now - parsed) - timedelta(days=7)) < timedelta(seconds=5)


def test_parse_since_iso8601() -> None:
    parsed = _parse_since("2026-01-02T03:04:05+00:00")
    assert parsed == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_since_rejects_garbage() -> None:
    with pytest.raises(Exception):  # typer.BadParameter
        _parse_since("nope")


def test_parse_since_none() -> None:
    assert _parse_since(None) is None
