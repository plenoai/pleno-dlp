"""CLI tests for the generic --option/-o pass-through.

Exercises ``_coerce_option`` and verifies that ``list-connectors`` lists
every saas-retriever 1.0 connector kind. Doesn't run a full scan — the
pipeline path is covered by ``test_pipeline.py``.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from pleno_dlp.cli import _coerce_option, app

runner = CliRunner()


def test_coerce_option_handles_bool_int_none() -> None:
    assert _coerce_option("true") is True
    assert _coerce_option("True") is True
    assert _coerce_option("false") is False
    assert _coerce_option("none") is None
    assert _coerce_option("null") is None
    assert _coerce_option("42") == 42
    assert _coerce_option("xoxb-not-an-int") == "xoxb-not-an-int"
    assert _coerce_option("https://acme.atlassian.net") == "https://acme.atlassian.net"


def test_list_connectors_includes_every_v1_kind() -> None:
    result = runner.invoke(app, ["list-connectors"])
    assert result.exit_code == 0, result.output
    for kind in ("github", "gitlab", "bitbucket", "notion", "confluence", "jira", "slack"):
        assert kind in result.output


def test_scan_rejects_malformed_option() -> None:
    result = runner.invoke(
        app,
        ["scan", "github", "--option", "no-equals-sign"],
    )
    assert result.exit_code != 0
    assert "key=value" in result.output


def test_scan_rejects_unknown_connector() -> None:
    result = runner.invoke(app, ["scan", "salesforce"])
    assert result.exit_code == 2
    assert "unknown connector" in result.output


@pytest.mark.parametrize(
    "kind",
    ["github", "gitlab", "bitbucket", "notion", "confluence", "jira", "slack"],
)
def test_every_connector_is_addressable(kind: str) -> None:
    """``scan <kind>`` reaches the registry without exiting via the unknown-kind branch.

    We stop short of running the actual scan — the fact that the
    connector factory is invoked (and surfaces a constructor error
    rather than an "unknown connector" error) is enough to prove the
    bridge wired the kind through.
    """
    result = runner.invoke(app, ["scan", kind])
    # Either a 0/1/2 from the pipeline (fully wired) or a non-zero
    # surfaced from the factory (missing required kwargs). What we
    # explicitly do NOT want is the "unknown connector" string.
    assert "unknown connector" not in result.output
