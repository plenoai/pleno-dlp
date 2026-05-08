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
    """Without a spec hint, scalar literals coerce; everything else passes through."""
    assert _coerce_option("true", None) is True
    assert _coerce_option("True", None) is True
    assert _coerce_option("false", None) is False
    assert _coerce_option("none", None) is None
    assert _coerce_option("null", None) is None
    assert _coerce_option("42", None) == 42
    assert _coerce_option("xoxb-not-an-int", None) == "xoxb-not-an-int"
    assert _coerce_option("https://acme.atlassian.net", None) == "https://acme.atlassian.net"


def test_coerce_option_uses_spec_type_when_available() -> None:
    """When the spec declares list[str] / int, the parser respects it."""
    from saas_retriever import OptionSpec

    list_opt = OptionSpec("resources", "list[str]", "test")
    assert _coerce_option("code,issues", list_opt) == ("code", "issues")
    assert _coerce_option("", list_opt) == ()

    int_opt = OptionSpec("max_repos", "int", "test")
    assert _coerce_option("500", int_opt) == 500


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


def test_scan_rejects_unknown_kwarg() -> None:
    """Spec-driven validation surfaces typos in --option keys."""
    result = runner.invoke(
        app,
        ["scan", "github", "--option", "owner=plenoai", "--option", "ownr=typo"],
    )
    assert result.exit_code == 2
    assert "unexpected kwargs" in result.output


def test_describe_renders_options_table() -> None:
    result = runner.invoke(app, ["describe", "github"])
    assert result.exit_code == 0
    assert "owner" in result.output
    assert "code" in result.output


def test_describe_unknown_connector_exits_2() -> None:
    result = runner.invoke(app, ["describe", "salesforce"])
    assert result.exit_code == 2


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
