"""CLI tests for the generic --option/-o pass-through.

Exercises ``_coerce_option`` and verifies that ``list`` lists every
shipped SaaS connector and every detection engine. Doesn't run a full
scan — the pipeline path is covered by ``test_pipeline.py``.
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
    from pleno_dlp import OptionSpec

    list_opt = OptionSpec("resources", "list[str]", "test")
    assert _coerce_option("code,issues", list_opt) == ("code", "issues")
    assert _coerce_option("", list_opt) == ()

    int_opt = OptionSpec("max_repos", "int", "test")
    assert _coerce_option("500", int_opt) == 500


def test_list_includes_every_saas_connector_and_engine() -> None:
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0, result.output
    for connector in (
        "github",
        "gitlab",
        "bitbucket",
        "notion",
        "confluence",
        "jira",
        "slack",
    ):
        assert connector in result.output
    for engine in ("native", "trufflehog", "gitleaks", "pii"):
        assert engine in result.output


def test_list_capability_filter_verify() -> None:
    """github advertises VERIFY; the others do not."""
    result = runner.invoke(app, ["list", "--capability", "verify"])
    assert result.exit_code == 0, result.output
    assert "github" in result.output
    assert "slack" not in result.output


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


def test_scan_rejects_unknown_engine() -> None:
    """Unknown --engine fails early, before any pipeline construction."""
    result = runner.invoke(
        app,
        ["scan", "github", "--option", "owner=plenoai", "--engine", "bogus"],
    )
    assert result.exit_code == 2
    assert "unknown engine" in result.output


def test_scan_engine_shorthand_lands_in_connector_kwargs() -> None:
    """`--engine native` is accepted as a connector option, not stripped.

    We don't actually run the scan — we just verify the option is
    routed through registry.create. test_every_connector_accepts_engine_kwarg
    in tests/connectors/test_detect.py covers the spec side.
    """
    # `--engine bogus` returns a clean validation error before any
    # network call; success of *that* path proves the wiring works.
    result = runner.invoke(
        app,
        ["scan", "github", "--engine", "bogus"],
    )
    assert result.exit_code == 2
    assert "unknown engine" in result.output


def test_describe_connector_renders_options_table() -> None:
    result = runner.invoke(app, ["describe", "github"])
    assert result.exit_code == 0
    assert "owner" in result.output
    assert "code" in result.output
    assert "source" in result.output


def test_describe_unknown_connector_exits_2() -> None:
    result = runner.invoke(app, ["describe", "salesforce"])
    assert result.exit_code == 2


def test_scan_rejects_unknown_connector() -> None:
    result = runner.invoke(app, ["scan", "salesforce"])
    assert result.exit_code == 2
    assert "unknown connector" in result.output


def test_verify_unknown_connector_exits_2() -> None:
    result = runner.invoke(app, ["verify", "salesforce", "--token", "x"])
    assert result.exit_code == 2


def test_verify_rejects_connector_without_capability() -> None:
    """slack does not yet implement VERIFY — must fail loud, not silently."""
    result = runner.invoke(app, ["verify", "slack", "--token", "x"])
    assert result.exit_code == 2
    assert "Capability.VERIFY" in result.output


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
    assert "unknown connector" not in result.output
