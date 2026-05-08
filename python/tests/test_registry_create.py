"""Registry-driven connector instantiation + output factory error paths."""

from __future__ import annotations

import pytest

from pleno_dlp import engines, output, registry


def test_engines_factory_known_names() -> None:
    for name in ("native", "trufflehog", "gitleaks", "pii"):
        eng = engines.make(name)
        assert eng.name == name


def test_engines_factory_unknown_raises() -> None:
    with pytest.raises(KeyError, match="Unknown engine"):
        engines.make("does-not-exist")


def test_connector_factory_known_names() -> None:
    """Every shipped SaaS connector is reachable through the registry."""
    for name in ("github", "gitlab", "bitbucket", "slack", "notion", "confluence", "jira"):
        assert registry.spec(name).name == name


def test_connector_factory_unknown_raises() -> None:
    with pytest.raises(KeyError, match="Unknown connector"):
        registry.create("does-not-exist")


def test_connector_factory_rejects_unknown_kwargs() -> None:
    """Connectors reject unknown kwargs loud — a typo'd flag must surface."""
    with pytest.raises(TypeError, match="unexpected kwargs"):
        registry.create("github", owner="plenoai", bogus="typo")


def test_output_factory_known_formats() -> None:
    for fmt in ("json", "sarif", "table"):
        s = output.make(fmt)
        assert s is not None


def test_output_factory_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        output.make("xml")
