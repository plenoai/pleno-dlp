"""Registry and connector-package wiring."""

from __future__ import annotations

import pytest

# ``import saas_retriever`` alone must populate the registry. Importing
# the subpackage here is belt-and-braces in case someone refactors the
# top-level __init__.
import saas_retriever.connectors  # noqa: F401
from saas_retriever import ConnectorSpec
from saas_retriever.registry import registry


def test_builtin_connectors_registered() -> None:
    """Every shipped connector registers with a matching spec."""
    names = set(registry.names())
    expected = {"github", "gitlab", "bitbucket", "slack", "notion", "confluence", "jira"}
    assert expected <= names
    for name in expected:
        assert registry.spec(name).name == name


def test_unknown_connector_raises() -> None:
    with pytest.raises(KeyError):
        registry.create("does-not-exist")


def test_register_overrides_last_write_wins() -> None:
    sentinel = object()

    class _Factory:
        spec = ConnectorSpec(name="__test_override__", kind="test", summary="test factory")

        def __new__(cls, **kwargs: object) -> object:  # type: ignore[misc]
            return sentinel

    registry.register("__test_override__", _Factory)
    assert registry.create("__test_override__") is sentinel


def test_register_rejects_factory_without_spec() -> None:
    """A factory missing the spec ClassVar fails registration loudly."""

    class _NoSpec:
        pass

    with pytest.raises(TypeError, match="missing a"):
        registry.register("__no_spec__", _NoSpec)


def test_register_rejects_spec_name_mismatch() -> None:
    """spec.name must match the registry key."""

    class _Mismatched:
        spec = ConnectorSpec(name="actual", kind="t", summary="")

    with pytest.raises(ValueError, match="spec name mismatch"):
        registry.register("declared", _Mismatched)


def test_create_rejects_unknown_kwargs() -> None:
    """Unknown kwargs surface a TypeError instead of being silently dropped."""
    with pytest.raises(TypeError, match="unexpected kwargs"):
        registry.create("github", owner="plenoai", token="ghp_x", bogus=True)
