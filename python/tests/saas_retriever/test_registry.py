"""Registry and connector-package wiring."""

from __future__ import annotations

import pytest

# ``import saas_retriever`` alone must populate the registry. Importing
# the subpackage here is belt-and-braces in case someone refactors the
# top-level __init__.
import saas_retriever.connectors  # noqa: F401
from saas_retriever.registry import registry


def test_builtin_connectors_registered() -> None:
    """v0.1.x ships only the GitHub connector. Slack / Jira / Notion / ...
    return as separate API-based connectors in later releases."""
    assert "github" in set(registry.names())


def test_unknown_connector_raises() -> None:
    with pytest.raises(KeyError):
        registry.create("does-not-exist")


def test_register_overrides_last_write_wins() -> None:
    sentinel = object()

    def factory(**kwargs: object) -> object:
        return sentinel

    registry.register("__test_override__", factory)
    assert registry.create("__test_override__") is sentinel
