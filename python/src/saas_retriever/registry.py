"""Connector registry — name → factory mapping.

Connectors register themselves by importing their module (which calls
`registry.register`). The CLI imports `saas_retriever.connectors` to
trigger every registration; programmatic users can either import the
same package or register their own connectors at runtime.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from saas_retriever.core import Connector

# Looser than Callable[..., Connector] so subclasses of an abstract base —
# whose runtime shape is a Connector but whose static type is the concrete
# class — register without a cast at every call site. The contract is
# enforced at use time by `create()`'s return annotation.
ConnectorFactory = Callable[..., Any]


class _Registry:
    """In-memory registry. Single shared instance exposed as `registry`."""

    def __init__(self) -> None:
        self._factories: dict[str, ConnectorFactory] = {}

    def register(self, name: str, factory: ConnectorFactory) -> None:
        """Add a connector factory. Duplicate registration overrides — last
        write wins, which lets downstream packages monkey-patch a builtin
        connector with a hardened version without forcing an unregister.
        """
        self._factories[name] = factory

    def names(self) -> list[str]:
        """Sorted list of registered connector names."""
        return sorted(self._factories)

    def create(self, name: str, **kwargs: Any) -> Connector:
        """Instantiate the connector named `name` with `kwargs`.

        v0.1: connectors own their own HTTP clients; the registry no
        longer threads a shared session through. Provider-specific
        kwargs flow through verbatim.
        """
        try:
            factory = self._factories[name]
        except KeyError:
            available = ", ".join(self.names()) or "(none)"
            raise KeyError(f"Unknown connector: {name!r}. Available: {available}") from None
        result: Connector = factory(**kwargs)
        return result


registry = _Registry()
