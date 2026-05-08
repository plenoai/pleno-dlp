"""Connector registry — name → factory mapping with spec validation.

Connectors register themselves by importing their module (which calls
``registry.register``). The CLI imports ``saas_retriever.connectors`` to
trigger every registration; programmatic users can either import the
same package or register their own connectors at runtime.

Each registered factory must expose a ``spec: ConnectorSpec`` ClassVar
whose ``name`` matches the registry key. ``register()`` validates the
match, ``spec(name)`` looks the spec up, and ``create()`` filters
incoming kwargs against ``spec.accepted_kwargs()`` so unknown options
fail loud instead of silently no-op'ing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from saas_retriever.core import Connector, ConnectorSpec

# Looser than Callable[..., Connector] so subclasses of an abstract base —
# whose runtime shape is a Connector but whose static type is the concrete
# class — register without a cast at every call site. The contract is
# enforced at use time by `create()`'s return annotation. Factories must
# also expose a ``spec: ConnectorSpec`` ClassVar (validated by
# ``register()``) — see ``_spec_of`` for the cast helper.
ConnectorFactory = Callable[..., Any]


def _spec_of(factory: ConnectorFactory) -> ConnectorSpec:
    """Return the ``spec`` attribute attached to a factory, with the right type.

    ``register()`` already verified that ``factory.spec`` exists and is a
    ``ConnectorSpec``; this helper just makes that contract visible to mypy.
    """
    return cast(ConnectorSpec, factory.spec)  # type: ignore[attr-defined]


class _Registry:
    """In-memory registry. Single shared instance exposed as `registry`."""

    def __init__(self) -> None:
        self._factories: dict[str, ConnectorFactory] = {}

    def register(self, name: str, factory: ConnectorFactory) -> None:
        """Add a connector factory. Duplicate registration overrides — last
        write wins, which lets downstream packages monkey-patch a builtin
        connector with a hardened version without forcing an unregister.

        The factory must expose a ``spec`` ClassVar whose ``name`` matches
        ``name``; this catches copy-paste registration bugs early.
        """
        spec = getattr(factory, "spec", None)
        if not isinstance(spec, ConnectorSpec):
            raise TypeError(
                f"Connector {name!r} ({factory!r}) is missing a `spec: ConnectorSpec` "
                "ClassVar. Declare one alongside `kind` so the CLI/docs can "
                "introspect the connector."
            )
        if spec.name != name:
            raise ValueError(
                f"Connector spec name mismatch: registered as {name!r} but "
                f"spec.name is {spec.name!r}. Keep them aligned."
            )
        self._factories[name] = factory

    def names(self) -> list[str]:
        """Sorted list of registered connector names."""
        return sorted(self._factories)

    def spec(self, name: str) -> ConnectorSpec:
        """Return the ConnectorSpec for ``name``. KeyError if unknown."""
        return _spec_of(self._factories[name])

    def specs(self) -> list[ConnectorSpec]:
        """Every registered spec, sorted by name. Useful for docs / CLI tables."""
        return [self.spec(n) for n in self.names()]

    def create(self, name: str, **kwargs: Any) -> Connector:
        """Instantiate the connector named ``name`` with ``kwargs``.

        Kwargs not declared in ``spec.accepted_kwargs()`` raise
        ``TypeError`` — this catches operator typos at the boundary
        instead of letting the connector silently ignore them.
        Connectors own their own HTTP clients; the registry does not
        thread a shared session through.
        """
        try:
            factory = self._factories[name]
        except KeyError:
            available = ", ".join(self.names()) or "(none)"
            raise KeyError(f"Unknown connector: {name!r}. Available: {available}") from None
        accepted = _spec_of(factory).accepted_kwargs()
        unknown = sorted(set(kwargs) - accepted)
        if unknown:
            offered = ", ".join(sorted(accepted)) or "(none)"
            raise TypeError(
                f"Connector {name!r} got unexpected kwargs: {', '.join(unknown)}. "
                f"Accepted: {offered}."
            )
        result: Connector = factory(**kwargs)
        return result


registry = _Registry()
