"""Internal helper: equip a SaaS connector with a configurable engine.

Each shipped connector adopts the same pattern: an ``engine`` kwarg
selects which detection engine runs internally (default: ``native``),
and the connector's own ``detect()`` delegates to that engine. The
spec advertises ``Capability.DETECT`` so the registry / CLI surface
treats every connector as capable of producing findings.

Concentrating the boilerplate here keeps the seven connectors
consistent and means future engine additions (or a per-connector
multi-engine composition) only need to land here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from pleno_dlp.core import Document, OptionSpec
from pleno_dlp.engines import ENGINE_NAMES
from pleno_dlp.engines import make as _make_engine
from pleno_dlp.findings import Finding

__all__ = ["DETECT_ENGINE_OPTION", "DetectViaEngineMixin"]


DETECT_ENGINE_OPTION = OptionSpec(
    "engine",
    "str",
    f"Detection engine to run inside this connector. One of: {', '.join(ENGINE_NAMES)}.",
    default="native",
    choices=ENGINE_NAMES,
    cli_flag="--engine",
)


class DetectViaEngineMixin:
    """Adds an internal engine and a ``detect()`` delegating to it.

    Subclasses must call ``self._init_engine(engine)`` from their own
    ``__init__`` once the connector finishes wiring its source-side
    state. The mixin intentionally does not define ``__init__``
    itself to avoid colliding with each connector's bespoke
    constructor signature.
    """

    name: str  # connector name (e.g. "github")

    def _init_engine(self, engine: str) -> None:
        if engine not in ENGINE_NAMES:
            raise ValueError(
                f"unknown engine {engine!r}; choose from {', '.join(ENGINE_NAMES)}"
            )
        self._engine_name = engine
        self._engine = _make_engine(engine)

    async def detect(self, doc: Document) -> AsyncIterator[Finding]:
        """Hand the Document to the configured engine and re-yield Findings."""
        async for finding in self._engine.detect(doc):
            yield finding

    async def _close_engine(self) -> None:
        """Release the engine's resources (HTTP clients, subprocess pools).

        Called from each connector's ``close()``. Engines without an
        ``aclose`` (the regex / subprocess wrappers) no-op.
        """
        aclose = getattr(self._engine, "aclose", None)
        if aclose is not None:
            await aclose()
