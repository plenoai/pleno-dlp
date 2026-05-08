"""End-to-end scan pipeline.

Wires a SaaS source ``Connector`` to a detection ``Engine`` and a
sink. The pipeline owns the iteration order — it calls the source's
``discover_and_fetch``, hands each Document to the engine, and
forwards Findings to the sink.

Connectors come out of the registry; engines come from
``pleno_dlp.engines`` and are passed in directly. The pipeline only
needs the Protocol shapes — it does not care which kind of engine
(regex / trufflehog / gitleaks / pii) is wired up.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from pleno_dlp.core import Connector, Engine, SourceFilter
from pleno_dlp.findings import Finding


@dataclass(frozen=True, slots=True)
class Pipeline:
    """Source connector + detection engine pair. Sinks live separately
    so the same scan output can fan out to multiple formatters from a
    single run."""

    connector: Connector
    engine: Engine

    async def run(self, filter: SourceFilter | None = None) -> AsyncIterator[Finding]:
        """Drive the source → engine chain. Yields every Finding."""
        async for doc in self.connector.discover_and_fetch(filter):
            if doc.text is None:
                continue
            async for finding in self.engine.scan(doc):
                yield finding  # type: ignore[misc]
