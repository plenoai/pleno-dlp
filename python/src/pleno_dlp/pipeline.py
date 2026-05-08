"""End-to-end scan pipeline.

Wires a source ``Connector`` to a ``Detector`` and a sink. The pipeline
owns the iteration order — it calls the source's ``discover_and_fetch``,
hands each Document to the detector, and forwards Findings to the sink.

Both source and detector connectors come out of the same registry; the
pipeline just doesn't care which sub-roles registered them — it only
needs the Protocol shapes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from pleno_dlp.core import Connector, Detector, SourceFilter
from pleno_dlp.findings import Finding


@dataclass(frozen=True, slots=True)
class Pipeline:
    """Source connector + detector connector pair. Sinks live separately
    so the same scan output can fan out to multiple formatters from a
    single run."""

    connector: Connector
    detector: Detector

    async def run(self, filter: SourceFilter | None = None) -> AsyncIterator[Finding]:
        """Drive the source → detector chain. Yields every Finding."""
        async for doc in self.connector.discover_and_fetch(filter):
            if doc.text is None:
                continue
            async for finding in self.detector.scan(doc):
                yield finding  # type: ignore[misc]
