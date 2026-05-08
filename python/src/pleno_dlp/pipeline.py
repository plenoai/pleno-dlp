"""End-to-end scan pipeline.

Wires a SaaS source ``Connector`` to a ``Detector`` and drives the
discover-fetch-detect loop. Both the connector and any detection
engine satisfy the ``Detector`` Protocol — by default the pipeline
hands each Document to the connector itself, so
``pleno-dlp scan github`` runs github's discovery and its
SaaS-tuned detection in one call.

Operators who want to substitute a single engine can pass one
explicitly via ``Pipeline(connector=..., detector=NativeEngine())``;
the connector's bundled detection is then bypassed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from pleno_dlp.core import Connector, Detector, SourceFilter
from pleno_dlp.findings import Finding


@dataclass(frozen=True, slots=True)
class Pipeline:
    """Source connector + Detector pair.

    ``detector`` defaults to ``None``, which means "use the connector
    as the detector" — the standard SaaS-unit flow. Passing an
    explicit Detector (engine instance, or another connector) swaps
    in alternate detection without touching discover/fetch.
    """

    connector: Connector
    detector: Detector | None = None

    async def run(self, filter: SourceFilter | None = None) -> AsyncIterator[Finding]:
        """Drive the source → detector chain. Yields every Finding."""
        det: Detector = self.detector if self.detector is not None else self.connector  # type: ignore[assignment]
        async for doc in self.connector.discover_and_fetch(filter):
            if doc.text is None:
                continue
            async for finding in det.detect(doc):
                yield finding  # type: ignore[misc]
