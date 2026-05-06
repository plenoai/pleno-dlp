"""End-to-end scan pipeline.

Wires a saas_scraper Connector to a Backend and a Sink. The pipeline owns
the iteration order — it calls the connector's ``discover_and_fetch``,
hands each Document to the backend, and forwards Findings to the sink.

Concurrency note: connectors and backends are both async iterables, but
the pipeline itself runs sequentially. Per-document parallelism would
require a redesign of saas_scraper's BrowserSession, which is a single
Chrome instance — so we stick with serial for now.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from saas_scraper import Connector, SourceFilter

from pleno_secret_scanner.backends import Backend
from pleno_secret_scanner.findings import Finding


@dataclass(frozen=True, slots=True)
class Pipeline:
    """Connector + Backend pair. Sinks live separately so the same scan
    output can fan out to multiple formatters from a single run."""

    connector: Connector
    backend: Backend

    async def run(self, filter: SourceFilter | None = None) -> AsyncIterator[Finding]:
        """Drive the connector → backend chain. Yields every Finding."""
        async for doc in self.connector.discover_and_fetch(filter):
            if doc.text is None:
                continue
            async for finding in self.backend.scan(doc):
                yield finding
