"""Bridge a saas-retriever Connector into pleno-anonymize's pii-scanner.

Why this file exists: saas-retriever and pleno-anonymize both speak a
``Document`` / ``DocumentRef`` / ``Principal`` / ``SourceFilter`` shape
that was deliberately kept field-compatible. A ``saas_retriever.Document``
can be translated into a ``pleno_pii_scanner.sources.base.Document`` with
a one-line field copy — no schema migration, no JSON round-trip.

This module ships the adapter as runnable code so the contract can be
type-checked in CI and exercised manually before we promote it into a
proper ``pleno-pii-scanner-saas-retriever`` workspace package on the
pleno-anonymize side.

Usage::

    # In a venv with both packages installed:
    #   uv pip install pleno-dlp pleno-pii-scanner pleno-pii-scanner-recognizers
    #   playwright install chromium
    python -m pleno_dlp.examples.pleno_anonymize_bridge slack --workspace acme
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from saas_retriever import BrowserSession
from saas_retriever import SourceFilter as ScraperFilter
from saas_retriever import connectors as _connectors  # noqa: F401  registry side-effect
from saas_retriever.core import Document as ScraperDocument
from saas_retriever.registry import registry

if TYPE_CHECKING:
    # Imported lazily inside the function body so this example file remains
    # importable without pleno-anonymize installed (pleno-dlp's
    # own test suite never installs it). Type-checker still sees the names.
    from pleno_pii_scanner.sources.base import (
        Capabilities,
        Cursor,
    )
    from pleno_pii_scanner.sources.base import (
        Document as PiiDocument,
    )
    from pleno_pii_scanner.sources.base import (
        DocumentRef as PiiDocumentRef,
    )
    from pleno_pii_scanner.sources.base import (
        SourceFilter as PiiFilter,
    )


def _to_pii_document(doc: ScraperDocument) -> PiiDocument:
    """Translate one saas-retriever Document into a pleno-anonymize Document.

    Field-for-field copy. The shapes were aligned at saas-retriever 0.1.0
    so this stays a one-liner — if it grows, a field has drifted and
    one of the two packages needs a corresponding migration.
    """
    from pleno_pii_scanner.sources.base import (
        Document as PiiDocument,
    )
    from pleno_pii_scanner.sources.base import (
        DocumentRef as PiiDocumentRef,
    )
    from pleno_pii_scanner.sources.base import (
        Principal as PiiPrincipal,
    )

    ref = PiiDocumentRef(
        source_id=doc.ref.source_id,
        source_kind=doc.ref.source_kind,
        path=doc.ref.path,
        native_url=doc.ref.native_url,
        parent_chain=doc.ref.parent_chain,
        content_type=doc.ref.content_type,
        size=doc.ref.size,
        etag=doc.ref.etag,
        last_modified=doc.ref.last_modified,
        metadata=dict(doc.ref.metadata),
    )
    created_by = (
        PiiPrincipal(
            id=doc.created_by.id,
            display_name=doc.created_by.display_name,
            email=doc.created_by.email,
        )
        if doc.created_by is not None
        else None
    )
    return PiiDocument(
        ref=ref,
        text=doc.text,
        binary=doc.binary,
        fetched_at=doc.fetched_at,
        content_hash=doc.content_hash,
        created_by=created_by,
        extra=dict(doc.extra),
    )


class SaasScraperAdapter:
    """Wrap a saas-retriever Connector behind pleno-anonymize's SourceConnector.

    Implements the minimum surface (id, kind, discover, fetch,
    capabilities, close) so a scheduler can drive it. ``Cursor`` and
    incremental subsource enumeration are out of scope for the POC —
    every scan is a full re-walk, which is fine for human-driven runs.
    """

    def __init__(self, scraper_connector: Any, *, kind: str | None = None) -> None:
        self._scraper = scraper_connector
        self.id = scraper_connector.id
        self.kind = kind or scraper_connector.kind

    async def discover(
        self,
        filter: PiiFilter,
        cursor: Cursor | None,
    ) -> AsyncIterator[PiiDocumentRef]:
        from pleno_pii_scanner.sources.base import DocumentRef as PiiDocumentRef

        scraper_filter = ScraperFilter(
            include=filter.include,
            exclude=filter.exclude,
            since=filter.since,
            max_size=filter.max_size,
        )
        async for ref in self._scraper.discover(scraper_filter):
            yield PiiDocumentRef(
                source_id=ref.source_id,
                source_kind=ref.source_kind,
                path=ref.path,
                native_url=ref.native_url,
                parent_chain=ref.parent_chain,
                content_type=ref.content_type,
                size=ref.size,
                etag=ref.etag,
                last_modified=ref.last_modified,
                metadata=dict(ref.metadata),
            )

    async def fetch(
        self,
        ref: PiiDocumentRef,
    ) -> AsyncIterator[PiiDocument]:
        from saas_retriever.core import DocumentRef as ScraperDocumentRef

        scraper_ref = ScraperDocumentRef(
            source_id=ref.source_id,
            source_kind=ref.source_kind,
            path=ref.path,
            native_url=ref.native_url,
            parent_chain=ref.parent_chain,
            content_type=ref.content_type,
            size=ref.size,
            etag=ref.etag,
            last_modified=ref.last_modified,
            metadata=dict(ref.metadata),
        )
        async for doc in self._scraper.fetch(scraper_ref):
            yield _to_pii_document(doc)

    def capabilities(self) -> Capabilities:
        from pleno_pii_scanner.sources.base import Capabilities

        # Browser-driven sources serialise on a single Chrome instance,
        # so concurrency is 1. They also lack cheap incremental cursors
        # (the UI doesn't expose a delta token) and never deliver binary
        # bodies for v0.4.x — every connector returns text or skips.
        return Capabilities(
            incremental=False,
            binary=False,
            content_hash_delta=False,
            max_concurrent_fetches=1,
            streaming=False,
        )

    async def close(self) -> None:
        await self._scraper.close()


async def _main(argv: list[str]) -> int:
    if len(argv) < 1:
        print("usage: pleno_anonymize_bridge <connector> [--workspace ...]", file=sys.stderr)
        return 2
    connector_name = argv[0]
    kwargs: dict[str, Any] = {}
    for k, v in zip(argv[1::2], argv[2::2], strict=False):
        kwargs[k.removeprefix("--")] = v
    if connector_name not in registry.names():
        print(f"unknown connector: {connector_name}", file=sys.stderr)
        return 2

    async with BrowserSession(headless=True) as session:
        scraper = registry.create(connector_name, session=session, **kwargs)
        adapter = SaasScraperAdapter(scraper)
        try:
            from pleno_pii_scanner.sources.base import SourceFilter as PiiFilter

            filter = PiiFilter()
            n = 0
            async for ref in adapter.discover(filter, cursor=None):
                async for doc in adapter.fetch(ref):
                    n += 1
                    text_len = len(doc.text) if doc.text else 0
                    print(f"[{n}] {doc.ref.source_kind}:{doc.ref.path} ({text_len} chars)")
            print(f"streamed {n} documents into pleno-pii-scanner shape", file=sys.stderr)
        finally:
            await adapter.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
