"""Pipeline integration: stub connector → native engine → findings.

The default Pipeline uses the connector itself as the Detector. The
StubConnector here doesn't implement detect(), so we pass an explicit
``detector=NativeEngine()`` to exercise the pipeline path.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

from pleno_dlp import Document, DocumentRef, SourceFilter
from pleno_dlp.engines.native import NativeEngine
from pleno_dlp.pipeline import Pipeline


class StubConnector:
    """In-memory connector that yields a fixed list of Documents."""

    id = "stub"
    kind = "stub"

    def __init__(self, docs: list[Document]) -> None:
        self._docs = docs

    async def discover(self, filter: SourceFilter) -> AsyncIterator[DocumentRef]:
        for d in self._docs:
            yield d.ref

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        for d in self._docs:
            if d.ref == ref:
                yield d
                return

    async def discover_and_fetch(
        self, filter: SourceFilter | None = None
    ) -> AsyncIterator[Document]:
        for d in self._docs:
            yield d

    async def close(self) -> None:
        return None


def _doc(text: str, path: str) -> Document:
    return Document(
        ref=DocumentRef(source_id="ws", source_kind="stub", path=path),
        text=text,
        fetched_at=datetime.now(UTC),
    )


async def test_pipeline_emits_findings_from_each_doc() -> None:
    docs = [
        _doc("clean\n", "/a.txt"),
        _doc("leaked AKIAIOSFODNN7EXAMPLE here", "/b.txt"),
        _doc("ghp_" + "a" * 36 + "\n", "/c.txt"),
    ]
    pipeline = Pipeline(connector=StubConnector(docs), detector=NativeEngine())
    findings = [f async for f in pipeline.run()]
    paths = {f.path for f in findings}
    assert paths == {"/b.txt", "/c.txt"}
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"aws-access-key-id", "github-pat"}


async def test_pipeline_skips_binary_documents() -> None:
    docs = [
        Document(
            ref=DocumentRef(source_id="ws", source_kind="stub", path="/x.bin"),
            binary=b"AKIAIOSFODNN7EXAMPLE",
        ),
    ]
    pipeline = Pipeline(connector=StubConnector(docs), detector=NativeEngine())
    findings = [f async for f in pipeline.run()]
    assert findings == []
