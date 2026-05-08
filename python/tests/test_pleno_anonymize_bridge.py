"""Bridge: pleno_dlp.Document round-trips into a pleno_pii_scanner.Document.

Skipped when pleno-pii-scanner is not installed in the environment — the
bridge is an example, not a hard dependency. CI in the same job that
installs pleno-pii-scanner will run it.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pleno_dlp.core import (
    Document as ScraperDocument,
)
from pleno_dlp.core import (
    DocumentRef as ScraperDocumentRef,
)
from pleno_dlp.core import (
    Principal as ScraperPrincipal,
)

pytest.importorskip("pleno_pii_scanner.sources.base")

# Examples live outside the importable package; add them to sys.path
# instead of restructuring the layout. POC scope.
_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))

from pleno_anonymize_bridge import _to_pii_document  # noqa: E402


def test_full_field_translation() -> None:
    ref = ScraperDocumentRef(
        source_id="ws",
        source_kind="slack",
        path="/general",
        native_url="https://acme.slack.com/archives/C001",
        parent_chain=("acme", "general"),
        content_type="text/plain",
        size=42,
        etag="abc123",
        last_modified=datetime(2026, 5, 6, tzinfo=UTC),
        metadata={"channel_id": "C001"},
    )
    doc = ScraperDocument(
        ref=ref,
        text="leaked secret content here",
        fetched_at=datetime(2026, 5, 6, 12, 0, tzinfo=UTC),
        content_hash="sha256:deadbeef",
        created_by=ScraperPrincipal(id="u1", display_name="Alice", email="alice@acme.com"),
        extra={"thread_ts": "1234.5678"},
    )

    pii_doc = _to_pii_document(doc)

    from pleno_pii_scanner.sources.base import (
        Document as PiiDocument,
    )
    from pleno_pii_scanner.sources.base import (
        Principal as PiiPrincipal,
    )

    assert isinstance(pii_doc, PiiDocument)
    assert pii_doc.text == doc.text
    assert pii_doc.fetched_at == doc.fetched_at
    assert pii_doc.content_hash == doc.content_hash
    assert pii_doc.ref.source_id == ref.source_id
    assert pii_doc.ref.source_kind == ref.source_kind
    assert pii_doc.ref.path == ref.path
    assert pii_doc.ref.native_url == ref.native_url
    assert pii_doc.ref.parent_chain == ref.parent_chain
    assert pii_doc.ref.content_type == ref.content_type
    assert pii_doc.ref.size == ref.size
    assert pii_doc.ref.etag == ref.etag
    assert pii_doc.ref.last_modified == ref.last_modified
    assert dict(pii_doc.ref.metadata) == dict(ref.metadata)
    assert pii_doc.created_by == PiiPrincipal(
        id="u1", display_name="Alice", email="alice@acme.com"
    )
    assert dict(pii_doc.extra) == dict(doc.extra)


def test_anonymous_document_translates() -> None:
    ref = ScraperDocumentRef(source_id="ws", source_kind="github", path="/repo/file.py")
    doc = ScraperDocument(ref=ref, text="text body")
    pii_doc = _to_pii_document(doc)
    assert pii_doc.created_by is None
    assert pii_doc.text == "text body"


def test_binary_document_translates() -> None:
    ref = ScraperDocumentRef(source_id="ws", source_kind="slack", path="/file.bin")
    doc = ScraperDocument(ref=ref, binary=b"\x00\x01\x02")
    pii_doc = _to_pii_document(doc)
    assert pii_doc.text is None
    assert pii_doc.binary == b"\x00\x01\x02"
