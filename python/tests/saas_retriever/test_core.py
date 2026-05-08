"""Smoke tests for the Document / DocumentRef / Connector contract."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from saas_retriever import Connector, Document, DocumentRef, Principal, SourceFilter


def test_document_ref_fingerprint_stable() -> None:
    a = DocumentRef(source_id="slack:acme", source_kind="slack", path="C123")
    b = DocumentRef(source_id="slack:acme", source_kind="slack", path="C123")
    assert a.fingerprint() == b.fingerprint()
    assert len(a.fingerprint()) == 32


def test_document_ref_fingerprint_changes_with_etag() -> None:
    a = DocumentRef(source_id="s", source_kind="k", path="p", etag="v1")
    b = DocumentRef(source_id="s", source_kind="k", path="p", etag="v2")
    assert a.fingerprint() != b.fingerprint()


def test_document_text_xor_binary_enforced() -> None:
    ref = DocumentRef(source_id="s", source_kind="k", path="p")
    Document(ref=ref, text="hi")
    Document(ref=ref, binary=b"hi")
    with pytest.raises(ValueError):
        Document(ref=ref)
    with pytest.raises(ValueError):
        Document(ref=ref, text="hi", binary=b"hi")


def test_principal_optional_fields() -> None:
    p = Principal(id="U123")
    assert p.email is None
    assert p.display_name is None


def test_source_filter_defaults() -> None:
    f = SourceFilter()
    assert f.include == ()
    assert f.exclude == ()
    assert f.since is None
    assert f.max_size is None


def test_source_filter_since_accepts_datetime() -> None:
    SourceFilter(since=datetime.now(UTC))


def test_connector_protocol_runtime_checkable() -> None:
    """A class with the right shape passes isinstance(_, Connector)."""

    class _Stub:
        id = "s"
        kind = "stub"

        async def discover(self, filter: SourceFilter, cursor: str | None = None):
            if False:
                yield  # type: ignore[unreachable]

        async def fetch(self, ref: DocumentRef):
            if False:
                yield  # type: ignore[unreachable]

        async def discover_and_fetch(self, filter: SourceFilter | None = None):
            if False:
                yield  # type: ignore[unreachable]

        def capabilities(self):
            from saas_retriever import Capabilities

            return Capabilities()

        async def close(self) -> None:
            return None

    assert isinstance(_Stub(), Connector)
