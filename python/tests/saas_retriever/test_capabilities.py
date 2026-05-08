"""Capabilities, DocumentChunk, Subsource, IncrementalConnector smoke tests."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from saas_retriever import (
    SUBSOURCE_METADATA_KEY,
    Capabilities,
    DocumentChunk,
    DocumentRef,
    IncrementalConnector,
    Subsource,
)

# --- Capabilities -------------------------------------------------------


def test_capabilities_defaults() -> None:
    c = Capabilities()
    assert c.incremental is False
    assert c.binary is False
    assert c.content_hash_delta is False
    assert c.max_concurrent_fetches == 8
    assert c.streaming is False


def test_capabilities_overrides() -> None:
    c = Capabilities(
        incremental=True,
        binary=True,
        content_hash_delta=True,
        max_concurrent_fetches=4,
        streaming=True,
    )
    assert c.incremental is True
    assert c.binary is True
    assert c.max_concurrent_fetches == 4


# --- DocumentChunk ------------------------------------------------------


def _ref() -> DocumentRef:
    return DocumentRef(source_id="s", source_kind="k", path="p")


def test_document_chunk_text_xor_binary_enforced() -> None:
    DocumentChunk(ref=_ref(), byte_range=(0, 10), is_final=True, text="x")
    DocumentChunk(ref=_ref(), byte_range=(0, 10), is_final=False, binary=b"x")
    with pytest.raises(ValueError):
        DocumentChunk(ref=_ref(), byte_range=(0, 10), is_final=True)
    with pytest.raises(ValueError):
        DocumentChunk(ref=_ref(), byte_range=(0, 10), is_final=True, text="x", binary=b"x")


def test_document_chunk_byte_range_validated() -> None:
    with pytest.raises(ValueError, match="byte_range"):
        DocumentChunk(ref=_ref(), byte_range=(-1, 10), is_final=True, text="x")
    with pytest.raises(ValueError, match="byte_range"):
        DocumentChunk(ref=_ref(), byte_range=(10, 5), is_final=True, text="x")


# --- Subsource + IncrementalConnector -----------------------------------


def test_subsource_metadata_key_is_well_known() -> None:
    # Connectors that aggregate sub-units must populate this exact key
    # on every emitted ref. Locking the constant down here means a
    # rename surfaces immediately as a test failure.
    assert SUBSOURCE_METADATA_KEY == "_subsource_id"


def test_subsource_holds_id_and_fingerprint() -> None:
    s = Subsource(sub_id="repo-1", fingerprint="abcdef0123")
    assert s.sub_id == "repo-1"
    assert s.fingerprint == "abcdef0123"


def test_incremental_connector_runtime_checkable() -> None:
    class _Stub:
        async def list_subsources(self) -> Sequence[Subsource]:
            return [Subsource(sub_id="a", fingerprint="f")]

        def set_subsource_skip(self, skip: frozenset[str]) -> None:
            pass

    assert isinstance(_Stub(), IncrementalConnector)
