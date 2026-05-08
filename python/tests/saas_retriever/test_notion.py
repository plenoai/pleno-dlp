"""Notion connector tests using httpx.MockTransport.

Every HTTP call is intercepted; unmatched URLs return 404 so a missing
mock fails loudly rather than silently passing.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.notion import (
    NOTION_VERSION,
    NotionConnector,
    _parent_uri,
    _parse_iso,
)
from saas_retriever.connectors.notion_markdown import (
    DEPTH_TRUNCATED_MARKER,
    MAX_DEPTH,
    render_blocks,
    render_database_row,
    render_rich_text,
)
from saas_retriever.core import DocumentRef, SourceFilter
from saas_retriever.credentials import Credential, CredentialMisconfiguredError
from saas_retriever.rate_limit import RateLimited


def _routes(handler_map: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, payload in handler_map.items():
            if path == prefix:
                if callable(payload):
                    return payload(request)
                return _make_response(payload)
        return httpx.Response(404, json={"message": "not found", "path": path})

    return httpx.MockTransport(handler)


def _make_response(spec: Any) -> httpx.Response:
    if isinstance(spec, httpx.Response):
        return spec
    return httpx.Response(200, json=spec)


# --- helpers -----------------------------------------------------------


def test_parse_iso_handles_z_suffix() -> None:
    parsed = _parse_iso("2026-05-06T12:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026


def test_parse_iso_returns_none_on_invalid() -> None:
    assert _parse_iso("not-a-date") is None
    assert _parse_iso(None) is None


def test_parent_uri_handles_known_types() -> None:
    assert _parent_uri({"type": "page_id", "page_id": "p"}) == "notion://page/p"
    assert _parent_uri({"type": "database_id", "database_id": "d"}) == "notion://database/d"
    assert _parent_uri({"type": "block_id", "block_id": "b"}) == "notion://block/b"
    assert _parent_uri({"type": "workspace"}) == "notion://workspace"
    assert _parent_uri({"type": "unknown"}) is None


# --- markdown converters (smoke) ---------------------------------------


def test_render_rich_text_concatenates_with_annotations() -> None:
    out = render_rich_text(
        [
            {
                "type": "text",
                "text": {"content": "leak"},
                "annotations": {"bold": True, "code": False},
            },
            {"type": "text", "text": {"content": " AKIA"}, "annotations": {}},
        ]
    )
    assert "**leak**" in out
    assert "AKIA" in out


def test_render_blocks_emits_unsupported_marker_for_unknown_type() -> None:
    out = render_blocks([{"type": "weird_block", "weird_block": {}}])
    assert "<!-- unsupported: weird_block -->" in out


def test_render_blocks_truncates_at_max_depth() -> None:
    children = {"root": [{"id": "a", "type": "paragraph", "paragraph": {"rich_text": []}, "has_children": True}]}

    def lookup(block_id: str | None) -> list[dict[str, Any]]:
        return children.get(block_id or "", [])

    # Pre-set depth past the cap to assert the sentinel.
    out = render_blocks(children["root"], children_for=lookup, depth=MAX_DEPTH)
    assert out == DEPTH_TRUNCATED_MARKER


def test_render_database_row_skips_low_signal_props() -> None:
    out = render_database_row(
        {
            "Email": {"type": "email", "email": "alice@example.com"},
            "Created": {"type": "created_time", "created_time": "2026-01-01"},
            "Phone": {"type": "phone_number", "phone_number": "+1-555-0101"},
        }
    )
    assert "Email: alice@example.com" in out
    assert "Phone: +1-555-0101" in out
    assert "Created" not in out


# --- construction validation -------------------------------------------


def test_token_required_when_credential_missing() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        NotionConnector()


def test_token_resolved_from_credential() -> None:
    cred = Credential(kind="notion", payload={"token": "secret"})
    c = NotionConnector(credential=cred)
    assert c._token == "secret"


def test_default_id_uses_workspace_or_default() -> None:
    a = NotionConnector(token="x")
    assert a.id == "notion:default"
    b = NotionConnector(token="x", workspace_id="ws-1")
    assert b.id == "notion:ws-1"


def test_capabilities_is_text_incremental() -> None:
    c = NotionConnector(token="x")
    caps = c.capabilities()
    assert caps.binary is False
    assert caps.incremental is True
    assert caps.max_concurrent_fetches == 3


def test_notion_version_pinned() -> None:
    assert NOTION_VERSION == "2022-06-28"


# --- end-to-end --------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_search_paginates_and_dedups() -> None:
    base = "/v1"
    page_a = {"object": "page", "id": "p-a", "url": "https://notion.so/p-a"}
    page_b = {"object": "page", "id": "p-b", "url": "https://notion.so/p-b"}
    page_a_dup = {"object": "page", "id": "p-a", "url": "https://notion.so/p-a"}

    pages = [
        httpx.Response(
            200,
            json={"results": [page_a, page_b], "has_more": True, "next_cursor": "c2"},
        ),
        httpx.Response(
            200,
            json={"results": [page_a_dup], "has_more": False, "next_cursor": None},
        ),
    ]

    def search_handler(request: httpx.Request) -> httpx.Response:
        return pages.pop(0)

    transport = _routes({f"{base}/search": search_handler})
    c = NotionConnector(token="t", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    ids = [r.metadata["object_id"] for r in refs]
    assert ids == ["p-a", "p-b"]


@pytest.mark.asyncio
async def test_discover_explicit_pages_short_circuits_to_get() -> None:
    base = "/v1"
    transport = _routes(
        {
            f"{base}/pages/abc": {
                "object": "page",
                "id": "abc",
                "url": "https://notion.so/abc",
            }
        }
    )
    c = NotionConnector(token="t", pages=("abc",), transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert len(refs) == 1
    assert refs[0].metadata["object_id"] == "abc"
    assert refs[0].path == "notion://page/abc"


@pytest.mark.asyncio
async def test_discover_explicit_database_emits_rows_with_database_id() -> None:
    base = "/v1"
    rows = {
        "results": [
            {"object": "page", "id": "row-1", "url": "https://notion.so/row-1"},
            {"object": "page", "id": "row-2", "url": "https://notion.so/row-2"},
        ],
        "has_more": False,
    }
    transport = _routes({f"{base}/databases/db-1/query": rows})
    c = NotionConnector(token="t", databases=("db-1",), transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert [r.metadata["database_id"] for r in refs] == ["db-1", "db-1"]
    assert refs[0].path == "notion://database-row/row-1"
    assert refs[0].parent_chain == ("notion://database/db-1",)


@pytest.mark.asyncio
async def test_discover_skips_archived_by_default() -> None:
    base = "/v1"
    transport = _routes(
        {
            f"{base}/pages/abc": {
                "object": "page",
                "id": "abc",
                "archived": True,
            }
        }
    )
    c = NotionConnector(token="t", pages=("abc",), transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert refs == []


@pytest.mark.asyncio
async def test_fetch_renders_block_tree_to_markdown() -> None:
    base = "/v1"
    page_obj = {"object": "page", "id": "p-1"}
    children_root = {
        "results": [
            {
                "object": "block",
                "id": "b-1",
                "type": "heading_1",
                "heading_1": {"rich_text": [{"type": "text", "text": {"content": "Title"}, "annotations": {}}]},
                "has_children": False,
            },
            {
                "object": "block",
                "id": "b-2",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {"content": "AKIAIOSFODNN7EXAMPLE"},
                            "annotations": {},
                        }
                    ]
                },
                "has_children": False,
            },
        ],
        "has_more": False,
    }
    transport = _routes(
        {
            f"{base}/pages/p-1": page_obj,
            f"{base}/blocks/p-1/children": children_root,
        }
    )
    c = NotionConnector(token="t", transport=transport)
    ref = DocumentRef(
        source_id=c.id,
        source_kind="notion",
        path="notion://page/p-1",
        metadata={"object_type": "page", "object_id": "p-1"},
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert len(docs) == 1
    assert "# Title" in docs[0].text
    assert "AKIAIOSFODNN7EXAMPLE" in docs[0].text


@pytest.mark.asyncio
async def test_fetch_database_row_includes_property_lines() -> None:
    base = "/v1"
    page_obj = {
        "object": "page",
        "id": "row-1",
        "properties": {
            "Email": {"type": "email", "email": "alice@example.com"},
            "Title": {"type": "title", "title": [{"type": "text", "text": {"content": "Alice"}, "annotations": {}}]},
        },
    }
    transport = _routes(
        {
            f"{base}/pages/row-1": page_obj,
            f"{base}/blocks/row-1/children": {"results": [], "has_more": False},
        }
    )
    c = NotionConnector(token="t", transport=transport)
    ref = DocumentRef(
        source_id=c.id,
        source_kind="notion",
        path="notion://database-row/row-1",
        metadata={
            "object_type": "page",
            "object_id": "row-1",
            "database_id": "db-1",
        },
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert len(docs) == 1
    assert "Email: alice@example.com" in docs[0].text
    assert "Title: Alice" in docs[0].text


@pytest.mark.asyncio
async def test_fetch_yields_nothing_when_object_invisible_404() -> None:
    base = "/v1"
    transport = _routes(
        {
            f"{base}/pages/missing": httpx.Response(
                404, json={"message": "not visible"}
            ),
        }
    )
    c = NotionConnector(token="t", transport=transport)
    ref = DocumentRef(
        source_id=c.id,
        source_kind="notion",
        path="notion://page/missing",
        metadata={"object_type": "page", "object_id": "missing"},
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert docs == []


@pytest.mark.asyncio
async def test_429_eventually_raises_rate_limited() -> None:
    base = "/v1"

    def throttle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    transport = _routes({f"{base}/search": throttle})
    c = NotionConnector(token="t", transport=transport)
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_pagination_cursor_round_tripped_on_search_refs() -> None:
    base = "/v1"
    body = {
        "results": [{"object": "page", "id": "p-1", "url": "https://notion.so/p-1"}],
        "has_more": False,
        "next_cursor": "cur-2",
    }
    transport = _routes({f"{base}/search": body})
    c = NotionConnector(token="t", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert refs[0].metadata.get("_cursor") == "cur-2"
