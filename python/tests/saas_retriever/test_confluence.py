"""Confluence connector tests using httpx.MockTransport.

Both Cloud + Data Center flavors are exercised. Every HTTP call is
intercepted; unmatched URLs return 404.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.confluence import (
    ConfluenceConnector,
    _decode_cursor,
    _encode_cursor,
    _host_from_base_url,
    _is_archived,
    _resolve_auth,
    _resolve_link,
)
from saas_retriever.connectors.confluence_storage import storage_to_text
from saas_retriever.core import SourceFilter
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


def test_host_from_base_url_strips_scheme_and_path() -> None:
    assert _host_from_base_url("https://acme.atlassian.net/wiki") == "acme.atlassian.net"
    assert _host_from_base_url("http://confluence.internal/") == "confluence.internal"


def test_resolve_link_handles_absolute_and_relative() -> None:
    assert (
        _resolve_link("https://acme.atlassian.net/wiki", "/spaces/ENG")
        == "https://acme.atlassian.net/wiki/spaces/ENG"
    )
    assert (
        _resolve_link("https://acme.atlassian.net/wiki", "https://x/y")
        == "https://x/y"
    )


def test_is_archived_recognises_status() -> None:
    assert _is_archived({"status": "archived"})
    assert _is_archived({"status": "trashed"})
    assert not _is_archived({"status": "current"})
    assert not _is_archived({})


def test_cursor_round_trip() -> None:
    from datetime import UTC, datetime

    when = datetime(2026, 5, 6, 12, 0, tzinfo=UTC)
    encoded = _encode_cursor(when)
    decoded = _decode_cursor(encoded)
    assert decoded == when


def test_cursor_decode_tolerates_garbage() -> None:
    assert _decode_cursor("not-json") is None
    assert _decode_cursor("[1,2,3]") is None
    assert _decode_cursor(None) is None


def test_storage_to_text_strips_macro_markup() -> None:
    body = (
        '<ac:structured-macro ac:name="info">'
        "<ac:rich-text-body><p>AKIAIOSFODNN7EXAMPLE</p></ac:rich-text-body>"
        "</ac:structured-macro>"
    )
    assert "AKIAIOSFODNN7EXAMPLE" in storage_to_text(body)


# --- auth resolution ---------------------------------------------------


def test_auth_token_wins_over_credential() -> None:
    cred = Credential(kind="confluence", payload={"token": "from-cred"})
    auth = _resolve_auth(
        flavor="cloud",
        credential=cred,
        token="explicit",
        username=None,
        password=None,
        email=None,
        api_token=None,
    )
    assert auth.header_value() == "Bearer explicit"


def test_auth_falls_back_to_credential_token() -> None:
    cred = Credential(kind="confluence", payload={"token": "cred-tok"})
    auth = _resolve_auth(
        flavor="datacenter",
        credential=cred,
        token=None,
        username=None,
        password=None,
        email=None,
        api_token=None,
    )
    assert auth.header_value() == "Bearer cred-tok"


def test_auth_cloud_basic_email_api_token() -> None:
    auth = _resolve_auth(
        flavor="cloud",
        credential=None,
        token=None,
        username=None,
        password=None,
        email="alice@example.com",
        api_token="api-tok",
    )
    assert auth.header_value().startswith("Basic ")


def test_auth_dc_basic_username_password() -> None:
    auth = _resolve_auth(
        flavor="datacenter",
        credential=None,
        token=None,
        username="alice",
        password="pass",
        email=None,
        api_token=None,
    )
    assert auth.header_value().startswith("Basic ")


def test_auth_raises_when_nothing_supplied() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        _resolve_auth(
            flavor="cloud",
            credential=None,
            token=None,
            username=None,
            password=None,
            email=None,
            api_token=None,
        )


# --- construction ------------------------------------------------------


def test_unknown_flavor_rejected() -> None:
    with pytest.raises(ValueError, match="flavor"):
        ConfluenceConnector(
            flavor="github",  # type: ignore[arg-type]
            base_url="https://x",
            token="t",
        )


def test_base_url_required() -> None:
    with pytest.raises(ValueError, match="base_url"):
        ConfluenceConnector(flavor="cloud", base_url="", token="t")


def test_page_size_validated() -> None:
    with pytest.raises(ValueError, match="page_size"):
        ConfluenceConnector(
            flavor="cloud",
            base_url="https://x",
            token="t",
            page_size=0,
        )
    with pytest.raises(ValueError, match="page_size"):
        ConfluenceConnector(
            flavor="cloud",
            base_url="https://x",
            token="t",
            page_size=300,
        )


def test_default_id_includes_flavor_and_host() -> None:
    c = ConfluenceConnector(
        flavor="cloud",
        base_url="https://acme.atlassian.net/wiki",
        token="t",
    )
    assert c.id == "confluence-cloud:acme.atlassian.net"


# --- end-to-end --------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_walks_spaces_and_pages() -> None:
    base = "/wiki"
    base_url = f"https://acme.atlassian.net{base}"

    spaces = {
        "results": [{"key": "ENG"}, {"key": "SEC"}],
        "_links": {},
    }
    pages_eng = {
        "results": [
            {
                "id": "p-eng-1",
                "title": "Onboarding",
                "status": "current",
                "version": {"when": "2026-05-01T10:00:00.000Z"},
                "body": {"storage": {"value": "<p>Welcome AKIAIOSFODNN7EXAMPLE</p>"}},
                "_links": {"webui": "/spaces/ENG/pages/p-eng-1"},
            },
        ],
        "_links": {},
    }
    pages_sec = {"results": [], "_links": {}}

    transport = _routes(
        {
            f"{base}/rest/api/space": spaces,
            f"{base}/rest/api/space/ENG/content/page": pages_eng,
            f"{base}/rest/api/space/SEC/content/page": pages_sec,
            f"{base}/rest/api/content/p-eng-1/child/comment": {
                "results": [],
                "_links": {},
            },
            f"{base}/rest/api/content/p-eng-1/child/attachment": {
                "results": [],
                "_links": {},
            },
        }
    )
    c = ConfluenceConnector(
        flavor="cloud",
        base_url=base_url,
        token="t",
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    assert len(refs) == 1
    assert refs[0].metadata["page_id"] == "p-eng-1"
    assert refs[0].metadata["space_key"] == "ENG"
    # Cursor is round-tripped on the ref.
    assert "_cursor" in refs[0].metadata

    # Fetch should hit the cache and produce text.
    docs = [d async for d in c.fetch(refs[0])]
    await c.close()
    assert len(docs) == 1
    assert "AKIAIOSFODNN7EXAMPLE" in docs[0].text
    assert "title=Onboarding" in docs[0].text


@pytest.mark.asyncio
async def test_discover_with_explicit_spaces_skips_space_listing() -> None:
    base = "/wiki"
    base_url = f"https://acme.atlassian.net{base}"
    pages_eng = {
        "results": [
            {
                "id": "p-eng-1",
                "title": "T",
                "version": {"when": "2026-05-01T10:00:00Z"},
                "body": {"storage": {"value": "<p>x</p>"}},
                "_links": {},
            }
        ],
        "_links": {},
    }
    transport = _routes(
        {
            f"{base}/rest/api/space/ENG/content/page": pages_eng,
            f"{base}/rest/api/content/p-eng-1/child/comment": {
                "results": [],
                "_links": {},
            },
            f"{base}/rest/api/content/p-eng-1/child/attachment": {
                "results": [],
                "_links": {},
            },
        }
    )
    c = ConfluenceConnector(
        flavor="cloud",
        base_url=base_url,
        token="t",
        spaces=("ENG",),
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert [r.metadata["space_key"] for r in refs] == ["ENG"]


@pytest.mark.asyncio
async def test_discover_skips_archived_pages() -> None:
    base = "/wiki"
    base_url = f"https://acme.atlassian.net{base}"
    pages = {
        "results": [
            {
                "id": "p-1",
                "title": "old",
                "status": "archived",
                "version": {"when": "2026-05-01T10:00:00Z"},
                "body": {"storage": {"value": "<p>x</p>"}},
            }
        ],
        "_links": {},
    }
    transport = _routes(
        {
            f"{base}/rest/api/space/ENG/content/page": pages,
        }
    )
    c = ConfluenceConnector(
        flavor="cloud",
        base_url=base_url,
        token="t",
        spaces=("ENG",),
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert refs == []


@pytest.mark.asyncio
async def test_discover_incremental_cursor_skips_old_pages() -> None:
    base = "/wiki"
    base_url = f"https://acme.atlassian.net{base}"
    pages = {
        "results": [
            {
                "id": "p-old",
                "title": "old",
                "status": "current",
                "version": {"when": "2025-01-01T00:00:00Z"},
                "body": {"storage": {"value": "<p>old</p>"}},
            },
            {
                "id": "p-new",
                "title": "new",
                "status": "current",
                "version": {"when": "2027-01-01T00:00:00Z"},
                "body": {"storage": {"value": "<p>new</p>"}},
            },
        ],
        "_links": {},
    }
    transport = _routes(
        {
            f"{base}/rest/api/space/ENG/content/page": pages,
            f"{base}/rest/api/content/p-new/child/comment": {
                "results": [],
                "_links": {},
            },
            f"{base}/rest/api/content/p-new/child/attachment": {
                "results": [],
                "_links": {},
            },
        }
    )
    c = ConfluenceConnector(
        flavor="cloud",
        base_url=base_url,
        token="t",
        spaces=("ENG",),
        transport=transport,
    )
    cursor = _encode_cursor(__import__("datetime").datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
    refs = [r async for r in c.discover(SourceFilter(), cursor=cursor)]
    await c.close()
    assert [r.metadata["page_id"] for r in refs] == ["p-new"]


@pytest.mark.asyncio
async def test_dc_503_eventually_raises_rate_limited() -> None:
    base_url = "https://confluence.internal"

    def overload(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, headers={"Retry-After": "0"})

    transport = _routes({"/rest/api/space/ENG/content/page": overload})
    c = ConfluenceConnector(
        flavor="datacenter",
        base_url=base_url,
        token="t",
        spaces=("ENG",),
        transport=transport,
    )
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_cloud_429_eventually_raises_rate_limited() -> None:
    base = "/wiki"
    base_url = f"https://acme.atlassian.net{base}"

    def throttle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    transport = _routes({f"{base}/rest/api/space/ENG/content/page": throttle})
    c = ConfluenceConnector(
        flavor="cloud",
        base_url=base_url,
        token="t",
        spaces=("ENG",),
        transport=transport,
    )
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_pagination_follows_links_next() -> None:
    base = "/wiki"
    base_url = f"https://acme.atlassian.net{base}"
    pages_a = {
        "results": [
            {
                "id": "p-a",
                "title": "a",
                "status": "current",
                "version": {"when": "2026-05-01T00:00:00Z"},
                "body": {"storage": {"value": "<p>a</p>"}},
            }
        ],
        "_links": {"next": "/rest/api/space/ENG/content/page?start=1"},
    }
    pages_b = {
        "results": [
            {
                "id": "p-b",
                "title": "b",
                "status": "current",
                "version": {"when": "2026-05-02T00:00:00Z"},
                "body": {"storage": {"value": "<p>b</p>"}},
            }
        ],
        "_links": {},
    }

    def page_handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("start") == "1":
            return httpx.Response(200, json=pages_b)
        return httpx.Response(200, json=pages_a)

    transport = _routes(
        {
            f"{base}/rest/api/space/ENG/content/page": page_handler,
            f"{base}/rest/api/content/p-a/child/comment": {
                "results": [],
                "_links": {},
            },
            f"{base}/rest/api/content/p-a/child/attachment": {
                "results": [],
                "_links": {},
            },
            f"{base}/rest/api/content/p-b/child/comment": {
                "results": [],
                "_links": {},
            },
            f"{base}/rest/api/content/p-b/child/attachment": {
                "results": [],
                "_links": {},
            },
        }
    )
    c = ConfluenceConnector(
        flavor="cloud",
        base_url=base_url,
        token="t",
        spaces=("ENG",),
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert [r.metadata["page_id"] for r in refs] == ["p-a", "p-b"]
