"""Jira connector tests using httpx.MockTransport."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.jira import (
    JiraConnector,
    _build_jql,
    _decode_cursor,
    _display_name,
    _host_only,
    _named,
    _parse_iso,
    _resolve_auth,
)
from saas_retriever.connectors.jira_adf import adf_to_text
from saas_retriever.connectors.jira_storage import storage_to_text
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


def test_build_jql_orders_by_updated_asc() -> None:
    assert _build_jql("ENG", None) == 'project = "ENG" ORDER BY updated ASC'
    assert (
        _build_jql("ENG", "2026-05-01T00:00:00Z")
        == 'project = "ENG" AND updated >= "2026-05-01T00:00:00Z" ORDER BY updated ASC'
    )


def test_decode_cursor_round_trips() -> None:
    cursor = '{"highest_updated": "2026-05-04T12:34:56Z"}'
    assert _decode_cursor(cursor) == "2026-05-04T12:34:56Z"
    assert _decode_cursor(None) is None
    assert _decode_cursor("not-json") is None
    assert _decode_cursor('{"other":"field"}') is None


def test_parse_iso_normalises_offset() -> None:
    parsed = _parse_iso("2026-05-04T12:34:56.789+0000")
    assert parsed is not None
    assert parsed.year == 2026


def test_named_and_display_name_extract_fields() -> None:
    assert _named({"name": "Done"}) == "Done"
    assert _named(None) == ""
    assert _display_name({"displayName": "Alice", "name": "ali"}) == "Alice"
    assert _display_name({"name": "ali"}) == "ali"
    assert _display_name(None) == ""


def test_host_only_strips_scheme_and_path() -> None:
    assert _host_only("https://acme.atlassian.net/wiki") == "acme.atlassian.net"
    assert _host_only("http://jira.internal") == "jira.internal"


def test_adf_to_text_handles_paragraph() -> None:
    doc = {
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "AKIAIOSFODNN7EXAMPLE"},
                ],
            }
        ],
    }
    assert "AKIAIOSFODNN7EXAMPLE" in adf_to_text(doc)


def test_storage_to_text_strips_html() -> None:
    assert "secret" in storage_to_text("<p>secret</p>")


# --- auth resolution ---------------------------------------------------


def test_auth_access_token_wins() -> None:
    auth = _resolve_auth(
        credential=None,
        email=None,
        api_token=None,
        access_token="tok",
        username=None,
        password=None,
    )
    assert auth.header_value() == "Bearer tok"


def test_auth_cloud_basic() -> None:
    auth = _resolve_auth(
        credential=None,
        email="alice@example.com",
        api_token="api-tok",
        access_token=None,
        username=None,
        password=None,
    )
    assert auth.header_value().startswith("Basic ")


def test_auth_dc_basic() -> None:
    auth = _resolve_auth(
        credential=None,
        email=None,
        api_token=None,
        access_token=None,
        username="alice",
        password="pass",
    )
    assert auth.header_value().startswith("Basic ")


def test_auth_credential_token() -> None:
    cred = Credential(kind="jira", payload={"access_token": "from-cred"})
    auth = _resolve_auth(
        credential=cred,
        email=None,
        api_token=None,
        access_token=None,
        username=None,
        password=None,
    )
    assert auth.header_value() == "Bearer from-cred"


def test_auth_raises_when_nothing_supplied() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        _resolve_auth(
            credential=None,
            email=None,
            api_token=None,
            access_token=None,
            username=None,
            password=None,
        )


# --- construction ------------------------------------------------------


def test_unknown_flavor_rejected() -> None:
    with pytest.raises(ValueError, match="flavor"):
        JiraConnector(
            flavor="github",  # type: ignore[arg-type]
            base_url="https://x",
            access_token="t",
        )


def test_base_url_required_and_validated() -> None:
    with pytest.raises(ValueError, match="base_url"):
        JiraConnector(flavor="cloud", base_url="", access_token="t")
    with pytest.raises(ValueError, match="http"):
        JiraConnector(flavor="cloud", base_url="acme.atlassian.net", access_token="t")


def test_default_id_uses_flavor_and_host() -> None:
    c = JiraConnector(
        flavor="cloud",
        base_url="https://acme.atlassian.net",
        access_token="t",
    )
    assert c.id == "jira-cloud:acme.atlassian.net"


# --- end-to-end --------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_walks_projects_and_issues() -> None:
    base_url = "https://acme.atlassian.net"
    project_search = {
        "values": [{"key": "ENG"}, {"key": "OPS"}],
        "isLast": True,
    }
    issues_eng = {
        "issues": [
            {
                "key": "ENG-1",
                "fields": {
                    "summary": "leak",
                    "updated": "2026-05-01T00:00:00.000+0000",
                    "description": {
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {"type": "text", "text": "AKIAIOSFODNN7EXAMPLE"}
                                ],
                            }
                        ],
                    },
                    "status": {"name": "Open"},
                    "assignee": {"displayName": "Alice"},
                    "reporter": {"displayName": "Bob"},
                    "attachment": [
                        {"filename": "leak.txt", "content": "https://x/a/leak.txt"},
                    ],
                },
            }
        ],
        "total": 1,
    }
    issues_ops: dict[str, Any] = {"issues": [], "total": 0}
    comments_eng_1 = {
        "comments": [
            {
                "id": "10001",
                "author": {"displayName": "Charlie"},
                "body": {
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": "lgtm"}],
                        }
                    ],
                },
            }
        ],
        "total": 1,
    }

    transport = _routes(
        {
            "/rest/api/3/project/search": project_search,
            "/rest/api/3/search": lambda r: httpx.Response(
                200,
                json=issues_eng if 'project = "ENG"' in r.url.params.get("jql", "") else issues_ops,
            ),
            "/rest/api/3/issue/ENG-1/comment": comments_eng_1,
        }
    )

    c = JiraConnector(
        flavor="cloud",
        base_url=base_url,
        access_token="t",
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    assert len(refs) == 1
    assert refs[0].metadata["key"] == "ENG-1"
    assert refs[0].metadata["project"] == "ENG"
    assert refs[0].path == "jira://ENG/ENG-1"
    assert refs[0].native_url == "https://acme.atlassian.net/browse/ENG-1"

    docs = [d async for d in c.fetch(refs[0])]
    await c.close()
    text = docs[0].text
    assert "key=ENG-1" in text
    assert "summary=leak" in text
    assert "status=Open" in text
    assert "assignee=Alice" in text
    assert "reporter=Bob" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text
    assert "comment[10001]=Charlie: lgtm" in text
    assert "attachment=leak.txt, url=https://x/a/leak.txt" in text


@pytest.mark.asyncio
async def test_discover_skips_project_listing_when_allowlist_supplied() -> None:
    base_url = "https://acme.atlassian.net"
    issues = {"issues": [], "total": 0}
    transport = _routes(
        {
            "/rest/api/3/search": issues,
        }
    )
    c = JiraConnector(
        flavor="cloud",
        base_url=base_url,
        access_token="t",
        projects=("ENG",),
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert refs == []


@pytest.mark.asyncio
async def test_discover_includes_since_clause_in_jql() -> None:
    base_url = "https://acme.atlassian.net"
    seen: dict[str, str] = {}

    def search(request: httpx.Request) -> httpx.Response:
        seen["jql"] = request.url.params.get("jql", "")
        return httpx.Response(200, json={"issues": [], "total": 0})

    transport = _routes({"/rest/api/3/search": search})
    c = JiraConnector(
        flavor="cloud",
        base_url=base_url,
        access_token="t",
        projects=("ENG",),
        transport=transport,
    )
    cursor = '{"highest_updated":"2026-01-01T00:00:00Z"}'
    refs = [r async for r in c.discover(SourceFilter(), cursor=cursor)]
    await c.close()
    assert refs == []
    assert 'updated >= "2026-01-01T00:00:00Z"' in seen["jql"]


@pytest.mark.asyncio
async def test_dc_503_eventually_raises_rate_limited() -> None:
    base_url = "https://jira.internal"

    def overload(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, headers={"Retry-After": "0"})

    transport = _routes({"/rest/api/2/search": overload})
    c = JiraConnector(
        flavor="datacenter",
        base_url=base_url,
        access_token="t",
        projects=("ENG",),
        transport=transport,
    )
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_cursor_after_run_serialises_high_water() -> None:
    base_url = "https://acme.atlassian.net"
    issues = {
        "issues": [
            {
                "key": "ENG-1",
                "fields": {
                    "summary": "x",
                    "updated": "2026-05-04T12:34:56.789+0000",
                    "description": "",
                },
            }
        ],
        "total": 1,
    }
    transport = _routes(
        {
            "/rest/api/3/search": issues,
            "/rest/api/3/issue/ENG-1/comment": {"comments": [], "total": 0},
        }
    )
    c = JiraConnector(
        flavor="cloud",
        base_url=base_url,
        access_token="t",
        projects=("ENG",),
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    cursor = c.cursor_after_run()
    await c.close()
    assert len(refs) == 1
    assert cursor is not None
    assert "2026-05-04T12:34:56.789+0000" in cursor


@pytest.mark.asyncio
async def test_dc_uses_storage_format_for_description() -> None:
    base_url = "https://jira.internal"
    issues = {
        "issues": [
            {
                "key": "ENG-2",
                "fields": {
                    "summary": "x",
                    "updated": "2026-05-04T12:34:56.789+0000",
                    "description": "<p>secret <strong>AKIA</strong></p>",
                },
            }
        ],
        "total": 1,
    }
    transport = _routes(
        {
            "/rest/api/2/search": issues,
            "/rest/api/2/issue/ENG-2/comment": {"comments": [], "total": 0},
        }
    )
    c = JiraConnector(
        flavor="datacenter",
        base_url=base_url,
        access_token="t",
        projects=("ENG",),
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    docs = [d async for d in c.fetch(refs[0])]
    await c.close()
    assert "secret" in docs[0].text
    assert "AKIA" in docs[0].text
