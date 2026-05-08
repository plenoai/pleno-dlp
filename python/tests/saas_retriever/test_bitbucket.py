"""Bitbucket connector tests using httpx.MockTransport.

Every HTTP call is intercepted so the suite never touches bitbucket.org
or any Server installation. Routes return 404 by default so a missing
mock fails loudly rather than passing silently.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.bitbucket import (
    DEFAULT_CLOUD_BASE_URL,
    DEFAULT_RESOURCES,
    BitbucketConnector,
    _join_issue_text_cloud,
    _join_pr_text_cloud,
    _join_pr_text_server,
    _principal_cloud,
    _principal_server,
    _quote_path,
    _resolve_auth,
    _retry_after_seconds,
)
from saas_retriever.core import SourceFilter
from saas_retriever.credentials import Credential, CredentialMisconfiguredError

# --- routing helpers ----------------------------------------------------


def _routes(handler_map: dict[str, Any]) -> httpx.MockTransport:
    """Build a MockTransport keyed by URL path prefix.

    Values are either a static dict / list / Response, or a callable
    receiving the request. A list is popped one element per call so a
    test can sequence pages.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, payload in handler_map.items():
            if path == prefix:
                if callable(payload):
                    return payload(request)
                if isinstance(payload, list):
                    if not payload:
                        return httpx.Response(404)
                    return _make_response(payload.pop(0))
                return _make_response(payload)
        return httpx.Response(404, json={"message": "not found", "path": path})

    return httpx.MockTransport(handler)


def _make_response(spec: Any) -> httpx.Response:
    if isinstance(spec, httpx.Response):
        return spec
    if isinstance(spec, dict) and "status_code" in spec:
        return httpx.Response(
            spec["status_code"],
            json=spec.get("json"),
            headers=spec.get("headers", {}),
            content=spec.get("content"),
        )
    return httpx.Response(200, json=spec)


# --- pure helpers -------------------------------------------------------


def test_default_resources_covers_all() -> None:
    assert DEFAULT_RESOURCES == frozenset({"code", "issues", "prs"})


def test_quote_path_keeps_segment_separators() -> None:
    assert _quote_path("a/b c/d.txt") == "a/b%20c/d.txt"
    assert _quote_path("foo/bar?baz") == "foo/bar%3Fbaz"
    assert _quote_path("simple") == "simple"


def test_retry_after_seconds_parses_numeric_header() -> None:
    r = httpx.Response(429, headers={"Retry-After": "12"})
    assert _retry_after_seconds(r) == 12.0


def test_retry_after_seconds_falls_back_when_missing() -> None:
    r = httpx.Response(429)
    assert _retry_after_seconds(r) > 0


def test_retry_after_seconds_falls_back_on_garbage() -> None:
    r = httpx.Response(429, headers={"Retry-After": "soon"})
    assert _retry_after_seconds(r) > 0


def test_principal_cloud_extracts_uuid_and_display_name() -> None:
    p = _principal_cloud({"uuid": "{abc}", "display_name": "Alice", "nickname": "ali"})
    assert p is not None
    assert p.id == "{abc}"
    assert p.display_name == "Alice"


def test_principal_server_carries_email() -> None:
    p = _principal_server({"id": 1, "name": "alice", "displayName": "Alice", "emailAddress": "a@x"})
    assert p is not None
    assert p.email == "a@x"
    assert p.display_name == "Alice"


def test_join_issue_text_cloud() -> None:
    text = _join_issue_text_cloud(
        {"title": "leak", "content": {"raw": "AKIAIOSFODNN7EXAMPLE"}},
        [{"content": {"raw": "thanks"}}, {"content": {"raw": ""}}, {"content": {"raw": "again"}}],
    )
    assert "leak" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text
    assert "thanks" in text
    assert "again" in text


def test_join_pr_text_cloud_includes_diff() -> None:
    text = _join_pr_text_cloud(
        {"title": "fix", "description": "rotate"},
        [{"content": {"raw": "lgtm"}}],
        "@@ -1 +1 @@\n-OLD=secret\n+NEW=stub",
    )
    assert "fix" in text
    assert "rotate" in text
    assert "lgtm" in text
    assert "OLD=secret" in text


def test_join_pr_text_server_extracts_commented_activities() -> None:
    text = _join_pr_text_server(
        {"title": "fix", "description": "rotate"},
        [
            {"action": "OPENED"},
            {"action": "COMMENTED", "comment": {"text": "review nit"}},
            {"action": "MERGED"},
        ],
        "diff body",
    )
    assert "review nit" in text
    assert "OPENED" not in text
    assert "diff body" in text


# --- auth resolution ----------------------------------------------------


def test_auth_prefers_explicit_token_over_credential() -> None:
    cred = Credential(kind="bitbucket", payload={"token": "from-cred"})
    auth = _resolve_auth(
        flavor="cloud",
        credential=cred,
        username=None,
        app_password=None,
        password=None,
        token="explicit",
    )
    assert auth.header_value() == "Bearer explicit"


def test_auth_uses_credential_token_when_no_explicit_token() -> None:
    cred = Credential(kind="bitbucket", payload={"token": "from-cred"})
    auth = _resolve_auth(
        flavor="cloud",
        credential=cred,
        username=None,
        app_password=None,
        password=None,
        token=None,
    )
    assert auth.header_value() == "Bearer from-cred"


def test_auth_basic_cloud_uses_app_password() -> None:
    auth = _resolve_auth(
        flavor="cloud",
        credential=None,
        username="alice",
        app_password="secret",
        password=None,
        token=None,
    )
    assert auth.header_value().startswith("Basic ")


def test_auth_basic_server_uses_password() -> None:
    auth = _resolve_auth(
        flavor="server",
        credential=None,
        username="alice",
        app_password=None,
        password="pat",
        token=None,
    )
    assert auth.header_value().startswith("Basic ")


def test_auth_raises_when_neither_basic_nor_token() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        _resolve_auth(
            flavor="cloud",
            credential=None,
            username=None,
            app_password=None,
            password=None,
            token=None,
        )


def test_auth_raises_when_username_without_secret() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        _resolve_auth(
            flavor="cloud",
            credential=None,
            username="alice",
            app_password=None,
            password=None,
            token=None,
        )


# --- construction validation -------------------------------------------


def test_unknown_flavor_rejected() -> None:
    with pytest.raises(ValueError, match="flavor"):
        BitbucketConnector(flavor="github", workspace="x", token="t")  # type: ignore[arg-type]


def test_cloud_requires_workspace() -> None:
    with pytest.raises(ValueError, match="workspace"):
        BitbucketConnector(flavor="cloud", token="t")


def test_server_requires_project_and_base_url() -> None:
    with pytest.raises(ValueError, match="project"):
        BitbucketConnector(flavor="server", base_url="https://b/rest/api/1.0", token="t")
    with pytest.raises(ValueError, match="base_url"):
        BitbucketConnector(flavor="server", project="P", token="t")


def test_unknown_resource_rejected() -> None:
    with pytest.raises(ValueError, match="resources"):
        BitbucketConnector(
            flavor="cloud", workspace="acme", token="t", resources={"branches"}
        )


def test_server_drops_issues_silently() -> None:
    c = BitbucketConnector(
        flavor="server",
        project="ENG",
        base_url="https://b.example/rest/api/1.0",
        token="t",
        resources={"code", "issues", "prs"},
    )
    assert "issues" not in c.resources
    assert "code" in c.resources and "prs" in c.resources


def test_capabilities_marks_binary_only() -> None:
    c = BitbucketConnector(flavor="cloud", workspace="acme", token="t")
    caps = c.capabilities()
    assert caps.binary is True
    assert caps.streaming is False
    assert caps.incremental is False


def test_default_id_includes_flavor_and_scope() -> None:
    c = BitbucketConnector(flavor="cloud", workspace="acme", repo_slug="r", token="t")
    assert c.id == "bitbucket:cloud:acme/r"
    s = BitbucketConnector(
        flavor="server", project="ENG", base_url="https://b/rest/api/1.0", token="t"
    )
    assert s.id == "bitbucket:server:ENG"


# --- end-to-end Cloud --------------------------------------------------


@pytest.mark.asyncio
async def test_cloud_discover_walks_repo_tree_and_emits_blob_refs() -> None:
    workspace = "acme"
    slug = "alpha"
    branch = "main"
    repo_meta = {
        "slug": slug,
        "name": slug,
        "workspace": {"slug": workspace},
        "mainbranch": {"name": branch},
        "has_issues": False,
    }
    src_root = {
        "values": [
            {"type": "commit_directory", "path": "lib"},
            {
                "type": "commit_file",
                "path": "README.md",
                "size": 12,
                "commit": {"hash": "deadbeef"},
            },
        ],
    }
    src_lib = {
        "values": [
            {
                "type": "commit_file",
                "path": "lib/util.py",
                "size": 50,
                "commit": {"hash": "deadbeef"},
            },
        ],
    }

    base = "/2.0"

    def src_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == f"{base}/repositories/{workspace}/{slug}/src/{branch}":
            return httpx.Response(200, json=src_root)
        if path == f"{base}/repositories/{workspace}/{slug}/src/{branch}/lib":
            return httpx.Response(200, json=src_lib)
        return httpx.Response(404)

    transport = _routes(
        {
            f"{base}/repositories/{workspace}/{slug}": repo_meta,
            f"{base}/repositories/{workspace}/{slug}/src/{branch}": src_handler,
            f"{base}/repositories/{workspace}/{slug}/src/{branch}/lib": src_handler,
            f"{base}/repositories/{workspace}/{slug}/pullrequests": {"values": []},
        }
    )

    c = BitbucketConnector(
        flavor="cloud",
        workspace=workspace,
        repo_slug=slug,
        token="t",
        transport=transport,
        resources={"code", "prs"},
        base_url=DEFAULT_CLOUD_BASE_URL,
    )
    refs = []
    async for ref in c.discover(SourceFilter()):
        refs.append(ref)
    await c.close()

    paths = sorted(r.metadata["blob_path"] for r in refs)
    assert paths == ["README.md", "lib/util.py"]
    assert all(r.metadata["resource_type"] == "code" for r in refs)
    assert all(r.metadata["commit"] == "deadbeef" for r in refs)


@pytest.mark.asyncio
async def test_cloud_fetch_blob_returns_text_when_utf8() -> None:
    workspace = "acme"
    slug = "alpha"
    branch = "main"
    base = "/2.0"

    def blob_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello world")

    transport = _routes(
        {
            f"{base}/repositories/{workspace}/{slug}": {
                "slug": slug,
                "workspace": {"slug": workspace},
                "mainbranch": {"name": branch},
            },
            f"{base}/repositories/{workspace}/{slug}/src/deadbeef/README.md": blob_handler,
        }
    )
    c = BitbucketConnector(
        flavor="cloud",
        workspace=workspace,
        repo_slug=slug,
        token="t",
        transport=transport,
        resources={"code"},
    )
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id=c.id,
        source_kind="bitbucket",
        path=f"{workspace}/{slug}:README.md",
        metadata={
            "flavor": "cloud",
            "workspace": workspace,
            "repo": slug,
            "branch": branch,
            "blob_path": "README.md",
            "commit": "deadbeef",
            "resource_type": "code",
        },
    )
    docs = []
    async for doc in c.fetch(ref):
        docs.append(doc)
    await c.close()
    assert len(docs) == 1
    assert docs[0].text == "hello world"
    assert docs[0].binary is None
    assert docs[0].content_hash == "sha1:deadbeef"


@pytest.mark.asyncio
async def test_cloud_fetch_blob_falls_back_to_binary_when_not_utf8() -> None:
    workspace = "acme"
    slug = "alpha"
    branch = "main"
    base = "/2.0"
    payload = b"\xff\xfe\xfd"  # invalid UTF-8

    transport = _routes(
        {
            f"{base}/repositories/{workspace}/{slug}/src/deadbeef/blob.bin": httpx.Response(
                200, content=payload
            ),
        }
    )
    c = BitbucketConnector(
        flavor="cloud",
        workspace=workspace,
        repo_slug=slug,
        token="t",
        transport=transport,
        resources={"code"},
    )
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id=c.id,
        source_kind="bitbucket",
        path=f"{workspace}/{slug}:blob.bin",
        metadata={
            "flavor": "cloud",
            "workspace": workspace,
            "repo": slug,
            "branch": branch,
            "blob_path": "blob.bin",
            "commit": "deadbeef",
            "resource_type": "code",
        },
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert docs[0].text is None
    assert docs[0].binary == payload


@pytest.mark.asyncio
async def test_cloud_pagination_follows_next_url() -> None:
    workspace = "acme"
    slug = "alpha"
    base = "/2.0"
    first = {
        "values": [{"id": 1, "title": "A"}, {"id": 2, "title": "B"}],
        "next": f"https://api.bitbucket.org{base}/repositories/{workspace}/{slug}/pullrequests?page=2",
    }
    second = {"values": [{"id": 3, "title": "C"}]}

    transport = _routes(
        {
            f"{base}/repositories/{workspace}/{slug}": {
                "slug": slug,
                "workspace": {"slug": workspace},
                "mainbranch": {"name": "main"},
            },
            f"{base}/repositories/{workspace}/{slug}/pullrequests": [first, second],
        }
    )
    c = BitbucketConnector(
        flavor="cloud",
        workspace=workspace,
        repo_slug=slug,
        token="t",
        transport=transport,
        resources={"prs"},
    )
    refs = [ref async for ref in c.discover(SourceFilter())]
    await c.close()
    assert [r.metadata["number"] for r in refs] == ["1", "2", "3"]
    assert all(r.metadata["resource_type"] == "pr" for r in refs)


@pytest.mark.asyncio
async def test_cloud_429_eventually_raises_rate_limited() -> None:
    from saas_retriever.rate_limit import RateLimited

    workspace = "acme"
    slug = "alpha"
    base = "/2.0"

    def always_throttle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    transport = _routes(
        {
            f"{base}/repositories/{workspace}/{slug}": always_throttle,
        }
    )
    c = BitbucketConnector(
        flavor="cloud",
        workspace=workspace,
        repo_slug=slug,
        token="t",
        transport=transport,
        resources={"code"},
    )
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


# --- end-to-end Server -------------------------------------------------


@pytest.mark.asyncio
async def test_server_discover_walks_files_endpoint_and_paginates() -> None:
    base = "/rest/api/1.0"
    project = "ENG"
    slug = "alpha"

    page1 = {
        "values": ["src/a.py", "src/b.py"],
        "size": 2,
        "isLastPage": False,
        "nextPageStart": 2,
    }
    page2 = {
        "values": ["src/c.py"],
        "size": 1,
        "isLastPage": True,
    }

    def files_handler(request: httpx.Request) -> httpx.Response:
        start = request.url.params.get("start", "0")
        if start == "0":
            return httpx.Response(200, json=page1)
        if start == "2":
            return httpx.Response(200, json=page2)
        return httpx.Response(404)

    transport = _routes(
        {
            f"{base}/projects/{project}/repos/{slug}": {
                "slug": slug,
                "project": {"key": project},
            },
            f"{base}/projects/{project}/repos/{slug}/branches/default": {
                "id": "refs/heads/main",
                "displayId": "main",
            },
            f"{base}/projects/{project}/repos/{slug}/files": files_handler,
            f"{base}/projects/{project}/repos/{slug}/pull-requests": {
                "values": [],
                "isLastPage": True,
            },
        }
    )

    c = BitbucketConnector(
        flavor="server",
        project=project,
        repo_slug=slug,
        base_url=f"https://b.example{base}",
        token="t",
        transport=transport,
        resources={"code", "prs"},
    )
    refs = [ref async for ref in c.discover(SourceFilter())]
    await c.close()
    paths = sorted(r.metadata["blob_path"] for r in refs)
    assert paths == ["src/a.py", "src/b.py", "src/c.py"]
    assert all(r.metadata["resource_type"] == "code" for r in refs)
    assert all(r.metadata["branch"] == "main" for r in refs)


@pytest.mark.asyncio
async def test_server_fetch_blob_uses_raw_endpoint() -> None:
    base = "/rest/api/1.0"
    project = "ENG"
    slug = "alpha"

    def raw_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("at") == "main"
        return httpx.Response(200, content=b"server text")

    transport = _routes(
        {
            f"{base}/projects/{project}/repos/{slug}/raw/src/a.py": raw_handler,
        }
    )
    c = BitbucketConnector(
        flavor="server",
        project=project,
        repo_slug=slug,
        base_url=f"https://b.example{base}",
        token="t",
        transport=transport,
        resources={"code"},
    )
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id=c.id,
        source_kind="bitbucket",
        path=f"{project}/{slug}:src/a.py",
        metadata={
            "flavor": "server",
            "project": project,
            "repo": slug,
            "branch": "main",
            "blob_path": "src/a.py",
            "resource_type": "code",
        },
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert docs[0].text == "server text"


@pytest.mark.asyncio
async def test_server_pr_uses_activities_endpoint_and_filters_since() -> None:
    base = "/rest/api/1.0"
    project = "ENG"
    slug = "alpha"

    pr_list = {
        "values": [
            {"id": 1, "title": "old", "updatedDate": 1_000_000},
            {"id": 2, "title": "new", "updatedDate": 1_900_000_000_000},
        ],
        "isLastPage": True,
    }

    transport = _routes(
        {
            f"{base}/projects/{project}/repos/{slug}": {
                "slug": slug,
                "project": {"key": project},
            },
            f"{base}/projects/{project}/repos/{slug}/branches/default": {
                "displayId": "main"
            },
            f"{base}/projects/{project}/repos/{slug}/pull-requests": pr_list,
        }
    )
    c = BitbucketConnector(
        flavor="server",
        project=project,
        repo_slug=slug,
        base_url=f"https://b.example{base}",
        token="t",
        transport=transport,
        resources={"prs"},
    )
    from datetime import UTC, datetime

    flt = SourceFilter(since=datetime(2025, 1, 1, tzinfo=UTC))
    refs = [r async for r in c.discover(flt)]
    await c.close()
    assert [r.metadata["number"] for r in refs] == ["2"]
