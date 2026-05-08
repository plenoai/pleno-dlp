"""GitHub API connector tests using httpx.MockTransport.

Every HTTP call is intercepted so the suite never touches api.github.com.
Each test installs a route handler keyed on URL path; unmatched URLs
return 404 so a missing route fails loudly rather than silently passing.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.github import (
    DEFAULT_RESOURCES,
    GitHubConnector,
    _join_issue_text,
    _join_pr_text,
    _next_link,
    _parse_ts,
)
from saas_retriever.core import SourceFilter


def _routes(handler_map: dict[str, Any]) -> httpx.MockTransport:
    """Build a MockTransport that dispatches by URL path prefix.

    Each value is either a list (single response) or a callable that
    receives the request and returns ``httpx.Response``. Lists are
    consumed one element per call so a test can sequence responses.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        params = dict(request.url.params)
        for prefix, payload in handler_map.items():
            if path == prefix:
                if callable(payload):
                    return payload(request)
                if isinstance(payload, list):
                    if not payload:
                        return httpx.Response(404)
                    return _make_response(payload.pop(0), request, params)
                return _make_response(payload, request, params)
        return httpx.Response(404, json={"message": "not found", "path": path})

    return httpx.MockTransport(handler)


def _make_response(spec: Any, request: httpx.Request, params: dict[str, str]) -> httpx.Response:
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


def test_next_link_picks_rel_next() -> None:
    h = (
        '<https://api.github.com/repos/x/y/issues?page=2>; rel="next", '
        '<https://api.github.com/repos/x/y/issues?page=10>; rel="last"'
    )
    assert _next_link(h) == "https://api.github.com/repos/x/y/issues?page=2"


def test_next_link_returns_none_when_no_next() -> None:
    h = '<https://api.github.com/x?page=1>; rel="last"'
    assert _next_link(h) is None
    assert _next_link("") is None


def test_parse_ts_handles_z_suffix() -> None:
    parsed = _parse_ts("2026-05-06T12:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026
    assert parsed.tzinfo is not None


def test_join_issue_text_concatenates_title_body_comments() -> None:
    text = _join_issue_text(
        {"title": "leak", "body": "AKIAIOSFODNN7EXAMPLE"},
        [{"body": "thanks"}, {"body": ""}, {"body": "more"}],
    )
    assert "leak" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text
    assert "thanks" in text
    assert "more" in text


def test_join_pr_text_includes_diff() -> None:
    text = _join_pr_text(
        {"title": "fix", "body": "rotate"},
        [{"body": "lgtm"}],
        [{"body": "review nit"}],
        "@@ -1 +1 @@\n-OLD=ghp_abc\n+NEW=stub",
    )
    assert "fix" in text
    assert "rotate" in text
    assert "lgtm" in text
    assert "review nit" in text
    assert "OLD=ghp_abc" in text


# --- construction validation -------------------------------------------


def test_default_resources_covers_all() -> None:
    assert DEFAULT_RESOURCES == frozenset({"code", "issues", "prs"})


def test_unknown_resource_rejected() -> None:
    with pytest.raises(ValueError, match="unknown resources"):
        GitHubConnector(owner="plenoai", resources={"discussions"})


def test_explicit_token_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    monkeypatch.setattr(
        "saas_retriever.connectors.github.shutil.which",
        lambda _: None,
    )
    conn = GitHubConnector(owner="plenoai", token="explicit")
    assert conn.token == "explicit"


def test_token_from_env_when_not_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    monkeypatch.setattr(
        "saas_retriever.connectors.github.shutil.which",
        lambda _: None,
    )
    conn = GitHubConnector(owner="plenoai")
    assert conn.token == "from-env"


# --- repo listing -------------------------------------------------------


@pytest.mark.asyncio
async def test_list_repos_org_path_paginates_and_skips_archived() -> None:
    page1 = [
        {"name": "alpha", "owner": {"login": "plenoai"}, "default_branch": "main", "archived": False},
        {"name": "archived-thing", "owner": {"login": "plenoai"}, "default_branch": "main", "archived": True},
    ]
    page2 = [
        {"name": "beta", "owner": {"login": "plenoai"}, "default_branch": "main", "archived": False},
    ]
    page1_resp = httpx.Response(
        200,
        json=page1,
        headers={"Link": '<https://api.github.com/orgs/plenoai/repos?page=2>; rel="next"'},
    )
    page2_resp = httpx.Response(200, json=page2)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/orgs/plenoai/repos":
            calls["n"] += 1
            return page1_resp if calls["n"] == 1 else page2_resp
        return httpx.Response(404)

    conn = GitHubConnector(
        owner="plenoai",
        token="x",
        transport=httpx.MockTransport(handler),
    )
    repos = await conn._list_repos()
    names = [r["name"] for r in repos]
    assert names == ["alpha", "beta"]  # archived dropped, paginated through both pages
    await conn.close()


@pytest.mark.asyncio
async def test_list_repos_falls_back_to_user_endpoint_on_org_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/orgs/hikae/repos":
            return httpx.Response(404, json={"message": "Not Found"})
        if request.url.path == "/users/hikae/repos":
            return httpx.Response(
                200,
                json=[{"name": "personal", "owner": {"login": "hikae"}, "default_branch": "main"}],
            )
        return httpx.Response(404)

    conn = GitHubConnector(owner="hikae", token="x", transport=httpx.MockTransport(handler))
    repos = await conn._list_repos()
    assert [r["name"] for r in repos] == ["personal"]
    await conn.close()


@pytest.mark.asyncio
async def test_list_repos_single_repo_mode_skips_enumeration() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/plenoai/saas-retriever":
            return httpx.Response(
                200,
                json={
                    "name": "saas-retriever",
                    "owner": {"login": "plenoai"},
                    "default_branch": "main",
                },
            )
        return httpx.Response(500)  # the org endpoint must NOT be hit

    conn = GitHubConnector(
        owner="plenoai",
        repo="saas-retriever",
        token="x",
        transport=httpx.MockTransport(handler),
    )
    repos = await conn._list_repos()
    assert [r["name"] for r in repos] == ["saas-retriever"]
    await conn.close()


# --- discover (code / issues / PRs) ------------------------------------


@pytest.mark.asyncio
async def test_discover_code_yields_blob_refs_and_skips_trees() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/plenoai/saas-retriever":
            return httpx.Response(
                200,
                json={"name": "saas-retriever", "owner": {"login": "plenoai"}, "default_branch": "main"},
            )
        if request.url.path == "/repos/plenoai/saas-retriever/git/trees/main":
            return httpx.Response(
                200,
                json={
                    "tree": [
                        {"type": "blob", "path": "README.md", "sha": "aaa", "size": 100},
                        {"type": "tree", "path": "src", "sha": "bbb"},
                        {"type": "blob", "path": "src/__init__.py", "sha": "ccc", "size": 0},
                    ]
                },
            )
        return httpx.Response(404)

    conn = GitHubConnector(
        owner="plenoai",
        repo="saas-retriever",
        token="x",
        resources={"code"},
        transport=httpx.MockTransport(handler),
    )
    refs = [r async for r in conn.discover(SourceFilter())]
    paths = sorted(r.path for r in refs)
    assert paths == ["plenoai/saas-retriever:README.md", "plenoai/saas-retriever:src/__init__.py"]
    assert refs[0].metadata["resource_type"] == "code"
    assert refs[0].metadata["sha"] == "aaa"
    await conn.close()


@pytest.mark.asyncio
async def test_discover_issues_skips_pull_requests() -> None:
    """The /issues endpoint mixes PRs into the response. The connector
    must filter them out so PRs aren't double-emitted (we get them via
    /pulls separately)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/plenoai/saas-retriever":
            return httpx.Response(
                200,
                json={"name": "saas-retriever", "owner": {"login": "plenoai"}, "default_branch": "main"},
            )
        if request.url.path == "/repos/plenoai/saas-retriever/issues":
            return httpx.Response(
                200,
                json=[
                    {"number": 1, "title": "real issue", "html_url": "...", "updated_at": "2026-05-06T00:00:00Z"},
                    {"number": 2, "title": "looks like issue but is PR", "pull_request": {"url": "..."}},
                    {"number": 3, "title": "another real one"},
                ],
            )
        return httpx.Response(404)

    conn = GitHubConnector(
        owner="plenoai",
        repo="saas-retriever",
        token="x",
        resources={"issues"},
        transport=httpx.MockTransport(handler),
    )
    refs = [r async for r in conn.discover(SourceFilter())]
    numbers = [r.metadata["number"] for r in refs]
    assert numbers == ["1", "3"]
    assert all(r.metadata["resource_type"] == "issue" for r in refs)
    await conn.close()


@pytest.mark.asyncio
async def test_discover_prs_emits_pull_refs() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/plenoai/saas-retriever":
            return httpx.Response(
                200,
                json={"name": "saas-retriever", "owner": {"login": "plenoai"}, "default_branch": "main"},
            )
        if request.url.path == "/repos/plenoai/saas-retriever/pulls":
            return httpx.Response(
                200,
                json=[
                    {"number": 42, "title": "rotate token", "html_url": "...", "updated_at": "2026-05-06T00:00:00Z"},
                ],
            )
        return httpx.Response(404)

    conn = GitHubConnector(
        owner="plenoai",
        repo="saas-retriever",
        token="x",
        resources={"prs"},
        transport=httpx.MockTransport(handler),
    )
    refs = [r async for r in conn.discover(SourceFilter())]
    assert [r.path for r in refs] == ["plenoai/saas-retriever:pull/42"]
    assert refs[0].metadata["resource_type"] == "pr"
    await conn.close()


# --- fetch (blob / issue / PR) -----------------------------------------


@pytest.mark.asyncio
async def test_fetch_blob_decodes_utf8() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/plenoai/saas-retriever/git/blobs/aaa":
            assert request.headers.get("Accept") == "application/vnd.github.raw"
            return httpx.Response(200, content=b"hello world")
        return httpx.Response(404)

    conn = GitHubConnector(
        owner="plenoai",
        repo="saas-retriever",
        token="x",
        transport=httpx.MockTransport(handler),
    )
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id="x",
        source_kind="github",
        path="plenoai/saas-retriever:README.md",
        metadata={
            "owner": "plenoai",
            "repo": "saas-retriever",
            "sha": "aaa",
            "resource_type": "code",
        },
    )
    docs = [d async for d in conn.fetch(ref)]
    assert docs[0].text == "hello world"
    assert docs[0].binary is None
    assert docs[0].content_hash == "sha1:aaa"
    await conn.close()


@pytest.mark.asyncio
async def test_fetch_blob_falls_back_to_binary() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/git/blobs/" in request.url.path:
            return httpx.Response(200, content=b"\x00\x01\x02\xff")
        return httpx.Response(404)

    conn = GitHubConnector(owner="x", repo="y", token="x", transport=httpx.MockTransport(handler))
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id="s",
        source_kind="github",
        path="x/y:f.bin",
        metadata={"owner": "x", "repo": "y", "sha": "z", "resource_type": "code"},
    )
    docs = [d async for d in conn.fetch(ref)]
    assert docs[0].binary == b"\x00\x01\x02\xff"
    assert docs[0].text is None
    await conn.close()


@pytest.mark.asyncio
async def test_fetch_issue_collects_body_and_comments() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/x/y/issues/1":
            return httpx.Response(
                200,
                json={
                    "number": 1,
                    "title": "leak",
                    "body": "AKIAIOSFODNN7EXAMPLE",
                    "user": {"id": 99, "login": "alice"},
                },
            )
        if path == "/repos/x/y/issues/1/comments":
            return httpx.Response(
                200,
                json=[{"body": "rotated"}, {"body": "lgtm"}],
            )
        return httpx.Response(404)

    conn = GitHubConnector(owner="x", repo="y", token="x", transport=httpx.MockTransport(handler))
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id="s",
        source_kind="github",
        path="x/y:issues/1",
        metadata={"owner": "x", "repo": "y", "number": "1", "resource_type": "issue"},
    )
    docs = [d async for d in conn.fetch(ref)]
    text = docs[0].text or ""
    assert "leak" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text
    assert "rotated" in text
    assert "lgtm" in text
    assert docs[0].created_by is not None
    assert docs[0].created_by.display_name == "alice"
    await conn.close()


@pytest.mark.asyncio
async def test_fetch_pr_includes_diff_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        accept = request.headers.get("Accept", "")
        if path == "/repos/x/y/pulls/7" and "diff" in accept:
            return httpx.Response(
                200,
                content=b"diff --git a/x b/x\n@@ -1 +1 @@\n-OLD=ghp_aaaaaaaaaaaa\n+NEW=stub\n",
            )
        if path == "/repos/x/y/pulls/7":
            return httpx.Response(
                200,
                json={
                    "number": 7,
                    "title": "rotate",
                    "body": "replace leaked key",
                    "user": {"id": 1, "login": "bob"},
                },
            )
        if path == "/repos/x/y/issues/7/comments":
            return httpx.Response(200, json=[{"body": "thanks"}])
        if path == "/repos/x/y/pulls/7/comments":
            return httpx.Response(200, json=[{"body": "review nit"}])
        return httpx.Response(404)

    conn = GitHubConnector(owner="x", repo="y", token="x", transport=httpx.MockTransport(handler))
    from saas_retriever.core import DocumentRef

    ref = DocumentRef(
        source_id="s",
        source_kind="github",
        path="x/y:pull/7",
        metadata={"owner": "x", "repo": "y", "number": "7", "resource_type": "pr"},
    )
    docs = [d async for d in conn.fetch(ref)]
    text = docs[0].text or ""
    assert "rotate" in text
    assert "replace leaked key" in text
    assert "thanks" in text
    assert "review nit" in text
    assert "OLD=ghp_aaaaaaaaaaaa" in text
    await conn.close()


# --- discover_and_fetch end-to-end -------------------------------------


@pytest.mark.asyncio
async def test_org_wide_walk_emits_documents_from_every_repo() -> None:
    """End-to-end: org-wide enumeration → for each repo, walk code +
    issues + PRs → fetch every ref → emit Documents."""
    org_repos = [
        {"name": "alpha", "owner": {"login": "plenoai"}, "default_branch": "main"},
        {"name": "beta", "owner": {"login": "plenoai"}, "default_branch": "main"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/orgs/plenoai/repos":
            return httpx.Response(200, json=org_repos)
        # Each repo: 1 code blob, 1 issue, 1 PR.
        if path.endswith("/git/trees/main"):
            return httpx.Response(
                200,
                json={"tree": [{"type": "blob", "path": "f.txt", "sha": "s1", "size": 5}]},
            )
        if path.endswith("/issues") and not path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[{"number": 1, "title": "issue-t", "body": "issue-b"}],
            )
        if path.endswith("/pulls") and not path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[{"number": 2, "title": "pr-t", "body": "pr-b"}],
            )
        if path.endswith("/git/blobs/s1"):
            return httpx.Response(200, content=b"blob-content")
        if "/issues/1/comments" in path:
            return httpx.Response(200, json=[])
        if "/pulls/2/comments" in path:
            return httpx.Response(200, json=[])
        if "/issues/1" in path and not path.endswith("/comments"):
            return httpx.Response(200, json={"number": 1, "title": "issue-t", "body": "issue-b"})
        if "/pulls/2" in path and not path.endswith("/comments"):
            if "diff" in request.headers.get("Accept", ""):
                return httpx.Response(200, content=b"@@diff@@")
            return httpx.Response(200, json={"number": 2, "title": "pr-t", "body": "pr-b"})
        if "/issues/2/comments" in path:
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"path": path})

    conn = GitHubConnector(
        owner="plenoai",
        token="x",
        transport=httpx.MockTransport(handler),
    )
    docs = [d async for d in conn.discover_and_fetch()]
    # 2 repos x 3 resources = 6 documents.
    assert len(docs) == 6
    sources = sorted({d.ref.path for d in docs})
    # Two repos, three resource types each.
    assert "plenoai/alpha:f.txt" in sources
    assert "plenoai/alpha:issues/1" in sources
    assert "plenoai/alpha:pull/2" in sources
    assert "plenoai/beta:f.txt" in sources
    await conn.close()
