"""GitLab connector tests using httpx.MockTransport.

Every HTTP call is intercepted; unmatched URLs return 404 so a missing
mock fails loudly rather than silently passing.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.gitlab import (
    DEFAULT_BASE_URL,
    DEFAULT_RESOURCES,
    GitlabAuthMode,
    GitlabConnector,
    _join_issue_text,
    _join_mr_text,
    _next_link,
    _parse_ts,
    _principal,
    _resolve_credential,
)
from saas_retriever.core import DocumentRef, SourceFilter
from saas_retriever.credentials import Credential, CredentialMisconfiguredError


def _routes(handler_map: dict[str, Any]) -> httpx.MockTransport:
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
    assert DEFAULT_RESOURCES == frozenset({"code", "issues", "mrs"})


def test_next_link_picks_rel_next() -> None:
    h = (
        '<https://gitlab.com/api/v4/projects?page=2>; rel="next", '
        '<https://gitlab.com/api/v4/projects?page=10>; rel="last"'
    )
    assert _next_link(h) == "https://gitlab.com/api/v4/projects?page=2"


def test_next_link_returns_none_when_absent() -> None:
    assert _next_link("") is None
    assert _next_link('<https://x>; rel="last"') is None


def test_parse_ts_handles_z_suffix() -> None:
    parsed = _parse_ts("2026-05-06T12:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026


def test_principal_uses_username_fallback() -> None:
    p = _principal({"id": 7, "name": "Alice", "username": "alice"})
    assert p is not None
    assert p.id == "7"
    assert p.display_name == "Alice"


def test_join_issue_text_skips_system_notes() -> None:
    text = _join_issue_text(
        {"title": "leak", "description": "AKIAIOSFODNN7EXAMPLE"},
        [
            {"body": "real note"},
            {"system": True, "body": "changed milestone to %X"},
            {"body": "another"},
        ],
    )
    assert "leak" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text
    assert "real note" in text
    assert "another" in text
    assert "milestone" not in text


def test_join_mr_text_includes_diff() -> None:
    text = _join_mr_text(
        {"title": "fix", "description": "rotate"},
        [{"body": "lgtm"}],
        "@@ -1 +1 @@\n-OLD=glpat-xxx\n+NEW=stub",
    )
    assert "fix" in text
    assert "lgtm" in text
    assert "OLD=glpat-xxx" in text


# --- credential resolution ---------------------------------------------


def test_credential_resolution_pat_explicit_token() -> None:
    mode, token = _resolve_credential(credential=None, token="glpat-x", auth="pat")
    assert mode is GitlabAuthMode.PAT
    assert token == "glpat-x"


def test_credential_resolution_oauth_via_credential() -> None:
    cred = Credential(
        kind="gitlab",
        payload={"auth": "oauth", "access_token": "oauth-tok"},
    )
    mode, token = _resolve_credential(credential=cred, token=None, auth="pat")
    assert mode is GitlabAuthMode.OAUTH
    assert token == "oauth-tok"


def test_credential_resolution_falls_back_across_token_keys() -> None:
    cred = Credential(kind="gitlab", payload={"auth": "oauth", "token": "oauth-tok"})
    mode, token = _resolve_credential(credential=cred, token=None, auth="pat")
    assert mode is GitlabAuthMode.OAUTH
    assert token == "oauth-tok"


def test_credential_resolution_explicit_kwarg_wins_over_credential() -> None:
    cred = Credential(kind="gitlab", payload={"auth": "oauth", "access_token": "x"})
    mode, _ = _resolve_credential(
        credential=cred, token="explicit", auth=GitlabAuthMode.PROJECT
    )
    assert mode is GitlabAuthMode.PROJECT


def test_credential_resolution_rejects_unknown_mode_string() -> None:
    with pytest.raises(ValueError, match="unsupported gitlab auth mode"):
        _resolve_credential(credential=None, token="t", auth="bearer")


def test_credential_resolution_requires_token() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        _resolve_credential(credential=None, token=None, auth="pat")


# --- construction validation -------------------------------------------


def test_requires_exactly_one_of_project_group() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        GitlabConnector(token="t")
    with pytest.raises(ValueError, match="exactly one"):
        GitlabConnector(token="t", project="ns/p", group="g")


def test_unknown_resource_rejected() -> None:
    with pytest.raises(ValueError, match="resources"):
        GitlabConnector(token="t", project="ns/p", resources={"branches"})


def test_visibility_validated() -> None:
    with pytest.raises(ValueError, match="visibility"):
        GitlabConnector(token="t", group="g", visibility="publik")


def test_default_id_for_group_and_project() -> None:
    g = GitlabConnector(token="t", group="acme")
    assert g.id == "gitlab-group:acme"
    p = GitlabConnector(token="t", project="acme/alpha")
    assert p.id == "gitlab:acme/alpha"


def test_capabilities_marks_binary() -> None:
    c = GitlabConnector(token="t", project="ns/p")
    caps = c.capabilities()
    assert caps.binary is True
    assert caps.streaming is False


def test_pat_auth_uses_private_token_header() -> None:
    received: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received.update(dict(request.headers))
        return httpx.Response(404)

    c = GitlabConnector(
        token="glpat-x",
        project="ns/p",
        transport=httpx.MockTransport(handler),
    )
    headers = c._headers()
    assert headers.get("PRIVATE-TOKEN") == "glpat-x"
    assert "Authorization" not in headers


def test_oauth_auth_uses_bearer_header() -> None:
    c = GitlabConnector(
        token="oauth-x",
        project="ns/p",
        auth="oauth",
    )
    headers = c._headers()
    assert headers.get("Authorization") == "Bearer oauth-x"
    assert "PRIVATE-TOKEN" not in headers


# --- end-to-end --------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_walks_group_paginates_and_emits_code() -> None:
    base = "/api/v4"
    project_a = {
        "id": 1,
        "path_with_namespace": "acme/alpha",
        "default_branch": "main",
        "web_url": "https://gitlab.com/acme/alpha",
    }
    project_b = {
        "id": 2,
        "path_with_namespace": "acme/beta",
        "default_branch": "main",
        "web_url": "https://gitlab.com/acme/beta",
    }
    page1 = httpx.Response(
        200,
        json=[project_a],
        headers={
            "Link": (
                f'<{DEFAULT_BASE_URL}{base}/groups/acme/projects?page=2>; rel="next"'
            )
        },
    )
    page2 = httpx.Response(200, json=[project_b])
    tree_a = httpx.Response(
        200,
        json=[
            {"type": "blob", "path": "README.md", "id": "aaa"},
            {"type": "tree", "path": "src"},
            {"type": "blob", "path": "src/main.py", "id": "bbb"},
        ],
    )
    tree_b = httpx.Response(200, json=[])

    def group_handler(request: httpx.Request) -> httpx.Response:
        page = request.url.params.get("page")
        if page == "2":
            return page2
        return page1

    transport = _routes(
        {
            f"{base}/groups/acme/projects": group_handler,
            f"{base}/projects/1/repository/tree": tree_a,
            f"{base}/projects/2/repository/tree": tree_b,
            f"{base}/projects/1/issues": httpx.Response(200, json=[]),
            f"{base}/projects/2/issues": httpx.Response(200, json=[]),
            f"{base}/projects/1/merge_requests": httpx.Response(200, json=[]),
            f"{base}/projects/2/merge_requests": httpx.Response(200, json=[]),
        }
    )
    c = GitlabConnector(
        token="t",
        group="acme",
        transport=transport,
    )
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    blob_paths = sorted(r.metadata["blob_path"] for r in refs if r.metadata["resource_type"] == "code")
    assert blob_paths == ["README.md", "src/main.py"]
    assert all(r.metadata["branch"] == "main" for r in refs)


@pytest.mark.asyncio
async def test_discover_single_project_short_circuits_to_get() -> None:
    base = "/api/v4"
    project = {
        "id": 42,
        "path_with_namespace": "ns/alpha",
        "default_branch": "main",
        "web_url": "https://gitlab.com/ns/alpha",
    }
    tree = httpx.Response(200, json=[{"type": "blob", "path": "README.md", "id": "abc"}])
    transport = _routes(
        {
            f"{base}/projects/ns/alpha": project,
            f"{base}/projects/42/repository/tree": tree,
            f"{base}/projects/42/issues": httpx.Response(200, json=[]),
            f"{base}/projects/42/merge_requests": httpx.Response(200, json=[]),
        }
    )
    c = GitlabConnector(token="t", project="ns/alpha", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    code_refs = [r for r in refs if r.metadata["resource_type"] == "code"]
    assert len(code_refs) == 1
    assert code_refs[0].metadata["blob_path"] == "README.md"


@pytest.mark.asyncio
async def test_discover_filters_archived_by_default() -> None:
    base = "/api/v4"
    project = {
        "id": 1,
        "path_with_namespace": "ns/old",
        "default_branch": "main",
        "archived": True,
    }
    transport = _routes(
        {
            f"{base}/projects/ns/old": project,
        }
    )
    c = GitlabConnector(token="t", project="ns/old", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert refs == []


@pytest.mark.asyncio
async def test_fetch_blob_returns_text_when_utf8() -> None:
    base = "/api/v4"
    transport = _routes(
        {
            f"{base}/projects/42/repository/files/src/main.py/raw": httpx.Response(
                200, content=b"print('hi')"
            ),
        }
    )
    c = GitlabConnector(token="t", project="ns/alpha", transport=transport)
    ref = DocumentRef(
        source_id=c.id,
        source_kind="gitlab",
        path="ns/alpha:src/main.py",
        metadata={
            "project_id": "42",
            "path_with_namespace": "ns/alpha",
            "branch": "main",
            "blob_path": "src/main.py",
            "blob_sha": "abc",
            "resource_type": "code",
        },
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert docs[0].text == "print('hi')"
    assert docs[0].content_hash == "sha1:abc"


@pytest.mark.asyncio
async def test_fetch_blob_falls_back_to_binary() -> None:
    base = "/api/v4"
    payload = b"\xff\xfe\x00"
    transport = _routes(
        {
            f"{base}/projects/42/repository/files/binary.bin/raw": httpx.Response(
                200, content=payload
            ),
        }
    )
    c = GitlabConnector(token="t", project="ns/alpha", transport=transport)
    ref = DocumentRef(
        source_id=c.id,
        source_kind="gitlab",
        path="ns/alpha:binary.bin",
        metadata={
            "project_id": "42",
            "path_with_namespace": "ns/alpha",
            "branch": "main",
            "blob_path": "binary.bin",
            "blob_sha": "x",
            "resource_type": "code",
        },
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert docs[0].text is None
    assert docs[0].binary == payload


@pytest.mark.asyncio
async def test_429_eventually_raises_rate_limited() -> None:
    base = "/api/v4"

    def throttle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    transport = _routes({f"{base}/projects/ns/alpha": throttle})
    c = GitlabConnector(token="t", project="ns/alpha", transport=transport)
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_403_with_quota_exhausted_raises_rate_limited() -> None:
    base = "/api/v4"

    def quota(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"RateLimit-Remaining": "0"})

    transport = _routes({f"{base}/projects/ns/alpha": quota})
    c = GitlabConnector(token="t", project="ns/alpha", transport=transport)
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_fetch_mr_concatenates_diff_pages() -> None:
    base = "/api/v4"
    mr = {"id": 99, "iid": 9, "title": "fix", "description": "rotate", "author": {"id": 1, "username": "alice"}}
    notes = [{"body": "lgtm"}]
    diffs_page = [
        {"old_path": "a.py", "new_path": "a.py", "diff": "@@ -1 +1 @@\n-OLD\n+NEW"},
    ]
    transport = _routes(
        {
            f"{base}/projects/42/merge_requests/9": mr,
            f"{base}/projects/42/merge_requests/9/notes": notes,
            f"{base}/projects/42/merge_requests/9/diffs": diffs_page,
        }
    )
    c = GitlabConnector(token="t", project="ns/alpha", transport=transport)
    ref = DocumentRef(
        source_id=c.id,
        source_kind="gitlab",
        path="ns/alpha:merge_requests/9",
        metadata={
            "project_id": "42",
            "path_with_namespace": "ns/alpha",
            "iid": "9",
            "title": "fix",
            "resource_type": "mr",
        },
    )
    docs = [d async for d in c.fetch(ref)]
    await c.close()
    assert "fix" in docs[0].text
    assert "lgtm" in docs[0].text
    assert "OLD" in docs[0].text


# Late import: only pulled in the rate-limit tests above. Keeps the
# module-level imports tidy at top while letting the asyncio tests
# reference the symbol.
from saas_retriever.rate_limit import RateLimited  # noqa: E402
