"""GitHub connector — REST-API driven, no scraping.

What ``discover()`` does:

* Owner-only construction (``owner=plenoai``): enumerates every
  repository under that org via ``/orgs/{owner}/repos`` (falling back
  to ``/users/{owner}/repos`` if the owner is a user account).
* ``+ repo=...``: scopes to a single repository.

For each repository, refs are emitted from the resources enabled in
``resources``:

* ``"code"`` — every blob in the default branch via the recursive
  Git Tree API. Refs carry the blob ``sha`` so ``fetch()`` can pull
  the raw bytes in one call without re-walking the tree.
* ``"issues"`` — every issue (excluding pull requests, which the
  ``/issues`` endpoint mixes in by default). Refs carry
  ``metadata["number"]`` and ``metadata["title"]``.
* ``"prs"`` — every pull request, with refs identified by their PR
  number.

What ``fetch()`` does, dispatched on ``ref.metadata["resource_type"]``:

* ``"code"`` — raw blob bytes via ``/repos/{owner}/{repo}/git/blobs/{sha}``
  with ``Accept: application/vnd.github.raw``. Decoded as UTF-8 when
  valid; binary fallback otherwise.
* ``"issue"`` — title + body + every issue comment, joined into one
  ``Document.text``.
* ``"pr"`` — title + body + conversation comments + review comments
  + the unified diff retrieved via ``Accept: application/vnd.github.diff``.

Auth precedence:

1. ``token=`` constructor argument
2. ``GITHUB_TOKEN`` environment variable
3. ``gh auth token`` if the GitHub CLI is on PATH

Anonymous (token=None) requests work for public content but are
rate-limited to 60/h, which is enough for a smoke run but not a real
scan. The connector reports authenticated requests in ``X-RateLimit-*``
and backs off on ``Retry-After`` / ``X-RateLimit-Reset``.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from collections.abc import AsyncIterator, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx

from saas_retriever.core import (
    Capabilities,
    Document,
    DocumentRef,
    Principal,
    SourceFilter,
)
from saas_retriever.registry import registry

DEFAULT_RESOURCES: frozenset[str] = frozenset({"code", "issues", "prs"})
SUPPORTED_RESOURCES: frozenset[str] = frozenset({"code", "issues", "prs"})

_DEFAULT_BASE_URL = "https://api.github.com"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3


class GitHubConnector:
    """API-driven GitHub source connector.

    The connector owns one ``httpx.AsyncClient`` for its lifetime; call
    ``close()`` (or use it inside the ``discover_and_fetch`` flow which
    closes for you) to release the underlying connection pool.
    """

    kind = "github"

    def __init__(
        self,
        *,
        owner: str,
        repo: str | None = None,
        token: str | None = None,
        resources: Iterable[str] | None = None,
        base_url: str = _DEFAULT_BASE_URL,
        include_archived: bool = False,
        max_repos: int = 1000,
        max_items_per_repo: int = 1000,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
    ) -> None:
        self.owner = owner
        self.repo = repo
        self.token = token if token is not None else _resolve_token()
        chosen = frozenset(resources) if resources is not None else DEFAULT_RESOURCES
        unknown = chosen - SUPPORTED_RESOURCES
        if unknown:
            raise ValueError(f"unknown resources {sorted(unknown)}; supported: {sorted(SUPPORTED_RESOURCES)}")
        self.resources: frozenset[str] = chosen
        self.base_url = base_url.rstrip("/")
        self.include_archived = include_archived
        self.max_repos = max_repos
        self.max_items_per_repo = max_items_per_repo
        scope = f"{owner}/{repo}" if repo else owner
        self.id = source_id or f"github:{scope}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._auth_headers(),
            timeout=timeout,
            transport=transport,
        )

    # --- public protocol --------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        repos = await self._list_repos()
        for repo_info in repos:
            owner = repo_info["owner"]["login"]
            name = repo_info["name"]
            default_branch = repo_info.get("default_branch") or "main"
            if "code" in self.resources:
                async for ref in self._discover_code(owner, name, default_branch, filter):
                    yield ref
            if "issues" in self.resources:
                async for ref in self._discover_issues(owner, name, filter):
                    yield ref
            if "prs" in self.resources:
                async for ref in self._discover_prs(owner, name, filter):
                    yield ref

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        rt = ref.metadata.get("resource_type", "code")
        if rt == "code":
            async for d in self._fetch_blob(ref):
                yield d
        elif rt == "issue":
            async for d in self._fetch_issue(ref):
                yield d
        elif rt == "pr":
            async for d in self._fetch_pr(ref):
                yield d
        else:
            raise ValueError(f"unknown resource_type {rt!r}; expected code|issue|pr")

    async def discover_and_fetch(self, filter: SourceFilter | None = None) -> AsyncIterator[Document]:
        flt = filter or SourceFilter()
        async for ref in self.discover(flt, None):
            async for doc in self.fetch(ref):
                yield doc

    def capabilities(self) -> Capabilities:
        return Capabilities(
            incremental=False,
            binary=True,
            content_hash_delta=False,
            max_concurrent_fetches=4,
            streaming=False,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # --- repo enumeration ------------------------------------------------

    async def _list_repos(self) -> list[Mapping[str, Any]]:
        if self.repo:
            r = await self._get(f"/repos/{self.owner}/{self.repo}")
            return [r.json()]
        # Org-wide. /orgs/{owner}/repos works for orgs; falls back to
        # /users/{owner}/repos for personal accounts. We try org first
        # because that's the dominant production case; a 404 there
        # short-circuits to the user endpoint.
        out: list[Mapping[str, Any]] = []
        for url_path in (f"/orgs/{self.owner}/repos", f"/users/{self.owner}/repos"):
            try:
                async for batch in self._paginate(url_path, params={"type": "all", "per_page": 100}):
                    for repo in batch:
                        if not self.include_archived and repo.get("archived"):
                            continue
                        out.append(repo)
                        if len(out) >= self.max_repos:
                            return out
                return out
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    continue
                raise
        return out

    # --- code -----------------------------------------------------------

    async def _discover_code(
        self,
        owner: str,
        name: str,
        branch: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        try:
            r = await self._get(
                f"/repos/{owner}/{name}/git/trees/{branch}",
                params={"recursive": "1"},
            )
        except httpx.HTTPStatusError as exc:
            # 404 = bad branch, 409 = empty repo. Skip silently.
            if exc.response.status_code in (404, 409):
                return
            raise
        tree = r.json()
        for item in tree.get("tree", []):
            if item.get("type") != "blob":
                continue
            path = item["path"]
            size = item.get("size") or 0
            if filter.max_size is not None and size > filter.max_size:
                continue
            slug_path = f"{owner}/{name}:{path}"
            yield DocumentRef(
                source_id=self.id,
                source_kind=self.kind,
                path=slug_path,
                native_url=f"https://github.com/{owner}/{name}/blob/{branch}/{path}",
                size=size or None,
                content_type="application/octet-stream",
                metadata={
                    "owner": owner,
                    "repo": name,
                    "branch": branch,
                    "sha": item.get("sha", ""),
                    "blob_path": path,
                    "resource_type": "code",
                },
            )

    async def _fetch_blob(self, ref: DocumentRef) -> AsyncIterator[Document]:
        owner = ref.metadata["owner"]
        repo = ref.metadata["repo"]
        sha = ref.metadata.get("sha")
        if not sha:
            raise ValueError("code ref is missing metadata['sha']")
        r = await self._get(
            f"/repos/{owner}/{repo}/git/blobs/{sha}",
            headers={"Accept": "application/vnd.github.raw"},
        )
        body = r.content
        text: str | None
        binary: bytes | None
        try:
            text = body.decode("utf-8")
            binary = None
        except UnicodeDecodeError:
            text = None
            binary = body
        yield Document(
            ref=ref,
            text=text,
            binary=binary,
            fetched_at=datetime.now(UTC),
            content_hash=f"sha1:{sha}",
        )

    # --- issues ---------------------------------------------------------

    async def _discover_issues(
        self,
        owner: str,
        name: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {"state": "all", "per_page": 100}
        if filter.since is not None:
            params["since"] = filter.since.isoformat()
        emitted = 0
        async for batch in self._paginate(f"/repos/{owner}/{name}/issues", params=params):
            for issue in batch:
                # /issues mixes PRs in by default. Skip — PRs come from
                # /pulls so we don't double-emit them.
                if "pull_request" in issue:
                    continue
                emitted += 1
                if emitted > self.max_items_per_repo:
                    return
                number = issue["number"]
                yield DocumentRef(
                    source_id=self.id,
                    source_kind=self.kind,
                    path=f"{owner}/{name}:issues/{number}",
                    native_url=issue.get("html_url"),
                    content_type="text/markdown",
                    last_modified=_parse_ts(issue.get("updated_at")),
                    metadata={
                        "owner": owner,
                        "repo": name,
                        "number": str(number),
                        "title": issue.get("title", ""),
                        "resource_type": "issue",
                    },
                )

    async def _fetch_issue(self, ref: DocumentRef) -> AsyncIterator[Document]:
        owner = ref.metadata["owner"]
        repo = ref.metadata["repo"]
        number = ref.metadata["number"]
        issue = (await self._get(f"/repos/{owner}/{repo}/issues/{number}")).json()
        comments: list[Mapping[str, Any]] = []
        async for batch in self._paginate(
            f"/repos/{owner}/{repo}/issues/{number}/comments",
            params={"per_page": 100},
        ):
            comments.extend(batch)
        text = _join_issue_text(issue, comments)
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            created_by=_principal(issue.get("user")),
        )

    # --- pull requests --------------------------------------------------

    async def _discover_prs(
        self,
        owner: str,
        name: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {"state": "all", "per_page": 100}
        emitted = 0
        async for batch in self._paginate(f"/repos/{owner}/{name}/pulls", params=params):
            for pr in batch:
                if filter.since is not None:
                    updated = _parse_ts(pr.get("updated_at"))
                    if updated is not None and updated < filter.since:
                        continue
                emitted += 1
                if emitted > self.max_items_per_repo:
                    return
                number = pr["number"]
                yield DocumentRef(
                    source_id=self.id,
                    source_kind=self.kind,
                    path=f"{owner}/{name}:pull/{number}",
                    native_url=pr.get("html_url"),
                    content_type="text/markdown",
                    last_modified=_parse_ts(pr.get("updated_at")),
                    metadata={
                        "owner": owner,
                        "repo": name,
                        "number": str(number),
                        "title": pr.get("title", ""),
                        "resource_type": "pr",
                    },
                )

    async def _fetch_pr(self, ref: DocumentRef) -> AsyncIterator[Document]:
        owner = ref.metadata["owner"]
        repo = ref.metadata["repo"]
        number = ref.metadata["number"]
        pr = (await self._get(f"/repos/{owner}/{repo}/pulls/{number}")).json()
        issue_comments: list[Mapping[str, Any]] = []
        async for batch in self._paginate(
            f"/repos/{owner}/{repo}/issues/{number}/comments",
            params={"per_page": 100},
        ):
            issue_comments.extend(batch)
        review_comments: list[Mapping[str, Any]] = []
        async for batch in self._paginate(
            f"/repos/{owner}/{repo}/pulls/{number}/comments",
            params={"per_page": 100},
        ):
            review_comments.extend(batch)
        diff_text = ""
        try:
            diff_r = await self._get(
                f"/repos/{owner}/{repo}/pulls/{number}",
                headers={"Accept": "application/vnd.github.diff"},
            )
            diff_text = diff_r.text
        except httpx.HTTPStatusError:
            # If the diff fetch fails (large PR, server-side cap), the
            # PR body + comments are still useful — keep going rather
            # than dropping the whole document.
            diff_text = ""
        text = _join_pr_text(pr, issue_comments, review_comments, diff_text)
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            created_by=_principal(pr.get("user")),
        )

    # --- HTTP plumbing --------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "saas-retriever/0.1",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        backoff = 1.0
        last_response: httpx.Response | None = None
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.get(path, params=params, headers=headers)
            last_response = r
            if r.status_code == 429:
                # Hard rate limit. Sleep until Retry-After.
                retry_after = float(r.headers.get("Retry-After", "60"))
                await asyncio.sleep(min(retry_after, 300))
                continue
            if r.status_code == 403 and _is_rate_limited(r):
                # Secondary rate limit / abuse detection. Sleep until
                # X-RateLimit-Reset, capped so a misconfigured clock
                # doesn't park the connector for hours.
                reset = r.headers.get("X-RateLimit-Reset")
                if reset is not None:
                    sleep_for = max(1, int(reset) - int(datetime.now(UTC).timestamp()) + 1)
                    await asyncio.sleep(min(sleep_for, 300))
                    continue
            if 500 <= r.status_code < 600 and attempt < _DEFAULT_MAX_RETRIES - 1:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            r.raise_for_status()
            return r
        # Out of retries — surface the final response status.
        assert last_response is not None
        last_response.raise_for_status()
        return last_response

    async def _paginate(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> AsyncIterator[list[Mapping[str, Any]]]:
        url: str | None = path
        next_params: Mapping[str, Any] | None = params
        while url is not None:
            r = await self._get(url, params=next_params)
            data = r.json()
            if isinstance(data, list):
                yield data
            else:
                # Non-list payload (e.g. a single object) — yield as a
                # single-element batch so callers can keep one shape.
                yield [data]
            url = _next_link(r.headers.get("Link", ""))
            # The next URL already encodes the original query, so don't
            # re-pass params on subsequent requests.
            next_params = None


# --- helpers ------------------------------------------------------------


def _resolve_token() -> str | None:
    """Token from $GITHUB_TOKEN, falling back to ``gh auth token``."""
    env = os.environ.get("GITHUB_TOKEN")
    if env:
        return env
    if shutil.which("gh") is None:
        return None
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None


def _is_rate_limited(r: httpx.Response) -> bool:
    if r.status_code != 403:
        return False
    body = r.text.lower()
    if "rate limit" in body or "secondary rate" in body:
        return True
    remaining = r.headers.get("X-RateLimit-Remaining")
    return bool(remaining == "0")


_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _next_link(link_header: str) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        m = _LINK_NEXT_RE.search(part)
        if m:
            return m.group(1)
    return None


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    # GitHub timestamps are ISO 8601 with `Z`. Python 3.12 happily
    # parses the `+00:00` form but not the `Z` form, so swap.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _principal(user: Mapping[str, Any] | None) -> Principal | None:
    if not user:
        return None
    login = user.get("login")
    return Principal(
        id=str(user.get("id") or login or ""),
        display_name=login,
    )


def _join_issue_text(
    issue: Mapping[str, Any],
    comments: list[Mapping[str, Any]],
) -> str:
    parts: list[str] = []
    title = issue.get("title")
    if title:
        parts.append(str(title))
    body = issue.get("body")
    if body:
        parts.append(str(body))
    for c in comments:
        body = c.get("body")
        if body:
            parts.append(str(body))
    return "\n\n".join(parts)


def _join_pr_text(
    pr: Mapping[str, Any],
    issue_comments: list[Mapping[str, Any]],
    review_comments: list[Mapping[str, Any]],
    diff_text: str,
) -> str:
    parts: list[str] = []
    title = pr.get("title")
    if title:
        parts.append(str(title))
    body = pr.get("body")
    if body:
        parts.append(str(body))
    for c in issue_comments:
        b = c.get("body")
        if b:
            parts.append(str(b))
    for c in review_comments:
        b = c.get("body")
        if b:
            parts.append(str(b))
    if diff_text:
        parts.append(diff_text)
    return "\n\n".join(parts)


registry.register("github", GitHubConnector)
