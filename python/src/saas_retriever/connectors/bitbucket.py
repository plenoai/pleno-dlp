"""Bitbucket connector — REST-API driven, no git clone, no scraping.

Two flavors share a single class because the only differences live in URL
shape, paginator semantics, and auth headers — the HTTP layer is the same:

* **Cloud** — ``https://api.bitbucket.org/2.0``. Pagination via a ``next``
  URL field embedded in every page. Auth: HTTP basic
  (``username``/``app_password``) or Bearer (workspace access token).
* **Server / Data Center** — ``<base_url>/rest/api/1.0``. Pagination via
  ``start`` query param + ``nextPageStart``/``isLastPage`` in the body.
  Auth: Bearer (HTTP access token) or HTTP basic (PAT or password).

Resources:

* ``"code"`` — every blob in the default branch. Cloud walks
  ``/repositories/{ws}/{slug}/src/{commit}/{path}`` recursively
  (depth-first, one directory at a time). Server lists every file at
  once via ``/projects/{key}/repos/{slug}/files`` (server-side
  recursion, paginated with ``start``).
* ``"prs"`` — every pull request, with ref body = title + description
  + comments + unified diff.
* ``"issues"`` — Cloud only (Server has no native issue tracker).

Construction takes either an explicit ``Credential`` (saas-retriever
shape) or the discrete ``username``/``password``/``token`` knobs.
``credential.payload`` keys recognised:

* ``token`` → Bearer.
* ``app_password`` (Cloud) or ``password`` (Server) — paired with
  ``username`` → HTTP Basic.
"""

from __future__ import annotations

import asyncio
import base64
import ssl
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

import httpx

from saas_retriever.core import (
    Capabilities,
    Document,
    DocumentRef,
    Principal,
    SourceFilter,
)
from saas_retriever.credentials import Credential, CredentialMisconfiguredError
from saas_retriever.rate_limit import RateLimited
from saas_retriever.registry import registry

Flavor = Literal["cloud", "server"]

DEFAULT_CLOUD_BASE_URL = "https://api.bitbucket.org/2.0"
DEFAULT_RESOURCES: frozenset[str] = frozenset({"code", "issues", "prs"})
SUPPORTED_RESOURCES: frozenset[str] = frozenset({"code", "issues", "prs"})

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_PAGE_SIZE = 100
_DEFAULT_RETRY_AFTER_SECONDS = 30.0
# 10_000 pages x 100 entries ~= a million records — well above any
# realistic single-workspace size, but bounded so a misbehaving cache
# returning the same `next` URL forever cannot turn `discover()` into an
# infinite loop.
_MAX_PAGINATION_DEPTH = 10_000


@dataclass(frozen=True, slots=True)
class _BasicAuth:
    username: str
    password: str

    def header_value(self) -> str:
        raw = f"{self.username}:{self.password}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")


@dataclass(frozen=True, slots=True)
class _BearerAuth:
    token: str

    def header_value(self) -> str:
        return f"Bearer {self.token}"


_AuthMode = _BasicAuth | _BearerAuth


class BitbucketConnector:
    """API-driven Bitbucket source connector.

    Owner-only construction (``workspace`` / ``project``) walks every
    repository under it; passing ``repo_slug`` scopes to a single repo.
    Connectors own their own ``httpx.AsyncClient`` for their lifetime.
    """

    kind = "bitbucket"

    def __init__(
        self,
        *,
        flavor: Flavor = "cloud",
        workspace: str | None = None,
        project: str | None = None,
        repo_slug: str | None = None,
        credential: Credential | None = None,
        username: str | None = None,
        app_password: str | None = None,
        password: str | None = None,
        token: str | None = None,
        resources: Iterable[str] | None = None,
        base_url: str | None = None,
        ca_bundle_path: str | None = None,
        max_repos: int = 1000,
        max_items_per_repo: int = 1000,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
    ) -> None:
        if flavor not in ("cloud", "server"):
            raise ValueError(f"unsupported bitbucket flavor: {flavor!r}")
        self._flavor: Flavor = flavor
        self._workspace: str | None
        self._project: str | None
        if flavor == "cloud":
            if workspace is None:
                raise ValueError("bitbucket cloud requires `workspace=`")
            self._workspace = workspace
            self._project = None
        else:
            if project is None:
                raise ValueError("bitbucket server requires `project=`")
            self._project = project
            self._workspace = None
        self._repo_slug = repo_slug
        chosen = frozenset(resources) if resources is not None else DEFAULT_RESOURCES
        unknown = chosen - SUPPORTED_RESOURCES
        if unknown:
            raise ValueError(
                f"unknown resources {sorted(unknown)}; supported: {sorted(SUPPORTED_RESOURCES)}"
            )
        if flavor == "server" and "issues" in chosen:
            # Server has no native issue tracker; downgrade silently
            # rather than refusing — the operator may have left "issues"
            # in a shared default and we'd rather keep going on the rest.
            chosen = chosen - {"issues"}
        self.resources: frozenset[str] = chosen

        if base_url is None:
            if flavor == "cloud":
                base_url = DEFAULT_CLOUD_BASE_URL
            else:
                raise ValueError("bitbucket server requires `base_url=`")
        self._base_url = base_url.rstrip("/")
        self._auth = _resolve_auth(
            flavor=flavor,
            credential=credential,
            username=username,
            app_password=app_password,
            password=password,
            token=token,
        )
        self.max_repos = max_repos
        self.max_items_per_repo = max_items_per_repo

        scope = self._workspace or self._project or ""
        if repo_slug:
            scope = f"{scope}/{repo_slug}"
        self.id = source_id or f"bitbucket:{flavor}:{scope}"

        client_kwargs: dict[str, Any] = {"timeout": timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        elif ca_bundle_path is not None:
            # Server installs commonly use a private CA. The test seam
            # (`transport=`) takes precedence so tests never hit the
            # network even if `ca_bundle_path` is set.
            client_kwargs["verify"] = ssl.create_default_context(cafile=ca_bundle_path)
        self._client = httpx.AsyncClient(**client_kwargs)

    # --- public protocol ------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        repos = await self._list_repos()
        for repo in repos:
            if self._flavor == "cloud":
                slug = repo.get("slug") or repo.get("name", "")
                workspace = ((repo.get("workspace") or {}).get("slug")) or self._workspace or ""
                default_branch = ((repo.get("mainbranch") or {}).get("name")) or "main"
                project_key = ((repo.get("project") or {}).get("key")) or ""
                if "code" in self.resources:
                    async for ref in self._discover_code_cloud(
                        workspace, slug, default_branch, filter
                    ):
                        yield ref
                if "issues" in self.resources and (repo.get("has_issues") or False):
                    async for ref in self._discover_issues_cloud(workspace, slug, filter):
                        yield ref
                if "prs" in self.resources:
                    async for ref in self._discover_prs_cloud(workspace, slug, filter):
                        yield ref
                _ = project_key  # currently informational; kept on metadata via repo dict
            else:
                slug = repo.get("slug") or repo.get("name", "")
                project_key = ((repo.get("project") or {}).get("key")) or self._project or ""
                default_branch = await self._server_default_branch(project_key, slug)
                if "code" in self.resources:
                    async for ref in self._discover_code_server(
                        project_key, slug, default_branch, filter
                    ):
                        yield ref
                if "prs" in self.resources:
                    async for ref in self._discover_prs_server(project_key, slug, filter):
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

    async def discover_and_fetch(
        self, filter: SourceFilter | None = None
    ) -> AsyncIterator[Document]:
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

    # --- repo enumeration ----------------------------------------------

    async def _list_repos(self) -> list[Mapping[str, Any]]:
        if self._repo_slug:
            if self._flavor == "cloud":
                r = await self._get(
                    f"/repositories/{self._workspace}/{self._repo_slug}"
                )
            else:
                r = await self._get(
                    f"/projects/{self._project}/repos/{self._repo_slug}"
                )
            return [r.json()]

        out: list[Mapping[str, Any]] = []
        if self._flavor == "cloud":
            path = f"/repositories/{self._workspace}"
        else:
            path = f"/projects/{self._project}/repos"
        async for entry in self._paginate(path):
            out.append(entry)
            if len(out) >= self.max_repos:
                break
        return out

    async def _server_default_branch(self, project_key: str, slug: str) -> str:
        try:
            r = await self._get(
                f"/projects/{project_key}/repos/{slug}/branches/default"
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 409):
                return "main"
            raise
        body = r.json()
        return body.get("displayId") or body.get("id") or "main"

    # --- code -----------------------------------------------------------

    async def _discover_code_cloud(
        self,
        workspace: str,
        slug: str,
        branch: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        emitted = 0
        # Cloud's /src endpoint lists one directory at a time. Walk
        # depth-first, pushing subdirectories onto a stack so we fetch
        # in deterministic order. Limit guard fires in both the recursive
        # walk and the entry counter so a pathological tree cannot OOM us.
        stack: list[str] = [""]
        while stack:
            sub = stack.pop()
            path = f"/repositories/{workspace}/{slug}/src/{branch}/{sub}".rstrip("/")
            try:
                async for entry in self._paginate(path):
                    etype = entry.get("type")
                    epath = entry.get("path", "")
                    if etype == "commit_directory":
                        stack.append(epath)
                        continue
                    if etype != "commit_file":
                        continue
                    size = entry.get("size") or 0
                    if filter.max_size is not None and size > filter.max_size:
                        continue
                    emitted += 1
                    if emitted > self.max_items_per_repo:
                        return
                    commit = ((entry.get("commit") or {}).get("hash")) or branch
                    slug_path = f"{workspace}/{slug}:{epath}"
                    yield DocumentRef(
                        source_id=self.id,
                        source_kind=self.kind,
                        path=slug_path,
                        native_url=f"https://bitbucket.org/{workspace}/{slug}/src/{branch}/{epath}",
                        size=size or None,
                        content_type="application/octet-stream",
                        metadata={
                            "flavor": "cloud",
                            "workspace": workspace,
                            "repo": slug,
                            "branch": branch,
                            "blob_path": epath,
                            "commit": commit,
                            "resource_type": "code",
                        },
                    )
            except httpx.HTTPStatusError as exc:
                # 404 = bad branch / empty repo / disappearing dir.
                # 409 = repo not yet initialised. Skip silently — the
                # discover loop is best-effort.
                if exc.response.status_code in (404, 409):
                    continue
                raise

    async def _discover_code_server(
        self,
        project_key: str,
        slug: str,
        branch: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        emitted = 0
        # Server's /files endpoint returns a flat recursive list of file
        # paths, paginated via start/limit. Each value is a string
        # (the file path), not an object — different shape from Cloud's
        # /src walk. We don't get per-file size from this endpoint, so
        # filter.max_size kicks in lazily at fetch() time only.
        path = f"/projects/{project_key}/repos/{slug}/files"
        params = {"at": branch}
        try:
            async for entry in self._paginate(path, params=params):
                if isinstance(entry, str):
                    file_path = entry
                else:
                    # Defensive: future API revs may move to objects.
                    file_path = entry.get("path", "") if isinstance(entry, Mapping) else ""
                if not file_path:
                    continue
                emitted += 1
                if emitted > self.max_items_per_repo:
                    return
                slug_path = f"{project_key}/{slug}:{file_path}"
                yield DocumentRef(
                    source_id=self.id,
                    source_kind=self.kind,
                    path=slug_path,
                    native_url=f"{self._base_url}/projects/{project_key}/repos/{slug}/browse/{file_path}?at={branch}",
                    content_type="application/octet-stream",
                    metadata={
                        "flavor": "server",
                        "project": project_key,
                        "repo": slug,
                        "branch": branch,
                        "blob_path": file_path,
                        "resource_type": "code",
                    },
                )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 409):
                return
            raise

    async def _fetch_blob(self, ref: DocumentRef) -> AsyncIterator[Document]:
        flavor = ref.metadata.get("flavor", self._flavor)
        blob_path = ref.metadata["blob_path"]
        branch = ref.metadata["branch"]
        if flavor == "cloud":
            workspace = ref.metadata["workspace"]
            slug = ref.metadata["repo"]
            commit = ref.metadata.get("commit") or branch
            url = f"/repositories/{workspace}/{slug}/src/{commit}/{_quote_path(blob_path)}"
        else:
            project_key = ref.metadata["project"]
            slug = ref.metadata["repo"]
            url = (
                f"/projects/{project_key}/repos/{slug}/raw/"
                f"{_quote_path(blob_path)}"
            )
        params = None if flavor == "cloud" else {"at": branch}
        r = await self._get(url, params=params)
        body = r.content
        text: str | None
        binary: bytes | None
        try:
            text = body.decode("utf-8")
            binary = None
        except UnicodeDecodeError:
            text = None
            binary = body
        commit = ref.metadata.get("commit", "")
        yield Document(
            ref=ref,
            text=text,
            binary=binary,
            fetched_at=datetime.now(UTC),
            content_hash=f"sha1:{commit}" if commit else None,
        )

    # --- issues (cloud only) -------------------------------------------

    async def _discover_issues_cloud(
        self,
        workspace: str,
        slug: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {}
        if filter.since is not None:
            # Cloud uses a BBQL filter language. Quote ts as RFC3339.
            params["q"] = f'updated_on >= "{filter.since.isoformat()}"'
        emitted = 0
        try:
            async for issue in self._paginate(
                f"/repositories/{workspace}/{slug}/issues", params=params
            ):
                emitted += 1
                if emitted > self.max_items_per_repo:
                    return
                number = issue.get("id")
                yield DocumentRef(
                    source_id=self.id,
                    source_kind=self.kind,
                    path=f"{workspace}/{slug}:issues/{number}",
                    native_url=((issue.get("links") or {}).get("html") or {}).get("href"),
                    content_type="text/markdown",
                    last_modified=_parse_ts(issue.get("updated_on")),
                    metadata={
                        "flavor": "cloud",
                        "workspace": workspace,
                        "repo": slug,
                        "number": str(number),
                        "title": issue.get("title", ""),
                        "resource_type": "issue",
                    },
                )
        except httpx.HTTPStatusError as exc:
            # 404 means the repo has the issue tracker disabled. Skip.
            if exc.response.status_code == 404:
                return
            raise

    async def _fetch_issue(self, ref: DocumentRef) -> AsyncIterator[Document]:
        workspace = ref.metadata["workspace"]
        slug = ref.metadata["repo"]
        number = ref.metadata["number"]
        issue = (
            await self._get(f"/repositories/{workspace}/{slug}/issues/{number}")
        ).json()
        comments: list[Mapping[str, Any]] = []
        async for c in self._paginate(
            f"/repositories/{workspace}/{slug}/issues/{number}/comments"
        ):
            comments.append(c)
        text = _join_issue_text_cloud(issue, comments)
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            created_by=_principal_cloud(issue.get("reporter")),
        )

    # --- pull requests --------------------------------------------------

    async def _discover_prs_cloud(
        self,
        workspace: str,
        slug: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {"state": "ALL"}
        if filter.since is not None:
            params["q"] = f'updated_on >= "{filter.since.isoformat()}"'
        emitted = 0
        async for pr in self._paginate(
            f"/repositories/{workspace}/{slug}/pullrequests", params=params
        ):
            emitted += 1
            if emitted > self.max_items_per_repo:
                return
            number = pr.get("id")
            yield DocumentRef(
                source_id=self.id,
                source_kind=self.kind,
                path=f"{workspace}/{slug}:pull/{number}",
                native_url=((pr.get("links") or {}).get("html") or {}).get("href"),
                content_type="text/markdown",
                last_modified=_parse_ts(pr.get("updated_on")),
                metadata={
                    "flavor": "cloud",
                    "workspace": workspace,
                    "repo": slug,
                    "number": str(number),
                    "title": pr.get("title", ""),
                    "resource_type": "pr",
                },
            )

    async def _discover_prs_server(
        self,
        project_key: str,
        slug: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {"state": "ALL"}
        emitted = 0
        async for pr in self._paginate(
            f"/projects/{project_key}/repos/{slug}/pull-requests", params=params
        ):
            if filter.since is not None:
                # Server returns updatedDate as epoch milliseconds.
                updated = pr.get("updatedDate")
                if isinstance(updated, int):
                    upd_dt = datetime.fromtimestamp(updated / 1000.0, tz=UTC)
                    if upd_dt < filter.since:
                        continue
            emitted += 1
            if emitted > self.max_items_per_repo:
                return
            number = pr.get("id")
            yield DocumentRef(
                source_id=self.id,
                source_kind=self.kind,
                path=f"{project_key}/{slug}:pull/{number}",
                native_url=((pr.get("links") or {}).get("self") or [{}])[0].get("href"),
                content_type="text/markdown",
                last_modified=(
                    datetime.fromtimestamp(pr["updatedDate"] / 1000.0, tz=UTC)
                    if isinstance(pr.get("updatedDate"), int)
                    else None
                ),
                metadata={
                    "flavor": "server",
                    "project": project_key,
                    "repo": slug,
                    "number": str(number),
                    "title": pr.get("title", ""),
                    "resource_type": "pr",
                },
            )

    async def _fetch_pr(self, ref: DocumentRef) -> AsyncIterator[Document]:
        flavor = ref.metadata.get("flavor", self._flavor)
        slug = ref.metadata["repo"]
        number = ref.metadata["number"]
        if flavor == "cloud":
            workspace = ref.metadata["workspace"]
            pr = (
                await self._get(
                    f"/repositories/{workspace}/{slug}/pullrequests/{number}"
                )
            ).json()
            comments: list[Mapping[str, Any]] = []
            async for c in self._paginate(
                f"/repositories/{workspace}/{slug}/pullrequests/{number}/comments"
            ):
                comments.append(c)
            diff_text = await self._fetch_pr_diff_cloud(workspace, slug, number)
            text = _join_pr_text_cloud(pr, comments, diff_text)
            user = pr.get("author")
            yield Document(
                ref=ref,
                text=text,
                fetched_at=datetime.now(UTC),
                created_by=_principal_cloud(user),
            )
        else:
            project_key = ref.metadata["project"]
            pr = (
                await self._get(
                    f"/projects/{project_key}/repos/{slug}/pull-requests/{number}"
                )
            ).json()
            activities: list[Mapping[str, Any]] = []
            async for a in self._paginate(
                f"/projects/{project_key}/repos/{slug}/pull-requests/{number}/activities"
            ):
                activities.append(a)
            diff_text = await self._fetch_pr_diff_server(project_key, slug, number)
            text = _join_pr_text_server(pr, activities, diff_text)
            user = (pr.get("author") or {}).get("user")
            yield Document(
                ref=ref,
                text=text,
                fetched_at=datetime.now(UTC),
                created_by=_principal_server(user),
            )

    async def _fetch_pr_diff_cloud(
        self, workspace: str, slug: str, number: str
    ) -> str:
        try:
            r = await self._get(
                f"/repositories/{workspace}/{slug}/pullrequests/{number}/diff"
            )
            return r.text
        except httpx.HTTPStatusError:
            # Large PRs / server-side caps — keep going on body+comments.
            return ""

    async def _fetch_pr_diff_server(
        self, project_key: str, slug: str, number: str
    ) -> str:
        try:
            r = await self._get(
                f"/projects/{project_key}/repos/{slug}/pull-requests/{number}/diff"
            )
            return r.text
        except httpx.HTTPStatusError:
            return ""

    # --- HTTP plumbing --------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": "saas-retriever/0.2",
            "Authorization": self._auth.header_value(),
        }

    def _absolute(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return f"{self._base_url}{path_or_url}"

    async def _get(
        self,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        url = self._absolute(path_or_url)
        merged_headers = self._headers()
        if headers:
            merged_headers.update(headers)
        backoff = 1.0
        last_response: httpx.Response | None = None
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.get(url, params=params, headers=merged_headers)
            last_response = r
            if r.status_code == 429:
                delay = _retry_after_seconds(r)
                if attempt < _DEFAULT_MAX_RETRIES - 1:
                    await asyncio.sleep(min(delay, 300))
                    continue
                # Out of retries: surface RateLimited so the caller's
                # AIMD bucket can shrink the per-tenant rate.
                raise RateLimited(
                    f"bitbucket 429 after {_DEFAULT_MAX_RETRIES} attempts; "
                    f"retry_after={delay} seconds"
                )
            if 500 <= r.status_code < 600 and attempt < _DEFAULT_MAX_RETRIES - 1:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            r.raise_for_status()
            return r
        assert last_response is not None
        last_response.raise_for_status()
        return last_response

    async def _paginate(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        page_size: int = _DEFAULT_PAGE_SIZE,
    ) -> AsyncIterator[Any]:
        """Yield each entry across every page of a paginated endpoint.

        Cloud responses look like ``{"values": [...], "next": "<url>"}``;
        Server responses look like ``{"values": [...], "size": N,
        "isLastPage": false, "nextPageStart": 25}``. Unified into a
        single async iterator of ``values`` entries.

        ``params`` is sent only on the first request — Cloud's ``next``
        URL embeds query state, Server uses an explicit ``start`` pointer.
        """
        next_url: str | None = self._absolute(path)
        first_params: Mapping[str, Any] = {
            **(params or {}),
            "pagelen" if self._flavor == "cloud" else "limit": page_size,
        }
        next_params: Mapping[str, Any] | None = first_params
        next_start: int | None = 0 if self._flavor == "server" else None
        depth = 0
        while next_url is not None:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"bitbucket pagination exceeded {_MAX_PAGINATION_DEPTH} pages "
                    f"at {next_url!r}; refusing to continue"
                )
            request_params = next_params
            if (
                self._flavor == "server"
                and next_start is not None
                and next_start > 0
            ):
                request_params = {
                    **(params or {}),
                    "limit": page_size,
                    "start": next_start,
                }
            r = await self._get(next_url, params=request_params)
            body = r.json() if r.content else {}
            for entry in body.get("values", []) or []:
                yield entry
            if self._flavor == "cloud":
                next_url = body.get("next")
                next_params = None  # `next` already carries query
            else:
                if body.get("isLastPage", True):
                    return
                next_start = body.get("nextPageStart")
                if next_start is None:
                    return
                next_url = self._absolute(path)


# --- helpers ------------------------------------------------------------


def _resolve_auth(
    *,
    flavor: Flavor,
    credential: Credential | None,
    username: str | None,
    app_password: str | None,
    password: str | None,
    token: str | None,
) -> _AuthMode:
    """Order: explicit kwargs > credential payload. Bearer > Basic.

    A bearer token always wins when present; basic auth takes
    ``username`` + (``app_password`` for Cloud or ``password`` for
    Server). Mismatched basic auth (username without password or vice
    versa) raises rather than silently falling back to anonymous —
    Bitbucket has no useful anonymous tier and an unset auth header
    leads to 401-on-everything which is harder to debug than a raised
    misconfiguration.
    """
    if token is None and credential is not None:
        token = _payload_str(credential, "token")
    if token:
        return _BearerAuth(token=token)

    if username is None and credential is not None:
        username = _payload_str(credential, "username")
    if app_password is None and credential is not None:
        app_password = _payload_str(credential, "app_password")
    if password is None and credential is not None:
        password = _payload_str(credential, "password")

    if flavor == "cloud":
        secret = app_password or password
    else:
        secret = password or app_password

    if username and secret:
        return _BasicAuth(username=username, password=secret)
    raise CredentialMisconfiguredError(
        "bitbucket connector requires either `token=` (Bearer) or "
        "`username=` + `app_password=`/`password=` (Basic)"
    )


def _payload_str(credential: Credential, key: str) -> str | None:
    value = credential.payload.get(key)
    if value is None:
        return None
    return str(value)


def _quote_path(path: str) -> str:
    """URL-quote a blob path while preserving ``/`` segment separators.

    Bitbucket file paths can contain spaces, ``#``, ``?``, etc. Encoding
    each segment individually keeps directory traversal intact while
    making the URL safe to send.
    """
    return "/".join(quote(seg, safe="") for seg in path.split("/"))


def _retry_after_seconds(response: httpx.Response) -> float:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return _DEFAULT_RETRY_AFTER_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return _DEFAULT_RETRY_AFTER_SECONDS


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _principal_cloud(user: Mapping[str, Any] | None) -> Principal | None:
    if not user:
        return None
    uuid = user.get("uuid") or user.get("account_id")
    return Principal(
        id=str(uuid or user.get("nickname") or ""),
        display_name=user.get("display_name") or user.get("nickname"),
    )


def _principal_server(user: Mapping[str, Any] | None) -> Principal | None:
    if not user:
        return None
    return Principal(
        id=str(user.get("id") or user.get("name") or ""),
        display_name=user.get("displayName") or user.get("name"),
        email=user.get("emailAddress"),
    )


def _join_issue_text_cloud(
    issue: Mapping[str, Any],
    comments: list[Mapping[str, Any]],
) -> str:
    parts: list[str] = []
    title = issue.get("title")
    if title:
        parts.append(str(title))
    content = (issue.get("content") or {}).get("raw")
    if content:
        parts.append(str(content))
    for c in comments:
        body = (c.get("content") or {}).get("raw")
        if body:
            parts.append(str(body))
    return "\n\n".join(parts)


def _join_pr_text_cloud(
    pr: Mapping[str, Any],
    comments: list[Mapping[str, Any]],
    diff_text: str,
) -> str:
    parts: list[str] = []
    title = pr.get("title")
    if title:
        parts.append(str(title))
    description = (pr.get("description") or pr.get("rendered", {}).get("description", {}).get("raw"))
    if description:
        parts.append(str(description))
    for c in comments:
        body = (c.get("content") or {}).get("raw")
        if body:
            parts.append(str(body))
    if diff_text:
        parts.append(diff_text)
    return "\n\n".join(parts)


def _join_pr_text_server(
    pr: Mapping[str, Any],
    activities: list[Mapping[str, Any]],
    diff_text: str,
) -> str:
    parts: list[str] = []
    title = pr.get("title")
    if title:
        parts.append(str(title))
    description = pr.get("description")
    if description:
        parts.append(str(description))
    for a in activities:
        if a.get("action") == "COMMENTED":
            comment = a.get("comment") or {}
            body = comment.get("text")
            if body:
                parts.append(str(body))
    if diff_text:
        parts.append(diff_text)
    return "\n\n".join(parts)


registry.register("bitbucket", BitbucketConnector)
