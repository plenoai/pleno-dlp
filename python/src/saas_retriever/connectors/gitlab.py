"""GitLab connector — REST-API driven, no git clone, no scraping.

Walks projects via ``/api/v4`` and lists code via the recursive Tree
API, mirroring the github connector's pattern. Single-instance
``base_url`` (gitlab.com or a self-managed host); a private CA bundle
is honoured when supplied.

Targets (exactly one):

* ``project="ns/path"`` — single project (URL-encoded server-side).
* ``group="ns"`` — recursive walk of every project under the group,
  honouring ``include_subgroups=True``.

Resources (default = all):

* ``"code"`` — every blob in the default branch via the recursive
  ``/repository/tree`` endpoint. ``fetch()`` pulls raw bytes via
  ``/repository/files/:path/raw``.
* ``"issues"`` — every issue with title + description + every note,
  joined into one ``Document.text``.
* ``"mrs"`` — every merge request with title + description + notes +
  per-file diff (collapsed into unified diff text).

Auth modes (operator-selected):

* PAT / project access token → ``PRIVATE-TOKEN: <t>``
* OAuth2 access token → ``Authorization: Bearer <t>``

Pagination follows the ``rel="next"`` URL in the ``Link`` header.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any
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

DEFAULT_BASE_URL = "https://gitlab.com"
_API_VERSION_PREFIX = "/api/v4"
_USER_AGENT = "saas-retriever/0.2"

DEFAULT_RESOURCES: frozenset[str] = frozenset({"code", "issues", "mrs"})
SUPPORTED_RESOURCES: frozenset[str] = frozenset({"code", "issues", "mrs"})

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_PAGE_SIZE = 100
_LEGAL_VISIBILITY: frozenset[str] = frozenset({"private", "internal", "public"})


class GitlabAuthMode(Enum):
    """Auth mode chosen explicitly by the operator.

    PAT and PROJECT both ride the ``PRIVATE-TOKEN`` header — the scope
    difference is enforced server-side; the wire is identical. Kept
    distinct so error messages can name the misfiring scope.
    """

    PAT = "pat"
    OAUTH = "oauth"
    PROJECT = "project"


_LEGAL_AUTH_MODES = {m.value for m in GitlabAuthMode}


class GitlabConnector:
    """API-driven GitLab source connector.

    Owns one ``httpx.AsyncClient`` for its lifetime. Construction takes
    either a ``Credential`` (with ``payload['auth']`` + ``payload['token']``
    or ``payload['access_token']``) or the discrete ``token=`` /
    ``auth=`` knobs. Bearer (OAuth) is selected when ``auth='oauth'``;
    everything else uses ``PRIVATE-TOKEN``.
    """

    kind = "gitlab"

    def __init__(
        self,
        *,
        project: str | None = None,
        group: str | None = None,
        credential: Credential | None = None,
        token: str | None = None,
        auth: str | GitlabAuthMode = GitlabAuthMode.PAT,
        resources: Iterable[str] | None = None,
        base_url: str = DEFAULT_BASE_URL,
        include_archived: bool = False,
        visibility: str | None = None,
        ca_bundle_path: str | None = None,
        max_projects: int = 1000,
        max_items_per_project: int = 1000,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
    ) -> None:
        targets = [t for t in (project, group) if t is not None]
        if len(targets) != 1:
            raise ValueError("gitlab connector requires exactly one of `project=` or `group=`")
        if visibility is not None and visibility not in _LEGAL_VISIBILITY:
            raise ValueError(
                f"visibility must be one of {sorted(_LEGAL_VISIBILITY)} or None; got {visibility!r}"
            )
        chosen = frozenset(resources) if resources is not None else DEFAULT_RESOURCES
        unknown = chosen - SUPPORTED_RESOURCES
        if unknown:
            raise ValueError(
                f"unknown resources {sorted(unknown)}; supported: {sorted(SUPPORTED_RESOURCES)}"
            )

        self.project_path = project
        self.group_path = group
        self.resources: frozenset[str] = chosen
        self.include_archived = include_archived
        self.visibility = visibility
        self.max_projects = max_projects
        self.max_items_per_project = max_items_per_project
        self._base_url = base_url.rstrip("/")
        self._auth_mode, self._token = _resolve_credential(
            credential=credential, token=token, auth=auth
        )
        scope = group if group is not None else project
        self.id = source_id or (
            f"gitlab-group:{scope}" if group is not None else f"gitlab:{scope}"
        )

        client_kwargs: dict[str, Any] = {"timeout": timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        elif ca_bundle_path is not None:
            client_kwargs["verify"] = ca_bundle_path
        self._client = httpx.AsyncClient(**client_kwargs)

    # --- public protocol ------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        del cursor  # GitLab keyset pagination follows Link headers
        async for project in self._iter_projects():
            project_id = project.get("id")
            path_with_ns = project.get("path_with_namespace") or ""
            default_branch = project.get("default_branch") or "HEAD"
            web_url = project.get("web_url") or f"{self._base_url}/{path_with_ns}"
            if project_id is None or not path_with_ns:
                continue
            if "code" in self.resources:
                async for ref in self._discover_code(
                    project_id, path_with_ns, default_branch, web_url, filter
                ):
                    yield ref
            if "issues" in self.resources:
                async for ref in self._discover_issues(
                    project_id, path_with_ns, web_url, filter
                ):
                    yield ref
            if "mrs" in self.resources:
                async for ref in self._discover_mrs(
                    project_id, path_with_ns, web_url, filter
                ):
                    yield ref

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        rt = ref.metadata.get("resource_type", "code")
        if rt == "code":
            async for d in self._fetch_blob(ref):
                yield d
        elif rt == "issue":
            async for d in self._fetch_issue(ref):
                yield d
        elif rt == "mr":
            async for d in self._fetch_mr(ref):
                yield d
        else:
            raise ValueError(f"unknown resource_type {rt!r}; expected code|issue|mr")

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

    # --- project enumeration -------------------------------------------

    async def _iter_projects(self) -> AsyncIterator[Mapping[str, Any]]:
        if self.project_path is not None:
            encoded = quote(self.project_path, safe="")
            r = await self._get(f"/projects/{encoded}")
            project = r.json()
            if self._project_passes_filters(project):
                yield project
            return
        assert self.group_path is not None
        encoded = quote(self.group_path, safe="")
        params: dict[str, Any] = {
            "include_subgroups": "true",
            "per_page": str(_DEFAULT_PAGE_SIZE),
            "archived": "true" if self.include_archived else "false",
        }
        if self.visibility is not None:
            params["visibility"] = self.visibility
        emitted = 0
        async for project in self._paginate(
            f"/groups/{encoded}/projects", params=params
        ):
            if not isinstance(project, Mapping):
                continue
            if not self._project_passes_filters(project):
                continue
            emitted += 1
            if emitted > self.max_projects:
                return
            yield project

    def _project_passes_filters(self, project: Mapping[str, Any]) -> bool:
        # Belt-and-braces: GitLab < 13.0 ignored ?archived= on
        # /groups/:id/projects, and the single-project endpoint has no
        # such param.
        if not self.include_archived and project.get("archived"):
            return False
        return True

    # --- code -----------------------------------------------------------

    async def _discover_code(
        self,
        project_id: int,
        path_with_ns: str,
        branch: str,
        web_url: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {
            "recursive": "true",
            "per_page": str(_DEFAULT_PAGE_SIZE),
            "ref": branch,
        }
        emitted = 0
        try:
            async for entry in self._paginate(
                f"/projects/{project_id}/repository/tree", params=params
            ):
                if not isinstance(entry, Mapping):
                    continue
                if entry.get("type") != "blob":
                    continue
                blob_path = entry.get("path") or ""
                blob_id = entry.get("id") or ""
                if not blob_path:
                    continue
                emitted += 1
                if emitted > self.max_items_per_project:
                    return
                yield DocumentRef(
                    source_id=self.id,
                    source_kind=self.kind,
                    path=f"{path_with_ns}:{blob_path}",
                    native_url=f"{web_url}/-/blob/{branch}/{blob_path}",
                    content_type="application/octet-stream",
                    metadata={
                        "project_id": str(project_id),
                        "path_with_namespace": path_with_ns,
                        "branch": branch,
                        "blob_path": blob_path,
                        "blob_sha": str(blob_id),
                        "resource_type": "code",
                    },
                )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 409):
                return
            raise

    async def _fetch_blob(self, ref: DocumentRef) -> AsyncIterator[Document]:
        project_id = ref.metadata["project_id"]
        blob_path = ref.metadata["blob_path"]
        branch = ref.metadata["branch"]
        encoded = quote(blob_path, safe="")
        r = await self._get(
            f"/projects/{project_id}/repository/files/{encoded}/raw",
            params={"ref": branch},
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
        sha = ref.metadata.get("blob_sha", "")
        yield Document(
            ref=ref,
            text=text,
            binary=binary,
            fetched_at=datetime.now(UTC),
            content_hash=f"sha1:{sha}" if sha else None,
        )

    # --- issues ---------------------------------------------------------

    async def _discover_issues(
        self,
        project_id: int,
        path_with_ns: str,
        web_url: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {
            "scope": "all",
            "per_page": str(_DEFAULT_PAGE_SIZE),
        }
        if filter.since is not None:
            params["updated_after"] = filter.since.isoformat()
        emitted = 0
        async for issue in self._paginate(
            f"/projects/{project_id}/issues", params=params
        ):
            if not isinstance(issue, Mapping):
                continue
            emitted += 1
            if emitted > self.max_items_per_project:
                return
            iid = issue.get("iid")
            yield DocumentRef(
                source_id=self.id,
                source_kind=self.kind,
                path=f"{path_with_ns}:issues/{iid}",
                native_url=issue.get("web_url"),
                content_type="text/markdown",
                last_modified=_parse_ts(issue.get("updated_at")),
                metadata={
                    "project_id": str(project_id),
                    "path_with_namespace": path_with_ns,
                    "iid": str(iid),
                    "title": str(issue.get("title", "")),
                    "resource_type": "issue",
                },
            )

    async def _fetch_issue(self, ref: DocumentRef) -> AsyncIterator[Document]:
        project_id = ref.metadata["project_id"]
        iid = ref.metadata["iid"]
        issue = (
            await self._get(f"/projects/{project_id}/issues/{iid}")
        ).json()
        notes: list[Mapping[str, Any]] = []
        async for note in self._paginate(
            f"/projects/{project_id}/issues/{iid}/notes",
            params={"per_page": str(_DEFAULT_PAGE_SIZE), "order_by": "created_at", "sort": "asc"},
        ):
            if isinstance(note, Mapping):
                notes.append(note)
        text = _join_issue_text(issue, notes)
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            created_by=_principal(issue.get("author")),
        )

    # --- merge requests -------------------------------------------------

    async def _discover_mrs(
        self,
        project_id: int,
        path_with_ns: str,
        web_url: str,
        filter: SourceFilter,
    ) -> AsyncIterator[DocumentRef]:
        params: dict[str, Any] = {
            "scope": "all",
            "state": "all",
            "per_page": str(_DEFAULT_PAGE_SIZE),
        }
        if filter.since is not None:
            params["updated_after"] = filter.since.isoformat()
        emitted = 0
        async for mr in self._paginate(
            f"/projects/{project_id}/merge_requests", params=params
        ):
            if not isinstance(mr, Mapping):
                continue
            emitted += 1
            if emitted > self.max_items_per_project:
                return
            iid = mr.get("iid")
            yield DocumentRef(
                source_id=self.id,
                source_kind=self.kind,
                path=f"{path_with_ns}:merge_requests/{iid}",
                native_url=mr.get("web_url"),
                content_type="text/markdown",
                last_modified=_parse_ts(mr.get("updated_at")),
                metadata={
                    "project_id": str(project_id),
                    "path_with_namespace": path_with_ns,
                    "iid": str(iid),
                    "title": str(mr.get("title", "")),
                    "resource_type": "mr",
                },
            )

    async def _fetch_mr(self, ref: DocumentRef) -> AsyncIterator[Document]:
        project_id = ref.metadata["project_id"]
        iid = ref.metadata["iid"]
        mr = (
            await self._get(f"/projects/{project_id}/merge_requests/{iid}")
        ).json()
        notes: list[Mapping[str, Any]] = []
        async for note in self._paginate(
            f"/projects/{project_id}/merge_requests/{iid}/notes",
            params={"per_page": str(_DEFAULT_PAGE_SIZE), "order_by": "created_at", "sort": "asc"},
        ):
            if isinstance(note, Mapping):
                notes.append(note)
        diff_text = await self._fetch_mr_diff(project_id, iid)
        text = _join_mr_text(mr, notes, diff_text)
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            created_by=_principal(mr.get("author")),
        )

    async def _fetch_mr_diff(self, project_id: str, iid: str) -> str:
        try:
            parts: list[str] = []
            async for change in self._paginate(
                f"/projects/{project_id}/merge_requests/{iid}/diffs",
                params={"per_page": str(_DEFAULT_PAGE_SIZE)},
            ):
                if not isinstance(change, Mapping):
                    continue
                old_path = change.get("old_path") or change.get("new_path") or ""
                new_path = change.get("new_path") or old_path
                diff = change.get("diff") or ""
                if not diff:
                    continue
                parts.append(f"--- a/{old_path}\n+++ b/{new_path}\n{diff}")
            return "\n".join(parts)
        except httpx.HTTPStatusError:
            # Large MRs / server-side caps — keep going on body+notes.
            return ""

    # --- HTTP plumbing --------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }
        if self._auth_mode is GitlabAuthMode.OAUTH:
            h["Authorization"] = f"Bearer {self._token}"
        else:
            h["PRIVATE-TOKEN"] = self._token
        return h

    def _resolve_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return f"{self._base_url}{_API_VERSION_PREFIX}{path_or_url}"

    async def _get(
        self,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        url = self._resolve_url(path_or_url)
        merged = self._headers()
        if headers:
            merged.update(headers)
        backoff = 1.0
        last_response: httpx.Response | None = None
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.get(url, params=params, headers=merged)
            last_response = r
            if r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After", "30"))
                if attempt < _DEFAULT_MAX_RETRIES - 1:
                    await asyncio.sleep(min(retry_after, 300))
                    continue
                raise RateLimited(
                    f"gitlab 429 after {_DEFAULT_MAX_RETRIES} attempts; "
                    f"retry_after={retry_after} seconds"
                )
            if r.status_code == 403 and (
                r.headers.get("RateLimit-Remaining") == "0"
                or r.headers.get("X-RateLimit-Remaining") == "0"
            ):
                raise RateLimited(
                    "gitlab quota exhausted (403 + RateLimit-Remaining=0)"
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
    ) -> AsyncIterator[Any]:
        url: str | None = path
        next_params: Mapping[str, Any] | None = params
        while url is not None:
            r = await self._get(url, params=next_params)
            data = r.json()
            if isinstance(data, list):
                for entry in data:
                    yield entry
            elif isinstance(data, Mapping):
                # Single-resource endpoint hit with paginate(): yield once.
                yield data
                return
            else:
                return
            url = _next_link(r.headers.get("Link", ""))
            next_params = None  # next URL embeds the cursor


# --- helpers ------------------------------------------------------------


def _resolve_credential(
    *,
    credential: Credential | None,
    token: str | None,
    auth: str | GitlabAuthMode,
) -> tuple[GitlabAuthMode, str]:
    """Order: explicit kwargs > credential payload.

    Mode resolution order: explicit ``auth=`` if non-default kwarg, else
    ``credential.payload['auth']``, else PAT default. Token is taken from
    ``token=`` first, then from ``payload['token']`` /
    ``payload['access_token']`` (canonical key per mode tried first).
    """
    if isinstance(auth, str):
        if auth not in _LEGAL_AUTH_MODES:
            raise ValueError(
                f"unsupported gitlab auth mode {auth!r}; "
                f"expected one of {sorted(_LEGAL_AUTH_MODES)}"
            )
        mode = GitlabAuthMode(auth)
    else:
        mode = auth

    if credential is not None:
        cred_auth = credential.payload.get("auth")
        # Operator-supplied credential overrides the constructor default
        # (PAT) but does not override an explicit non-default kwarg.
        if isinstance(cred_auth, str) and mode is GitlabAuthMode.PAT:
            if cred_auth not in _LEGAL_AUTH_MODES:
                raise ValueError(
                    f"unsupported gitlab auth mode {cred_auth!r} "
                    f"in credential.payload['auth']; expected one of {sorted(_LEGAL_AUTH_MODES)}"
                )
            mode = GitlabAuthMode(cred_auth)

    if token is None and credential is not None:
        primary = "access_token" if mode is GitlabAuthMode.OAUTH else "token"
        fallback = "token" if mode is GitlabAuthMode.OAUTH else "access_token"
        value = credential.payload.get(primary) or credential.payload.get(fallback)
        if isinstance(value, str) and value:
            token = value

    if not token:
        raise CredentialMisconfiguredError(
            "gitlab connector requires `token=` (PAT/project) or `token=`/"
            "credential.payload['access_token'] (OAuth)"
        )
    return mode, token


def _next_link(link_header: str) -> str | None:
    """Extract ``rel="next"`` from an RFC 5988 Link header."""
    if not link_header:
        return None
    for entry in link_header.split(","):
        parts = [p.strip() for p in entry.split(";")]
        if len(parts) < 2:
            continue
        url_part = parts[0]
        if not (url_part.startswith("<") and url_part.endswith(">")):
            continue
        url = url_part[1:-1]
        for attr in parts[1:]:
            if attr.replace(" ", "") == 'rel="next"':
                return url
    return None


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _principal(user: Mapping[str, Any] | None) -> Principal | None:
    if not user:
        return None
    return Principal(
        id=str(user.get("id") or user.get("username") or ""),
        display_name=user.get("name") or user.get("username"),
    )


def _join_issue_text(
    issue: Mapping[str, Any], notes: list[Mapping[str, Any]]
) -> str:
    parts: list[str] = []
    title = issue.get("title")
    if title:
        parts.append(str(title))
    description = issue.get("description")
    if description:
        parts.append(str(description))
    for note in notes:
        if note.get("system"):
            # Skip GitLab system notes ("changed milestone to ..."); they
            # carry no operator-authored content.
            continue
        body = note.get("body")
        if body:
            parts.append(str(body))
    return "\n\n".join(parts)


def _join_mr_text(
    mr: Mapping[str, Any],
    notes: list[Mapping[str, Any]],
    diff_text: str,
) -> str:
    parts: list[str] = []
    title = mr.get("title")
    if title:
        parts.append(str(title))
    description = mr.get("description")
    if description:
        parts.append(str(description))
    for note in notes:
        if note.get("system"):
            continue
        body = note.get("body")
        if body:
            parts.append(str(body))
    if diff_text:
        parts.append(diff_text)
    return "\n\n".join(parts)


registry.register("gitlab", GitlabConnector)
