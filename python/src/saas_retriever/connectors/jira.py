"""Jira connector — Cloud (/rest/api/3) + Data Center (/rest/api/2).

Single kind, two wire flavors selected at construction. Differences:

* **Cloud** — ``/rest/api/3``. Issue ``description`` and comment
  ``body`` are ADF JSON; converted via ``jira_adf.adf_to_text``.
  Throttle signal: 429 + ``Retry-After``.
* **Data Center** — ``/rest/api/2``. Bodies are storage-XHTML strings;
  converted via ``jira_storage.storage_to_text``. Throttle signal: 503
  + ``Retry-After`` from the DC reverse-proxy rate limiter.

Pipeline per scan:

1. Enumerate projects (``/project/search``, paginated).
2. Per project, JQL-search ``project = X AND updated >= cursor ORDER
   BY updated ASC``.
3. Per issue, paginate ``/issue/{key}/comment`` (when
   ``include_comments``).
4. Render one ``Document.text`` per issue: key + summary + status +
   reporter/assignee + description + comments + attachment refs.
   Attachment bodies are never downloaded — emit URL only.

Cursor: JSON ``{"highest_updated": "<iso8601>"}``. Malformed cursors
silently fall back to a full re-walk.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatch
from typing import Any, Literal

import httpx

from saas_retriever.connectors.jira_adf import adf_to_text
from saas_retriever.connectors.jira_storage import storage_to_text
from saas_retriever.core import (
    Capabilities,
    Document,
    DocumentRef,
    SourceFilter,
)
from saas_retriever.credentials import Credential, CredentialMisconfiguredError
from saas_retriever.rate_limit import RateLimited
from saas_retriever.registry import registry

Flavor = Literal["cloud", "datacenter"]

_USER_AGENT = "saas-retriever/0.2"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_RETRY_AFTER_SECONDS = 30.0
_MAX_RETRY_AFTER_SECONDS = 60.0
_PAGE_SIZE = 100
_COMMENT_PAGE_SIZE = 100
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


def _api_prefix(flavor: Flavor) -> str:
    return "/rest/api/3" if flavor == "cloud" else "/rest/api/2"


class JiraConnector:
    """API-driven Jira connector (Cloud + Data Center)."""

    kind = "jira"

    def __init__(
        self,
        *,
        flavor: Flavor = "cloud",
        base_url: str,
        credential: Credential | None = None,
        email: str | None = None,
        api_token: str | None = None,
        access_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        projects: Iterable[str] = (),
        include_comments: bool = True,
        include_attachments: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
    ) -> None:
        if flavor not in ("cloud", "datacenter"):
            raise ValueError(f"unsupported jira flavor: {flavor!r}")
        if not base_url:
            raise ValueError("jira connector requires `base_url=`")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(
                f"jira `base_url` must start with http:// or https://; got {base_url!r}"
            )
        self._flavor: Flavor = flavor
        self._base_url = base_url.rstrip("/")
        self._api_prefix = _api_prefix(flavor)
        self.projects: tuple[str, ...] = tuple(projects)
        self.include_comments = include_comments
        self.include_attachments = include_attachments
        self._auth = _resolve_auth(
            credential=credential,
            email=email,
            api_token=api_token,
            access_token=access_token,
            username=username,
            password=password,
        )

        host = _host_only(base_url)
        self.id = source_id or f"jira-{flavor}:{host}"

        client_kwargs: dict[str, Any] = {"timeout": timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.AsyncClient(**client_kwargs)

        # issue key → {"issue": ..., "comments": [...]} populated by
        # discover() so fetch() avoids re-issuing /issue/{key}.
        self._issue_cache: dict[str, dict[str, Any]] = {}
        self._high_water: str | None = None
        self._lock = asyncio.Lock()

    # --- public protocol ------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        prior_high_water = _decode_cursor(cursor)
        # filter.since overrides the cursor when both are present —
        # operator-supplied --since is the authoritative knob.
        since = (
            filter.since.isoformat()
            if filter.since is not None
            else prior_high_water
        )
        projects = await self._enumerate_projects(filter)
        for project_key in projects:
            async for issue in self._iter_issues(project_key, since=since):
                key = issue.get("key")
                if not isinstance(key, str) or not key:
                    continue
                comments: list[Mapping[str, Any]] = []
                if self.include_comments:
                    comments = await self._fetch_comments(key)
                async with self._lock:
                    self._issue_cache[key] = {
                        "issue": issue,
                        "comments": comments,
                    }
                    updated = _issue_updated(issue)
                    if updated and (
                        self._high_water is None or updated > self._high_water
                    ):
                        self._high_water = updated
                yield self._issue_to_ref(project_key, issue, comments)

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        key = ref.metadata.get("key")
        if not key:
            return
        async with self._lock:
            cached = self._issue_cache.get(key)
        if cached is None:
            issue = await self._get_json(f"/issue/{key}")
            comments: list[Mapping[str, Any]] = []
            if self.include_comments and issue:
                comments = await self._fetch_comments(key)
        else:
            issue = cached["issue"]
            comments = cached["comments"]
        if not issue:
            return
        text = self._serialise_issue(issue, comments)
        if not text:
            return
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            content_hash=str(key),
        )

    async def discover_and_fetch(
        self, filter: SourceFilter | None = None
    ) -> AsyncIterator[Document]:
        flt = filter or SourceFilter()
        async for ref in self.discover(flt, None):
            async for doc in self.fetch(ref):
                yield doc

    def capabilities(self) -> Capabilities:
        return Capabilities(
            incremental=True,
            binary=False,
            content_hash_delta=False,
            max_concurrent_fetches=4,
            streaming=False,
        )

    async def close(self) -> None:
        async with self._lock:
            self._issue_cache.clear()
            self._high_water = None
        await self._client.aclose()

    def cursor_after_run(self) -> str | None:
        if self._high_water is None:
            return None
        return json.dumps({"highest_updated": self._high_water}, sort_keys=True)

    # --- discovery internals -------------------------------------------

    async def _enumerate_projects(self, filter: SourceFilter) -> list[str]:
        if self.projects:
            allow = list(self.projects)
        else:
            allow = await self._list_all_projects()
        out: list[str] = []
        for project_key in allow:
            if filter.include and not _matches_any(project_key, filter.include):
                continue
            if filter.exclude and _matches_any(project_key, filter.exclude):
                continue
            out.append(project_key)
        return out

    async def _list_all_projects(self) -> list[str]:
        keys: list[str] = []
        start_at = 0
        depth = 0
        while True:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"jira /project/search exceeded {_MAX_PAGINATION_DEPTH} pages"
                )
            body = await self._get_json(
                "/project/search",
                params={"startAt": start_at, "maxResults": _PAGE_SIZE},
            )
            if not body:
                return keys
            values = body.get("values") or []
            for project in values:
                key = project.get("key") if isinstance(project, Mapping) else None
                if isinstance(key, str) and key:
                    keys.append(key)
            if body.get("isLast", True) or not values:
                return keys
            start_at += len(values)

    async def _iter_issues(
        self, project_key: str, *, since: str | None
    ) -> AsyncIterator[Mapping[str, Any]]:
        jql = _build_jql(project_key, since)
        fields = ",".join(
            (
                "summary",
                "status",
                "assignee",
                "reporter",
                "description",
                "updated",
                "attachment",
                "issuetype",
                "priority",
            )
        )
        start_at = 0
        depth = 0
        while True:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"jira /search exceeded {_MAX_PAGINATION_DEPTH} pages"
                )
            body = await self._get_json(
                "/search",
                params={
                    "jql": jql,
                    "startAt": start_at,
                    "maxResults": _PAGE_SIZE,
                    "fields": fields,
                },
            )
            if not body:
                return
            issues = body.get("issues") or []
            for issue in issues:
                if isinstance(issue, Mapping):
                    yield issue
            total = body.get("total")
            new_start = start_at + len(issues)
            if not issues:
                return
            if isinstance(total, int) and new_start >= total:
                return
            if len(issues) < _PAGE_SIZE:
                return
            start_at = new_start

    async def _fetch_comments(self, issue_key: str) -> list[Mapping[str, Any]]:
        out: list[Mapping[str, Any]] = []
        start_at = 0
        depth = 0
        while True:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"jira /issue/{issue_key}/comment exceeded "
                    f"{_MAX_PAGINATION_DEPTH} pages"
                )
            body = await self._get_json(
                f"/issue/{issue_key}/comment",
                params={
                    "startAt": start_at,
                    "maxResults": _COMMENT_PAGE_SIZE,
                },
            )
            if not body:
                return out
            comments = body.get("comments") or []
            for comment in comments:
                if isinstance(comment, Mapping):
                    out.append(comment)
            total = body.get("total")
            new_start = start_at + len(comments)
            if not comments:
                return out
            if isinstance(total, int) and new_start >= total:
                return out
            if len(comments) < _COMMENT_PAGE_SIZE:
                return out
            start_at = new_start

    # --- ref + serialisation -------------------------------------------

    def _issue_to_ref(
        self,
        project_key: str,
        issue: Mapping[str, Any],
        comments: Sequence[Mapping[str, Any]],
    ) -> DocumentRef:
        key = str(issue.get("key", ""))
        fields = issue.get("fields") or {}
        summary = fields.get("summary") if isinstance(fields, Mapping) else None
        last_modified = _parse_iso(_issue_updated(issue))
        etag = _issue_updated(issue)
        size = len(summary) if isinstance(summary, str) else None
        host = _host_only(self._base_url)
        native_url = f"https://{host}/browse/{key}" if key else None
        return DocumentRef(
            source_id=self.id,
            source_kind=self.kind,
            path=f"jira://{project_key}/{key}",
            native_url=native_url,
            parent_chain=(f"jira://{project_key}",),
            content_type="text/plain",
            size=size,
            etag=etag,
            last_modified=last_modified,
            metadata={
                "key": key,
                "project": project_key,
                "flavor": self._flavor,
                "comment_count": str(len(comments)),
            },
        )

    def _serialise_issue(
        self,
        issue: Mapping[str, Any],
        comments: Sequence[Mapping[str, Any]],
    ) -> str:
        fields = issue.get("fields")
        if not isinstance(fields, Mapping):
            fields = {}
        parts: list[str] = []
        key = issue.get("key")
        if isinstance(key, str) and key:
            parts.append(f"key={key}")
        summary = fields.get("summary")
        if isinstance(summary, str) and summary:
            parts.append(f"summary={summary}")
        status = _named(fields.get("status"))
        if status:
            parts.append(f"status={status}")
        assignee = _display_name(fields.get("assignee"))
        if assignee:
            parts.append(f"assignee={assignee}")
        reporter = _display_name(fields.get("reporter"))
        if reporter:
            parts.append(f"reporter={reporter}")
        description_text = self._convert_body(fields.get("description"))
        if description_text:
            parts.append(f"description={description_text}")
        for comment in comments:
            comment_id = comment.get("id")
            author = _display_name(
                comment.get("author") or comment.get("updateAuthor")
            )
            body_text = self._convert_body(comment.get("body"))
            if not body_text:
                continue
            label = f"comment[{comment_id}]" if comment_id else "comment"
            if author:
                parts.append(f"{label}={author}: {body_text}")
            else:
                parts.append(f"{label}={body_text}")
        if self.include_attachments:
            for attachment in fields.get("attachment") or []:
                if not isinstance(attachment, Mapping):
                    continue
                name = attachment.get("filename") or attachment.get("name") or ""
                content_url = (
                    attachment.get("content") or attachment.get("contentUrl") or ""
                )
                if name or content_url:
                    parts.append(f"attachment={name}, url={content_url}")
        return "\n".join(parts)

    def _convert_body(self, body: Any) -> str:
        if body is None or body == "":
            return ""
        if self._flavor == "cloud":
            # Cloud sometimes returns a raw string for legacy custom
            # fields configured to use "text" representation; fall back
            # to the storage stripper which handles plain strings too.
            if isinstance(body, str):
                return storage_to_text(body)
            return adf_to_text(body)
        return storage_to_text(body)

    # --- HTTP plumbing --------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
            "Authorization": self._auth.header_value(),
        }

    def _absolute(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        if path_or_url.startswith("/rest/"):
            return f"{self._base_url}{path_or_url}"
        return f"{self._base_url}{self._api_prefix}{path_or_url}"

    async def _get_json(
        self,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self._absolute(path_or_url)
        clean_params = (
            {k: v for k, v in params.items() if v is not None} if params else None
        )
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.get(
                url, params=clean_params, headers=self._headers()
            )
            if not _is_throttle(r, self._flavor):
                if r.status_code == 404:
                    # Atlassian idiom: 404 conflates "no permission" with
                    # "doesn't exist". Surface as empty so callers can
                    # `if not body: return`.
                    return {}
                r.raise_for_status()
                data = r.json()
                return dict(data) if isinstance(data, Mapping) else {}
            delay = _retry_after_seconds(r)
            if attempt < _DEFAULT_MAX_RETRIES - 1:
                await asyncio.sleep(min(delay, 300))
                continue
            raise RateLimited(
                f"jira {r.status_code} after {_DEFAULT_MAX_RETRIES} attempts; "
                f"retry_after={delay} seconds"
            )
        # Unreachable.
        return {}


# --- helpers ------------------------------------------------------------


def _resolve_auth(
    *,
    credential: Credential | None,
    email: str | None,
    api_token: str | None,
    access_token: str | None,
    username: str | None,
    password: str | None,
) -> _AuthMode:
    """Order: explicit kwargs > credential payload. Bearer > Basic.

    Modes (any one):
      * ``access_token`` → Bearer (Cloud OAuth or DC PAT).
      * ``email`` + ``api_token`` → Cloud Basic.
      * ``username`` + ``password`` → DC Basic.
    """
    if credential is not None:
        if access_token is None:
            value = credential.payload.get("access_token") or credential.payload.get(
                "token"
            )
            if isinstance(value, str) and value:
                access_token = value
        if email is None:
            value = credential.payload.get("email")
            if isinstance(value, str) and value:
                email = value
        if api_token is None:
            value = credential.payload.get("api_token")
            if isinstance(value, str) and value:
                api_token = value
        if username is None:
            value = credential.payload.get("username")
            if isinstance(value, str) and value:
                username = value
        if password is None:
            value = credential.payload.get("password")
            if isinstance(value, str) and value:
                password = value

    if access_token:
        return _BearerAuth(token=access_token)
    if email and api_token:
        return _BasicAuth(username=email, password=api_token)
    if username and password:
        return _BasicAuth(username=username, password=password)
    raise CredentialMisconfiguredError(
        "jira connector requires one of: `access_token=` (Bearer), "
        "`email=`+`api_token=` (Cloud Basic), or `username=`+`password=` (DC Basic)"
    )


def _build_jql(project_key: str, since: str | None) -> str:
    clauses = [f'project = "{project_key}"']
    if since:
        clauses.append(f'updated >= "{since}"')
    return " AND ".join(clauses) + " ORDER BY updated ASC"


def _decode_cursor(cursor: str | None) -> str | None:
    if not cursor:
        return None
    try:
        decoded = json.loads(cursor)
    except (ValueError, TypeError):
        return None
    if not isinstance(decoded, Mapping):
        return None
    value = decoded.get("highest_updated")
    if isinstance(value, str) and value:
        return value
    return None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalised = value
    if "+" in normalised[19:] or "-" in normalised[19:]:
        head, sep, tail = (
            normalised.rpartition("+")
            if "+" in normalised[19:]
            else normalised.rpartition("-")
        )
        if sep and len(tail) == 4 and tail.isdigit():
            normalised = f"{head}{sep}{tail[:2]}:{tail[2:]}"
    try:
        return datetime.fromisoformat(normalised.replace("Z", "+00:00"))
    except ValueError:
        return None


def _issue_updated(issue: Mapping[str, Any]) -> str | None:
    fields = issue.get("fields")
    if not isinstance(fields, Mapping):
        return None
    updated = fields.get("updated")
    if isinstance(updated, str) and updated:
        return updated
    return None


def _named(field: Any) -> str:
    if isinstance(field, Mapping):
        name = field.get("name")
        if isinstance(name, str):
            return name
    return ""


def _display_name(field: Any) -> str:
    if isinstance(field, Mapping):
        for key in ("displayName", "name", "emailAddress", "accountId"):
            v = field.get(key)
            if isinstance(v, str) and v:
                return v
    return ""


def _host_only(base_url: str) -> str:
    s = base_url
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    if "/" in s:
        s = s.split("/", 1)[0]
    return s


def _matches_any(s: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch(s, p) for p in patterns)


def _is_throttle(response: httpx.Response, flavor: Flavor) -> bool:
    if response.status_code == 429:
        return True
    if response.status_code == 503 and flavor == "datacenter":
        return True
    return False


def _retry_after_seconds(response: httpx.Response) -> float:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return _DEFAULT_RETRY_AFTER_SECONDS
    try:
        seconds = max(0.0, float(raw))
    except (ValueError, TypeError):
        return _DEFAULT_RETRY_AFTER_SECONDS
    return min(seconds, _MAX_RETRY_AFTER_SECONDS)


registry.register("jira", JiraConnector)
