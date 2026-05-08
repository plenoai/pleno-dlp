"""Confluence connector — Cloud + Data Center, REST-API driven.

Single connector kind backed by two REST flavors selected at
construction time. Wire-level differences (paginator quirks, URL
prefix, 503 vs 429 throttling) are folded into the request layer; the
discover/fetch protocol surface is identical for both flavors.

Pipeline per scan run:

1. Enumerate spaces (``/rest/api/space``, paginated). Optional config
   ``spaces=("ENG", "SEC")`` narrows to an allowlist.
2. Per space, enumerate pages (``/space/{key}/content/page``,
   paginated, expanding ``body.storage,version,space``). Filter
   client-side by ``version.when > cursor`` so DC installs without the
   server-side CQL filter still get incremental scans.
3. Per page, fetch comments + attachment refs and synthesise one
   ``Document`` whose text concatenates the page body + comment
   bodies + serialised attachment refs.

Cursor: JSON-encoded ``{"high_water": "<isoformat>"}``. Future fields
namespaced under that JSON object so we can extend without breaking
existing checkpoints — readers ignore unknown keys, writers preserve
them.
"""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from saas_retriever.connectors.confluence_storage import storage_to_text
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
_MAX_PAGINATION_DEPTH = 10_000
_PAGE_EXPAND = "body.storage,version,space"


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


class ConfluenceConnector:
    """API-driven Confluence source connector (Cloud + Data Center)."""

    kind = "confluence"

    def __init__(
        self,
        *,
        flavor: Flavor = "cloud",
        base_url: str,
        credential: Credential | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        spaces: Iterable[str] = (),
        include_archived: bool = False,
        page_size: int = 100,
        ca_bundle_path: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        if flavor not in ("cloud", "datacenter"):
            raise ValueError(f"unsupported confluence flavor: {flavor!r}")
        if not base_url:
            raise ValueError(
                "confluence connector requires `base_url=` "
                "(Cloud has no shared default; DC is self-hosted)"
            )
        if page_size < 1 or page_size > 250:
            # Confluence's documented per-request ceiling is 250 on v1
            # and 100 on v2. Reject obvious misconfiguration upfront.
            raise ValueError("page_size must be between 1 and 250")
        self._flavor: Flavor = flavor
        self._base_url = base_url.rstrip("/")
        self.spaces: tuple[str, ...] = tuple(spaces)
        self.include_archived = include_archived
        self.page_size = page_size
        self._auth = _resolve_auth(
            flavor=flavor,
            credential=credential,
            token=token,
            username=username,
            password=password,
            email=email,
            api_token=api_token,
        )

        host = _host_from_base_url(base_url)
        self.id = source_id or f"confluence-{flavor}:{host}"
        self.tenant_id = tenant_id or self.id

        client_kwargs: dict[str, Any] = {"timeout": timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        elif ca_bundle_path is not None:
            client_kwargs["verify"] = ssl.create_default_context(cafile=ca_bundle_path)
        self._client = httpx.AsyncClient(**client_kwargs)

        # page_id → cached payload for fetch(). Populated in discover()
        # so a discover→fetch round-trip is one HTTP request set.
        self._page_cache: dict[str, _PageBundle] = {}
        self._high_water: datetime | None = None

    # --- public protocol ------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        del filter  # Confluence has no native include/exclude filter
        prior_high_water = _decode_cursor(cursor)
        self._page_cache.clear()
        self._high_water = prior_high_water
        for space_key in await self._resolve_spaces():
            async for page in self._enumerate_pages(space_key):
                ref = await self._page_to_ref(space_key, page, prior_high_water)
                if ref is not None:
                    yield ref

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        page_id = ref.metadata.get("page_id")
        if not page_id:
            return
        bundle = self._page_cache.get(page_id)
        if bundle is None:
            # Either the ref came from a different connector instance
            # or discover() never ran. Yield nothing rather than
            # raise — orchestrators treat empty fetch as "nothing to scan".
            return
        text = _serialise_bundle(bundle)
        if not text:
            return
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
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
        self._page_cache.clear()
        await self._client.aclose()

    def cursor_after_run(self) -> str | None:
        if self._high_water is None:
            return None
        return _encode_cursor(self._high_water)

    # --- discovery internals -------------------------------------------

    async def _resolve_spaces(self) -> list[str]:
        if self.spaces:
            return list(self.spaces)
        keys: list[str] = []
        async for entry in self._paginate("/rest/api/space"):
            key = entry.get("key")
            if isinstance(key, str) and key:
                keys.append(key)
        return keys

    async def _enumerate_pages(
        self, space_key: str
    ) -> AsyncIterator[Mapping[str, Any]]:
        async for page in self._paginate(
            f"/rest/api/space/{space_key}/content/page",
            params={"expand": _PAGE_EXPAND},
        ):
            yield page

    async def _page_to_ref(
        self,
        space_key: str,
        page: Mapping[str, Any],
        prior_high_water: datetime | None,
    ) -> DocumentRef | None:
        page_id = page.get("id")
        if not isinstance(page_id, str) or not page_id:
            return None
        if not self.include_archived and _is_archived(page):
            return None
        version = page.get("version") or {}
        last_modified = _parse_iso(version.get("when"))
        if (
            prior_high_water is not None
            and last_modified is not None
            and last_modified <= prior_high_water
        ):
            return None
        title = page.get("title") or page_id
        body = ((page.get("body") or {}).get("storage") or {}).get("value") or ""
        comments = await self._collect_comments(page_id)
        attachments = await self._collect_attachments(page_id)
        bundle = _PageBundle(
            page_id=page_id,
            space_key=space_key,
            title=str(title),
            body_storage=str(body),
            version_when=last_modified,
            comments=tuple(comments),
            attachments=tuple(attachments),
        )
        self._page_cache[page_id] = bundle
        if last_modified is not None:
            if self._high_water is None or last_modified > self._high_water:
                self._high_water = last_modified
        cursor_value = _encode_cursor(self._high_water) if self._high_water else None
        metadata: dict[str, str] = {
            "page_id": page_id,
            "space_key": space_key,
            "title": str(title),
            "flavor": self._flavor,
        }
        if cursor_value is not None:
            metadata["_cursor"] = cursor_value
        return DocumentRef(
            source_id=self.id,
            source_kind=self.kind,
            path=f"confluence://{space_key}/{page_id}",
            native_url=_browse_url(self._base_url, page),
            parent_chain=(f"confluence://{space_key}",),
            content_type="text/plain",
            last_modified=last_modified,
            metadata=metadata,
        )

    async def _collect_comments(self, page_id: str) -> list[str]:
        out: list[str] = []
        async for comment in self._paginate(
            f"/rest/api/content/{page_id}/child/comment",
            params={"expand": "body.storage"},
        ):
            body = ((comment.get("body") or {}).get("storage") or {}).get("value")
            if isinstance(body, str) and body:
                out.append(storage_to_text(body))
        return out

    async def _collect_attachments(self, page_id: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        async for attachment in self._paginate(
            f"/rest/api/content/{page_id}/child/attachment",
        ):
            title = attachment.get("title")
            links = attachment.get("_links") or {}
            href = links.get("download") or links.get("webui")
            if isinstance(title, str) and isinstance(href, str):
                out.append((title, _resolve_link(self._base_url, href)))
        return out

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
        return f"{self._base_url}{path_or_url}"

    async def _get(
        self,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        url = self._absolute(path_or_url)
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.get(url, params=params, headers=self._headers())
            if not _is_throttled(r, self._flavor):
                return r
            delay = _retry_after_seconds(r)
            if attempt < _DEFAULT_MAX_RETRIES - 1:
                await asyncio.sleep(min(delay, 300))
                continue
            raise RateLimited(
                f"confluence {r.status_code} after {_DEFAULT_MAX_RETRIES} attempts; "
                f"retry_after={delay} seconds"
            )
        # Unreachable (loop returns or raises).
        raise RateLimited("confluence: throttled past retry budget")

    async def _paginate(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        next_url: str | None = self._absolute(path)
        next_params: Mapping[str, Any] | None = {
            **(params or {}),
            "limit": self.page_size,
        }
        depth = 0
        while next_url is not None:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"confluence pagination exceeded {_MAX_PAGINATION_DEPTH} pages "
                    f"at {next_url!r}; refusing to continue"
                )
            r = await self._get(next_url, params=next_params)
            if r.status_code != 200:
                # 401/403/404 on a paginated endpoint: yield nothing.
                # Mirrors the bitbucket pattern — discover-time HTTP
                # errors are treated as empty result sets so a deleted
                # space between enumeration and walk doesn't crash the run.
                return
            body = r.json()
            for entry in body.get("results", []) or []:
                if isinstance(entry, Mapping):
                    yield entry
            links = body.get("_links") or {}
            raw_next = links.get("next")
            if not isinstance(raw_next, str) or not raw_next:
                return
            next_url = self._absolute(raw_next)
            next_params = None  # `next` already carries the cursor


# --- helpers ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PageBundle:
    page_id: str
    space_key: str
    title: str
    body_storage: str
    version_when: datetime | None
    comments: tuple[str, ...] = ()
    attachments: tuple[tuple[str, str], ...] = ()


def _serialise_bundle(bundle: _PageBundle) -> str:
    parts: list[str] = []
    parts.append(f"title={bundle.title}")
    parts.append(f"space={bundle.space_key}")
    if bundle.version_when is not None:
        parts.append(f"version={bundle.version_when.isoformat()}")
    body_text = storage_to_text(bundle.body_storage)
    if body_text:
        parts.append("")
        parts.append(body_text)
    for comment in bundle.comments:
        if comment:
            parts.append("")
            parts.append(f"comment={comment}")
    for title, href in bundle.attachments:
        parts.append(f"attachment={title}, url={href}")
    return "\n".join(parts).strip()


def _resolve_auth(
    *,
    flavor: Flavor,
    credential: Credential | None,
    token: str | None,
    username: str | None,
    password: str | None,
    email: str | None,
    api_token: str | None,
) -> _AuthMode:
    """Order: explicit kwargs > credential payload. Bearer > Basic.

    Cloud Basic = ``email`` + ``api_token`` (preferred) or
    ``username``/``password``. DC Basic = ``username`` + ``password``.
    """
    if token is None and credential is not None:
        cred_token = credential.payload.get("access_token") or credential.payload.get(
            "token"
        )
        if isinstance(cred_token, str) and cred_token:
            token = cred_token
    if token:
        return _BearerAuth(token=token)

    if credential is not None:
        if username is None:
            payload_username = credential.payload.get("username")
            if isinstance(payload_username, str):
                username = payload_username
        if email is None:
            payload_email = credential.payload.get("email")
            if isinstance(payload_email, str):
                email = payload_email
        if api_token is None:
            payload_api_token = credential.payload.get("api_token")
            if isinstance(payload_api_token, str):
                api_token = payload_api_token
        if password is None:
            payload_password = credential.payload.get("password")
            if isinstance(payload_password, str):
                password = payload_password

    if flavor == "cloud":
        basic_user = email or username
        basic_secret = api_token or password
    else:
        basic_user = username
        basic_secret = password or api_token

    if basic_user and basic_secret:
        return _BasicAuth(username=basic_user, password=basic_secret)

    raise CredentialMisconfiguredError(
        f"confluence-{flavor} connector requires either `token=` (Bearer) or "
        f"{'`email`+`api_token`' if flavor == 'cloud' else '`username`+`password`'} (Basic)"
    )


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_archived(page: Mapping[str, Any]) -> bool:
    status = page.get("status")
    return isinstance(status, str) and status in {"archived", "trashed"}


def _encode_cursor(when: datetime) -> str:
    return json.dumps({"high_water": when.isoformat()}, sort_keys=True)


def _decode_cursor(cursor: str | None) -> datetime | None:
    if not cursor:
        return None
    try:
        decoded = json.loads(cursor)
    except (ValueError, TypeError):
        return None
    if not isinstance(decoded, dict):
        return None
    raw = decoded.get("high_water")
    return _parse_iso(raw)


def _host_from_base_url(base_url: str) -> str:
    host = base_url
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
            break
    return host.split("/", 1)[0].rstrip("/")


def _is_throttled(response: httpx.Response, flavor: Flavor) -> bool:
    if response.status_code == 429:
        return True
    if flavor == "datacenter" and response.status_code == 503:
        # DC reverse proxies emit 503 (with Retry-After) under sustained
        # load — Atlassian's documented overload signal in front of the JVM.
        return True
    return False


def _retry_after_seconds(response: httpx.Response) -> float:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return _DEFAULT_RETRY_AFTER_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return _DEFAULT_RETRY_AFTER_SECONDS


def _browse_url(base_url: str, page: Mapping[str, Any]) -> str | None:
    links = page.get("_links") or {}
    webui = links.get("webui")
    if not isinstance(webui, str) or not webui:
        return None
    return _resolve_link(base_url, webui)


def _resolve_link(base_url: str, href: str) -> str:
    if href.startswith("http://") or href.startswith("https://"):
        return href
    base = base_url.rstrip("/")
    if not href.startswith("/"):
        href = "/" + href
    return f"{base}{href}"


registry.register("confluence", ConfluenceConnector)
