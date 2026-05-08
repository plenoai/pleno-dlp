"""Notion connector — REST-API driven (pinned Notion-Version).

Three independent discovery modes:

* **Search** — ``POST /v1/search`` with empty query yields every page +
  database the integration has been shared with. Default when no
  ``pages`` / ``databases`` is configured.
* **Explicit pages** — ``pages=("<page-id>", ...)`` scans the given
  pages and their descendant blocks.
* **Database query** — ``databases=("<db-id>", ...)`` enumerates rows
  via ``/v1/databases/{id}/query``.

The three modes are not mutually exclusive; the connector merges
results and yields one ``DocumentRef`` per page or database row.
``fetch()`` materialises the block tree (or the row's properties + the
row's child blocks) into Markdown via ``notion_markdown.render_blocks``.

Concurrency defaults to 3 — Notion's published cap is ~3 RPS averaged
and 429 ramps up quickly past it.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx

from saas_retriever.connectors.notion_markdown import (
    MAX_DEPTH,
    render_blocks,
    render_database_row,
)
from saas_retriever.core import (
    Capabilities,
    Document,
    DocumentRef,
    SourceFilter,
)
from saas_retriever.credentials import Credential, CredentialMisconfiguredError
from saas_retriever.rate_limit import RateLimited
from saas_retriever.registry import registry

DEFAULT_BASE_URL = "https://api.notion.com/v1"
# Pinned API version. Bumping requires re-validating every block /
# property parser in `notion_markdown.py`; do NOT silently track
# upstream's "latest". 2022-06-28 is Notion's GA schema we parse against.
NOTION_VERSION = "2022-06-28"
PAGE_SIZE = 100  # Notion's hard ceiling on every paginated endpoint.

_USER_AGENT = "saas-retriever/0.2"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3


class NotionConnector:
    """API-driven Notion source connector."""

    kind = "notion"

    def __init__(
        self,
        *,
        token: str | None = None,
        credential: Credential | None = None,
        pages: Iterable[str] = (),
        databases: Iterable[str] = (),
        include_archived: bool = False,
        workspace_id: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        notion_version: str = NOTION_VERSION,
        max_concurrent_fetches: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
    ) -> None:
        if token is None and credential is not None:
            cred_token = credential.payload.get("token")
            if isinstance(cred_token, str):
                token = cred_token
        if not token:
            raise CredentialMisconfiguredError(
                "notion connector requires `token=` (Bearer integration token)"
            )
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._notion_version = notion_version
        self.pages: tuple[str, ...] = tuple(pages)
        self.databases: tuple[str, ...] = tuple(databases)
        self.include_archived = include_archived
        self.workspace_id = workspace_id
        self._max_concurrent_fetches = max_concurrent_fetches
        scope = workspace_id or "default"
        self.id = source_id or f"notion:{scope}"

        client_kwargs: dict[str, Any] = {"timeout": timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.AsyncClient(**client_kwargs)
        self._discover_seen: set[tuple[str, str]] = set()

    # --- public protocol ------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        # Notion has no native include/exclude/since filter on /search;
        # the orchestrator's filter is honoured client-side at fetch
        # time only (via include_archived). Keep the parameter for
        # protocol parity.
        del filter
        self._discover_seen = set()
        if self.pages:
            for page_id in self.pages:
                async for ref in self._discover_page(page_id):
                    yield ref
        if self.databases:
            for db_id in self.databases:
                async for ref in self._discover_database(db_id):
                    yield ref
        if not self.pages and not self.databases:
            async for ref in self._discover_search(cursor):
                yield ref

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        meta = ref.metadata
        object_id = meta.get("object_id")
        object_type = meta.get("object_type")
        if not object_id or not object_type:
            return
        page_or_row = await self._fetch_object(object_type, object_id)
        if not page_or_row:
            return
        properties_md = ""
        if object_type == "page" and meta.get("database_id"):
            properties_md = render_database_row(page_or_row.get("properties"))
        body_md = await self._fetch_block_tree(object_id)
        text_parts = [p for p in (properties_md, body_md) if p]
        if not text_parts:
            # Document XOR-rule forbids an empty body — yield nothing.
            return
        yield Document(
            ref=ref,
            text="\n\n".join(text_parts),
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
            max_concurrent_fetches=self._max_concurrent_fetches,
            streaming=False,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # --- discovery ------------------------------------------------------

    async def _discover_page(self, page_id: str) -> AsyncIterator[DocumentRef]:
        page = await self._get_json(f"/pages/{page_id}")
        ref = self._object_to_ref(page)
        if ref is not None:
            yield ref

    async def _discover_database(
        self, database_id: str
    ) -> AsyncIterator[DocumentRef]:
        cursor: str | None = None
        while True:
            body: dict[str, Any] = {"page_size": PAGE_SIZE}
            if cursor:
                body["start_cursor"] = cursor
            payload = await self._post_json(
                f"/databases/{database_id}/query", json=body
            )
            for row in payload.get("results", []):
                ref = self._object_to_ref(row, parent_database_id=database_id)
                if ref is not None:
                    yield ref
            if not payload.get("has_more"):
                return
            cursor = payload.get("next_cursor")
            if not cursor:
                return

    async def _discover_search(
        self, cursor: str | None
    ) -> AsyncIterator[DocumentRef]:
        next_cursor: str | None = cursor
        while True:
            body: dict[str, Any] = {"page_size": PAGE_SIZE}
            if next_cursor:
                body["start_cursor"] = next_cursor
            payload = await self._post_json("/search", json=body)
            for obj in payload.get("results", []):
                ref = self._object_to_ref(obj)
                if ref is not None:
                    # Round-trip the search cursor on every ref so the
                    # caller can checkpoint mid-search.
                    yield self._with_cursor(ref, payload.get("next_cursor"))
            if not payload.get("has_more"):
                return
            next_cursor = payload.get("next_cursor")
            if not next_cursor:
                return

    def _object_to_ref(
        self,
        obj: Mapping[str, Any] | None,
        *,
        parent_database_id: str | None = None,
    ) -> DocumentRef | None:
        if not isinstance(obj, Mapping) or not obj:
            return None
        object_type = obj.get("object")
        object_id = obj.get("id")
        if not isinstance(object_id, str) or object_type not in {"page", "database"}:
            return None
        if not self.include_archived and obj.get("archived"):
            return None
        key = (str(object_type), object_id)
        if key in self._discover_seen:
            return None
        self._discover_seen.add(key)
        last_modified = _parse_iso(obj.get("last_edited_time"))
        native_url = obj.get("url") if isinstance(obj.get("url"), str) else None
        path_kind = "database-row" if parent_database_id else object_type
        path = f"notion://{path_kind}/{object_id}"
        parent_chain: tuple[str, ...] = ()
        if parent_database_id:
            parent_chain = (f"notion://database/{parent_database_id}",)
        elif isinstance(obj.get("parent"), Mapping):
            parent_uri = _parent_uri(obj["parent"])
            if parent_uri is not None:
                parent_chain = (parent_uri,)
        metadata: dict[str, str] = {
            "object_type": str(object_type),
            "object_id": object_id,
        }
        if parent_database_id:
            metadata["database_id"] = parent_database_id
        return DocumentRef(
            source_id=self.id,
            source_kind=self.kind,
            path=path,
            native_url=native_url,
            parent_chain=parent_chain,
            content_type="text/markdown",
            last_modified=last_modified,
            metadata=metadata,
        )

    def _with_cursor(self, ref: DocumentRef, cursor: str | None) -> DocumentRef:
        if not cursor:
            return ref
        new_meta = dict(ref.metadata)
        new_meta["_cursor"] = cursor
        return DocumentRef(
            source_id=ref.source_id,
            source_kind=ref.source_kind,
            path=ref.path,
            native_url=ref.native_url,
            parent_chain=ref.parent_chain,
            content_type=ref.content_type,
            size=ref.size,
            etag=ref.etag,
            last_modified=ref.last_modified,
            metadata=new_meta,
        )

    # --- fetch ----------------------------------------------------------

    async def _fetch_object(
        self, object_type: str, object_id: str
    ) -> Mapping[str, Any] | None:
        if object_type == "page":
            obj = await self._get_json(f"/pages/{object_id}")
        elif object_type == "database":
            obj = await self._get_json(f"/databases/{object_id}")
        else:
            return None
        return obj or None

    async def _fetch_block_tree(self, root_id: str) -> str:
        children_cache: dict[str, list[Mapping[str, Any]]] = {}

        async def _walk(block_id: str, depth: int) -> None:
            if depth >= MAX_DEPTH:
                return
            children = await self._list_block_children(block_id)
            children_cache[block_id] = children
            for child in children:
                if child.get("has_children"):
                    child_id = child.get("id")
                    if isinstance(child_id, str):
                        await _walk(child_id, depth + 1)

        await _walk(root_id, depth=0)

        def lookup(block_id: str | None) -> list[Mapping[str, Any]]:
            if not isinstance(block_id, str):
                return []
            return children_cache.get(block_id, [])

        return render_blocks(
            children_cache.get(root_id, []),
            children_for=lookup,
            include_archived=self.include_archived,
        )

    async def _list_block_children(
        self, block_id: str
    ) -> list[Mapping[str, Any]]:
        out: list[Mapping[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"page_size": PAGE_SIZE}
            if cursor:
                params["start_cursor"] = cursor
            payload = await self._get_json(
                f"/blocks/{block_id}/children", params=params
            )
            for block in payload.get("results", []):
                if not isinstance(block, Mapping):
                    continue
                if not self.include_archived and block.get("archived"):
                    continue
                out.append(block)
            if not payload.get("has_more"):
                return out
            cursor = payload.get("next_cursor")
            if not cursor:
                return out

    # --- HTTP plumbing --------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Notion-Version": self._notion_version,
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _resolve_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return f"{self._base_url}{path_or_url}"

    async def _request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self._resolve_url(path_or_url)
        backoff = 1.0
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.request(
                method,
                url,
                params=params,
                json=dict(json or {}) if json is not None else None,
                headers=self._headers(),
            )
            if r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After", "30"))
                if attempt < _DEFAULT_MAX_RETRIES - 1:
                    await asyncio.sleep(min(retry_after, 300))
                    continue
                raise RateLimited(
                    f"notion 429 after {_DEFAULT_MAX_RETRIES} attempts; "
                    f"retry_after={retry_after} seconds"
                )
            if r.status_code == 404:
                # Notion conflates "object not visible to integration"
                # with "object does not exist". The connector treats both
                # as a silent skip — surface as an empty mapping the
                # callers can `if not body: return` on.
                return {}
            if 500 <= r.status_code < 600 and attempt < _DEFAULT_MAX_RETRIES - 1:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            r.raise_for_status()
            data = r.json()
            return dict(data) if isinstance(data, Mapping) else {}
        # Unreachable: the loop either returns or raises.
        return {}

    async def _get_json(
        self,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self._request("GET", path_or_url, params=params)

    async def _post_json(
        self,
        path_or_url: str,
        *,
        json: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self._request("POST", path_or_url, json=json)


# --- helpers ------------------------------------------------------------


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parent_uri(parent: Mapping[str, Any]) -> str | None:
    p_type = parent.get("type")
    if p_type == "database_id":
        return f"notion://database/{parent.get('database_id')}"
    if p_type == "page_id":
        return f"notion://page/{parent.get('page_id')}"
    if p_type == "block_id":
        return f"notion://block/{parent.get('block_id')}"
    if p_type == "workspace":
        return "notion://workspace"
    return None


registry.register("notion", NotionConnector)
