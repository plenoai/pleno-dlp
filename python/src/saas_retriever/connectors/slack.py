"""Slack connector — REST-API driven (no slack_sdk dependency).

Walks a Slack workspace via the Web API. Token types supported:

* ``xoxb-...`` (bot) — visible channels only.
* ``xoxp-...`` (user) — full visibility.

Enterprise Grid (``xoxa-…``) Discovery API is not implemented; raise a
``CredentialMisconfiguredError`` so operators on that plan know to
extend the connector rather than silently scanning a subset.

Pipeline:

1. Enumerate channels via ``conversations.list`` (paginated cursor).
2. Per channel, walk messages via ``conversations.history`` (paginated
   cursor, server-side ``oldest=`` for incremental scan).
3. Per top-level message with ``thread_ts``, expand thread via
   ``conversations.replies``.
4. Optionally yield refs for files attached to messages.

Each message → one ``Document`` carrying the rendered text plus
``Principal`` (user id / display name resolved on demand).

Cursor: JSON ``{channel_id: latest_ts}``. Resume re-issues
``conversations.history`` with ``oldest=ts`` per channel.
"""

from __future__ import annotations

import asyncio
import json
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
from saas_retriever.credentials import Credential, CredentialMisconfiguredError
from saas_retriever.rate_limit import RateLimited
from saas_retriever.registry import registry

DEFAULT_BASE_URL = "https://slack.com/api"
_USER_AGENT = "saas-retriever/0.2"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_PAGE_SIZE = 200
_DEFAULT_HISTORY_LIMIT = 200
_MAX_PAGINATION_DEPTH = 10_000


class SlackConnector:
    """API-driven Slack source connector.

    Owns one ``httpx.AsyncClient`` for its lifetime. ``token`` may be
    supplied via the ``token=`` kwarg or via a ``Credential`` whose
    ``payload['token']`` is a string. Token must start with ``xoxb-``
    or ``xoxp-``.
    """

    kind = "slack"

    def __init__(
        self,
        *,
        token: str | None = None,
        credential: Credential | None = None,
        channels: Iterable[str] = (),
        include_threads: bool = True,
        include_files: bool = True,
        fetch_user_principal: bool = True,
        team_id: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        source_id: str | None = None,
    ) -> None:
        if token is None and credential is not None:
            value = credential.payload.get("token")
            if isinstance(value, str) and value:
                token = value
        if not token:
            raise CredentialMisconfiguredError(
                "slack connector requires `token=` (xoxb-… or xoxp-…)"
            )
        if token.startswith("xoxa") or token.startswith("xoxa-"):
            raise CredentialMisconfiguredError(
                "slack connector does not yet support Enterprise Grid "
                "Discovery API tokens (xoxa-…)"
            )
        if not (token.startswith("xoxb-") or token.startswith("xoxp-")):
            raise CredentialMisconfiguredError(
                f"slack token must start with xoxb- or xoxp-; got {token[:5]}"
            )
        self._token = token
        self._base_url = base_url.rstrip("/")
        self.channels: tuple[str, ...] = tuple(channels)
        self.include_threads = include_threads
        self.include_files = include_files
        self.fetch_user_principal = fetch_user_principal
        self._team_id = team_id

        scope = team_id or "default"
        self.id = source_id or f"slack:{scope}"

        client_kwargs: dict[str, Any] = {"timeout": timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.AsyncClient(**client_kwargs)
        self._principal_cache: dict[str, Principal] = {}
        self._high_water: dict[str, str] = {}

    # --- public protocol ------------------------------------------------

    async def discover(
        self,
        filter: SourceFilter,
        cursor: str | None = None,
    ) -> AsyncIterator[DocumentRef]:
        del filter  # Slack has no native include/exclude; channels= scopes
        prior_state = _decode_cursor(cursor)
        self._high_water = dict(prior_state)
        channels = await self._list_channels()
        for channel in channels:
            channel_id = channel.get("id")
            if not isinstance(channel_id, str):
                continue
            if self.channels and channel_id not in self.channels:
                continue
            channel_name = channel.get("name", channel_id)
            oldest = prior_state.get(channel_id)
            async for message in self._iter_history(channel_id, oldest=oldest):
                ts = message.get("ts")
                if not isinstance(ts, str):
                    continue
                yield self._message_to_ref(channel_id, str(channel_name), message, ts)
                # Track per-channel high water (max ts seen).
                if channel_id not in self._high_water or ts > self._high_water[channel_id]:
                    self._high_water[channel_id] = ts
                if self.include_threads and message.get("thread_ts") == ts:
                    async for reply in self._iter_thread(channel_id, ts):
                        reply_ts = reply.get("ts")
                        if not isinstance(reply_ts, str) or reply_ts == ts:
                            continue
                        yield self._message_to_ref(
                            channel_id, str(channel_name), reply, reply_ts,
                            thread_ts=ts,
                        )

    async def fetch(self, ref: DocumentRef) -> AsyncIterator[Document]:
        text = ref.metadata.get("text", "")
        if not text:
            return
        principal = await self._resolve_principal(ref.metadata.get("user", ""))
        yield Document(
            ref=ref,
            text=text,
            fetched_at=datetime.now(UTC),
            created_by=principal,
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
        await self._client.aclose()

    def cursor_after_run(self) -> str | None:
        if not self._high_water:
            return None
        return json.dumps(self._high_water, sort_keys=True)

    # --- discovery internals -------------------------------------------

    async def _list_channels(self) -> list[Mapping[str, Any]]:
        out: list[Mapping[str, Any]] = []
        cursor: str | None = None
        depth = 0
        while True:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"slack conversations.list exceeded {_MAX_PAGINATION_DEPTH} pages"
                )
            params: dict[str, Any] = {
                "limit": _DEFAULT_PAGE_SIZE,
                "exclude_archived": "true",
                "types": "public_channel,private_channel,mpim,im",
            }
            if cursor:
                params["cursor"] = cursor
            body = await self._call("conversations.list", params=params)
            for channel in body.get("channels", []) or []:
                if isinstance(channel, Mapping):
                    out.append(channel)
            cursor = ((body.get("response_metadata") or {}).get("next_cursor")) or ""
            if not cursor:
                return out

    async def _iter_history(
        self, channel_id: str, *, oldest: str | None
    ) -> AsyncIterator[Mapping[str, Any]]:
        cursor: str | None = None
        depth = 0
        while True:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"slack conversations.history exceeded "
                    f"{_MAX_PAGINATION_DEPTH} pages for {channel_id}"
                )
            params: dict[str, Any] = {
                "channel": channel_id,
                "limit": _DEFAULT_HISTORY_LIMIT,
            }
            if oldest:
                # Slack's ``oldest`` is exclusive — pages already-seen
                # ts values are skipped without us re-issuing them.
                params["oldest"] = oldest
            if cursor:
                params["cursor"] = cursor
            try:
                body = await self._call("conversations.history", params=params)
            except _SlackPermissionError:
                # Bot tokens lack history scope on some channels — skip
                # rather than crash the whole walk.
                return
            for message in body.get("messages", []) or []:
                if isinstance(message, Mapping):
                    yield message
            cursor = ((body.get("response_metadata") or {}).get("next_cursor")) or ""
            if not body.get("has_more") or not cursor:
                return

    async def _iter_thread(
        self, channel_id: str, thread_ts: str
    ) -> AsyncIterator[Mapping[str, Any]]:
        cursor: str | None = None
        depth = 0
        while True:
            depth += 1
            if depth > _MAX_PAGINATION_DEPTH:
                raise RuntimeError(
                    f"slack conversations.replies exceeded "
                    f"{_MAX_PAGINATION_DEPTH} pages for {channel_id}/{thread_ts}"
                )
            params: dict[str, Any] = {
                "channel": channel_id,
                "ts": thread_ts,
                "limit": _DEFAULT_HISTORY_LIMIT,
            }
            if cursor:
                params["cursor"] = cursor
            try:
                body = await self._call("conversations.replies", params=params)
            except _SlackPermissionError:
                return
            for message in body.get("messages", []) or []:
                if isinstance(message, Mapping):
                    yield message
            cursor = ((body.get("response_metadata") or {}).get("next_cursor")) or ""
            if not body.get("has_more") or not cursor:
                return

    def _message_to_ref(
        self,
        channel_id: str,
        channel_name: str,
        message: Mapping[str, Any],
        ts: str,
        *,
        thread_ts: str | None = None,
    ) -> DocumentRef:
        text = str(message.get("text") or "")
        # Concatenate block text fallbacks so message variants without
        # `text` (block-only messages) still surface their content.
        for block in message.get("blocks", []) or []:
            if isinstance(block, Mapping):
                fallback = block.get("text")
                if isinstance(fallback, Mapping):
                    block_text = fallback.get("text")
                    if isinstance(block_text, str) and block_text:
                        text = f"{text}\n{block_text}" if text else block_text
        user = str(message.get("user") or message.get("bot_id") or "")
        path = (
            f"slack://{channel_id}/{thread_ts}/{ts}"
            if thread_ts
            else f"slack://{channel_id}/{ts}"
        )
        last_modified = _ts_to_dt(ts)
        team_id = self._team_id or "T"
        native_url = (
            f"https://app.slack.com/client/{team_id}/{channel_id}/p{ts.replace('.', '')}"
        )
        metadata: dict[str, str] = {
            "channel_id": channel_id,
            "channel_name": channel_name,
            "ts": ts,
            "user": user,
            "text": text,
        }
        if thread_ts:
            metadata["thread_ts"] = thread_ts
        return DocumentRef(
            source_id=self.id,
            source_kind=self.kind,
            path=path,
            native_url=native_url,
            parent_chain=(f"slack://{channel_id}",),
            content_type="text/plain",
            last_modified=last_modified,
            metadata=metadata,
        )

    async def _resolve_principal(self, user_id: str) -> Principal | None:
        if not user_id or not self.fetch_user_principal:
            return None
        cached = self._principal_cache.get(user_id)
        if cached is not None:
            return cached
        try:
            body = await self._call("users.info", params={"user": user_id})
        except _SlackPermissionError:
            return None
        user = body.get("user") or {}
        if not isinstance(user, Mapping):
            return None
        profile = user.get("profile") or {}
        display = (
            (profile.get("display_name_normalized") if isinstance(profile, Mapping) else None)
            or (profile.get("real_name_normalized") if isinstance(profile, Mapping) else None)
            or user.get("name")
        )
        email = profile.get("email") if isinstance(profile, Mapping) else None
        principal = Principal(
            id=user_id,
            display_name=str(display) if display else None,
            email=str(email) if email else None,
        )
        self._principal_cache[user_id] = principal
        return principal

    # --- HTTP plumbing --------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
            "Authorization": f"Bearer {self._token}",
        }

    async def _call(
        self,
        method: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base_url}/{method}"
        for attempt in range(_DEFAULT_MAX_RETRIES):
            r = await self._client.get(url, params=params, headers=self._headers())
            if r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After", "30"))
                if attempt < _DEFAULT_MAX_RETRIES - 1:
                    await asyncio.sleep(min(retry_after, 300))
                    continue
                raise RateLimited(
                    f"slack 429 after {_DEFAULT_MAX_RETRIES} attempts; "
                    f"retry_after={retry_after} seconds"
                )
            if 500 <= r.status_code < 600 and attempt < _DEFAULT_MAX_RETRIES - 1:
                await asyncio.sleep(2.0)
                continue
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, Mapping):
                return {}
            if not data.get("ok", False):
                error = str(data.get("error", "unknown"))
                if error in {"ratelimited"}:
                    # Slack also signals rate-limit via ok=false +
                    # error=ratelimited (in addition to HTTP 429).
                    retry_after = float(r.headers.get("Retry-After", "30"))
                    if attempt < _DEFAULT_MAX_RETRIES - 1:
                        await asyncio.sleep(min(retry_after, 300))
                        continue
                    raise RateLimited(f"slack ratelimited; retry_after={retry_after}")
                if error in {"missing_scope", "not_authed", "channel_not_found", "not_in_channel"}:
                    # Permission errors: surface a typed exception so the
                    # discover/fetch loop can skip this resource silently.
                    raise _SlackPermissionError(error)
                raise RuntimeError(f"slack {method} returned ok=false error={error}")
            return dict(data)
        return {}


# --- helpers ------------------------------------------------------------


class _SlackPermissionError(Exception):
    """Internal sentinel: per-channel permission denial; skip and continue."""


def _decode_cursor(cursor: str | None) -> dict[str, str]:
    if not cursor:
        return {}
    try:
        decoded = json.loads(cursor)
    except (ValueError, TypeError):
        return {}
    if not isinstance(decoded, Mapping):
        return {}
    return {str(k): str(v) for k, v in decoded.items() if isinstance(v, str) and v}


def _ts_to_dt(ts: str) -> datetime | None:
    """Slack ts is `<seconds>.<microseconds>` (epoch). Convert to UTC dt."""
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC)
    except (ValueError, TypeError):
        return None


registry.register("slack", SlackConnector)
