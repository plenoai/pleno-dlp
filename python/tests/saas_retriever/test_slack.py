"""Slack connector tests using httpx.MockTransport."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from saas_retriever.connectors.slack import (
    DEFAULT_BASE_URL,
    SlackConnector,
    _decode_cursor,
    _ts_to_dt,
)
from saas_retriever.core import SourceFilter
from saas_retriever.credentials import Credential, CredentialMisconfiguredError
from saas_retriever.rate_limit import RateLimited


def _routes(handler_map: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, payload in handler_map.items():
            if path == prefix:
                if callable(payload):
                    return payload(request)
                return _make_response(payload)
        return httpx.Response(404, json={"ok": False, "error": "unknown_method"})

    return httpx.MockTransport(handler)


def _make_response(spec: Any) -> httpx.Response:
    if isinstance(spec, httpx.Response):
        return spec
    return httpx.Response(200, json=spec)


# --- helpers -----------------------------------------------------------


def test_decode_cursor_round_trips() -> None:
    assert _decode_cursor('{"C123": "1234.0"}') == {"C123": "1234.0"}
    assert _decode_cursor(None) == {}
    assert _decode_cursor("") == {}
    assert _decode_cursor("not-json") == {}
    assert _decode_cursor("[1,2]") == {}


def test_ts_to_dt_handles_slack_format() -> None:
    parsed = _ts_to_dt("1700000000.000100")
    assert parsed is not None
    assert parsed.year == 2023


def test_ts_to_dt_returns_none_on_garbage() -> None:
    assert _ts_to_dt("not-a-ts") is None


# --- construction ------------------------------------------------------


def test_token_required_when_credential_missing() -> None:
    with pytest.raises(CredentialMisconfiguredError):
        SlackConnector()


def test_xoxa_token_explicitly_rejected() -> None:
    with pytest.raises(CredentialMisconfiguredError, match="Discovery"):
        SlackConnector(token="xoxa-1-2-3")


def test_unknown_token_prefix_rejected() -> None:
    with pytest.raises(CredentialMisconfiguredError, match="xoxb"):
        SlackConnector(token="abcdef")


def test_token_resolved_from_credential() -> None:
    cred = Credential(kind="slack", payload={"token": "xoxb-from-cred"})
    c = SlackConnector(credential=cred)
    assert c._token == "xoxb-from-cred"


def test_default_id_uses_team_or_default() -> None:
    a = SlackConnector(token="xoxb-x")
    assert a.id == "slack:default"
    b = SlackConnector(token="xoxb-x", team_id="T01")
    assert b.id == "slack:T01"


def test_capabilities_marks_incremental_text() -> None:
    c = SlackConnector(token="xoxb-x")
    caps = c.capabilities()
    assert caps.binary is False
    assert caps.incremental is True


# --- end-to-end --------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_walks_channels_and_messages() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {
        "ok": True,
        "channels": [
            {"id": "C100", "name": "general"},
            {"id": "C200", "name": "random"},
        ],
    }
    history_c100 = {
        "ok": True,
        "messages": [
            {"ts": "1700000001.000000", "user": "U1", "text": "AKIAIOSFODNN7EXAMPLE"},
        ],
        "has_more": False,
    }
    history_c200 = {"ok": True, "messages": [], "has_more": False}

    def history_handler(request: httpx.Request) -> httpx.Response:
        channel = request.url.params.get("channel")
        if channel == "C100":
            return httpx.Response(200, json=history_c100)
        return httpx.Response(200, json=history_c200)

    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history_handler,
        }
    )
    c = SlackConnector(token="xoxb-x", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert len(refs) == 1
    assert refs[0].metadata["channel_id"] == "C100"
    assert refs[0].metadata["text"] == "AKIAIOSFODNN7EXAMPLE"
    assert refs[0].path == "slack://C100/1700000001.000000"


@pytest.mark.asyncio
async def test_discover_expands_threads_when_enabled() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {"ok": True, "channels": [{"id": "C100", "name": "general"}]}
    history = {
        "ok": True,
        "messages": [
            {
                "ts": "1700000001.000000",
                "thread_ts": "1700000001.000000",
                "user": "U1",
                "text": "parent",
            }
        ],
        "has_more": False,
    }
    replies = {
        "ok": True,
        "messages": [
            {"ts": "1700000001.000000", "thread_ts": "1700000001.000000", "text": "parent"},
            {"ts": "1700000002.000000", "thread_ts": "1700000001.000000", "text": "reply-1"},
            {"ts": "1700000003.000000", "thread_ts": "1700000001.000000", "text": "reply-2"},
        ],
        "has_more": False,
    }
    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history,
            f"{base}/conversations.replies": replies,
        }
    )
    c = SlackConnector(token="xoxb-x", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    # 1 parent + 2 replies (the parent in the replies list is filtered).
    assert len(refs) == 3
    assert refs[1].metadata["thread_ts"] == "1700000001.000000"


@pytest.mark.asyncio
async def test_discover_skips_threads_when_disabled() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {"ok": True, "channels": [{"id": "C100", "name": "general"}]}
    history = {
        "ok": True,
        "messages": [
            {
                "ts": "1700000001.000000",
                "thread_ts": "1700000001.000000",
                "user": "U1",
                "text": "parent",
            }
        ],
        "has_more": False,
    }
    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history,
        }
    )
    c = SlackConnector(token="xoxb-x", include_threads=False, transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert len(refs) == 1


@pytest.mark.asyncio
async def test_discover_filters_to_channels_allowlist() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {
        "ok": True,
        "channels": [{"id": "C100"}, {"id": "C200"}, {"id": "C300"}],
    }
    history = {"ok": True, "messages": [], "has_more": False}
    seen: list[str] = []

    def history_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("channel", ""))
        return httpx.Response(200, json=history)

    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history_handler,
        }
    )
    c = SlackConnector(
        token="xoxb-x",
        channels=("C100", "C300"),
        transport=transport,
    )
    [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert sorted(seen) == ["C100", "C300"]


@pytest.mark.asyncio
async def test_discover_skips_channel_on_missing_scope() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {"ok": True, "channels": [{"id": "C100"}]}
    deny = {"ok": False, "error": "missing_scope"}
    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": deny,
        }
    )
    c = SlackConnector(token="xoxb-x", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    await c.close()
    assert refs == []


@pytest.mark.asyncio
async def test_429_eventually_raises_rate_limited() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")

    def throttle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    transport = _routes({f"{base}/conversations.list": throttle})
    c = SlackConnector(token="xoxb-x", transport=transport)
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_ok_false_ratelimited_eventually_raises() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    body = {"ok": False, "error": "ratelimited"}

    def throttle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body, headers={"Retry-After": "0"})

    transport = _routes({f"{base}/conversations.list": throttle})
    c = SlackConnector(token="xoxb-x", transport=transport)
    with pytest.raises(RateLimited):
        async for _ in c.discover(SourceFilter()):
            pass
    await c.close()


@pytest.mark.asyncio
async def test_cursor_after_run_includes_per_channel_high_water() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {"ok": True, "channels": [{"id": "C100", "name": "g"}]}
    history = {
        "ok": True,
        "messages": [
            {"ts": "1700000001.000000", "text": "a"},
            {"ts": "1700000002.000000", "text": "b"},
        ],
        "has_more": False,
    }
    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history,
        }
    )
    c = SlackConnector(token="xoxb-x", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    cursor = c.cursor_after_run()
    await c.close()
    assert len(refs) == 2
    assert cursor is not None
    assert "C100" in cursor
    assert "1700000002" in cursor


@pytest.mark.asyncio
async def test_fetch_resolves_principal_via_users_info() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {"ok": True, "channels": [{"id": "C100"}]}
    history = {
        "ok": True,
        "messages": [{"ts": "1700000001.000000", "user": "U1", "text": "hi"}],
        "has_more": False,
    }
    user_info = {
        "ok": True,
        "user": {
            "id": "U1",
            "name": "alice",
            "profile": {
                "display_name_normalized": "Alice",
                "email": "alice@example.com",
            },
        },
    }
    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history,
            f"{base}/users.info": user_info,
        }
    )
    c = SlackConnector(token="xoxb-x", transport=transport)
    refs = [r async for r in c.discover(SourceFilter())]
    docs = [d async for d in c.fetch(refs[0])]
    await c.close()
    assert docs[0].text == "hi"
    assert docs[0].created_by is not None
    assert docs[0].created_by.id == "U1"
    assert docs[0].created_by.email == "alice@example.com"


@pytest.mark.asyncio
async def test_block_text_fallback_concatenated() -> None:
    base = DEFAULT_BASE_URL.replace("https://slack.com", "")
    channels = {"ok": True, "channels": [{"id": "C100"}]}
    history = {
        "ok": True,
        "messages": [
            {
                "ts": "1700000001.000000",
                "user": "U1",
                "text": "",
                "blocks": [
                    {"text": {"text": "block-only-content"}},
                ],
            }
        ],
        "has_more": False,
    }
    transport = _routes(
        {
            f"{base}/conversations.list": channels,
            f"{base}/conversations.history": history,
        }
    )
    c = SlackConnector(
        token="xoxb-x", fetch_user_principal=False, transport=transport
    )
    refs = [r async for r in c.discover(SourceFilter())]
    docs = [d async for d in c.fetch(refs[0])]
    await c.close()
    assert "block-only-content" in docs[0].text
