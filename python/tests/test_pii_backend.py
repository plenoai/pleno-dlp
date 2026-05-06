"""PII backend tests — driven by httpx.MockTransport, no real anonymize server.

We mock the ``POST /api/analyze`` endpoint to return canned Presidio
``RecognizerResult`` rows and assert that ``PiiBackend`` translates each
into a ``Finding`` with the expected shape (entity_type → rule_id,
finding_class="pii", line numbers from offset, score forwarded, raw
substring sliced from the document text).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from saas_retriever import Document, DocumentRef

from pleno_dlp.backends.pii import PiiBackend
from pleno_dlp.findings import Finding


def _doc(text: str) -> Document:
    return Document(
        ref=DocumentRef(
            source_id="acme",
            source_kind="github",
            path="repo/README.md",
            native_url="https://github.com/acme/repo/blob/main/README.md",
        ),
        text=text,
        fetched_at=datetime.now(UTC),
    )


def _make_backend(
    handler: httpx.MockTransport,
    *,
    language: str = "ja",
    entities: tuple[str, ...] | None = None,
) -> PiiBackend:
    client = httpx.AsyncClient(
        base_url="http://test", transport=handler, timeout=5.0
    )
    return PiiBackend(language=language, entities=entities, client=client)


async def _collect(it: AsyncIterator[Finding]) -> list[Finding]:
    return [f async for f in it]


# --- happy path ---------------------------------------------------------


@pytest.mark.asyncio
async def test_yields_one_finding_per_entity() -> None:
    text = "Contact John Doe at john@example.com please."

    received: dict[str, Any] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        received["url"] = str(request.url)
        received["body"] = json.loads(request.content.decode())
        body = [
            {
                "entity_type": "PERSON",
                "start": 8,
                "end": 16,
                "score": 0.85,
                "text": "John Doe",
            },
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 20,
                "end": 36,
                "score": 1.0,
                "text": "john@example.com",
            },
        ]
        return httpx.Response(200, json=body)

    backend = _make_backend(httpx.MockTransport(respond), language="en")
    findings = await _collect(backend.scan(_doc(text)))

    assert received["url"].endswith("/api/analyze")
    assert received["body"] == {"text": text, "language": "en"}

    assert len(findings) == 2
    person = findings[0]
    assert person.rule_id == "PERSON"
    assert person.backend == "pii"
    assert person.finding_class == "pii"
    assert person.score == 0.85
    assert person.raw == "John Doe"
    assert person.path == "repo/README.md"
    assert person.source_kind == "github"
    assert person.line == 1

    email = findings[1]
    assert email.rule_id == "EMAIL_ADDRESS"
    assert email.raw == "john@example.com"
    assert email.score == 1.0
    assert email.extra["language"] == "en"
    assert email.extra["offset_start"] == "20"


@pytest.mark.asyncio
async def test_line_numbers_count_newlines_before_offset() -> None:
    # Two paragraphs; entity starts on line 3.
    text = "intro\n\nyamada taro\n"
    body = [
        {"entity_type": "PERSON", "start": 7, "end": 18, "score": 0.9}
    ]
    backend = _make_backend(httpx.MockTransport(lambda r: httpx.Response(200, json=body)))
    findings = await _collect(backend.scan(_doc(text)))
    assert len(findings) == 1
    assert findings[0].line == 3
    assert findings[0].raw == "yamada taro"


@pytest.mark.asyncio
async def test_entities_filter_forwarded_when_set() -> None:
    received: dict[str, Any] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        received["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json=[])

    backend = _make_backend(
        httpx.MockTransport(respond),
        entities=("EMAIL_ADDRESS", "JP_MY_NUMBER"),
    )
    await _collect(backend.scan(_doc("anything")))

    assert received["body"]["entities"] == ["EMAIL_ADDRESS", "JP_MY_NUMBER"]


# --- error / edge cases -------------------------------------------------


@pytest.mark.asyncio
async def test_empty_text_short_circuits_no_request() -> None:
    called = False

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json=[])

    backend = _make_backend(httpx.MockTransport(respond))
    findings = await _collect(backend.scan(_doc("   ")))

    assert findings == []
    assert called is False


@pytest.mark.asyncio
async def test_422_treated_as_no_findings() -> None:
    backend = _make_backend(
        httpx.MockTransport(lambda r: httpx.Response(422, json={"detail": "too long"}))
    )
    findings = await _collect(backend.scan(_doc("anything non-empty")))
    assert findings == []


@pytest.mark.asyncio
async def test_5xx_propagates() -> None:
    backend = _make_backend(
        httpx.MockTransport(lambda r: httpx.Response(500, text="boom"))
    )
    with pytest.raises(httpx.HTTPStatusError):
        await _collect(backend.scan(_doc("hello")))


@pytest.mark.asyncio
async def test_malformed_rows_are_skipped() -> None:
    body = [
        {"entity_type": "EMAIL_ADDRESS", "start": "not-int", "end": 5, "score": 1.0},
        {"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.5},
    ]
    backend = _make_backend(
        httpx.MockTransport(lambda r: httpx.Response(200, json=body))
    )
    findings = await _collect(backend.scan(_doc("Alice and Bob")))
    assert len(findings) == 1
    assert findings[0].rule_id == "PERSON"


@pytest.mark.asyncio
async def test_invalid_language_rejected() -> None:
    with pytest.raises(ValueError, match="language must be"):
        PiiBackend(language="fr")


@pytest.mark.asyncio
async def test_aclose_releases_owned_client() -> None:
    backend = PiiBackend(base_url="http://nowhere")
    await backend._ensure_client()
    assert backend._owned_client is True
    await backend.aclose()
    assert backend._client is None
    # Calling again is a no-op (idempotent).
    await backend.aclose()


@pytest.mark.asyncio
async def test_aclose_leaves_injected_client_alone() -> None:
    client = httpx.AsyncClient(base_url="http://nowhere")
    backend = PiiBackend(client=client)
    assert backend._owned_client is False
    await backend.aclose()
    # Injected client is still usable: aclose did NOT close it.
    assert not client.is_closed
    await client.aclose()
