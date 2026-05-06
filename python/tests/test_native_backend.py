"""Native regex backend should hit each known rule and miss similar non-secrets."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from saas_scraper import Document, DocumentRef

from pleno_secret_scanner.backends.native import NativeBackend


def _doc(text: str) -> Document:
    return Document(
        ref=DocumentRef(source_id="t", source_kind="test", path="/x.txt"),
        text=text,
        fetched_at=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    "rule_id,sample",
    [
        ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
        ("github-pat", "ghp_" + "a" * 36),
        ("slack-bot-token", "xoxb-1234567890-1234567890-" + "a" * 24),
        ("openai-api-key", "sk-" + "a" * 48),
        ("anthropic-api-key", "sk-ant-" + "a" * 95),
    ],
)
async def test_detects_known_secret(rule_id: str, sample: str) -> None:
    backend = NativeBackend()
    findings = [f async for f in backend.scan(_doc(f"prefix {sample} suffix"))]
    rule_ids = {f.rule_id for f in findings}
    assert rule_id in rule_ids
    hit = next(f for f in findings if f.rule_id == rule_id)
    assert hit.raw == sample
    assert hit.redacted != sample
    assert hit.line == 1


async def test_skips_non_secrets() -> None:
    backend = NativeBackend()
    findings = [f async for f in backend.scan(_doc("nothing exciting here"))]
    assert findings == []


async def test_binary_document_yields_nothing() -> None:
    backend = NativeBackend()
    doc = Document(
        ref=DocumentRef(source_id="t", source_kind="test", path="/x.bin"),
        binary=b"\x00\x01\x02",
    )
    findings = [f async for f in backend.scan(doc)]
    assert findings == []


async def test_line_number_is_correct() -> None:
    backend = NativeBackend()
    text = "line1\nline2\nline3 ghp_" + "a" * 36 + "\nline4"
    findings = [f async for f in backend.scan(_doc(text))]
    assert len(findings) == 1
    assert findings[0].line == 3
