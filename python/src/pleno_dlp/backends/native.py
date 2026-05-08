"""Built-in regex backend.

Five rules covering the highest-precedence cloud + AI provider secrets:
AWS access keys, GitHub PATs, Slack bot/user tokens, OpenAI keys, Anthropic
keys. No verification — these are pattern matches only.

Use this backend when you want zero system dependencies. For verified hits
prefer the trufflehog backend.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from pleno_dlp.findings import Finding
from saas_retriever import Document

# Each rule is (rule_id, compiled regex). Patterns are deliberately
# narrow — false positives in a secret scanner are noisy and erode trust.
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("slack-bot-token", re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}\b")),
    ("slack-user-token", re.compile(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b")),
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{80,}\b")),
)


class NativeBackend:
    """Regex-only detector, no verification."""

    name = "native"

    async def scan(self, doc: Document) -> AsyncIterator[Finding]:
        if doc.text is None:
            return
        text = doc.text
        for rule_id, pattern in _RULES:
            for m in pattern.finditer(text):
                yield Finding.make(
                    rule_id=rule_id,
                    backend=self.name,
                    raw=m.group(0),
                    source_id=doc.ref.source_id,
                    source_kind=doc.ref.source_kind,
                    path=doc.ref.path,
                    native_url=doc.ref.native_url,
                    line=text.count("\n", 0, m.start()) + 1,
                    verified=False,
                )
