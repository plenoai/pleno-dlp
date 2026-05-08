"""Wire-format Finding emitted by every backend.

A Finding is the cross-backend normalised result. Each backend
(trufflehog, gitleaks, native, pii) maps its own native shape into this
struct so downstream sinks (JSON / SARIF / table) only know one schema.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

# Two classes of finding live in pleno-dlp: secret leaks and PII leaks.
# Sinks render them differently (a leaked AWS key warrants a P0 SARIF
# entry; a Japanese person's name in a public README is a P3 advisory)
# but the Finding shape is shared so an operator wires one pipeline.
FindingClass = Literal["secret", "pii"]


def _redact(raw: str) -> str:
    """Default redaction: keep first 4 + last 2 chars, mask the middle.

    Backends can produce their own ``redacted`` value; this helper is
    what we use when the backend reports raw content without a
    pre-computed mask. Short strings (<=6 chars) are fully masked.
    """
    if len(raw) <= 6:
        return "*" * len(raw)
    return f"{raw[:4]}{'*' * (len(raw) - 6)}{raw[-2:]}"


@dataclass(frozen=True, slots=True)
class Finding:
    """One leak hit (secret or PII).

    ``source_*`` fields mirror ``pleno_dlp.DocumentRef`` so a
    Finding can be located back to the document it came from without
    joining tables.

    ``finding_class`` distinguishes ``"secret"`` (rule_id is e.g.
    ``aws-access-key``) from ``"pii"`` (rule_id is the entity type
    e.g. ``EMAIL_ADDRESS`` / ``PERSON``). ``score`` is populated for PII
    findings (Presidio confidence) and left as ``None`` for secret
    findings (which use ``verified`` as the binary yes/no signal).
    """

    rule_id: str
    backend: str
    verified: bool
    raw: str
    redacted: str
    source_id: str
    source_kind: str
    path: str
    native_url: str | None = None
    line: int | None = None
    finding_class: FindingClass = "secret"
    score: float | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def make(
        cls,
        *,
        rule_id: str,
        backend: str,
        raw: str,
        source_id: str,
        source_kind: str,
        path: str,
        verified: bool = False,
        redacted: str | None = None,
        native_url: str | None = None,
        line: int | None = None,
        finding_class: FindingClass = "secret",
        score: float | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> Finding:
        """Constructor that fills ``redacted`` from ``raw`` when omitted."""
        return cls(
            rule_id=rule_id,
            backend=backend,
            verified=verified,
            raw=raw,
            redacted=redacted if redacted is not None else _redact(raw),
            source_id=source_id,
            source_kind=source_kind,
            path=path,
            native_url=native_url,
            line=line,
            finding_class=finding_class,
            score=score,
            extra=dict(extra) if extra else {},
        )
