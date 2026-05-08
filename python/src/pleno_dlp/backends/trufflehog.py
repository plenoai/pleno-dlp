"""Trufflehog subprocess backend.

Pipes the document body into ``trufflehog filesystem --no-update --json``
through stdin (via a tempfile, since trufflehog requires a path). Each
trufflehog JSON line is mapped to a ``Finding``. Verification status comes
from trufflehog's own ``Verified`` field.

Requires ``trufflehog`` on PATH (``brew install trufflehog`` /
``go install github.com/trufflesecurity/trufflehog/v3@latest``).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pleno_dlp.findings import Finding
from saas_retriever import Document


class TrufflehogBackend:
    """Wraps the trufflehog CLI; verifies hits when the detector supports it."""

    name = "trufflehog"

    def __init__(self, binary: str = "trufflehog") -> None:
        self.binary = binary

    async def scan(self, doc: Document) -> AsyncIterator[Finding]:
        if doc.text is None:
            return
        if shutil.which(self.binary) is None:
            raise RuntimeError(
                f"{self.binary!r} not found on PATH. Install trufflehog or pass --backend native."
            )
        with tempfile.TemporaryDirectory(prefix="pleno-th-") as tmp:
            target = Path(tmp) / "document.txt"
            target.write_text(doc.text, encoding="utf-8")
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                "filesystem",
                "--no-update",
                "--json",
                str(target),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            async for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError:
                    continue
                f = _map(rec, doc)
                if f is not None:
                    yield f
            await proc.wait()


def _map(rec: dict[str, Any], doc: Document) -> Finding | None:
    """Map one trufflehog JSON record onto our Finding shape."""
    raw = rec.get("Raw") or rec.get("Redacted")
    if not raw:
        return None
    detector = rec.get("DetectorName") or rec.get("DetectorType") or "unknown"
    line = None
    src_meta = rec.get("SourceMetadata") or {}
    fs = src_meta.get("Data", {}).get("Filesystem") or {}
    if isinstance(fs, dict):
        line = fs.get("line")
    return Finding.make(
        rule_id=str(detector).lower(),
        backend="trufflehog",
        raw=raw,
        verified=bool(rec.get("Verified", False)),
        redacted=rec.get("Redacted"),
        source_id=doc.ref.source_id,
        source_kind=doc.ref.source_kind,
        path=doc.ref.path,
        native_url=doc.ref.native_url,
        line=line if isinstance(line, int) else None,
        extra={"trufflehog_decoder": rec.get("DecoderName")} if rec.get("DecoderName") else None,
    )
