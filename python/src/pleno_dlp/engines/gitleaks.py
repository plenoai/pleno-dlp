"""Gitleaks detection engine.

Runs ``gitleaks detect --no-git --report-format json --report-path -``
over a tempfile holding the document body. Gitleaks does not verify
hits; every Finding is emitted with ``verified=False``.

Requires ``gitleaks`` on PATH (``brew install gitleaks``).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pleno_dlp.core import Document
from pleno_dlp.findings import Finding


class GitleaksEngine:
    """Wraps the gitleaks CLI (no verification)."""

    name = "gitleaks"

    def __init__(self, binary: str = "gitleaks") -> None:
        self.binary = binary

    async def detect(self, doc: Document) -> AsyncIterator[Finding]:
        if doc.text is None:
            return
        if shutil.which(self.binary) is None:
            raise RuntimeError(
                f"{self.binary!r} not found on PATH. Install gitleaks or pass --engine native."
            )
        with tempfile.TemporaryDirectory(prefix="pleno-gl-") as tmp:
            tmp_path = Path(tmp)
            target = tmp_path / "document.txt"
            target.write_text(doc.text, encoding="utf-8")
            report = tmp_path / "gitleaks.json"
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                "detect",
                "--no-banner",
                "--no-git",
                "--source",
                str(tmp_path),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            if not report.exists():
                return
            try:
                records = json.loads(report.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return
            if not isinstance(records, list):
                return
            for rec in records:
                f = _map(rec, doc)
                if f is not None:
                    yield f


def _map(rec: dict[str, Any], doc: Document) -> Finding | None:
    raw = rec.get("Secret") or rec.get("Match")
    if not raw:
        return None
    rule = rec.get("RuleID") or rec.get("Description") or "unknown"
    line = rec.get("StartLine")
    return Finding.make(
        rule_id=str(rule).lower(),
        backend="gitleaks",
        raw=raw,
        verified=False,
        source_id=doc.ref.source_id,
        source_kind=doc.ref.source_kind,
        path=doc.ref.path,
        native_url=doc.ref.native_url,
        line=line if isinstance(line, int) else None,
    )
