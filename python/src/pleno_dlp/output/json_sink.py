"""NDJSON sink — one Finding per line.

Streaming line-by-line keeps memory flat for large scans and lets shells
pipe into ``jq`` while the scan is still running.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterable
from dataclasses import asdict
from typing import IO

from pleno_dlp.findings import Finding


class JsonSink:
    async def emit(self, findings: AsyncIterable[Finding], *, stream: IO[str]) -> int:
        n = 0
        async for f in findings:
            stream.write(json.dumps(asdict(f), ensure_ascii=False, separators=(",", ":")) + "\n")
            stream.flush()
            n += 1
        return n
