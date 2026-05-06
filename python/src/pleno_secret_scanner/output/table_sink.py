"""Rich table sink for human-readable output.

Streams rows as findings arrive so an interactive scan shows live progress.
"""

from __future__ import annotations

from collections.abc import AsyncIterable
from typing import IO

from rich.console import Console
from rich.table import Table

from pleno_secret_scanner.findings import Finding


class TableSink:
    async def emit(self, findings: AsyncIterable[Finding], *, stream: IO[str]) -> int:
        is_tty = stream.isatty() if hasattr(stream, "isatty") else False
        console = Console(file=stream, force_terminal=is_tty, width=200 if not is_tty else None)
        table = Table("rule", "verified", "backend", "source", "path", "line", "secret")
        n = 0
        async for f in findings:
            table.add_row(
                f.rule_id,
                "✓" if f.verified else "—",
                f.backend,
                f"{f.source_kind}:{f.source_id}",
                f.path,
                str(f.line) if f.line is not None else "",
                f.redacted,
            )
            n += 1
        console.print(table)
        return n
