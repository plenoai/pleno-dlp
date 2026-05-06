"""Output sinks: json, sarif, table.

A sink consumes Findings and writes them to a stream. JSON and SARIF batch
into a single document at the end (because their on-disk shape is a single
JSON object); table streams row-by-row for live progress.
"""

from __future__ import annotations

from collections.abc import AsyncIterable
from typing import IO, Protocol

from pleno_dlp.findings import Finding


class Sink(Protocol):
    """Output sink contract."""

    async def emit(self, findings: AsyncIterable[Finding], *, stream: IO[str]) -> int:
        """Drain `findings` to `stream`. Returns the count emitted."""
        ...


def make(format: str) -> Sink:
    """Construct a sink by format name. Raises ValueError on unknown."""
    from pleno_dlp.output.json_sink import JsonSink
    from pleno_dlp.output.sarif_sink import SarifSink
    from pleno_dlp.output.table_sink import TableSink

    sinks: dict[str, type[Sink]] = {
        "json": JsonSink,
        "sarif": SarifSink,
        "table": TableSink,
    }
    if format not in sinks:
        raise ValueError(f"unknown format {format!r}; available: {', '.join(sorted(sinks))}")
    return sinks[format]()


__all__ = ["Sink", "make"]
