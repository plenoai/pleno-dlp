"""Output sinks: JSON NDJSON, SARIF, table."""

from __future__ import annotations

import io
import json
from collections.abc import AsyncIterator

from pleno_secret_scanner.findings import Finding
from pleno_secret_scanner.output.json_sink import JsonSink
from pleno_secret_scanner.output.sarif_sink import SarifSink
from pleno_secret_scanner.output.table_sink import TableSink


def _f(rule_id: str = "aws-access-key-id", verified: bool = False, line: int | None = 1) -> Finding:
    return Finding.make(
        rule_id=rule_id,
        backend="native",
        raw="AKIAIOSFODNN7EXAMPLE",
        verified=verified,
        source_id="ws",
        source_kind="slack",
        path="/c.txt",
        native_url="https://example.com/c.txt",
        line=line,
    )


async def _gen(items: list[Finding]) -> AsyncIterator[Finding]:
    for x in items:
        yield x


async def test_json_sink_emits_one_line_per_finding() -> None:
    buf = io.StringIO()
    sink = JsonSink()
    n = await sink.emit(_gen([_f(), _f("github-pat")]), stream=buf)
    assert n == 2
    lines = buf.getvalue().splitlines()
    assert len(lines) == 2
    payload = json.loads(lines[0])
    assert payload["rule_id"] == "aws-access-key-id"
    assert payload["redacted"].startswith("AKIA")


async def test_sarif_sink_emits_valid_envelope() -> None:
    buf = io.StringIO()
    sink = SarifSink()
    n = await sink.emit(_gen([_f(verified=True), _f("github-pat")]), stream=buf)
    assert n == 2
    doc = json.loads(buf.getvalue())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pleno-secret-scanner"
    rules = run["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"aws-access-key-id", "github-pat"}
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "warning"


async def test_table_sink_returns_count() -> None:
    buf = io.StringIO()
    sink = TableSink()
    n = await sink.emit(_gen([_f(), _f()]), stream=buf)
    assert n == 2
    assert "aws-access-key-id" in buf.getvalue()


async def test_empty_findings_handled() -> None:
    buf = io.StringIO()
    n = await JsonSink().emit(_gen([]), stream=buf)
    assert n == 0
    assert buf.getvalue() == ""
