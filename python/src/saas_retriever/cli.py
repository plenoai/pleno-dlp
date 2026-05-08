"""saas-retriever command-line interface.

Surface (v0.1.0)::

    saas-retriever list
    saas-retriever fetch github --owner plenoai
    saas-retriever fetch github --owner plenoai --repo saas-retriever \\
        --resource code --resource issues --resource prs

``fetch`` streams Documents as NDJSON to stdout (or ``--out PATH``). One
line per ``Document``: ref, text or binary (base64), fetched_at,
content_hash, created_by, extra. The schema follows
``saas_retriever.core.Document`` 1:1.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from saas_retriever import __version__

# Importing the connectors package triggers per-connector
# registry.register calls. Done at module import time so
# ``registry.names()`` is populated by the time typer dispatches a
# subcommand.
from saas_retriever import connectors as _connectors  # noqa: F401
from saas_retriever.core import Document, SourceFilter
from saas_retriever.registry import registry

app = typer.Typer(
    name="saas-retriever",
    help="API-first SaaS content retriever.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command("list")
def cmd_list() -> None:
    """List registered connectors."""
    console = Console()
    table = Table(
        "name",
        "kind",
        title=f"saas-retriever {__version__} — registered connectors",
    )
    for name in registry.names():
        kind = getattr(registry._factories[name], "kind", "?")
        table.add_row(name, kind)
    console.print(table)


@app.command("fetch")
def cmd_fetch(
    connector: str = typer.Argument(..., help="Connector name (see `saas-retriever list`)."),
    owner: str | None = typer.Option(None, "--owner", help="Org / user / workspace identifier."),
    repo: str | None = typer.Option(None, "--repo", help="Single repository (omit for org-wide enumeration)."),
    token: str | None = typer.Option(
        None,
        "--token",
        help="API token. Falls back to GITHUB_TOKEN env var, then `gh auth token`.",
    ),
    resources: list[str] = typer.Option(
        [],
        "--resource",
        help="Resource types to fetch (repeatable). GitHub: code|issues|prs.",
    ),
    since: str | None = typer.Option(None, "--since", help="Filter to docs newer than this (e.g. 7d, 24h, ISO8601)."),
    include: list[str] = typer.Option([], "--include", help="Glob include filter (repeatable)."),
    exclude: list[str] = typer.Option([], "--exclude", help="Glob exclude filter (repeatable)."),
    include_archived: bool = typer.Option(
        False, "--include-archived", help="Include archived repos (GitHub org enumeration)."
    ),
    out: Path | None = typer.Option(None, "--out", help="Write NDJSON to this file instead of stdout."),
) -> None:
    """Retrieve Documents from a connector and stream NDJSON."""
    if connector not in registry.names():
        typer.echo(
            f"unknown connector: {connector!r}. available: {', '.join(registry.names())}",
            err=True,
        )
        raise typer.Exit(2)

    flt = SourceFilter(
        include=tuple(include),
        exclude=tuple(exclude),
        since=_parse_since(since),
    )

    connector_kwargs: dict[str, Any] = {}
    for k, v in (("owner", owner), ("repo", repo), ("token", token)):
        if v is not None:
            connector_kwargs[k] = v
    if resources:
        connector_kwargs["resources"] = frozenset(resources)
    if include_archived:
        connector_kwargs["include_archived"] = True

    asyncio.run(
        _run_fetch(
            connector=connector,
            connector_kwargs=connector_kwargs,
            filter=flt,
            out=out,
        )
    )


async def _run_fetch(
    *,
    connector: str,
    connector_kwargs: dict[str, Any],
    filter: SourceFilter,
    out: Path | None,
) -> None:
    """Drive one ``discover_and_fetch`` and emit NDJSON.

    Private async helper so tests can call it without going through the
    typer entry point.
    """
    sink = sys.stdout if out is None else out.open("w", encoding="utf-8")
    try:
        kwargs = _filter_supported_kwargs(connector, connector_kwargs)
        scraper = registry.create(connector, **kwargs)
        try:
            async for doc in scraper.discover_and_fetch(filter):
                sink.write(_encode_document(doc) + "\n")
                sink.flush()
        finally:
            await scraper.close()
    finally:
        if out is not None:
            sink.close()


def _filter_supported_kwargs(connector: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Drop kwargs the connector's __init__ doesn't declare."""
    factory = registry._factories[connector]
    init = getattr(factory, "__init__", None)
    if init is None:
        return {}
    code = init.__code__
    accepted = set(code.co_varnames[: code.co_argcount + code.co_kwonlyargcount])
    return {k: v for k, v in kwargs.items() if k in accepted}


_SINCE_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$")


def _parse_since(spec: str | None) -> datetime | None:
    """Parse a ``--since`` spec.

    Accepts a relative form (``7d``, ``24h``, ``30m``, ``4w``) or an
    ISO 8601 datetime. Returns ``None`` when ``spec is None``.
    """
    if spec is None:
        return None
    if m := _SINCE_RE.match(spec):
        n = int(m.group(1))
        unit = m.group(2)
        delta = {
            "s": timedelta(seconds=n),
            "m": timedelta(minutes=n),
            "h": timedelta(hours=n),
            "d": timedelta(days=n),
            "w": timedelta(weeks=n),
        }[unit]
        return datetime.now(UTC) - delta
    try:
        return datetime.fromisoformat(spec)
    except ValueError as exc:
        raise typer.BadParameter(f"unrecognised --since value: {spec!r}") from exc


def _encode_document(doc: Document) -> str:
    payload: dict[str, Any] = {
        "ref": _to_jsonable(doc.ref),
        "text": doc.text,
        "binary_b64": (base64.b64encode(doc.binary).decode("ascii") if doc.binary else None),
        "fetched_at": doc.fetched_at.isoformat() if doc.fetched_at else None,
        "content_hash": doc.content_hash,
        "created_by": _to_jsonable(doc.created_by) if doc.created_by else None,
        "extra": dict(doc.extra),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, tuple):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


@app.command("version")
def cmd_version() -> None:
    """Print the package version."""
    typer.echo(__version__)


def main() -> None:
    """Entry point exposed by the ``saas-retriever`` console script."""
    app()


if __name__ == "__main__":
    main()
