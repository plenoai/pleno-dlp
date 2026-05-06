"""pleno-dlp command-line interface.

    pleno-dlp list-connectors
    pleno-dlp list-backends
    pleno-dlp scan github --owner plenoai
    pleno-dlp scan github --owner plenoai --repo saas-retriever \\
        --resource code --resource issues --resource prs
    pleno-dlp scan github --owner plenoai \\
        --backend trufflehog --format sarif > findings.sarif
"""

from __future__ import annotations

import asyncio
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from saas_retriever import SourceFilter
from saas_retriever import connectors as _connectors  # noqa: F401  registry side-effect
from saas_retriever.registry import registry

from pleno_dlp import __version__, backends, output
from pleno_dlp.pipeline import Pipeline

app = typer.Typer(
    name="pleno-dlp",
    help="Unified DLP scanner — secrets and PII over SaaS sources.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command("list-connectors")
def cmd_list_connectors() -> None:
    """List registered saas-scraper connectors."""
    console = Console()
    table = Table("name", "kind", title="connectors")
    for name in registry.names():
        kind = getattr(registry._factories[name], "kind", "?")
        table.add_row(name, kind)
    console.print(table)


@app.command("list-backends")
def cmd_list_backends() -> None:
    """List available detection backends."""
    console = Console()
    table = Table("name", "class", "verifies", "system dep", title="backends")
    table.add_row("native", "secret", "no", "none (bundled regex)")
    table.add_row("trufflehog", "secret", "yes", "trufflehog on PATH")
    table.add_row("gitleaks", "secret", "no", "gitleaks on PATH")
    table.add_row("pii", "pii", "n/a", "pleno-anonymize server (HTTP API)")
    console.print(table)


@app.command("scan")
def cmd_scan(
    connector: str = typer.Argument(..., help="saas-retriever connector name (currently: github)."),
    backend: str = typer.Option("native", "--backend", help="Detection backend."),
    format: str = typer.Option("table", "--format", help="Output format: json|sarif|table."),
    owner: str | None = typer.Option(None, "--owner", help="Org or user. Required for the github connector."),
    repo: str | None = typer.Option(None, "--repo", help="Single repo (omit for org-wide enumeration)."),
    token: str | None = typer.Option(
        None,
        "--token",
        help="API token. Falls back to GITHUB_TOKEN env var, then `gh auth token`.",
    ),
    resources: list[str] = typer.Option(
        [],
        "--resource",
        help=(
            "GitHub resource(s) to scan, repeatable. One or more of "
            "code|issues|prs. Default: all three."
        ),
    ),
    include_archived: bool = typer.Option(
        False, "--include-archived", help="Include archived repos in org-wide GitHub scans."
    ),
    since: str | None = typer.Option(None, "--since"),
    include: list[str] = typer.Option([], "--include"),
    exclude: list[str] = typer.Option([], "--exclude"),
    out: Path | None = typer.Option(None, "--out"),
    pii_base_url: str = typer.Option(
        "http://127.0.0.1:8000",
        "--pii-base-url",
        help="pleno-anonymize server URL for the `pii` backend.",
    ),
    pii_language: str = typer.Option(
        "ja",
        "--pii-language",
        help="Language hint for the `pii` backend: ja or en.",
    ),
) -> None:
    """Scan one connector with one backend and emit findings."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)

    flt = SourceFilter(include=tuple(include), exclude=tuple(exclude), since=_parse_since(since))
    if backend == "pii":
        backend_obj = backends.make(
            backend, base_url=pii_base_url, language=pii_language
        )
    else:
        backend_obj = backends.make(backend)
    sink = output.make(format)

    connector_kwargs: dict[str, Any] = {}
    for k, v in (("owner", owner), ("repo", repo), ("token", token)):
        if v is not None:
            connector_kwargs[k] = v
    if resources:
        connector_kwargs["resources"] = frozenset(resources)
    if include_archived:
        connector_kwargs["include_archived"] = True

    rc = asyncio.run(
        _run(
            connector=connector,
            connector_kwargs=connector_kwargs,
            backend=backend_obj,
            sink=sink,
            filter=flt,
            out=out,
        )
    )
    raise typer.Exit(rc)


async def _run(
    *,
    connector: str,
    connector_kwargs: dict[str, Any],
    backend: backends.Backend,
    sink: output.Sink,
    filter: SourceFilter,
    out: Path | None,
) -> int:
    """Drive the pipeline. Exit code 0 = clean, 1 = findings, 2 = error."""
    stream = sys.stdout if out is None else out.open("w", encoding="utf-8")
    try:
        kwargs = _filter_supported_kwargs(connector, connector_kwargs)
        retriever = registry.create(connector, **kwargs)
        try:
            pipeline = Pipeline(connector=retriever, backend=backend)
            count = await sink.emit(pipeline.run(filter), stream=stream)
        finally:
            await retriever.close()
        return 1 if count > 0 else 0
    finally:
        if out is not None:
            stream.close()


def _filter_supported_kwargs(connector: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    factory = registry._factories[connector]
    init = getattr(factory, "__init__", None)
    if init is None:
        return {}
    code = init.__code__
    accepted = set(code.co_varnames[: code.co_argcount + code.co_kwonlyargcount])
    return {k: v for k, v in kwargs.items() if k in accepted}


_SINCE_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$")


def _parse_since(spec: str | None) -> datetime | None:
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


@app.command("version")
def cmd_version() -> None:
    """Print package version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
