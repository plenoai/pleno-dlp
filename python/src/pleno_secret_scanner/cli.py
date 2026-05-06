"""pleno-secret-scanner command-line interface.

    pleno-secret-scanner list-connectors
    pleno-secret-scanner list-backends
    pleno-secret-scanner scan <connector> [--backend native|trufflehog|gitleaks]
                                          [--format json|sarif|table]
                                          [--workspace ...] [--owner ...] [--repo ...]
                                          [--since 7d] [--out PATH]
                                          [--headed] [--profile-dir DIR]
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
from saas_scraper import BrowserSession, SourceFilter
from saas_scraper import connectors as _connectors  # noqa: F401  registry side-effect
from saas_scraper.registry import registry

from pleno_secret_scanner import __version__, backends, output
from pleno_secret_scanner.pipeline import Pipeline

app = typer.Typer(
    name="pleno-secret-scanner",
    help="Scan SaaS sources for leaked secrets.",
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
    table = Table("name", "verifies", "system dep", title="backends")
    table.add_row("native", "no", "none (bundled regex)")
    table.add_row("trufflehog", "yes", "trufflehog on PATH")
    table.add_row("gitleaks", "no", "gitleaks on PATH")
    console.print(table)


@app.command("scan")
def cmd_scan(
    connector: str = typer.Argument(..., help="saas-scraper connector name."),
    backend: str = typer.Option("native", "--backend", help="Detection backend."),
    format: str = typer.Option("table", "--format", help="Output format: json|sarif|table."),
    workspace: str | None = typer.Option(None, "--workspace"),
    owner: str | None = typer.Option(None, "--owner"),
    repo: str | None = typer.Option(None, "--repo"),
    project: str | None = typer.Option(None, "--project"),
    since: str | None = typer.Option(None, "--since"),
    include: list[str] = typer.Option([], "--include"),
    exclude: list[str] = typer.Option([], "--exclude"),
    out: Path | None = typer.Option(None, "--out"),
    headed: bool = typer.Option(False, "--headed"),
    profile_dir: Path | None = typer.Option(None, "--profile-dir"),
) -> None:
    """Scan one connector with one backend and emit findings."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)

    flt = SourceFilter(include=tuple(include), exclude=tuple(exclude), since=_parse_since(since))
    backend_obj = backends.make(backend)
    sink = output.make(format)

    connector_kwargs: dict[str, Any] = {}
    for k, v in (("workspace", workspace), ("owner", owner), ("repo", repo), ("project", project)):
        if v is not None:
            connector_kwargs[k] = v

    rc = asyncio.run(
        _run(
            connector=connector,
            connector_kwargs=connector_kwargs,
            backend=backend_obj,
            sink=sink,
            filter=flt,
            out=out,
            headless=not headed,
            profile_dir=profile_dir,
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
    headless: bool,
    profile_dir: Path | None,
) -> int:
    """Drive the pipeline. Exit code 0 = clean, 1 = findings, 2 = error."""
    stream = sys.stdout if out is None else out.open("w", encoding="utf-8")
    try:
        async with BrowserSession(headless=headless, profile_dir=profile_dir) as session:
            kwargs = _filter_supported_kwargs(connector, connector_kwargs)
            scraper = registry.create(connector, session=session, **kwargs)
            try:
                pipeline = Pipeline(connector=scraper, backend=backend)
                count = await sink.emit(pipeline.run(filter), stream=stream)
            finally:
                await scraper.close()
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
