"""pleno-dlp command-line interface.

Spec-driven: connector-specific knobs flow through the generic
``--option key=value`` flag. Each connector self-describes via its
``ConnectorSpec``, which the CLI introspects for ``list-connectors``,
``describe``, and validation. Adding a new connector requires no
changes here — implement the connector with a spec and register it.

    pleno-dlp list-connectors
    pleno-dlp list-backends
    pleno-dlp describe github
    pleno-dlp scan github --option owner=plenoai
    pleno-dlp scan github --option owner=plenoai --option repo=pleno-dlp \\
        --option resources=code,issues
    pleno-dlp scan github --option owner=plenoai \\
        --backend trufflehog --format sarif > findings.sarif
    pleno-dlp scan slack --token xoxb-... --option include_threads=false
    pleno-dlp scan jira --option flavor=cloud \\
        --option base_url=https://acme.atlassian.net \\
        --option email=alice@example.com --option api_token=xyz
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

from pleno_dlp import ConnectorSpec, OptionSpec, SourceFilter, __version__, backends, output
from pleno_dlp import connectors as _connectors  # noqa: F401  registry side-effect
from pleno_dlp.pipeline import Pipeline
from pleno_dlp.registry import registry

app = typer.Typer(
    name="pleno-dlp",
    help="Unified DLP scanner — secrets and PII over SaaS sources.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command("list-connectors")
def cmd_list_connectors() -> None:
    """List every registered SaaS connector with its summary and auth modes."""
    console = Console()
    table = Table("name", "kind", "auth", "resources", "summary", title="connectors")
    for spec in registry.specs():
        auth = ", ".join(m.value for m in spec.auth_modes)
        resources = ", ".join(r.name for r in spec.resources) or "—"
        table.add_row(spec.name, spec.kind, auth, resources, spec.summary)
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


@app.command("describe")
def cmd_describe(connector: str = typer.Argument(..., help="Connector name (see list-connectors).")) -> None:
    """Print the connector's full spec: auth modes, resources, options, docs."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)
    spec = registry.spec(connector)
    _render_describe(spec)


@app.command("scan")
def cmd_scan(
    connector: str = typer.Argument(
        ...,
        help="Connector name (see `pleno-dlp list-connectors`).",
    ),
    backend: str = typer.Option("native", "--backend", help="Detection backend."),
    format: str = typer.Option("table", "--format", help="Output format: json|sarif|table."),
    token: str | None = typer.Option(
        None,
        "--token",
        help=(
            "Shorthand for --option token=…. github falls back to "
            "GITHUB_TOKEN env / `gh auth token` when omitted."
        ),
    ),
    since: str | None = typer.Option(None, "--since", help="`<n>{s,m,h,d,w}` or ISO-8601 timestamp."),
    include: list[str] = typer.Option([], "--include", help="Glob patterns kept (SourceFilter.include)."),
    exclude: list[str] = typer.Option([], "--exclude", help="Glob patterns dropped (SourceFilter.exclude)."),
    options: list[str] = typer.Option(
        [],
        "--option",
        "-o",
        help=(
            "Connector kwarg `key=value`. Repeatable. true/false/int auto-coerced; "
            "comma lists become tuples. Run `pleno-dlp describe <connector>` to "
            "see the accepted keys."
        ),
    ),
    out: Path | None = typer.Option(None, "--out", help="Write findings to a file (default: stdout)."),
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
    spec = registry.spec(connector)

    flt = SourceFilter(include=tuple(include), exclude=tuple(exclude), since=_parse_since(since))
    if backend == "pii":
        backend_obj = backends.make(backend, base_url=pii_base_url, language=pii_language)
    else:
        backend_obj = backends.make(backend)
    sink = output.make(format)

    connector_kwargs: dict[str, Any] = {}
    if token is not None:
        connector_kwargs["token"] = token
    for raw in options:
        if "=" not in raw:
            raise typer.BadParameter(
                f"--option must be key=value; got {raw!r}",
                param_hint="--option",
            )
        key, _, value = raw.partition("=")
        opt = spec.option(key)
        connector_kwargs[key] = _coerce_option(value, opt)

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
        try:
            retriever = registry.create(connector, **connector_kwargs)
        except TypeError as exc:
            typer.echo(str(exc), err=True)
            return 2
        try:
            pipeline = Pipeline(connector=retriever, backend=backend)
            count = await sink.emit(pipeline.run(filter), stream=stream)
        finally:
            await retriever.close()
        return 1 if count > 0 else 0
    finally:
        if out is not None:
            stream.close()


def _coerce_option(value: str, opt: OptionSpec | None) -> Any:
    """Coerce a `--option key=value` string to the connector kwarg type.

    When the OptionSpec is known we coerce against its declared ``type``;
    otherwise we fall back to literal scalar coercion (true/false/int).
    Comma-separated values become tuples for `list[str]` options.
    """
    if opt is not None:
        match opt.type:
            case "bool":
                return _coerce_scalar(value)
            case "int":
                try:
                    return int(value)
                except ValueError as exc:
                    raise typer.BadParameter(f"--option {opt.name}= expects int; got {value!r}") from exc
            case "list[str]":
                return tuple(p for p in (s.strip() for s in value.split(",")) if p)
            case _:
                return value
    return _coerce_scalar(value)


def _coerce_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"none", "null"}:
        return None
    try:
        return int(value)
    except ValueError:
        return value


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


def _render_describe(spec: ConnectorSpec) -> None:
    console = Console()
    auth = ", ".join(m.value for m in spec.auth_modes) or "—"
    console.print(f"[bold]{spec.name}[/bold] — {spec.summary}")
    console.print(f"  kind: {spec.kind}")
    console.print(f"  auth: {auth}")
    if spec.docs_url:
        console.print(f"  docs: {spec.docs_url}")
    if spec.resources:
        rt = Table("name", "default", "summary", title="resources")
        for r in spec.resources:
            rt.add_row(r.name, "yes" if r.default else "no", r.summary)
        console.print(rt)
    if spec.options:
        ot = Table("option", "type", "default", "required", "secret", "help", title="options")
        for o in spec.options:
            default = "—" if o.default is None else repr(o.default)
            ot.add_row(o.name, o.type, default, "yes" if o.required else "", "yes" if o.secret else "", o.help)
        console.print(ot)


@app.command("version")
def cmd_version() -> None:
    """Print package version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
