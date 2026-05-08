"""pleno-dlp command-line interface.

Spec-driven across both source and detector connectors. Connector
kwargs flow through the generic ``--option key=value`` flag (or the
shorthand ``--token``); each connector self-describes via
``ConnectorSpec``, which the CLI introspects for ``list``,
``describe``, and validation.

    pleno-dlp list                          # everything
    pleno-dlp list --role source            # only sources
    pleno-dlp list --role detector          # only detectors
    pleno-dlp describe github
    pleno-dlp describe trufflehog
    pleno-dlp scan github --option owner=plenoai
    pleno-dlp scan github --option owner=plenoai --option repo=pleno-dlp \\
        --option resources=code,issues
    pleno-dlp scan github --option owner=plenoai \\
        --detector trufflehog --format sarif > findings.sarif
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

from pleno_dlp import (
    ConnectorRole,
    ConnectorSpec,
    OptionSpec,
    SourceFilter,
    __version__,
    output,
)
from pleno_dlp import connectors as _connectors  # noqa: F401  registry side-effect
from pleno_dlp.pipeline import Pipeline
from pleno_dlp.registry import registry

app = typer.Typer(
    name="pleno-dlp",
    help="Unified DLP scanner — secrets and PII over SaaS sources.",
    no_args_is_help=True,
    add_completion=False,
)


def _resolve_role(role: str | None) -> ConnectorRole | None:
    if role is None:
        return None
    try:
        return ConnectorRole(role)
    except ValueError as exc:
        raise typer.BadParameter(
            f"--role must be one of {[r.value for r in ConnectorRole]}; got {role!r}"
        ) from exc


@app.command("list")
def cmd_list(
    role: str | None = typer.Option(
        None,
        "--role",
        help="Filter by role: source or detector. Default: both.",
    ),
) -> None:
    """List every registered connector with its role, auth modes, and resources."""
    selected = _resolve_role(role)
    console = Console()
    table = Table("name", "role", "kind", "auth", "resources", "summary", title="connectors")
    for spec in registry.specs(role=selected):
        auth = ", ".join(m.value for m in spec.auth_modes)
        resources = ", ".join(r.name for r in spec.resources) or "—"
        table.add_row(spec.name, spec.role.value, spec.kind, auth, resources, spec.summary)
    console.print(table)


@app.command("describe")
def cmd_describe(connector: str = typer.Argument(..., help="Connector name (see `pleno-dlp list`).")) -> None:
    """Print one connector's full spec: role, auth modes, resources, options, docs."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)
    _render_describe(registry.spec(connector))


@app.command("scan")
def cmd_scan(
    connector: str = typer.Argument(
        ...,
        help="Source connector name (see `pleno-dlp list --role source`).",
    ),
    detector: str = typer.Option(
        "native",
        "--detector",
        help="Detector connector name (see `pleno-dlp list --role detector`).",
    ),
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
            "Source connector kwarg `key=value`. Repeatable. true/false/int auto-coerced; "
            "comma lists become tuples. Run `pleno-dlp describe <connector>` to "
            "see the accepted keys."
        ),
    ),
    detector_options: list[str] = typer.Option(
        [],
        "--detector-option",
        "-D",
        help=(
            "Detector connector kwarg `key=value`. Repeatable. Run "
            "`pleno-dlp describe <detector>` to see the accepted keys."
        ),
    ),
    out: Path | None = typer.Option(None, "--out", help="Write findings to a file (default: stdout)."),
    pii_base_url: str | None = typer.Option(
        None,
        "--pii-base-url",
        help="Shorthand for --detector-option base_url=… on the `pii` detector.",
    ),
    pii_language: str | None = typer.Option(
        None,
        "--pii-language",
        help="Shorthand for --detector-option language=… on the `pii` detector.",
    ),
) -> None:
    """Scan one source connector with one detector and emit findings."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.sources())}", err=True)
        raise typer.Exit(2)
    source_spec = registry.spec(connector)
    if source_spec.role is not ConnectorRole.SOURCE:
        typer.echo(f"{connector!r} is a {source_spec.role.value}, not a source connector.", err=True)
        raise typer.Exit(2)
    if detector not in registry.names():
        typer.echo(f"unknown detector: {detector!r}. available: {', '.join(registry.detectors())}", err=True)
        raise typer.Exit(2)
    detector_spec = registry.spec(detector)
    if detector_spec.role is not ConnectorRole.DETECTOR:
        typer.echo(f"{detector!r} is a {detector_spec.role.value}, not a detector connector.", err=True)
        raise typer.Exit(2)

    flt = SourceFilter(include=tuple(include), exclude=tuple(exclude), since=_parse_since(since))
    sink = output.make(format)

    source_kwargs = _build_kwargs(source_spec, options, token=token)
    det_kwargs = _build_kwargs(detector_spec, detector_options)
    if pii_base_url is not None:
        det_kwargs["base_url"] = pii_base_url
    if pii_language is not None:
        det_kwargs["language"] = pii_language

    rc = asyncio.run(
        _run(
            connector=connector,
            connector_kwargs=source_kwargs,
            detector=detector,
            detector_kwargs=det_kwargs,
            sink=sink,
            filter=flt,
            out=out,
        )
    )
    raise typer.Exit(rc)


def _build_kwargs(spec: ConnectorSpec, raw_options: list[str], *, token: str | None = None) -> dict[str, Any]:
    """Parse a list of `key=value` strings into a kwarg dict, spec-aware."""
    out: dict[str, Any] = {}
    if token is not None and "token" in spec.accepted_kwargs():
        out["token"] = token
    for raw in raw_options:
        if "=" not in raw:
            raise typer.BadParameter(
                f"--option must be key=value; got {raw!r}",
                param_hint="--option",
            )
        key, _, value = raw.partition("=")
        opt = spec.option(key)
        out[key] = _coerce_option(value, opt)
    return out


async def _run(
    *,
    connector: str,
    connector_kwargs: dict[str, Any],
    detector: str,
    detector_kwargs: dict[str, Any],
    sink: output.Sink,
    filter: SourceFilter,
    out: Path | None,
) -> int:
    """Drive the pipeline. Exit code 0 = clean, 1 = findings, 2 = error."""
    stream = sys.stdout if out is None else out.open("w", encoding="utf-8")
    try:
        try:
            source = registry.create(connector, **connector_kwargs)
            det = registry.create(detector, **detector_kwargs)
        except TypeError as exc:
            typer.echo(str(exc), err=True)
            return 2
        try:
            pipeline = Pipeline(connector=source, detector=det)
            count = await sink.emit(pipeline.run(filter), stream=stream)
        finally:
            await source.close()
            aclose = getattr(det, "aclose", None)
            if aclose is not None:
                await aclose()
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
    console.print(f"[bold]{spec.name}[/bold] ({spec.role.value}) — {spec.summary}")
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
