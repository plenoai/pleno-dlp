"""pleno-dlp command-line interface.

Spec-driven across every SaaS source connector. Connector kwargs flow
through the generic ``--option key=value`` flag (or the shorthand
``--token``); each connector self-describes via ``ConnectorSpec``,
which the CLI introspects for ``list``, ``describe``, and validation.

Detection engines (regex / trufflehog / gitleaks / pii) are *not*
connectors — they are picked with ``--engine`` and instantiated
directly from ``pleno_dlp.engines``.

    pleno-dlp list                          # every connector
    pleno-dlp list --capability verify      # connectors with VERIFY
    pleno-dlp describe github
    pleno-dlp scan github --option owner=plenoai
    pleno-dlp scan github --option owner=plenoai --option repo=pleno-dlp \\
        --option resources=code,issues
    pleno-dlp scan github --option owner=plenoai \\
        --engine trufflehog --format sarif > findings.sarif
    pleno-dlp scan slack --token xoxb-... --option include_threads=false
    pleno-dlp scan jira --option flavor=cloud \\
        --option base_url=https://acme.atlassian.net \\
        --option email=alice@example.com --option api_token=xyz
    pleno-dlp verify github --token ghp_…  # confirm a leaked PAT is live
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
    Capability,
    ConnectorSpec,
    OptionSpec,
    SourceFilter,
    __version__,
    engines,
    output,
)
from pleno_dlp import connectors as _connectors  # noqa: F401  registry side-effect
from pleno_dlp.core import Verifier, VerifyStatus
from pleno_dlp.pipeline import Pipeline
from pleno_dlp.registry import registry

app = typer.Typer(
    name="pleno-dlp",
    help="Unified DLP scanner — secrets and PII over SaaS sources.",
    no_args_is_help=True,
    add_completion=False,
)

ENGINES: tuple[str, ...] = ("native", "trufflehog", "gitleaks", "pii")


def _resolve_capability(capability: str | None) -> Capability | None:
    if capability is None:
        return None
    try:
        return Capability(capability)
    except ValueError as exc:
        raise typer.BadParameter(
            f"--capability must be one of {[c.value for c in Capability]}; got {capability!r}"
        ) from exc


@app.command("list")
def cmd_list(
    capability: str | None = typer.Option(
        None,
        "--capability",
        help=f"Filter by capability ({', '.join(c.value for c in Capability)}).",
    ),
) -> None:
    """List every registered SaaS connector with its capabilities, auth modes, and resources.

    Detection engines are listed alongside connectors — they are not
    in the registry but the CLI surfaces them so operators can see the
    full toolset in one place.
    """
    selected = _resolve_capability(capability)
    console = Console()

    table = Table(
        "name", "kind", "capabilities", "auth", "resources", "summary",
        title="connectors",
    )
    for spec in registry.specs(capability=selected):
        caps = ", ".join(sorted(c.value for c in spec.capabilities))
        auth = ", ".join(m.value for m in spec.auth_modes)
        resources = ", ".join(r.name for r in spec.resources) or "—"
        table.add_row(spec.name, spec.kind, caps, auth, resources, spec.summary)
    console.print(table)

    # Engines are surfaced in their own block — they're not connectors,
    # but operators discovering "what can I run?" want them visible too.
    if selected is None:
        engine_table = Table("engine", "summary", title="detection engines (--engine)")
        engine_table.add_row("native", "Bundled regex set (AWS, GitHub, Slack, OpenAI, Anthropic).")
        engine_table.add_row("trufflehog", "trufflehog CLI subprocess; verifies provider hits when supported.")
        engine_table.add_row("gitleaks", "gitleaks CLI subprocess; pattern matching only.")
        engine_table.add_row("pii", "PII analyser delegating to pleno-anonymize's /api/analyze.")
        console.print(engine_table)


@app.command("describe")
def cmd_describe(connector: str = typer.Argument(..., help="Connector name (see `pleno-dlp list`).")) -> None:
    """Print one connector's full spec: capabilities, auth modes, resources, options, docs."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)
    _render_describe(registry.spec(connector))


@app.command("scan")
def cmd_scan(
    connector: str = typer.Argument(
        ...,
        help="Source connector name (see `pleno-dlp list`).",
    ),
    engine: str = typer.Option(
        "native",
        "--engine",
        help=f"Detection engine to apply to each Document. One of: {', '.join(ENGINES)}.",
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
    out: Path | None = typer.Option(None, "--out", help="Write findings to a file (default: stdout)."),
    pii_base_url: str | None = typer.Option(
        None,
        "--pii-base-url",
        help="Override the pii engine's `base_url` (default http://127.0.0.1:8000).",
    ),
    pii_language: str | None = typer.Option(
        None,
        "--pii-language",
        help="Override the pii engine's `language` (ja|en).",
    ),
) -> None:
    """Scan one SaaS source connector with one detection engine and emit findings."""
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)
    if engine not in ENGINES:
        typer.echo(f"unknown engine: {engine!r}. available: {', '.join(ENGINES)}", err=True)
        raise typer.Exit(2)
    source_spec = registry.spec(connector)

    flt = SourceFilter(include=tuple(include), exclude=tuple(exclude), since=_parse_since(since))
    sink = output.make(format)

    source_kwargs = _build_kwargs(source_spec, options, token=token)

    rc = asyncio.run(
        _run(
            connector=connector,
            connector_kwargs=source_kwargs,
            engine_name=engine,
            pii_overrides={"base_url": pii_base_url, "language": pii_language},
            sink=sink,
            filter=flt,
            out=out,
        )
    )
    raise typer.Exit(rc)


@app.command("verify")
def cmd_verify(
    connector: str = typer.Argument(..., help="Connector name (must declare Capability.VERIFY)."),
    token: str = typer.Option(..., "--token", help="Credential to test against the provider."),
) -> None:
    """Probe a credential against the provider and report liveness.

    Exits 0 = LIVE, 1 = REVOKED, 2 = UNKNOWN/unsupported. Connectors
    advertise this capability via ``Capability.VERIFY`` in their spec;
    run ``pleno-dlp list --capability verify`` to see which providers
    currently support it.
    """
    if connector not in registry.names():
        typer.echo(f"unknown connector: {connector!r}. available: {', '.join(registry.names())}", err=True)
        raise typer.Exit(2)
    spec = registry.spec(connector)
    if not spec.has(Capability.VERIFY):
        typer.echo(
            f"{connector!r} does not implement Capability.VERIFY. "
            f"Capabilities: {', '.join(sorted(c.value for c in spec.capabilities))}.",
            err=True,
        )
        raise typer.Exit(2)
    rc = asyncio.run(_run_verify(connector, token))
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
    engine_name: str,
    pii_overrides: dict[str, str | None],
    sink: output.Sink,
    filter: SourceFilter,
    out: Path | None,
) -> int:
    """Drive the pipeline. Exit code 0 = clean, 1 = findings, 2 = error."""
    stream = sys.stdout if out is None else out.open("w", encoding="utf-8")
    try:
        try:
            source = registry.create(connector, **connector_kwargs)
        except TypeError as exc:
            typer.echo(str(exc), err=True)
            return 2
        eng = _make_engine(engine_name, pii_overrides)
        try:
            pipeline = Pipeline(connector=source, engine=eng)
            count = await sink.emit(pipeline.run(filter), stream=stream)
        finally:
            await source.close()
            aclose = getattr(eng, "aclose", None)
            if aclose is not None:
                await aclose()
        return 1 if count > 0 else 0
    finally:
        if out is not None:
            stream.close()


async def _run_verify(connector_name: str, token: str) -> int:
    """Drive a single verify call. Exit code 0=LIVE, 1=REVOKED, 2=UNKNOWN."""
    # The verify path needs a constructed connector instance because the
    # Verifier protocol is implemented as a method on the connector
    # class. A minimal kwargs payload that satisfies required options is
    # the operator's responsibility for now — verify-only flows on most
    # providers don't need owner/repo, so we pass an empty dict and let
    # any TypeError surface to the operator.
    spec = registry.spec(connector_name)
    kwargs: dict[str, Any] = {}
    if "token" in spec.accepted_kwargs():
        kwargs["token"] = token
    # Required options without a default would raise here — that's
    # fine; the operator must supply them via a future --option
    # extension if a provider's verify endpoint depends on tenant
    # context (not currently the case for the connectors we ship).
    try:
        instance = registry.create(connector_name, **kwargs)
    except TypeError as exc:
        typer.echo(str(exc), err=True)
        return 2
    if not isinstance(instance, Verifier):
        typer.echo(
            f"{connector_name!r} declares Capability.VERIFY but does not implement Verifier.",
            err=True,
        )
        return 2
    try:
        result = await instance.verify(token)
    finally:
        close = getattr(instance, "close", None)
        if close is not None:
            await close()
    actor = ", ".join(f"{k}={v}" for k, v in result.actor.items())
    suffix = f" ({actor})" if actor else ""
    detail = f" — {result.detail}" if result.detail else ""
    typer.echo(f"{connector_name}: {result.status.value}{suffix}{detail}")
    match result.status:
        case VerifyStatus.LIVE:
            return 0
        case VerifyStatus.REVOKED:
            return 1
        case _:
            return 2


def _make_engine(name: str, pii_overrides: dict[str, str | None]) -> Any:
    """Instantiate the engine; the `pii` engine accepts CLI overrides."""
    if name == "pii":
        kwargs: dict[str, Any] = {}
        if pii_overrides.get("base_url") is not None:
            kwargs["base_url"] = pii_overrides["base_url"]
        if pii_overrides.get("language") is not None:
            kwargs["language"] = pii_overrides["language"]
        return engines.PiiEngine(**kwargs)
    return engines.make(name)


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
    caps = ", ".join(sorted(c.value for c in spec.capabilities))
    console.print(f"[bold]{spec.name}[/bold] ({caps}) — {spec.summary}")
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
