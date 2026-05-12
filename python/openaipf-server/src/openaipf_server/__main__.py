"""CLI entrypoint: `python -m openaipf_server --host ... --port ... --device ...`.

The Go-side openai-pf-server subcommand invokes this module via uvx:

    uvx --from "git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server" \
        python -m openaipf_server --host 127.0.0.1 --port <ephemeral> --device <hint>

Loopback enforcement is duplicated here (it also lives in the Go
subcommand at flag-parse) as defence-in-depth: a misconfigured wrapper
script invoking this module directly must still refuse to bind a
public interface for a DLP tool (ADR-0001 §hard rule).
"""

from __future__ import annotations

import argparse
import ipaddress
import sys

import uvicorn

from .app import create_app


def _is_loopback_host(host: str) -> bool:
    """True if host is a literal loopback / private / link-local address
    or the string "localhost".

    We do not resolve hostnames here for the same reason the Go side
    doesn't: a hostile or split-horizon resolver could lead "internal"
    to a public address. Only literal loopback / RFC1918 / link-local
    plus "localhost" pass.
    """
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_unspecified:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="openaipf-server",
        description="Loopback HTTP wrapper around openai/privacy-filter for pleno-dlp.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (loopback / RFC1918 / link-local only; 0.0.0.0 and public IPs are refused)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="bind port; 0 lets the OS pick an ephemeral port (uvicorn prints it)",
    )
    parser.add_argument(
        "--device",
        choices=["auto", "cpu", "cuda", "mps"],
        default="auto",
        help="inference device hint passed through to opf",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        help="uvicorn log level (debug/info/warning/error/critical)",
    )
    args = parser.parse_args()

    if not _is_loopback_host(args.host):
        # Exit code 2 matches the Go subcommand's contract for a flag
        # validation failure and is distinguishable from a model-load
        # crash (exit code 1 from uvicorn).
        print(
            f"openaipf-server: refusing to bind non-loopback host {args.host!r} "
            f"(this is a DLP tool — public-interface binds are unsafe)",
            file=sys.stderr,
        )
        sys.exit(2)

    # Print the listening line on stdout for direct invokers — the Go
    # supervisor pre-allocates the port and doesn't depend on parsing
    # this, but `pleno-dlp openai-pf-server` does emit a similar line
    # for human callers.
    print(f"openaipf-server: listening on {args.host}:{args.port}", flush=True)

    app = create_app(device=args.device)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        # Disable uvicorn's own access log spam — every scan chunk
        # would otherwise emit a request log line. The Go supervisor
        # logs at the engine boundary; double-logging is just noise.
        access_log=False,
    )


if __name__ == "__main__":
    main()
