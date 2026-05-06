"""Detection backends.

A `Backend` consumes a `saas_retriever.Document` (text payload) and yields
`Finding`s. We ship three implementations:

* ``native`` — pure-python regex set (no system deps).
* ``trufflehog`` — subprocess wrapper, supports verification.
* ``gitleaks`` — subprocess wrapper, no verification.

`make(name)` is the factory used by the CLI; passing an unknown name raises
``ValueError`` with the available list.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable

from saas_retriever import Document

from pleno_secret_scanner.findings import Finding


@runtime_checkable
class Backend(Protocol):
    """Detection backend contract.

    Implementations must be safe to call from a single asyncio task and
    must not retain state between calls (the pipeline reuses one Backend
    instance across every Document of a scan).
    """

    name: str

    def scan(self, doc: Document) -> AsyncIterator[Finding]:
        """Detect secrets in `doc.text`. Binary documents are skipped upstream."""
        ...


def make(name: str) -> Backend:
    """Construct a Backend by name. Raises ValueError on unknown names."""
    from pleno_secret_scanner.backends.gitleaks import GitleaksBackend
    from pleno_secret_scanner.backends.native import NativeBackend
    from pleno_secret_scanner.backends.trufflehog import TrufflehogBackend

    backends: dict[str, type[Backend]] = {
        "native": NativeBackend,
        "trufflehog": TrufflehogBackend,
        "gitleaks": GitleaksBackend,
    }
    if name not in backends:
        raise ValueError(f"unknown backend {name!r}; available: {', '.join(sorted(backends))}")
    return backends[name]()


__all__ = ["Backend", "make"]
