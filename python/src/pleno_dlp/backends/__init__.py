"""Detection backends.

A ``Backend`` consumes a ``saas_retriever.Document`` (text payload) and
yields ``Finding`` s. Four implementations ship:

* ``native`` — pure-python regex set (no system deps).
* ``trufflehog`` — subprocess wrapper, supports verification.
* ``gitleaks`` — subprocess wrapper, no verification.
* ``pii`` — calls pleno-anonymize's ``/api/analyze`` endpoint over HTTP.
  Requires either a running pleno-anonymize server (``--pii-base-url``)
  or the ``pleno-dlp[pii]`` extra (which pulls pleno-anonymize as a
  library, embedded in-process).

``make(name, **kwargs)`` is the factory used by the CLI; passing an
unknown name raises ``ValueError`` with the available list.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from pleno_dlp.findings import Finding
from saas_retriever import Document


@runtime_checkable
class Backend(Protocol):
    """Detection backend contract.

    Implementations must be safe to call from a single asyncio task and
    must not retain state between calls (the pipeline reuses one Backend
    instance across every Document of a scan).
    """

    name: str

    def scan(self, doc: Document) -> AsyncIterator[Finding]:
        """Detect leaks (secret or PII) in ``doc.text``. Binary documents are
        skipped upstream."""
        ...


def make(name: str, **kwargs: Any) -> Backend:
    """Construct a Backend by name. Raises ValueError on unknown names.

    ``**kwargs`` are forwarded to the concrete backend constructor —
    only the ``pii`` backend currently consumes them
    (``base_url=`` / ``language=``). Other backends ignore any kwargs.
    """
    from pleno_dlp.backends.gitleaks import GitleaksBackend
    from pleno_dlp.backends.native import NativeBackend
    from pleno_dlp.backends.pii import PiiBackend
    from pleno_dlp.backends.trufflehog import TrufflehogBackend

    backends: dict[str, type[Backend]] = {
        "native": NativeBackend,
        "trufflehog": TrufflehogBackend,
        "gitleaks": GitleaksBackend,
        "pii": PiiBackend,
    }
    if name not in backends:
        raise ValueError(
            f"unknown backend {name!r}; available: {', '.join(sorted(backends))}"
        )
    cls = backends[name]
    if name == "pii":
        return cls(**kwargs)
    # The secret backends take no constructor args; reject misuse loudly
    # rather than silently swallow a typo'd ``--pii-base-url`` that
    # would be lost.
    if kwargs:
        raise TypeError(
            f"backend {name!r} takes no kwargs; got {sorted(kwargs)}"
        )
    return cls()


__all__ = ["Backend", "make"]
