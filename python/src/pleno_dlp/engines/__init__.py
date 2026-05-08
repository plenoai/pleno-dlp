"""Detection engines — cross-cutting text-to-Findings scanners.

Engines are *not* connectors and do not register in the connector
registry. They are stateless utility classes that turn an arbitrary
text body into ``Finding``\\s without belonging to a specific SaaS
provider:

* ``NativeEngine`` — bundled regex set (AWS, GitHub, Slack, OpenAI,
  Anthropic).
* ``TrufflehogEngine`` — subprocess wrapper around the ``trufflehog``
  CLI; verifies hits when the upstream detector supports it.
* ``GitleaksEngine`` — subprocess wrapper around the ``gitleaks`` CLI.
* ``PiiEngine`` — calls pleno-anonymize's ``/api/analyze`` HTTP API.

A connector that walks SaaS content (``Capability.SOURCE``) hands
every Document it produces to an engine; the pipeline owns the
plumbing.
"""

from pleno_dlp.engines.gitleaks import GitleaksEngine
from pleno_dlp.engines.native import NativeEngine
from pleno_dlp.engines.pii import PiiEngine
from pleno_dlp.engines.trufflehog import TrufflehogEngine

__all__ = ["GitleaksEngine", "NativeEngine", "PiiEngine", "TrufflehogEngine"]


def make(name: str) -> NativeEngine | TrufflehogEngine | GitleaksEngine | PiiEngine:
    """Factory for the four built-in engines, keyed by ``--engine`` name.

    Engines that take configuration (``pii.base_url``, ``trufflehog.binary``)
    are instantiated with their defaults here; callers that need
    overrides should construct the class directly.
    """
    match name:
        case "native":
            return NativeEngine()
        case "trufflehog":
            return TrufflehogEngine()
        case "gitleaks":
            return GitleaksEngine()
        case "pii":
            return PiiEngine()
        case _:
            raise KeyError(
                f"Unknown engine: {name!r}. Available: gitleaks, native, pii, trufflehog."
            )
