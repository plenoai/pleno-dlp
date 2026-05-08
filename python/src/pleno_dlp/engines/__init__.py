"""Detection engines — low-level text-to-Findings scanners.

Engines are *not* connectors and do not register in the connector
registry. They are stateless ``Detector`` implementations that
connectors compose internally:

* ``NativeEngine`` — bundled regex set (AWS, GitHub, Slack, OpenAI,
  Anthropic).
* ``TrufflehogEngine`` — subprocess wrapper around the ``trufflehog``
  CLI; verifies hits when the upstream detector supports it.
* ``GitleaksEngine`` — subprocess wrapper around the ``gitleaks`` CLI.
* ``PiiEngine`` — calls pleno-anonymize's ``/api/analyze`` HTTP API.

Operators address detection by SaaS connector
(``pleno-dlp scan github``); the engine is configured per connector
via ``--option engine=…`` and runs internally.
"""

from pleno_dlp.engines.gitleaks import GitleaksEngine
from pleno_dlp.engines.native import NativeEngine
from pleno_dlp.engines.pii import PiiEngine
from pleno_dlp.engines.trufflehog import TrufflehogEngine

__all__ = ["ENGINE_NAMES", "GitleaksEngine", "NativeEngine", "PiiEngine", "TrufflehogEngine", "make"]

ENGINE_NAMES: tuple[str, ...] = ("native", "trufflehog", "gitleaks", "pii")


def make(name: str) -> NativeEngine | TrufflehogEngine | GitleaksEngine | PiiEngine:
    """Factory for the four built-in engines, keyed by short name.

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
                f"Unknown engine: {name!r}. Available: {', '.join(ENGINE_NAMES)}."
            )
