"""Credential bundle — provider-specific secret payload, masked in logs.

Connectors take a ``Credential`` directly via constructor; saas-retriever
does not bundle a resolver / broker (env / keyring / file are the
caller's responsibility). The ``Credential`` shape mirrors
``pleno_pii_scanner.credentials.broker.Credential`` so the bridge wheel
can pass through whatever the pleno-anonymize broker resolved.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

# Keys whose values must be redacted in repr / str. Any Mapping key that
# matches one of these substrings (case-insensitive) is rendered as
# "***". Numeric / non-secret metadata (app_id, role_arn, region) keeps
# its real value to stay debug-useful.
_SECRET_KEY_HINTS: tuple[str, ...] = (
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "private",
    "credential",
    "session",
    "cert",
    "pem",
)

# Allow-list overrides: substring match would otherwise hide these
# operationally-important non-secret fields.
_NON_SECRET_KEY_ALLOWLIST: frozenset[str] = frozenset({"access_key_id", "key_id", "kid", "public_key"})


def _is_secret_key(key: str) -> bool:
    """Return True if ``key`` should be masked in repr / str output."""
    lowered = key.lower()
    if lowered in _NON_SECRET_KEY_ALLOWLIST:
        return False
    return any(hint in lowered for hint in _SECRET_KEY_HINTS)


def _mask_payload(payload: Mapping[str, object]) -> dict[str, object]:
    return {k: ("***" if _is_secret_key(k) else v) for k, v in payload.items()}


class CredentialError(Exception):
    """Base class for credential errors."""


class CredentialNotFoundError(CredentialError):
    """No credential resolved for the requested ``(kind, name)``."""


class CredentialMisconfiguredError(CredentialError):
    """A credential source is malformed (broken TOML, env without value, ...)."""


@dataclass(frozen=True, slots=True)
class Credential:
    """In-memory bundle for a single credential.

    ``payload`` carries provider-specific fields (token, access_key_id +
    secret_access_key, app_id + private_key, role_arn + external_id,
    ...). Secret-like keys are masked in repr/str via ``_is_secret_key``
    so the value never lands in logs by accident. ``expires_at`` lets a
    caller proactively refresh short-lived STS / OIDC creds before they
    fail mid-scan; ``refresh_callback`` produces a new Credential when
    invoked.
    """

    kind: str
    payload: Mapping[str, object]
    expires_at: datetime | None = None
    source: str = ""
    refresh_callback: Callable[[], Awaitable[Credential]] | None = None

    def __repr__(self) -> str:
        masked = _mask_payload(self.payload)
        return (
            f"Credential(kind={self.kind!r}, source={self.source!r}, "
            f"payload={masked!r}, expires_at={self.expires_at!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()
