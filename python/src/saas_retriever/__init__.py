"""saas-retriever — API-first SaaS content retriever.

Yields a uniform ``Document`` stream from SaaS providers via their
official APIs (no scraping, no Playwright, no Chrome). Downstream
pipelines (pleno-dlp, pleno-anonymize) consume the same ``Document``
shape they always have.

Public API:

* ``Document``, ``DocumentChunk``, ``DocumentRef``, ``Connector``,
  ``IncrementalConnector``, ``Principal``, ``SourceFilter``,
  ``Capabilities``, ``Cursor``, ``Subsource``, ``SUBSOURCE_METADATA_KEY``
  — the wire contract every connector honours.
* ``Credential``, ``CredentialError``, ``CredentialNotFoundError``,
  ``CredentialMisconfiguredError`` — credential bundle (provider-
  specific payload) connectors take via constructor.
* ``BucketKey``, ``RateLimited``, ``AdaptiveTokenBucket``,
  ``GlobalRateLimiter`` — adaptive AIMD rate limiter primitives.
* ``registry`` — a mapping of connector names to factories. Importing
  this package registers every built-in connector.

Versioning: SemVer on the public API surface above. Per-connector
configuration knobs (rate-limit budgets, retry counts) are not part of
the SemVer surface and may be tuned between minors.
"""

# Importing the connectors package triggers each connector's module-level
# `registry.register` call. Doing it here means `import saas_retriever`
# is enough — programmatic users don't have to remember a second import
# to populate the registry.
from saas_retriever import connectors as _connectors  # noqa: F401
from saas_retriever.core import (
    SUBSOURCE_METADATA_KEY,
    Capabilities,
    Connector,
    Cursor,
    Document,
    DocumentChunk,
    DocumentRef,
    IncrementalConnector,
    Principal,
    SourceFilter,
    Subsource,
)
from saas_retriever.credentials import (
    Credential,
    CredentialError,
    CredentialMisconfiguredError,
    CredentialNotFoundError,
)
from saas_retriever.rate_limit import (
    AdaptiveTokenBucket,
    BucketKey,
    GlobalRateLimiter,
    RateLimited,
)
from saas_retriever.registry import registry

__all__ = [
    "SUBSOURCE_METADATA_KEY",
    "AdaptiveTokenBucket",
    "BucketKey",
    "Capabilities",
    "Connector",
    "Credential",
    "CredentialError",
    "CredentialMisconfiguredError",
    "CredentialNotFoundError",
    "Cursor",
    "Document",
    "DocumentChunk",
    "DocumentRef",
    "GlobalRateLimiter",
    "IncrementalConnector",
    "Principal",
    "RateLimited",
    "SourceFilter",
    "Subsource",
    "registry",
]

__version__ = "1.0.0"
