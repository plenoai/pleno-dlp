"""pleno-dlp — unified DLP scanner: secrets + PII over SaaS content.

Public surface:

* ``Document``, ``DocumentChunk``, ``DocumentRef``, ``Connector``,
  ``IncrementalConnector``, ``Principal``, ``SourceFilter``,
  ``Capabilities``, ``Cursor``, ``Subsource``, ``SUBSOURCE_METADATA_KEY``
  — the runtime contract every connector honours.
* ``ConnectorSpec``, ``AuthMode``, ``ResourceSpec``, ``OptionSpec`` —
  the declarative contract each connector class exposes as ``spec``.
  Drives CLI ``--help`` generation, the docs matrix, and registry
  validation.
* ``Credential``, ``CredentialError``, ``CredentialNotFoundError``,
  ``CredentialMisconfiguredError`` — credential bundle (provider-
  specific payload) connectors take via constructor.
* ``BucketKey``, ``RateLimited``, ``AdaptiveTokenBucket``,
  ``GlobalRateLimiter`` — adaptive AIMD rate limiter primitives.
* ``registry`` — name → factory mapping. Importing this package
  populates the registry with every built-in connector.
* ``Finding`` — wire-format struct for one detection (secret or PII).
* ``Backend`` — protocol every detection backend honours.
* ``Pipeline`` — wires a connector to a backend and a sink.
* ``backends`` namespace — built-in trufflehog / gitleaks / native
  (secret detection); ``pii`` backend (delegates to pleno-anonymize)
  is enabled when the ``pii`` extra is installed.
"""

from pleno_dlp import connectors as _connectors  # noqa: F401  registry side-effect
from pleno_dlp.backends import Backend
from pleno_dlp.core import (
    SUBSOURCE_METADATA_KEY,
    AuthMode,
    Capabilities,
    Connector,
    ConnectorSpec,
    Cursor,
    Document,
    DocumentChunk,
    DocumentRef,
    IncrementalConnector,
    OptionSpec,
    Principal,
    ResourceSpec,
    SourceFilter,
    Subsource,
)
from pleno_dlp.credentials import (
    Credential,
    CredentialError,
    CredentialMisconfiguredError,
    CredentialNotFoundError,
)
from pleno_dlp.findings import Finding
from pleno_dlp.pipeline import Pipeline
from pleno_dlp.rate_limit import (
    AdaptiveTokenBucket,
    BucketKey,
    GlobalRateLimiter,
    RateLimited,
)
from pleno_dlp.registry import registry

__all__ = [
    "SUBSOURCE_METADATA_KEY",
    "AdaptiveTokenBucket",
    "AuthMode",
    "Backend",
    "BucketKey",
    "Capabilities",
    "Connector",
    "ConnectorSpec",
    "Credential",
    "CredentialError",
    "CredentialMisconfiguredError",
    "CredentialNotFoundError",
    "Cursor",
    "Document",
    "DocumentChunk",
    "DocumentRef",
    "Finding",
    "GlobalRateLimiter",
    "IncrementalConnector",
    "OptionSpec",
    "Pipeline",
    "Principal",
    "RateLimited",
    "ResourceSpec",
    "SourceFilter",
    "Subsource",
    "registry",
]
__version__ = "0.9.0"
