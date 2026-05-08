"""pleno-dlp — unified DLP scanner: secrets + PII over SaaS content.

Public surface:

* ``Document``, ``DocumentChunk``, ``DocumentRef``, ``Connector``,
  ``Detector``, ``IncrementalConnector``, ``Principal``,
  ``SourceFilter``, ``Capabilities``, ``Cursor``, ``Subsource``,
  ``SUBSOURCE_METADATA_KEY`` — the runtime contracts every connector
  honours. ``Connector`` is the source-role contract;
  ``Detector`` is the detector-role contract.
* ``ConnectorSpec``, ``ConnectorRole``, ``AuthMode``, ``ResourceSpec``,
  ``OptionSpec`` — the declarative contract each connector class
  exposes as ``spec``. Drives CLI ``--help`` generation, the docs
  matrix, and registry validation.
* ``Credential``, ``CredentialError``, ``CredentialNotFoundError``,
  ``CredentialMisconfiguredError`` — credential bundle (provider-
  specific payload) connectors take via constructor.
* ``BucketKey``, ``RateLimited``, ``AdaptiveTokenBucket``,
  ``GlobalRateLimiter`` — adaptive AIMD rate limiter primitives.
* ``registry`` — name → factory mapping spanning both source and
  detector connectors. Importing this package populates the registry
  with every built-in connector.
* ``Finding`` — wire-format struct for one detection (secret or PII).
* ``Pipeline`` — wires a source connector to a detector connector and
  a sink.
"""

from pleno_dlp import connectors as _connectors  # noqa: F401  registry side-effect
from pleno_dlp.core import (
    SUBSOURCE_METADATA_KEY,
    AuthMode,
    Capabilities,
    Connector,
    ConnectorRole,
    ConnectorSpec,
    Cursor,
    Detector,
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
    "BucketKey",
    "Capabilities",
    "Connector",
    "ConnectorRole",
    "ConnectorSpec",
    "Credential",
    "CredentialError",
    "CredentialMisconfiguredError",
    "CredentialNotFoundError",
    "Cursor",
    "Detector",
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
__version__ = "0.10.0"
