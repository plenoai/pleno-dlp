"""pleno-dlp — unified DLP scanner: secrets + PII over SaaS content.

Public surface:

* ``Document``, ``DocumentChunk``, ``DocumentRef``, ``Connector``,
  ``IncrementalConnector``, ``Detector``, ``Verifier``, ``Revoker``,
  ``Principal``, ``SourceFilter``, ``Capabilities``, ``Cursor``,
  ``Subsource``, ``SUBSOURCE_METADATA_KEY`` — runtime contracts.
  ``Connector`` is the SaaS-source contract; ``Detector`` is the
  text-to-Findings contract honoured by both connectors (per-SaaS
  detection) and engines (low-level scanners); ``Verifier`` /
  ``Revoker`` are optional secret-lifecycle extras a connector may
  implement.
* ``ConnectorSpec``, ``Capability``, ``AuthMode``, ``ResourceSpec``,
  ``OptionSpec``, ``VerifyResult``, ``VerifyStatus``, ``RevokeResult``,
  ``RevokeStatus`` — the declarative contract each connector class
  exposes as ``spec`` and the result types for the lifecycle
  protocols. Drives CLI ``--help`` generation, the docs matrix, and
  registry validation.
* ``Credential``, ``CredentialError``, ``CredentialNotFoundError``,
  ``CredentialMisconfiguredError`` — credential bundle (provider-
  specific payload) connectors take via constructor.
* ``BucketKey``, ``RateLimited``, ``AdaptiveTokenBucket``,
  ``GlobalRateLimiter`` — adaptive AIMD rate limiter primitives.
* ``registry`` — name → factory mapping for SaaS source connectors.
  Importing this package populates the registry with every built-in
  connector. Detection engines (regex / trufflehog / gitleaks / pii)
  do *not* live here — instantiate them directly from
  ``pleno_dlp.engines``.
* ``Finding`` — wire-format struct for one detection (secret or PII).
* ``Pipeline`` — wires a source connector to an engine and a sink.
"""

from pleno_dlp import connectors as _connectors  # noqa: F401  registry side-effect
from pleno_dlp.core import (
    SUBSOURCE_METADATA_KEY,
    AuthMode,
    Capabilities,
    Capability,
    Connector,
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
    Revoker,
    RevokeResult,
    RevokeStatus,
    SourceFilter,
    Subsource,
    Verifier,
    VerifyResult,
    VerifyStatus,
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
    "Capability",
    "Connector",
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
    "RevokeResult",
    "RevokeStatus",
    "Revoker",
    "SourceFilter",
    "Subsource",
    "Verifier",
    "VerifyResult",
    "VerifyStatus",
    "registry",
]
__version__ = "0.12.0"
