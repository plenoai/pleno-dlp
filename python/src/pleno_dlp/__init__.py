"""pleno-dlp — unified DLP scanner: secrets + PII over SaaS content.

Public surface:

* ``Finding`` — wire-format struct for one detection (secret or PII).
* ``Backend`` — protocol every detection backend honours.
* ``Pipeline`` — wires a saas-retriever connector to a backend and a sink.
* ``backends`` namespace — built-in trufflehog / gitleaks / native (secret
  detection); ``pii`` backend (delegates to pleno-anonymize for PII model
  inference) is enabled when the ``pii`` extra is installed.
"""

from pleno_dlp.backends import Backend
from pleno_dlp.findings import Finding
from pleno_dlp.pipeline import Pipeline

__all__ = ["Backend", "Finding", "Pipeline"]
__version__ = "0.5.0"
