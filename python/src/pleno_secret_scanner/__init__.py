"""pleno-secret-scanner — scan SaaS content for leaked secrets.

Public surface:

* ``Finding`` — wire-format struct for one secret hit.
* ``Backend`` — protocol every detection backend honours.
* ``Pipeline`` — wires a saas-scraper connector to a backend and a sink.
* ``backends`` namespace — built-in trufflehog / gitleaks / native.
"""

from pleno_secret_scanner.backends import Backend
from pleno_secret_scanner.findings import Finding
from pleno_secret_scanner.pipeline import Pipeline

__all__ = ["Backend", "Finding", "Pipeline"]
__version__ = "0.2.0"
