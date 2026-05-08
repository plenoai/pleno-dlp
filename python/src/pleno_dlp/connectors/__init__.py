"""Built-in connectors — both source and detector roles register here.

Importing this package triggers each connector's ``registry.register``
call so ``pleno_dlp.registry.names()`` is non-empty after a single
``import pleno_dlp``. Sources walk SaaS providers and yield Documents;
detectors consume Documents and yield Findings. The role lives in each
connector's ``ConnectorSpec``.
"""

# Both source and detector connectors are imported in alphabetical order.
# The split is documented in each module's docstring; the `role` field
# of every spec authoritatively classifies them at runtime.
from pleno_dlp.connectors import bitbucket as _bitbucket  # noqa: F401
from pleno_dlp.connectors import confluence as _confluence  # noqa: F401
from pleno_dlp.connectors import github as _github  # noqa: F401
from pleno_dlp.connectors import gitlab as _gitlab  # noqa: F401
from pleno_dlp.connectors import gitleaks as _gitleaks  # noqa: F401
from pleno_dlp.connectors import jira as _jira  # noqa: F401
from pleno_dlp.connectors import native as _native  # noqa: F401
from pleno_dlp.connectors import notion as _notion  # noqa: F401
from pleno_dlp.connectors import pii as _pii  # noqa: F401
from pleno_dlp.connectors import slack as _slack  # noqa: F401
from pleno_dlp.connectors import trufflehog as _trufflehog  # noqa: F401

__all__: list[str] = []
