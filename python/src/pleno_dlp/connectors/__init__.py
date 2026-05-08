"""Built-in connectors.

Importing this package triggers each connector's ``registry.register``
call so ``pleno_dlp.registry.names()`` is non-empty after a single
``import pleno_dlp``.
"""

from pleno_dlp.connectors import bitbucket as _bitbucket  # noqa: F401
from pleno_dlp.connectors import confluence as _confluence  # noqa: F401
from pleno_dlp.connectors import github as _github  # noqa: F401
from pleno_dlp.connectors import gitlab as _gitlab  # noqa: F401
from pleno_dlp.connectors import jira as _jira  # noqa: F401
from pleno_dlp.connectors import notion as _notion  # noqa: F401
from pleno_dlp.connectors import slack as _slack  # noqa: F401

__all__: list[str] = []
