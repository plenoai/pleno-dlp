"""Built-in connectors.

Importing this package triggers each connector's ``registry.register``
call so ``saas_retriever.registry.names()`` is non-empty after a single
``import saas_retriever``.
"""

from saas_retriever.connectors import bitbucket as _bitbucket  # noqa: F401
from saas_retriever.connectors import confluence as _confluence  # noqa: F401
from saas_retriever.connectors import github as _github  # noqa: F401
from saas_retriever.connectors import gitlab as _gitlab  # noqa: F401
from saas_retriever.connectors import jira as _jira  # noqa: F401
from saas_retriever.connectors import notion as _notion  # noqa: F401
from saas_retriever.connectors import slack as _slack  # noqa: F401

__all__: list[str] = []
