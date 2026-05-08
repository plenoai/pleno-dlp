"""Document / Connector protocol — wire contract for every connector.

Aligned with pleno-anonymize's ``pleno_pii_scanner.sources.base`` so a
single Document type can flow into either pipeline without translation.

Public protocol surface:

* ``Cursor`` — opaque per-connector resume token (str).
* ``Capabilities`` — runtime self-description (incremental, binary,
  streaming, max_concurrent_fetches, content_hash_delta).
* ``Document`` / ``DocumentChunk`` — payload (single-shot vs streamed).
* ``DocumentRef`` — cheap metadata-only handle.
* ``SourceFilter`` — discover-time include / exclude / since filter.
* ``Subsource`` + ``SUBSOURCE_METADATA_KEY`` — sub-unit fingerprinting
  for hierarchical sources (org → repos, workspace → channels, ...).
* ``Connector`` Protocol — the contract every connector implements.
* ``ConnectorSpec`` (+ ``AuthMode``, ``ResourceSpec``, ``OptionSpec``)
  — declarative metadata each connector class exposes as the
  ``spec`` ClassVar. Drives CLI ``--help`` generation, the docs
  matrix, and registry validation. Capabilities answers the
  *runtime* question ("can I incrementally resume?"); ConnectorSpec
  answers the *configuration* question ("what kwargs do you take?").
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import ClassVar, Protocol, runtime_checkable

# Reserved DocumentRef.metadata key. Connectors that aggregate sub-units
# (github org → repos, slack workspace → channels, gdrive → drives,
# postgres → tables) must populate this on every yielded ref so the
# scheduler / runner can attribute per-document findings back to the
# sub-source they belong to. Connectors with a flat namespace (single
# repo, one filesystem root) leave it absent.
SUBSOURCE_METADATA_KEY = "_subsource_id"


# Opaque per-connector resume token. Persisted verbatim by callers and
# round-tripped through ``discover(..., cursor=...)``. Never parsed
# outside the owning connector — keeps the runner agnostic of GitHub
# ``pushed:>ts`` vs Slack ts strings vs Notion ``next_cursor`` vs
# SharePoint delta tokens.
Cursor = str


@dataclass(frozen=True, slots=True)
class Principal:
    """Identity that produced or owns a document.

    Populated when the source exposes authorship (git author, Slack user,
    SharePoint owner, Jira reporter).
    """

    id: str
    display_name: str | None = None
    email: str | None = None


@dataclass(frozen=True, slots=True)
class Capabilities:
    """Connector self-description consumed by orchestrators.

    ``incremental`` lets the runner skip a full re-walk when a checkpoint
    exists. ``binary`` declares whether ``fetch()`` yields binary payloads
    that downstream extractors need to handle. ``content_hash_delta``
    means the connector can short-circuit on unchanged ETag/digest before
    re-fetching the body. ``max_concurrent_fetches`` bounds the
    per-connector asyncio Semaphore. ``streaming`` declares whether
    ``fetch()`` may yield ``DocumentChunk`` instead of ``Document``.
    """

    incremental: bool = False
    binary: bool = False
    content_hash_delta: bool = False
    max_concurrent_fetches: int = 8
    streaming: bool = False


@dataclass(frozen=True, slots=True)
class SourceFilter:
    """Discover-time include / exclude / since filter.

    Connectors apply server-side when the provider supports it (Slack
    ``oldest=``, Jira ``updated >= since``); otherwise they apply
    client-side so behaviour is uniform.
    """

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    since: datetime | None = None
    max_size: int | None = None


@dataclass(frozen=True, slots=True)
class DocumentRef:
    """Cheap metadata-only handle.

    Holds enough information to render a partial finding location even
    before the body is available, and to attribute work to a tenant for
    rate-limiting. Compatible with pleno-anonymize's DocumentRef shape.
    """

    source_id: str
    source_kind: str
    path: str
    native_url: str | None = None
    parent_chain: tuple[str, ...] = ()
    content_type: str = "application/octet-stream"
    size: int | None = None
    etag: str | None = None
    last_modified: datetime | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable 32-char hex hash for downstream dedup keys."""
        h = sha256()
        h.update(self.source_id.encode())
        h.update(b"\0")
        h.update(self.source_kind.encode())
        h.update(b"\0")
        h.update(self.path.encode())
        if self.etag:
            h.update(b"\0")
            h.update(self.etag.encode())
        return h.hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Document:
    """Full payload returned by a connector for a single document.

    Exactly one of ``text`` / ``binary`` is populated — enforced in
    ``__post_init__``. For streaming payloads (TB-scale S3 objects, large
    SharePoint files), connectors yield ``DocumentChunk`` instead.
    """

    ref: DocumentRef
    text: str | None = None
    binary: bytes | None = None
    fetched_at: datetime | None = None
    content_hash: str | None = None
    created_by: Principal | None = None
    extra: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (self.text is None) == (self.binary is None):
            raise ValueError(
                "Document must populate exactly one of `text` or `binary`; "
                f"got text={self.text is not None}, binary={self.binary is not None}"
            )


@dataclass(frozen=True, slots=True)
class DocumentChunk:
    """Streamed slice of a document payload.

    Yielded in order by ``fetch()`` for documents that exceed the
    in-memory size budget. The pipeline carries a small overlap window
    between consecutive chunks (max-pattern-length + 256B) so that a
    regex match spanning a chunk boundary is not lost.
    """

    ref: DocumentRef
    byte_range: tuple[int, int]
    is_final: bool
    text: str | None = None
    binary: bytes | None = None
    fetched_at: datetime | None = None

    def __post_init__(self) -> None:
        if (self.text is None) == (self.binary is None):
            raise ValueError("DocumentChunk must populate exactly one of `text` or `binary`")
        start, end = self.byte_range
        if start < 0 or end < start:
            raise ValueError(f"DocumentChunk.byte_range must be (start>=0, end>=start); got {self.byte_range}")


@dataclass(frozen=True, slots=True)
class Subsource:
    """An addressable sub-unit of a connector, with a content fingerprint.

    A connector that aggregates many sub-units yields one ``Subsource``
    per unit so an incremental runner can consult its cache and skip
    sub-units whose ``fingerprint`` matches a prior successful scan. The
    fingerprint is opaque to everything outside the connector that
    produced it — commit SHA for github/git, delta token for SharePoint,
    snapshot id for BigQuery, ``updated_at`` cursor for Jira, etc.
    """

    sub_id: str
    fingerprint: str


@runtime_checkable
class IncrementalConnector(Protocol):
    """Optional extension to ``Connector`` for hierarchical sources.

    Implementations populate ``DocumentRef.metadata[SUBSOURCE_METADATA_KEY]``
    on every ref they yield so the runner can attribute per-document
    findings back to a sub-unit.
    """

    async def list_subsources(self) -> Sequence[Subsource]:
        """Cheaply enumerate every sub-unit with its content fingerprint."""
        ...

    def set_subsource_skip(self, skip: frozenset[str]) -> None:
        """Tell the connector to omit these sub_ids from ``discover()``."""
        ...


class AuthMode(StrEnum):
    """How a connector authenticates against the provider.

    Declarative: drives CLI ``--help`` text and docs. The connector
    constructor still accepts whatever kwargs match the spec's
    ``options``; this enum just classifies them so operators know
    which token shape to provide.
    """

    NONE = "none"  # public APIs, anonymous read
    PAT = "pat"  # personal access token / API token
    BOT_TOKEN = "bot_token"  # bot user token (slack xoxb-, github bot, ...)
    USER_TOKEN = "user_token"  # user token (slack xoxp-, gitlab oauth)
    APP_PASSWORD = "app_password"  # bitbucket / atlassian app password
    OAUTH = "oauth"  # full OAuth flow (refresh tokens)
    BASIC = "basic"  # email + api_token paired (jira/confluence cloud)
    GH_APP = "gh_app"  # github app installation token
    KEY_PAIR = "key_pair"  # provider-issued id+secret pair


@dataclass(frozen=True, slots=True)
class OptionSpec:
    """Connector configuration knob exposed to the CLI / programmatic users.

    Every kwarg the connector's ``__init__`` accepts and that operators
    are expected to pass is declared here. Anything not declared is
    rejected by the registry to keep typos from silently no-op'ing.
    """

    name: str  # kwarg name on the connector __init__
    type: str  # "str" | "int" | "bool" | "list[str]" | "url" | "path"
    help: str  # one-line operator-facing description
    default: object | None = None
    required: bool = False
    secret: bool = False  # true → masked in echo/list-connectors output
    choices: tuple[str, ...] = ()
    cli_flag: str | None = None  # promoted long flag; None → only via --option


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """A scannable resource the connector can enumerate.

    Examples: github → (code, issues, prs); slack → (messages, files);
    notion → (pages, databases); jira → (issues, comments).
    Operators select via ``--option resources=code,issues`` (or the
    spec-driven ``--resource`` shorthand if exposed in the cli).
    """

    name: str  # logical resource name, e.g. "code"
    summary: str  # one-line description
    default: bool = True  # included when --option resources is unset


@dataclass(frozen=True, slots=True)
class ConnectorSpec:
    """Declarative metadata every connector class exposes as ``spec``.

    Capabilities answers the *runtime* question ("can I incrementally
    resume?"). ConnectorSpec answers the *configuration* question
    ("what kwargs do you take, and how do operators authenticate?").

    The registry validates that each registered connector has a
    matching ``spec.name``, and the CLI uses ``options`` to render
    ``--help`` and to whitelist kwargs forwarded to the constructor.
    """

    name: str  # registry key (matches the kwarg used at create() time)
    kind: str  # provider kind (e.g. "github", "slack")
    summary: str  # one-line summary for list-connectors
    auth_modes: tuple[AuthMode, ...] = (AuthMode.PAT,)
    resources: tuple[ResourceSpec, ...] = ()
    options: tuple[OptionSpec, ...] = ()
    capabilities: Capabilities = field(default_factory=Capabilities)
    docs_url: str | None = None

    def option(self, name: str) -> OptionSpec | None:
        for opt in self.options:
            if opt.name == name:
                return opt
        return None

    def accepted_kwargs(self) -> frozenset[str]:
        """Whitelist of kwargs the CLI / registry will forward."""
        return frozenset(opt.name for opt in self.options)


@runtime_checkable
class Connector(Protocol):
    """Contract every connector implements.

    Construction is the connector's responsibility — the registry forwards
    provider-specific kwargs (token, owner, base_url, ...) declared in
    ``spec.options``. Connectors own their own HTTP client; there is no
    shared session.

    Connectors must be safe to call concurrently up to
    ``capabilities().max_concurrent_fetches``. State that needs locking
    (HTTP session pools, paginator cursors) lives inside the connector
    instance.
    """

    spec: ClassVar[ConnectorSpec]
    id: str
    kind: str

    def discover(
        self,
        filter: SourceFilter,
        cursor: Cursor | None = None,
    ) -> AsyncIterator[DocumentRef]:
        """Enumerate document refs matching ``filter``, resuming at ``cursor``.

        Cheap-as-possible. Connectors paginate the provider's API, parse
        the listing, and yield refs. No payload download. Implementations
        may emit a fresh ``Cursor`` periodically by attaching it to a
        ``DocumentRef.metadata['_cursor']`` entry.
        """
        ...

    def fetch(self, ref: DocumentRef) -> AsyncIterator[Document | DocumentChunk]:
        """Retrieve the payload for one ref.

        Yields once for in-memory documents. Streaming connectors yield a
        sequence of ``DocumentChunk`` in byte order, last with
        ``is_final=True``.
        """
        ...

    def capabilities(self) -> Capabilities:
        """Return static connector capabilities."""
        ...

    def discover_and_fetch(self, filter: SourceFilter | None = None) -> AsyncIterator[Document]:
        """Convenience compound that yields full Documents end-to-end."""
        ...

    async def close(self) -> None:
        """Release per-connector resources (HTTP clients, sockets)."""
        ...
