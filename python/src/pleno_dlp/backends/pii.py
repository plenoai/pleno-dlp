"""PII detection backend — delegates to pleno-anonymize's HTTP API.

Strategy: every Document.text is POSTed to ``{base_url}/api/analyze``.
The response is a list of Presidio ``RecognizerResult`` shaped dicts:

    [{"entity_type": "EMAIL_ADDRESS", "start": 38, "end": 54,
      "score": 1.0, "text": "..."}, ...]

Each entry maps 1:1 to a ``Finding`` with ``finding_class="pii"``.

The ``raw`` substring is sliced from the document text (the API echoes
it under ``text`` but slicing is cheaper and keeps the byte boundary
authoritative on our side). Line numbers are derived from the offset
so a sink can render ``path:line`` consistent with secret findings.

We deliberately avoid bundling pleno-anonymize as a hard dependency.
The user runs the anonymize server locally (``docker compose up`` from
``pleno-anonymize/`` or ``uv run uvicorn server.app``) and points
``--pii-base-url`` at it, or installs the optional ``pleno-dlp[pii]``
extra which pulls the in-process library version.

Concurrency: one ``httpx.AsyncClient`` per backend instance. The
pipeline calls ``scan()`` serially per document but issues one HTTP
request per call — the underlying HTTP/2 multiplexing absorbs that
fine. The client is closed in ``aclose()``; the pipeline calls it once
at end-of-scan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
from saas_retriever import Document

from pleno_dlp.findings import Finding

_DEFAULT_BASE_URL = "http://127.0.0.1:8000"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_LANGUAGE = "ja"


class PiiBackend:
    """Backend that delegates PII detection to pleno-anonymize.

    The API is documented at
    https://github.com/plenoai/pleno-anonymize/blob/main/server/src/app.py
    — ``POST /api/analyze`` accepts ``{text, language, entities?}`` and
    returns Presidio's ``RecognizerResult`` rows.
    """

    name = "pii"

    def __init__(
        self,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        language: str = _DEFAULT_LANGUAGE,
        entities: tuple[str, ...] | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if language not in {"ja", "en"}:
            raise ValueError(
                f"language must be 'ja' or 'en'; got {language!r}"
            )
        self._base_url = base_url.rstrip("/")
        self._language = language
        # ``entities`` lets a caller scope the analyzer to a subset
        # (e.g. ``("EMAIL_ADDRESS", "JP_MY_NUMBER")``); ``None`` means
        # detect every recognizer the anonymize server registered.
        self._entities = list(entities) if entities is not None else None
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = client
        # ``_owned_client`` controls whether ``aclose()`` actually closes
        # the underlying HTTP pool — tests inject their own client and
        # want ownership semantics preserved.
        self._owned_client = client is None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url, timeout=self._timeout
            )
        return self._client

    async def scan(self, doc: Document) -> AsyncIterator[Finding]:
        """POST ``doc.text`` and yield one Finding per detected entity."""
        # The anonymize API rejects empty bodies with 422; short-circuit
        # so we don't waste a roundtrip on whitespace-only documents.
        text = doc.text
        if not text or not text.strip():
            return
        client = await self._ensure_client()
        body: dict[str, Any] = {"text": text, "language": self._language}
        if self._entities is not None:
            body["entities"] = self._entities
        response = await client.post("/api/analyze", json=body)
        # 422 means the document violated the API's max-length cap
        # (100k chars). We surface it to the operator as a swallowed
        # entry rather than crashing the scan; truncation belongs to
        # the upstream Pipeline if/when we add it.
        if response.status_code == 422:
            return
        response.raise_for_status()
        results = response.json()
        if not isinstance(results, list):
            return
        ref = doc.ref
        for result in results:
            if not isinstance(result, dict):
                continue
            try:
                start = int(result["start"])
                end = int(result["end"])
                entity_type = str(result["entity_type"])
                score = float(result["score"])
            except (KeyError, TypeError, ValueError):
                # Forward-compat: an upstream API revision may add
                # fields. Skip malformed rows rather than aborting.
                continue
            raw = text[start:end]
            line = text.count("\n", 0, start) + 1
            yield Finding.make(
                rule_id=entity_type,
                backend=self.name,
                raw=raw,
                source_id=ref.source_id,
                source_kind=ref.source_kind,
                path=ref.path,
                native_url=ref.native_url,
                line=line,
                finding_class="pii",
                score=score,
                extra={"language": self._language, "offset_start": str(start)},
            )

    async def aclose(self) -> None:
        """Release the HTTP client pool (if we own it)."""
        if self._owned_client and self._client is not None:
            await self._client.aclose()
            self._client = None
