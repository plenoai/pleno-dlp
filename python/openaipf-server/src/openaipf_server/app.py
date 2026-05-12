"""FastAPI app exposing /health, /ready, and POST /api/analyze.

Endpoint contract (matched by the Go supervisor at
pkg/piiengine/openaipf/client.go and health.go):

  GET  /health        always 200 once the process is listening.
                      Liveness only — does NOT imply the model is loaded.
  GET  /ready         200 only after the opf model has loaded AND a
                      warmup forward pass has completed. The Go side
                      polls this; DefaultReadyTimeout=300s on the
                      supervisor budgets for cold HF weight download.
  POST /api/analyze   body {"text": str, "language"?: str, "entities"?: [str]}
                      returns [{"entity_type": str, "bioes_tag": str,
                                "start": int, "end": int, "score": float,
                                "text": str}, ...]

The wrapper is intentionally stateless beyond the global model
singleton. No history, no telemetry, no auth: it is bound to a
loopback port by an upstream argv check and that is the entire
trust boundary. Anything fancier belongs in the Go side, where it
can be reasoned about under one set of pleno-dlp release cadence
rules rather than two.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import model

log = logging.getLogger("openaipf-server")


class AnalyzeRequest(BaseModel):
    """Wire shape of POST /api/analyze.

    language and entities are accepted for forward compatibility with
    the Go-side analyzeRequest struct (pkg/piiengine/openaipf/types.go).
    The current wrapper ignores them — opf does its own language
    inference, and we always run the full classifier — but accepting
    the fields lets callers populate them today without breaking the
    wire when wrapper-side honoring lands.
    """

    text: str = Field(..., description="text to scan")
    language: str | None = Field(default=None, description="ISO language hint; currently ignored")
    entities: list[str] | None = Field(default=None, description="filter list; currently ignored")


class AnalyzeFinding(BaseModel):
    """Response item — kept aligned with openaipf.Finding on the Go side."""

    entity_type: str
    bioes_tag: str = ""
    start: int
    end: int
    score: float
    text: str


def create_app(device: str | None = None) -> FastAPI:
    """Build the FastAPI app and register a startup hook that loads opf.

    Factored out (instead of a module-global `app = FastAPI()`) so
    __main__.py can pass the operator-chosen device through, and so
    tests can construct an app with a stubbed model without invoking
    uvicorn or opf at all.
    """
    app = FastAPI(title="openaipf-server", version="0.1.0")

    @app.on_event("startup")
    async def _startup() -> None:
        # Block startup on model load. If this raises, uvicorn exits
        # non-zero and the Go supervisor's reaper closes the child
        # exit channel, surfacing ErrEngineExited within one poll
        # tick rather than after the full 300s ReadyTimeout.
        try:
            model.load(device)
            log.info("openaipf-server: model loaded (device=%s)", model.device() or "default")
        except Exception:
            log.exception("openaipf-server: model load failed")
            raise

    @app.get("/health")
    async def health() -> dict[str, str]:
        # Liveness probe. We never gate this on model state — uvicorn
        # being able to answer at all is the signal. The Go supervisor
        # only polls /ready, but /health is here for direct curl
        # debugging and parity with anonymize's wrapper.
        return {"status": "ok"}

    @app.get("/ready")
    async def ready() -> dict[str, str]:
        if not model.loaded():
            # 503 lets the supervisor's pollReady retry rather than
            # treat the engine as failed. The supervisor's tick is
            # 250ms; a steady stream of 503 during checkpoint download
            # is exactly the expected cold path.
            raise HTTPException(status_code=503, detail="model not loaded")
        return {"status": "ready", "device": model.device() or "default"}

    @app.post("/api/analyze", response_model=list[AnalyzeFinding])
    async def analyze(req: AnalyzeRequest) -> list[AnalyzeFinding]:
        if not model.loaded():
            # Belt-and-braces: with /ready as the gate, this branch
            # should be unreachable in normal flow. It exists so an
            # operator hitting /api/analyze directly during cold
            # start gets a meaningful 503 rather than a stack trace.
            raise HTTPException(status_code=503, detail="model not loaded")
        try:
            spans = model.analyze(req.text)
        except RuntimeError as exc:
            log.exception("openaipf-server: analyze failed")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return [
            AnalyzeFinding(
                entity_type=s.entity_type,
                bioes_tag=s.bioes_tag,
                start=s.start,
                end=s.end,
                score=s.score,
                text=s.text,
            )
            for s in spans
        ]

    return app


def main() -> None:
    """Entrypoint for the `openaipf-server` console_script.

    Defers to __main__.main so the argparse + uvicorn launch lives in
    one place. Console_script users get the same flags and validation
    as `python -m openaipf_server` users.
    """
    from .__main__ import main as _main

    _main()
