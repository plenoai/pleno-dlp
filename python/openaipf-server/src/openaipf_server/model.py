"""Lazy opf model loader + analyze entrypoint.

The wrapper holds a single global model instance; opf checkpoints are
multi-GB and reloading per request would defeat the whole purpose of
the loopback HTTP supervisor. Loading happens once during FastAPI's
startup hook so /ready can gate on it (see app.py).

opf's public API surface is still in flux. This module isolates the
adapter so changes upstream land in one file. The contract this
module exposes to app.py is:

    load(device: str | None) -> None      # block until model is usable
    analyze(text: str) -> list[Span]      # bioes.Span records

Failure modes:

    - Import-time: opf is missing or incompatible. load() raises
      RuntimeError with the underlying exception chained; FastAPI's
      startup handler logs and re-raises, which causes uvicorn to
      exit non-zero — the Go supervisor sees /ready never flip and
      ErrEngineExited fires via the child-wait reaper.
    - Runtime: analyze() catches and re-raises as RuntimeError with
      context; app.py turns that into a 500 the Go side surfaces as
      ErrEngineFailed for the chunk (and the supervisor keeps
      serving the next request).
"""

from __future__ import annotations

import threading
from typing import Any

from .bioes import Span, Token, aggregate


# Module-global model singleton + a lock to serialize first-load
# attempts. We never expect concurrent load() calls (FastAPI startup
# is single-threaded), but the lock costs nothing and protects
# against test harnesses or future multi-worker layouts.
_lock = threading.Lock()
_model: Any | None = None
_chosen_device: str = ""


def load(device: str | None) -> None:
    """Load the opf model once. Idempotent — subsequent calls are no-ops.

    device: a hint passed through to opf's own device selector. One of
    "auto" / "cpu" / "cuda" / "mps" / None. The Python side does not
    validate; it forwards whatever the operator chose and lets opf
    raise if the runtime can't satisfy it.
    """
    global _model, _chosen_device
    with _lock:
        if _model is not None:
            return

        try:
            # The import is local because opf is a heavy dependency
            # (torch, transformers, …). Putting it at module scope
            # would slow `python -m openaipf_server --help` and would
            # surface unrelated import errors at the top of the file
            # rather than in load() where we can attach context.
            import opf  # type: ignore[import-not-found]
        except Exception as exc:
            raise RuntimeError(
                "failed to import openai-privacy-filter (opf); install it "
                "via `uv pip install git+https://github.com/openai/privacy-filter.git`"
            ) from exc

        try:
            # opf's exact factory name is in flux upstream. Try the
            # documented entry first, fall through to a few common
            # alternatives. If none work, raise with the full set so
            # the operator sees which surfaces we probed.
            factory = (
                getattr(opf, "load_model", None)
                or getattr(opf, "PrivacyFilter", None)
                or getattr(opf, "Model", None)
            )
            if factory is None:
                raise RuntimeError(
                    "openai-privacy-filter installed but no known entry "
                    "(load_model / PrivacyFilter / Model) is exposed; "
                    "upstream API may have changed"
                )
            kwargs = {}
            if device:
                kwargs["device"] = device
            _model = factory(**kwargs)
        except Exception as exc:
            raise RuntimeError("opf model load failed") from exc

        # Force a tiny forward pass so the first POST /api/analyze
        # doesn't pay JIT-compile latency. /ready only flips after
        # this returns, which is exactly what the Go supervisor's
        # ReadyTimeout budgets for.
        try:
            _ = _predict_tokens(_model, "warmup")
        except Exception as exc:
            _model = None
            raise RuntimeError("opf model warmup forward pass failed") from exc

        _chosen_device = device or ""


def device() -> str:
    """Return the device hint the model was loaded with. Empty if load() never ran."""
    return _chosen_device


def loaded() -> bool:
    """True once load() has completed successfully."""
    return _model is not None


def analyze(text: str) -> list[Span]:
    """Run opf on text and return aggregated entity spans.

    Raises RuntimeError if called before load() or if opf itself raises.
    app.py turns these into 503 (not loaded) / 500 (engine failure).
    """
    if _model is None:
        raise RuntimeError("openaipf: model not loaded")
    try:
        tokens = _predict_tokens(_model, text)
    except Exception as exc:
        raise RuntimeError("opf predict failed") from exc
    return aggregate(tokens)


def _predict_tokens(model: Any, text: str) -> list[Token]:
    """Adapter from opf's prediction output to the BIOES Token type.

    opf may return tokens via several method names depending on upstream
    version: predict / __call__ / tag / annotate. We probe in order
    and normalise whichever shape is returned into a uniform Token list.
    Each token must expose tag/start/end/score/text; opf already emits
    these but field names vary across versions (text vs surface,
    score vs probability). We coerce here so bioes.py sees a stable
    shape.
    """
    pred_fn = (
        getattr(model, "predict", None)
        or getattr(model, "tag", None)
        or getattr(model, "annotate", None)
        or model  # __call__
    )
    raw = pred_fn(text) if callable(pred_fn) else []

    out: list[Token] = []
    for item in raw:
        # Tolerate dict-shaped or object-shaped tokens.
        if isinstance(item, dict):
            get = item.get
        else:
            def get(k: str, default: Any = None, _i: Any = item) -> Any:
                return getattr(_i, k, default)

        tag = get("tag") or get("label") or "O"
        start = int(get("start", 0) or 0)
        end = int(get("end", 0) or 0)
        score = float(get("score", get("probability", 1.0)) or 0.0)
        token_text = str(get("text", get("surface", "")) or "")
        out.append(Token(tag=tag, start=start, end=end, score=score, text=token_text))
    return out
