"""BIOES → span aggregation for openai/privacy-filter token output.

opf emits per-token tags in the BIOES scheme:

    B-<cat>   begin of a multi-token entity
    I-<cat>   inside a multi-token entity
    O         outside (not an entity)
    E-<cat>   end of a multi-token entity
    S-<cat>   single-token entity

This module collapses a token stream into entity spans. The Go side
of the wire never sees raw BIOES tokens; it sees fully resolved
(entity_type, start, end, score, text) records. Keeping the state
machine in Python avoids duplicating it on the Go side where the
information is strictly less rich (no token offsets).

Token records the aggregator consumes are a small dataclass-shaped
dict, not a positional tuple — opf's API shape is in flux and a
named-field intermediate is cheaper to refactor than a tuple position.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Token:
    """One opf token with its BIOES tag and surface span."""

    tag: str          # full BIOES tag, e.g. "B-private_emails" or "O"
    start: int        # byte offset of the token in the original text
    end: int          # byte offset just past the token (Python slice)
    score: float      # opf's per-token confidence in [0, 1]
    text: str         # the surface substring of the token


@dataclass(frozen=True)
class Span:
    """One aggregated entity span ready to ship to the Go side."""

    entity_type: str  # the raw opf category (e.g. "private_emails")
    start: int
    end: int
    score: float      # mean of constituent token scores
    text: str
    bioes_tag: str    # the LAST tag of the span — informative for debugging


def _split_tag(tag: str) -> tuple[str, str]:
    """Return (prefix, category). Prefix is one of B/I/O/E/S; category
    is the part after the hyphen (or "" for O tags).

    Tolerant of malformed tags: anything not matching the expected
    shape is treated as O, because a misclassified single token is
    less damaging than crashing the whole scan on a wrapper-side
    parse error.
    """
    if not tag or tag == "O":
        return "O", ""
    if len(tag) < 3 or tag[1] != "-":
        return "O", ""
    return tag[0], tag[2:]


def aggregate(tokens: Iterable[Token]) -> list[Span]:
    """Collapse a BIOES token sequence into entity spans.

    Rules:
      - O tags break any open span.
      - S-<cat> emits a one-token span immediately.
      - B-<cat> opens a new span; consecutive I-/E-<cat> extend it.
      - A category mismatch (e.g. I-secrets after B-private_emails)
        closes the current span and opens a new one on the new token.
        This is defensive — well-formed opf output never mismatches —
        but a malformed sequence should still produce some result
        rather than silently drop a token.
      - At end of stream, any open span is flushed as-is.

    Score for a span is the arithmetic mean of constituent token
    scores. opf's per-token scores are independent probabilities;
    a mean is the simplest aggregator that preserves "low confidence
    anywhere drags the span down" semantics. If a future tuning pass
    wants a min-of or product-of aggregator, change here — the Go
    side treats Score as opaque.
    """
    out: list[Span] = []

    cur_cat = ""
    cur_start = 0
    cur_end = 0
    cur_text_parts: list[str] = []
    cur_scores: list[float] = []
    cur_last_tag = ""

    def flush() -> None:
        # Emit the current open span (if any) and reset accumulator
        # state. Inner closure so the loop body reads as a flat
        # state machine without explicit "if accumulating" guards
        # at every transition.
        nonlocal cur_cat, cur_start, cur_end, cur_text_parts, cur_scores, cur_last_tag
        if cur_cat:
            mean = sum(cur_scores) / len(cur_scores) if cur_scores else 0.0
            out.append(
                Span(
                    entity_type=cur_cat,
                    start=cur_start,
                    end=cur_end,
                    score=mean,
                    text="".join(cur_text_parts),
                    bioes_tag=cur_last_tag,
                )
            )
        cur_cat = ""
        cur_text_parts = []
        cur_scores = []
        cur_last_tag = ""

    for tok in tokens:
        prefix, cat = _split_tag(tok.tag)

        if prefix == "O":
            flush()
            continue

        if prefix == "S":
            # Single-token entity: flush any open span first so a
            # B/I/E run isn't conflated with a separate single-token
            # neighbour, then emit S as its own one-token span.
            flush()
            out.append(
                Span(
                    entity_type=cat,
                    start=tok.start,
                    end=tok.end,
                    score=tok.score,
                    text=tok.text,
                    bioes_tag=tok.tag,
                )
            )
            continue

        if prefix == "B":
            flush()
            cur_cat = cat
            cur_start = tok.start
            cur_end = tok.end
            cur_text_parts = [tok.text]
            cur_scores = [tok.score]
            cur_last_tag = tok.tag
            continue

        # I or E: extend if category matches; otherwise treat as a
        # new B (defensive against malformed sequences).
        if prefix in ("I", "E"):
            if cat != cur_cat:
                flush()
                cur_cat = cat
                cur_start = tok.start
                cur_text_parts = []
                cur_scores = []
            cur_end = tok.end
            cur_text_parts.append(tok.text)
            cur_scores.append(tok.score)
            cur_last_tag = tok.tag
            if prefix == "E":
                # E explicitly closes a span; flush so the next
                # B/S starts cleanly without an extension.
                flush()
            continue

        # Unknown prefix: be lenient — drop the token, keep going.
        # Crashing here would take down a whole scan on one bad
        # token; the Go side already tolerates empty results.

    flush()
    return out
