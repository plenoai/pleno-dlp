"""openaipf-server: FastAPI wrapper around openai/privacy-filter.

This package exists because openai/privacy-filter (opf) ships only a
Python API and a CLI — no HTTP server. The pleno-dlp Go binary's
openaipf supervisor (pkg/piiengine/openaipf) needs a long-running
loopback HTTP endpoint to amortize the multi-second-to-multi-minute
cold start of a 1.5B-parameter MoE classifier across an entire scan.

The wrapper is intentionally minimal: load opf once at startup, gate
/ready on first forward pass, accept POST /api/analyze with {"text":
"..."}, return spans of opf's 8 canonical categories. BIOES → span
aggregation lives in this package (Python side) because opf already
emits BIOES tokens and a Go-side state machine would duplicate work.
ADR-0004 in the pleno-dlp repo is the source of truth for the design.
"""

__version__ = "0.1.0"
