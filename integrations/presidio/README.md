# pleno-dlp × Presidio

Use **pleno-dlp as a recognizer inside the Presidio SDK** — the reverse
of pleno-dlp spawning a PII engine. pleno-dlp's 600+ secret detectors
become Presidio entities, and Presidio's false-positive machinery
(context boost, score threshold, allow list) applies to them.

## Install

```sh
uv pip install .            # from this directory (requires presidio-analyzer)
```

`pleno-dlp` must be on PATH (or pass `binary="/path/to/pleno-dlp"`).

## Usage

```python
from pleno_dlp_presidio import build_analyzer

analyzer = build_analyzer()  # pleno-dlp + Presidio's predefined PII recognizers

results = analyzer.analyze(
    text="contact me at john@example.com, AWS key AKIAIOSFODNN7EXAMPLE",
    language="en",
    score_threshold=0.4,          # FP reduction: drop low-confidence spans
    allow_list=["john@example.com"],  # FP reduction: known-safe literals
)
```

Each pleno-dlp finding becomes a `RecognizerResult` with:

- `entity_type` — mapped from the detector name (`AWS` →
  `AWS_ACCESS_KEY`, `OpenAI` → `OPENAI_API_KEY`, unmapped →
  `GENERIC_SECRET`); extend the mapping with
  `PlenoDLPRecognizer(entity_map={...})`.
- `start`/`end` — character offsets in the input text (pleno-dlp emits
  UTF-8 byte offsets; the recognizer converts). The secret text itself
  is never transported — slice it from your own copy of the text.
- `score` — derived from pleno-dlp's verification verdict:
  `verified` → 1.0, `indeterminate` → 0.5, `unverified` → 0.3.

### False-positive reduction

The recognizer declares context words (`token`, `key`, `password`, …),
so Presidio's default `LemmaContextAwareEnhancer` **boosts** findings
that appear near them and leaves lone matches at their base score —
pair with `score_threshold` so only context-supported or verified
findings survive. `allow_list` (and `--only-verified` via
`extra_args`) are the validator-style controls.

### Verification

By default the recognizer passes verification through (network
round-trips per credential — accurate `score`s, slower). For batch /
offline pipelines:

```python
build_analyzer(verify=False)  # appends --no-verify; scores become 0.3 (unverified)
```

## Notes

- One `pleno-dlp scan stdin` subprocess per `analyze()` call; text is
  piped, nothing is written to disk.
- pleno-dlp exits `0` even when findings exist (stdin scans never gate
  on findings); stdout is pure JSON and the scan summary goes to stderr.
- Requires pleno-dlp ≥ the version that emits `start`/`end` in JSON
  output; older binaries silently yield no results.

## Tests

```sh
python -m unittest discover -s tests   # stdlib only, fake binary
```
