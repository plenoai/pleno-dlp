# OSS comparison, 2026-09-21

[日本語レポート](../../docs/oss-comparison-2026-09-21.md)

This study compares a binary built from pleno-dlp v0.65.0
(`3c525ce46a98f4eaa88cf27ba53491f25612bf41`) with the official TruffleHog
v3.97.5 Darwin arm64 release. It does not measure subsequent scanner changes.
`manifest.json` pins 50 purposefully selected, well-known projects spanning
systems, infrastructure, web frameworks and scientific computing. This is not
a random sample of GitHub. Downloads use source archives without Git history.

`study.py prepare` retains regular UTF-8 files of at most 1 MiB without NUL
bytes. It records the archive hash, retained inventory hash and exclusions.
GitHub source archives also honor upstream `export-ignore`; submodules and
Git LFS objects are not fetched. Neither upstream code nor build scripts run.
`study.py scan` applies the same input to both scanners, disables verification,
disables pleno-dlp's default path exclusions and rotates execution order.
One warmup and three timed samples per tool/repository include process startup,
filesystem reading, detection and JSON output to disk. Output parsing, corpus
download and compilation are outside the timer. RSS is the scanner process's
peak reported by `/usr/bin/time`; CPU time is user plus system time.

The initial exploratory pass overlapped other development benchmarks and was
discarded. The published pass polls the process list every 0.5 seconds, waits
for other scanner processes and Go builds/tests, and discards a trial if one
appears during it. The guard does not isolate the OS, browser, thermal state or
workloads it does not recognize; this remains a development-machine experiment.
Retry counts are stored with each sample. Polling runs in the harness, outside
the scanner's process RSS and CPU counters, but shares the machine with it.

Each repository gets a deterministic, synthetic GitHub token in a temporary
control file. Every scan must find it exactly once; reported finding counts
exclude it. The original corpus inventory excludes these 50 files (54 bytes
each); the performance workload includes them. Both tools use eight workers
and `GOMAXPROCS=8`. Their default detector catalogs and filtering differ, so
this is an end-to-end product comparison, not a controlled engine microbenchmark.
The scanner invocations are captured in `results.json`.

CredData evaluation uses the 100 lowest SHA256 hashes of snapshot keys at
`c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Selection precedes scanner execution
and does not inspect labels. All selected metadata files must be acquired;
missing files fail preparation. Git fetch supplies files omitted by
`export-ignore` and the WebKit tree for which GitHub's archive endpoint returns
HTTP 422. Upstream's obfuscator runs with noise seed 0 and `pybase62==1.0.0`.
Its compatibility branch needs Python 3.12 at this revision.

Accuracy is classification of unique `(file, LineStart)` pairs. T is positive,
F/X negative; lines containing both labels are excluded. Multiple predictions
on one line count once. Unlabelled predicted lines are reported separately,
never silently declared false positives. Consequently the precision is
**conditional on labelled lines**, not the precision of all scanner output.
This metric does not measure exact value extraction or whether credentials
work. The report includes category results and the excluded-line count.
Both scanners run three times with alternating order. The first run supplies
the displayed confusion matrix; all repeats and agreement are preserved.
The same scores are also computed after excluding categories containing
`Private Key`: upstream obfuscation can invalidate cryptographic key material,
while the scanners differ in whether they retain unparseable PEM blocks.
`accuracy.py probe` checks this mechanism on a freshly generated, unused RSA
key. No private-key values enter its public result.

## Reproduce

Run from the repository root. Git, Go, Python, curl and GitHub CLI are needed;
`uv` supplies CredData's pinned Python dependency. Allow about 7 GiB of disk
for the selected input and acquisition caches. Raw output stays under the
gitignored cache, in private files; do not upload it.

```sh
mkdir -p bench/.tools/oss-study bench/.cache/oss-study
gh release download v3.97.5 --repo trufflesecurity/trufflehog \
  --pattern trufflehog_3.97.5_darwin_arm64.tar.gz \
  --dir bench/.tools/oss-study
echo 'b4e5fd54aaea368342b226cbea228e7a33898b177598d1d8cd66edb14f87444e  bench/.tools/oss-study/trufflehog_3.97.5_darwin_arm64.tar.gz' | shasum -a 256 -c -
tar -xzf bench/.tools/oss-study/trufflehog_3.97.5_darwin_arm64.tar.gz \
  -C bench/.tools/oss-study trufflehog

# Build the measured revision in an isolated worktree; never reset your checkout.
git worktree add --detach bench/.cache/oss-study/pleno-source \
  3c525ce46a98f4eaa88cf27ba53491f25612bf41
(cd bench/.cache/oss-study/pleno-source && \
  go build -o ../../../.tools/oss-study/pleno-dlp ./cmd/pleno-dlp)

git clone https://github.com/Samsung/CredData.git bench/.cache/oss-study/creddata
git -C bench/.cache/oss-study/creddata checkout c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d
python3 bench/oss-study/study.py prepare
uv run --python 3.12 --with pybase62==1.0.0 python bench/oss-study/accuracy.py prepare
python3 -m unittest discover -s bench/oss-study

# Run serially on an otherwise idle machine.
python3 bench/oss-study/study.py scan
python3 bench/oss-study/study.py verify
python3 bench/oss-study/accuracy.py scan
uv run --python 3.12 --with pybase62==1.0.0 python bench/oss-study/accuracy.py probe
python3 bench/oss-study/report.py
# Optional static figures (the numeric report requires only the standard library):
uv run --with matplotlib python bench/oss-study/plot.py
```

The reproduction overwrites the public aggregate results. Preserve the dated
snapshot or run in a separate worktree when comparing another machine. On
Linux, fetch and verify the corresponding TruffleHog release asset instead.
Changing the input, binaries or tool flags creates a new comparison.

## Evidence

- `manifest.json`, `inventory.json`: pinned source revisions and input sizes.
- `input-verification.json`: post-scan inventory checks and content deduplication counts.
- `results.json`: every timed sample, CPU time, RSS and aggregate detections.
- `creddata-inventory.json`: all 100 selected repositories and acquisition status.
- `accuracy.json`: labelled-line confusion matrices and category counts.
- `summary.json`: derived metrics used in the report.

Sources and findings are not redistributed. CredData source files retain their
upstream licenses; [CredData](https://github.com/Samsung/CredData) documents its
label and obfuscation policy. TruffleHog documents its verification and output
flags in the [v3.97.5 README](https://github.com/trufflesecurity/trufflehog/tree/v3.97.5).
