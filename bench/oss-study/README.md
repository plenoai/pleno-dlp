# OSS comparison, 2026-09-21

[日本語レポート](../../docs/oss-comparison-2026-09-21.md)

This study compares a binary built from pleno-dlp v0.65.0
(`3c525ce46a98f4eaa88cf27ba53491f25612bf41`) with the official TruffleHog
v3.97.5 Darwin arm64 release on a shared development Mac. Timing and memory
are reference observations under concurrent load, not an isolated speed
ranking. It does not measure subsequent scanner changes.
`manifest.json` pins 50 purposefully selected, well-known projects spanning
systems, infrastructure, web frameworks and scientific computing. This is not
a random sample of GitHub. Downloads use source archives without Git history.

`study.py prepare` retains regular UTF-8 files of at most 1 MiB without NUL
bytes. It records the archive hash, retained inventory hash and exclusions.
The inventory counts files actually materialized on disk. On this Mac, 13
case-only path collisions in Linux reduced 594,154 archive entries to 594,141
files. An independent audit against the identical Linux archive confirmed all
retained contents, including overwrite order; see `case-collisions.json`.
Archive entry counts and hashes are preserved separately in `inventory.json`.
Case-sensitive filesystems retain both names and therefore produce a different
corpus; compare input hashes before comparing reruns.
GitHub source archives also honor upstream `export-ignore`; submodules and
Git LFS objects are not fetched. Neither upstream code nor build scripts run.
`export-subst` can change archive content even at a fixed commit: Kubernetes'
`hack/lib/version.sh` differed by 28 bytes between preliminary acquisition
and the first cloud acquisition. Compare retained inventory hashes, not just
commit IDs, before treating a rerun as identical input.
`study.py scan` applies the same input to both scanners, disables verification,
disables pleno-dlp's default path exclusions and rotates execution order.
One warmup and three timed samples per tool/repository include process startup,
filesystem reading, detection and JSON output to disk. Output parsing, corpus
download and compilation are outside the timer. RSS is the scanner process's
peak reported by `/usr/bin/time`; CPU time is user plus system time.

The published results retain 23 completed repositories from the initial
shared-load pass and resume the other 27 with identical binaries and options.
Every repository still has one warmup and three measured samples per tool.
`OSS_STUDY_ALLOW_CONTENTION=1` explicitly allows concurrent work. Load averages
and timestamps accompany the samples; there is no reliable adjustment from
these observations to idle-machine speed. By default, the harness instead
polls every 0.5 seconds, waits for other scanners and Go builds/tests, and
discards trials that overlap them. This guard cannot recognize every workload.
No new CI job or schedule is installed. The attempted cloud run was cancelled;
its timing is not mixed into this report.

Each repository gets a deterministic, synthetic GitHub token in a temporary
control file. Every scan must find it exactly once; reported finding counts
exclude it. The original corpus inventory excludes these 50 files (54 bytes
each); the performance workload includes them. Both tools use eight workers
and `GOMAXPROCS=8`. Their default detector catalogs and filtering differ, so
this is an end-to-end product comparison, not a controlled engine microbenchmark.
The scanner invocations are captured in `results.json`.

CredData evaluation uses the 100 lowest SHA256 hashes among 337 snapshot keys at
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

Run from the repository root on macOS arm64. Git, Go 1.26.8, Python 3.12,
OpenSSL, curl and GitHub CLI are needed. Allow at least 12 GiB of free disk
for the selected input and acquisition caches. Raw output stays under the
gitignored cache, in private files; do not upload it.

```sh
mkdir -p bench/.tools/oss-study bench/.cache/oss-study
chmod 700 bench/.cache/oss-study
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
python3.12 -m venv bench/.cache/oss-study/_venv
bench/.cache/oss-study/_venv/bin/pip install pybase62==1.0.0
study_python="$PWD/bench/.cache/oss-study/_venv/bin/python"
"$study_python" bench/oss-study/study.py prepare
# Upstream obfuscation warnings may contain values; keep this log private.
"$study_python" bench/oss-study/accuracy.py prepare >bench/.cache/oss-study/prepare.log 2>&1
"$study_python" -m unittest discover -s bench/oss-study

# Set this only to reproduce the shared-load reference profile.
export OSS_STUDY_ALLOW_CONTENTION=1
# Run scanners serially, even when other development work shares the machine.
"$study_python" bench/oss-study/study.py scan
"$study_python" bench/oss-study/accuracy.py scan
"$study_python" bench/oss-study/accuracy.py probe
"$study_python" bench/oss-study/study.py verify
"$study_python" bench/oss-study/report.py
# Optional static figures (the numeric report requires only the standard library):
bench/.cache/oss-study/_venv/bin/pip install matplotlib
"$study_python" bench/oss-study/plot.py
"$study_python" bench/oss-study/report.py
```

The reproduction overwrites the public aggregate results. Preserve the dated
snapshot or run in a separate worktree when comparing another machine. On
other platforms, fetch and verify the corresponding TruffleHog release asset.
Changing the input, binaries or tool flags creates a new comparison.
`study.py scan --resume` reuses completed repositories only after checking
binary hashes, commands, platform and CPU count. `study.py verify` checks
the retained input; CredData scoring also verifies its obfuscated corpus hash.

## Evidence

- `manifest.json`, `inventory.json`: pinned source revisions and input sizes.
- `input-verification.json`: post-scan inventory checks and content deduplication counts.
- `case-collisions.json`: Linux case-only collisions and archive reconstruction check.
- `results.json`: every timed sample, CPU time, RSS and aggregate detections.
- `creddata-inventory.json`: all 100 selected repositories and acquisition status.
- `accuracy.json`: labelled-line confusion matrices and category counts.
- `pem-probe.json`: generated-key parsing and detection counts, without key values.
- `summary.json`: derived metrics used in the report.

Sources and findings are not redistributed. CredData source files retain their
upstream licenses; [CredData](https://github.com/Samsung/CredData) documents its
label and obfuscation policy. TruffleHog documents its verification and output
flags in the [v3.97.5 README](https://github.com/trufflesecurity/trufflehog/tree/v3.97.5).
