#!/usr/bin/env bash
# #970: an archive that fails to open or expand keeps its coverage gap AND
# has its raw bytes scanned, so plaintext secrets are still reported.
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/06-unopenable-archive"
mkdir -p "$case_dir/z01" "$case_dir/zip"
key="AKIA"'QYLPMN5HHHFPZAM2'

# Lone spanned-zip head volume (no siblings): split-volume gap.
printf 'PK\007\010PK\003\004 junk aws_access_key_id=%s\n' "$key" > "$case_dir/z01/backup.z01"

# Truncated zip: stored member present, central directory cut off.
printf 'PK\003\004\024\000\000\000\000\000\000\000\000\000aws_access_key_id=%s\n' "$key" > "$case_dir/zip/broken.zip"

for target in z01 zip; do
  set +e
  "$PLENO_DLP_E2E_BIN" scan --format json --no-verify --quiet \
    filesystem "$case_dir/$target" >"$case_dir/$target.json" 2>"$case_dir/$target.err"
  status=$?
  set -e
  # A finding sets the non-zero finding exit; anything else is a failure.
  grep -q '"DetectorName": *"AWS"\|"detector_name": *"AWS"\|"AWS"' "$case_dir/$target.json" || {
    echo "e2e 06: $target: secret inside unopenable archive not reported (exit $status)" >&2
    cat "$case_dir/$target.err" >&2
    exit 1
  }
  grep -q 'coverage: entry severity=[a-z-]* kind=archive' "$case_dir/$target.err" || {
    echo "e2e 06: $target: archive coverage gap not reported" >&2
    cat "$case_dir/$target.err" >&2
    exit 1
  }
done
