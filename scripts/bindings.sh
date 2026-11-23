#!/usr/bin/env bash
# Build and package the pleno-dlp language bindings (docs/library.md).
#
#   scripts/bindings.sh lib <out-dir>            build libpleno_dlp for the host
#   scripts/bindings.sh wheel <lib> <plat> <dist> build a py3-none-<plat> wheel
#                                                (plat manylinux-auto-<arch> derives the glibc floor)
#   scripts/bindings.sh stage-node <lib> <goos-goarch>  copy a lib into bindings/node
#   scripts/bindings.sh version <tag>            stamp both packages with a release version
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)

libname() {
  case "$(cd "$root" && go env GOOS)" in
    darwin) echo libpleno_dlp.dylib ;;
    *) echo libpleno_dlp.so ;;
  esac
}

case "${1:-}" in
  lib)
    out=${2:?out dir}
    mkdir -p "$out"
    (cd "$root" && CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags='-s -w' \
      -buildmode=c-shared -o "$out/$(libname)" ./cmd/libpleno-dlp)
    rm -f "$out/libpleno_dlp.h"
    ;;
  wheel)
    lib=${2:?lib path} plat=${3:?platform tag} dist=${4:?dist dir}
    if [[ "$plat" == manylinux-auto-* ]]; then
      # Tag with the newest glibc symbol version the library actually needs,
      # so pip never installs it on a system whose glibc is too old.
      glibc=$("${OBJDUMP:-objdump}" -T "$lib" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1)
      plat="manylinux_${glibc/./_}_${plat#manylinux-auto-}"
    fi
    pkg="$root/bindings/python"
    rm -rf "$pkg/pleno_dlp/lib" "$pkg/build"
    mkdir -p "$pkg/pleno_dlp/lib" "$dist"
    cp "$lib" "$pkg/pleno_dlp/lib/"
    tmp=$(mktemp -d)
    python -m pip wheel --no-deps --no-build-isolation -w "$tmp" "$pkg"
    python -m wheel tags --remove --python-tag py3 --abi-tag none --platform-tag "$plat" "$tmp"/*.whl
    mv "$tmp"/*.whl "$dist/"
    rm -rf "$tmp" "$pkg/pleno_dlp/lib" "$pkg/build"
    ;;
  stage-node)
    lib=${2:?lib path} target=${3:?goos-goarch}
    # Node names x86-64 "x64"; Go names it "amd64".
    dir="$root/bindings/node/lib/${target/amd64/x64}"
    mkdir -p "$dir"
    cp "$lib" "$dir/"
    ;;
  version)
    tag=${2:?tag}
    v=${tag#v}
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "unsupported release tag: $tag" >&2; exit 1; }
    printf '# Rewritten from the release tag by .github/workflows/release.yml.\n__version__ = "%s"\n' "$v" \
      >"$root/bindings/python/pleno_dlp/_version.py"
    (cd "$root/bindings/node" && npm version --no-git-tag-version --allow-same-version "$v" >/dev/null)
    ;;
  *)
    sed -n '2,9p' "$0" >&2
    exit 2
    ;;
esac
