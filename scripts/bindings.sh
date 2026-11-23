#!/usr/bin/env bash
# Build and package the pleno-dlp language bindings (docs/library.md).
#
#   scripts/bindings.sh lib <out-dir>            build libpleno_dlp for $GOOS/$GOARCH
#                                                (ZIG_TARGET=<triple> cross-links with zig cc)
#   scripts/bindings.sh darwin-stubs <dylib>     regenerate scripts/darwin-stubs from a native build
#   scripts/bindings.sh wheel <lib> <plat> <dist> build a py3-none-<plat> wheel
#                                                (plat manylinux-auto-<arch> derives the glibc floor)
#   scripts/bindings.sh stage-node <lib> <goos-goarch>  copy a lib into bindings/node
#   scripts/bindings.sh version <tag>            stamp both packages with a release version
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)

libname() {
  case "$(cd "$root" && go env GOOS)" in
    darwin) echo libpleno_dlp.dylib ;;
    windows) echo pleno_dlp.dll ;;
    *) echo libpleno_dlp.so ;;
  esac
}

stubs="$root/scripts/darwin-stubs"

# tbd <out> <install-name> [symbol...]: write a text-based dylib stub that
# exports only the named symbols. The stubs let zig link darwin c-shared
# libraries on Linux without the macOS SDK; a symbol a future Go release adds
# fails the link instead of producing a broken library.
tbd() {
  local out=$1 name=$2
  shift 2
  mkdir -p "$(dirname "$out")"
  {
    printf -- '--- !tapi-tbd\ntbd-version: 4\ntargets: [ x86_64-macos, arm64-macos ]\n'
    printf "install-name: '%s'\n" "$name"
    if [ $# -gt 0 ]; then
      printf 'exports:\n  - targets: [ x86_64-macos, arm64-macos ]\n    symbols: [ %s ]\n' "$(printf '%s\n' "$@" | sort | paste -sd, - | sed 's/,/, /g')"
    fi
    echo '...'
  } >"$out"
}

case "${1:-}" in
  lib)
    out=${2:?out dir}
    mkdir -p "$out"
    if [ -n "${ZIG_TARGET:-}" ]; then
      CC="zig cc -target $ZIG_TARGET"
      [[ "$ZIG_TARGET" == *macos* ]] && CC="$CC -F$stubs/System/Library/Frameworks -L$stubs/usr/lib"
      export CC
    fi
    (cd "$root" && CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags='-s -w' \
      -buildmode=c-shared -o "$out/$(libname)" ./cmd/libpleno-dlp)
    rm -f "$out"/*.h "$out"/*.lib "$out"/*.a
    ;;
  darwin-stubs)
    lib=${2:?dylib built natively on macOS}
    fw=/System/Library/Frameworks
    undef() { nm -m -u "$lib" | sed -n "s/.* external \\(_[A-Za-z0-9_]*\\) (from $1)$/\\1/p"; }
    # shellcheck disable=SC2046
    tbd "$stubs$fw/CoreFoundation.framework/CoreFoundation.tbd" "$fw/CoreFoundation.framework/Versions/A/CoreFoundation" $(undef CoreFoundation)
    # shellcheck disable=SC2046
    tbd "$stubs$fw/Security.framework/Security.tbd" "$fw/Security.framework/Versions/A/Security" $(undef Security)
    # shellcheck disable=SC2046
    tbd "$stubs/usr/lib/libresolv.tbd" /usr/lib/libresolv.9.dylib $(undef libresolv)
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
    # Node names x86-64 "x64" and Windows "win32"; Go says "amd64"/"windows".
    target=${target/amd64/x64}
    dir="$root/bindings/node/lib/${target/windows/win32}"
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
    sed -n '2,11p' "$0" >&2
    exit 2
    ;;
esac
