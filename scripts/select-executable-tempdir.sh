#!/bin/sh
set -eu
umask 077

workdir=
cleanup() {
    if [ -n "$workdir" ]; then
        rm -rf "$workdir"
    fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

newline='
'
carriage_return=$(printf '\r')
previous_candidate=

for candidate in "${RUNNER_TEMP:-}" "${TMPDIR:-}" /tmp "${GITHUB_WORKSPACE:-}" "${PWD:-}"; do
    [ -n "$candidate" ] || continue
    case "$candidate" in
        -*) candidate="./$candidate" ;;
    esac
    [ -d "$candidate" ] || continue

    canonical=$(CDPATH= cd "$candidate" 2>/dev/null && { pwd -P && printf '.'; }) || continue
    canonical=${canonical%.}
    candidate=${canonical%"$newline"}
    case "$candidate" in
        *"$newline"*|*"$carriage_return"*) continue ;;
    esac
    if [ "$candidate" = "$previous_candidate" ]; then
        continue
    fi
    previous_candidate=$candidate

    if [ "$candidate" = / ]; then
        template="/pleno-dlp-action.XXXXXX"
    else
        template="${candidate%/}/pleno-dlp-action.XXXXXX"
    fi
    workdir=$(mktemp -d "$template" 2>/dev/null) || continue
    case "$workdir" in
        *"$newline"*|*"$carriage_return"*) rm -rf "$workdir"; workdir=; continue ;;
    esac

    probe="$workdir/exec-probe"
    if printf '#!/bin/sh\nexit 0\n' > "$probe" 2>/dev/null \
        && chmod 700 "$probe" 2>/dev/null \
        && "$probe" >/dev/null 2>&1; then
        rm -f "$probe"
        printf '%s\n' "$workdir"
        workdir=
        exit 0
    fi
    rm -rf "$workdir"
    workdir=
done

printf 'no executable temporary directory found\n' >&2
exit 1
