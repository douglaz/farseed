# A synchronous metadata read: no job directory or machine mutation.
# @DIRECTORY@ is supplied by the core as octal data, never shell syntax.
export LC_ALL=C
d=$(printf '%b' '@DIRECTORY@') || exit 45
resolved=$(readlink -f -- "$d") || resolved=
if [ "$resolved" != "$d" ] || [ -L "$d" ] || [ ! -d "$d" ]; then
    printf 'TAUNONE\n'
    exit
fi
# Pin the directory while enumerating it, and refuse a renamed directory.
exec 3< "$d" || exit 45
[ "$(readlink -f -- "/proc/$$/fd/3")" = "$d" ] || exit 45
for p in "/proc/$$/fd/3/"*; do
    name=${p##*/}
    case "$name" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) continue;; esac
    [ "${#name}" -le 100 ] || continue
    [ ! -L "$p" ] && [ -f "$p" ] || continue
    [ "$(readlink -f -- "$p")" = "$d/$name" ] || continue
    metadata=$(stat -c '%F|%h|%s' -- "$p") || continue
    case "$metadata" in 'regular file|1|'*|'regular empty file|1|'*) ;; *) continue;; esac
    size=${metadata##*|}
    case "$size" in ''|*[!0-9]*) continue;; esac
    printf 'TAUENTRY %s %s\n' "$name" "$size"
done | sort | awk 'NR <= 32 { print } END { if (NR > 32) print "TAUMORE"; else print "TAUEND" }'
