# A synchronous read job: no job directory, stdout file, or machine mutation.
# @PATH@ is an octal printf operand; it is never evaluated as shell syntax.
p=$(printf '%b' '@PATH@') || exit 45
@CONFINEMENT@
resolved=$(readlink -f -- "$p") || exit 45
[ "$confined" != true ] || { [ "$resolved" = "$p" ] && [ ! -L "$p" ]; } || exit 45
case "$resolved" in /var/lib/tau-web|/var/lib/tau-web/*) exit 46;; esac
[ -f "$resolved" ] || exit 45
exec 3< "$resolved" || exit 45
# Validate the opened descriptor too, so a renamed path cannot switch this read.
opened=$(readlink -f -- "/proc/$$/fd/3") || exit 45
[ "$confined" != true ] || [ "$opened" = "$p" ] || exit 45
[ "$confined" != true ] || [ "$(stat -Lc %h -- "/proc/$$/fd/3")" = 1 ] || exit 45
case "$opened" in /var/lib/tau-web|/var/lib/tau-web/*) exit 46;; esac
[ -f "/proc/$$/fd/3" ] || exit 45
size=$(stat -Lc %s -- "/proc/$$/fd/3") || exit 45
case "$size" in ''|*[!0-9]*) exit 45;; esac
[ "$size" -le 1048576 ] || exit 44
printf 'TAUFILE %s\n' "$size" || exit 45
# Bound the transfer even if the file grows after stat; the page requires exact size.
head -c 1048577 <&3 | base64
