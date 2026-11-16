# This supervisor keeps writing the real exit after the observer detaches.
d=$1
IFS= read -r process < "/proc/$$/stat" || exit 1
process=${process##*) }
set -- $process
session=$4
shift 19
printf '%s %s\n' "$$" "$1" > "$d/group.pending" || exit 1
mv "$d/group.pending" "$d/group" || exit 1
# Monitor mode puts the command in its own process group in this same session.
# The child verifies both properties before publishing its identity or running.
set -m || exit 1
sh -c '
    d=$1
    session=$2
    identity() {
        IFS= read -r process < "/proc/$1/stat" || return 1
        process=${process##*) }
        case $process in Z*|X*) return 1;; esac
        set -- $process
        shift 19
        printf "%s\n" "$1"
    }
    IFS= read -r process < "/proc/$$/stat" || exit 1
    process=${process##*) }
    set -- $process
    [ "$3" = "$$" ] && [ "$4" = "$session" ] || exit 1
    shift 19
    printf "%s %s\n" "$$" "$1" > "$d/pid.pending" || exit 1
    mv "$d/pid.pending" "$d/pid" || exit 1
    IFS=" " read -r observer observer_start < "$d/runner" || exit 1
    IFS=" " read -r uptime rest < /proc/uptime || exit 1
    began=${uptime%%.*}
    startup_passes=0
    while [ ! -f "$d/go" ]; do
        [ "$(identity "$observer")" = "$observer_start" ] || exit 1
        IFS=" " read -r uptime rest < /proc/uptime || exit 1
        [ "$((${uptime%%.*} - began))" -lt 120 ] || exit 1
        startup_passes=$((startup_passes + 1))
        [ "$startup_passes" -lt 2400 ] || exit 1
        sleep 0.05
    done
    [ -f "$d/ready" ] || exit 1
    : > "$d/started" || exit 1
    exec sh "$d/command"
' sh "$d" "$session" > "$d/stdout" 2> "$d/stderr" &
command_pid=$!
set +m
wait "$command_pid"
status=$?
# A child that never received permission to start has no command outcome.
[ -f "$d/started" ] || exit 1
# POSIX wait cannot distinguish signal death from a normal exit above 128.
if [ "$status" -le 128 ]; then
    printf '%s\n' "$status" > "$d/exit.pending" || exit 1
    mv "$d/exit.pending" "$d/exit" || exit 1
    printf "exit %s\n" "$status" > "$d/result.pending" || exit 1
else
    printf "signal_or_high_exit %s\n" "$status" > "$d/result.pending" || exit 1
fi
mv "$d/result.pending" "$d/result" || exit 1
