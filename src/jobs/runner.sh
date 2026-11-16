umask 077
d=$1
# Linux stat field 22 distinguishes a live process from a recycled PID.
identity() {
    IFS= read -r process < "/proc/$1/stat" || return 1
    process=${process##*) }
    case $process in Z*|X*) return 1;; esac
    set -- $process
    shift 19
    printf '%s\n' "$1"
}
clock() {
    IFS=' ' read -r uptime rest < /proc/uptime || return 1
    seconds=${uptime%%.*}
    case $seconds in ''|*[!0-9]*) return 1;; esac
}
start=$(identity "$$") || exit 1
printf '%s %s\n' "$$" "$start" > "$d/runner.pending" || exit 1
mv "$d/runner.pending" "$d/runner" || exit 1
# The supervisor owns eventual exit publication, independently of this observer.
clock || exit 1
began=$seconds
sh -c @COMMAND_RUNNER@ sh "$d" &
supervisor=$!
startup_passes=0
while [ ! -f "$d/pid" ]; do
    [ ! -f "$d/result" ] && identity "$supervisor" >/dev/null || exit 1
    clock || exit 1
    [ "$((seconds - began))" -lt 120 ] || exit 1
    startup_passes=$((startup_passes + 1))
    [ "$startup_passes" -lt 2400 ] || exit 1
    # GNU coreutils (Arch) and busybox (Alpine) accept fractional sleep.
    sleep 0.05
done
IFS=' ' read -r recorded_supervisor supervisor_start < "$d/group" || exit 1
[ "$recorded_supervisor" = "$supervisor" ] || exit 1
IFS=' ' read -r command_pid command_start < "$d/pid" || exit 1
# Make the record readable before allowing any command bytes to execute. An
# abandoned startup cannot run later, even if identity publication was delayed.
: > "$d/ready" || exit 1
: > "$d/go" || exit 1
clock || exit 1
began=$seconds
while [ ! -f "$d/result" ]; do
    [ "$(identity "$supervisor")" = "$supervisor_start" ] || exit 1
    clock || exit 1
    if [ "$((seconds - began))" -ge 300 ]; then
        # Publish an observation only while both the command and its exit writer
        # are live. Never signal either one or invent an exit for a dead wrapper.
        [ "$(identity "$command_pid")" = "$command_start" ] || exit 1
        [ "$(identity "$supervisor")" = "$supervisor_start" ] || exit 1
        [ ! -f "$d/result" ] && [ ! -f "$d/exit" ] || exit 0
        printf '%s\n' 'still_running' > "$d/background.pending" || exit 1
        mv "$d/background.pending" "$d/background" || exit 1
        exit 0
    fi
    sleep 0.25
done
