# /v1 TCP relay PoC

This crate supplies one fixture-tested relay component. It does not establish a
checkpoint or specification conformance. The wire is paid-tcp-relay `844e834`, /v1;
the browser client stays unchanged. TLS terminates at the front proxy, on a
separate host from the TCP destination. No page is hosted here.

Run `tau-relay CONFIG.toml`. Example configuration (documentation addresses must
be replaced; public interface and NAT addresses must all be listed):

```toml
listen = "127.0.0.1:9000"
public_url = "wss://relay.example.net/"
pass_file = "/etc/tau-relay/passes.toml"
dns_server = "192.0.2.53:53"
own_public = ["203.0.113.10"]
```

The exact URL, including its slash, appears in the challenge and must match AUTH.
The listener must be loopback. The one startup line reports its actual address,
including when port zero is requested. Configuration errors contain no record
values. Connections write nothing to stdout, stderr or files. Each completed pass
reload writes one outcome line to stderr, as described below.

The pass file is TOML:

```toml
[[passes]]
key = "<64 lowercase hex characters: x-only public key>"
hosts = ["target.example.net"]
expiry = 1800000000
revoked = false
```

Expiry is a required Unix timestamp in seconds. Keys must be valid curve points;
unknown fields, duplicate keys/hosts (including a host on two passes) and invalid
hosts are refused. Every host is admitted at registration, even in an expired or
revoked record, and checked again
on every attempt. Empty files use `passes = []`. Registration of a forbidden
literal, failing DNS, or any forbidden DNS answer prevents startup. All ports on a
recorded host are eligible. There are no purchase, recording or signed revocation
endpoints.

Replace the configured pass file atomically (write a temporary file, then rename
it over the configured file) and send SIGHUP (`systemctl reload tau-relay`) to
apply pass changes. File snapshots are bounded to 256 KiB. The FIFO queue holds at
most four snapshots, plus the one being validated. When full, the signal task
waits for space before reading the file; further signals can coalesce meanwhile.
Already queued snapshots are never dropped. Snapshots are validated fully and in
order using the startup TOML schema,
curve-point keys, required expiry, duplicate checks, 128-pass/16-host caps and the
same address policy and DNS registration checks, including own-address exclusions.
A read or validation failure keeps the previous complete set and writes only
`pass reload refused` to stderr, with no record values or paths. Success atomically
replaces the whole set and writes exactly `pass reload applied: N passes, M in force`,
where N is the number of loaded records and M excludes revoked records and records
expired at that moment. Neither outcome includes keys, hosts or paths. An expired
or revoked pass may load, but admits no new session. A SIGHUP received during startup
is held and processed as one reload after startup.

Admissions take one complete pass-set snapshot; admissions already checking DNS
may finish against their earlier snapshot. New admissions use the published set.
Open sessions keep relaying under their original limits even when their pass is
dropped, revoked or expires: /v1 has no signed revocation mechanism. To cut existing
sessions, restart the relay; a restart ends existing sessions. Pacing for
each (pass key, host) survives reloads, including unsuccessful reloads; timestamps
continue to expire by the normal sweep. Updating interface or NAT inventory still
requires a restart. As with other Unix standard signals, the OS can coalesce
SIGHUPs before they are observed; wait for the reload outcome line before replacing
the file again when every intermediate revision must be applied.

The numeric DNS endpoint is an explicit operator choice; a loopback stub resolver
is supported. The bounded UDP stub queries A, then AAAA, with fresh transaction
IDs and no cache. Both responses must succeed. It accepts address records and
CNAME chains in the answer section, refuses malformed or truncated responses,
and does not follow a CNAME requiring another query. Unsupported DNS features
fail closed. Every returned address must pass policy; only the first is dialed,
as a numeric socket address. No alternate-target fallback or reconnect occurs.

The address policy denies every row of both IANA special-purpose registries,
Last Updated 2025-10-09, regardless of global-reachability flags. IPv4 also denies
multicast and reserved space. IPv6 must lie in 2000::/3 outside the denied ranges.
The policy also denies every interface address enumerated with `getifaddrs` at
startup and the configured public addresses. Enumeration failure is fatal.
Interface changes and NAT changes require a restart with an updated inventory.

Local PoC decisions are collected in `PocLimits`, separate from profile timing:

| Parameter | Value and reason |
|---|---|
| Handshake | 20 s from accept through upgrade, AUTH and admission; dial has its own deadline; OK flush is bounded by another 20 s |
| DNS | 5 s for both queries; no retry; 4096-byte packet, 64 answers, 128 name-decompression steps |
| TCP connect | 10 s; no alternate address retry |
| Idle | 300 s without activity; useful for SSH without unbounded idle sessions |
| Write stall | 30 s without a successful TCP write while data is pending; no progress closes 1013, including with a full queue |
| HTTP upgrade header | 64 KiB, bounded before the WebSocket parser; no frame prefetch |
| WebSocket frame/message | 64 KiB each; TCP read chunks 16 KiB |
| Close send | 1 s; a peer that stops reading cannot retain the TCP stream |
| TCP write queue | Four messages plus one active write and one pending enqueue (at most 384 KiB of payload); transient congestion pauses reads until space returns |
| Connections | 64; excess accepted sockets are dropped before upgrade |
| Pass file/config | 256 KiB each; at most 128 passes, 16 hosts per pass |
| Counter sweep | 1 s; expired timestamps also pruned on admission |

These caps suit a 1 vCPU / 1 GiB host and are local operating bounds, not a
resolution of the upstream destination-cap question. Profile `auth_skew`,
`min_spacing`, `window`, and `window_cap` come directly from the pinned timing
vector. Pacing uses a monotonic clock, scoped by (pass key, canonical host), across
ports. The sliding window is `(now - window, now]`; minimum-spacing equality is
allowed. Counting is atomic before dialing, so a failed dial consumes one slot.
Only timestamps still needed by the current window remain, with at most one
sweep interval of stale retention. Nothing records a connection verdict.

AUTH failures stop at the first WIR-6 check. Binary data before OK closes 1002;
this PoC also rejects extra text between AUTH and OK with 1002. That text case is
unspecified by /v1. Control ping/pong frames remain WebSocket controls. The socket
wins simultaneous readiness during admission, dialing and OK flushing. TCP is
neither read nor written until OK has finished sending. A frame guard rejects
forbidden data at its first header byte, including non-final frames, before
message reassembly. When the TCP queue is full, one bounded enqueue waits without
an independent deadline; successful partial TCP writes reset the writer's
no-progress deadline even if a message takes longer than 30 s to finish.
Controls behind that pending binary message wait for space or termination on
write failure or no progress. Regular write progress can delay later controls
and text while the buffered data drains.
Text and closure remain observable while the writer is blocked and queue space
remains. No queue overflow alone discards a healthy stream.

Build and test from the workspace root with `cargo test --locked -p tau-relay`.
Tests honor `TMPDIR` when supplied; otherwise scratch uses Cargo's target test
directory. Each test creates and removes its own randomly named directory. All network
fixtures stay on loopback; public addresses are synthetic policy/dialer inputs.
Test fixtures sign with the crate's existing crypto dependency. The release
dependency graph has no TLS stack or C build step; libc supplies interface
enumeration through the target runtime.

For a static release, supply an isolated Rust installation containing the
`x86_64-unknown-linux-musl` target, and run `relay/build-static.sh`. `CARGO` can
name an executable; `PATH`, `RUSTUP_HOME`, `CARGO_HOME`, `RUSTUP_TOOLCHAIN`,
`CARGO_TARGET_DIR`, linker selection and other normal build variables are
respected. The output is `${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/tau-relay`.
Verify static linking with `file` before deployment.

Deployment targets a dedicated Arch Linux x86_64 host, `arch` with passwordless
`sudo -n`, using packages installed in one full `pacman -Syu` transaction. The
script uses one pinned SSH transport; it never learns or rewrites a host key.
The known-hosts path must be absolute and contain only letters, digits, `/`, `_`,
`.` and `-`, preventing OpenSSH list parsing or expansion from adding trust sources.
Identity paths remain individual argv entries and may contain spaces or quotes.
Dry run reads no binary, pass, key or known-hosts file and opens no connection:

```sh
python3 relay/deploy/deploy.py --dry-run \
  --host relay.example.net --domain relay.example.net \
  --known-hosts /operator/known_hosts --identity /operator/ssh_key \
  --binary /artifacts/tau-relay --passes /operator/passes.toml \
  --dns-server 192.0.2.53 --own-address 203.0.113.10
```

Replace documentation placeholders and remove `--dry-run` only for a deliberate
deployment. Every interface/NAT public address needs its own `--own-address`.
The DNS option selects a numeric IPv4 server at UDP port 53. Caddy proxies every
path to loopback without access logging. The dedicated service has a 256 MiB
memory cap, no capabilities and read-only system files; AF_NETLINK allows
interface enumeration. The relay requires successful firewall startup. Its restart delay is 5 s.
Configuration and passes are root-owned, group-readable
only by the service.

The firewall owns only `inet tau_relay`; atomic replacement preserves established
SSH. It accepts only loopback, established inbound traffic and ports 22/80/443. Unsolicited IPv6 neighbour/router discovery is not allowed; deployment must
provide routing/neighbour configuration compatible with this inbound policy.
Relay-user egress denies
special/local/private/metadata routes and host-owned addresses. The sole DNS
exception permits UDP to the configured address at port 53; it cannot admit TCP
destinations. Established reply-direction loopback traffic permits replies to
Caddy; new relay TCP connections to loopback still fail. Existing host firewall
rules may further restrict this policy. Static validation never applies rules.

For fresh deployments, `relay.nft` also restricts the relay user's new TCP egress
to destination port 22 (`meta skuid $relay_uid tcp dport != 22 reject`). The existing
reply-direction loopback exception still permits replies to Caddy. The deployment
script substitutes the service UID in the rule along with its other UID rules.

For an existing relay2, use `relay/deploy/upgrade.py`, **not `deploy.py`**.
The upgrade replaces only `/usr/local/bin/tau-relay` and
`/etc/systemd/system/tau-relay.service`. It uses the same strict SSH option list
as deployment, one passwordless `sudo -n` session and `set -euo pipefail`.
It holds `/run/lock/tau-relay-passes.lock` to exclude pass-file operations during
the upgrade. The host needs Python 3 with `tomllib`, `flock`, `nft`, systemd and
journal access. The operator supplies an already reviewed executable; this script
performs no build, package transaction or host-key discovery.

```sh
python3 relay/deploy/upgrade.py --dry-run \
  --host relay.example.net --known-hosts /operator/known_hosts \
  --identity /operator/ssh_key --binary /artifacts/tau-relay \
  --standing-key "$STANDING_KEY" \
  --expect-old-binary-sha256 "$OLD_BINARY_SHA256" \
  --expect-old-unit-sha256 "$OLD_UNIT_SHA256"
```

The expected hashes identify the installed files before replacement. Before and
after, the script prints hashes of the binary, unit, configuration, pass file,
Caddyfile and stored firewall, plus the standing-record digest. That digest is
SHA-256 of the parsed standing record encoded as JSON with sorted keys and no
spaces. The standing pass must be present and in force. The live output chain and
stored firewall must both contain the numeric service UID's port-22 restriction.
Configuration, passes, Caddy and firewall hashes must remain unchanged.

The new binary and repository unit are staged as `.new`; the executable bit and
binary hash are checked, and `systemd-analyze verify` checks a copy of the staged
unit with a valid `.service` basename. The old binary and unit are durably saved
as `.prev` beside their installed files before replacement. After daemon reload,
the script captures a journal cursor and restarts only `tau-relay.service`.
Within 30 seconds, it requires an active unit, a fresh exact `listening <socket>`
startup line with a loopback socket, and the expected running executable hash
read through `/proc/<MainPID>/exe`. It checks the installed binary and unit too.
No firewall or Caddy service is restarted.

Failure after replacement restores both `.prev` files, reloads the systemd
manager, restarts the relay and checks active state, the old running binary hash,
both restored file hashes and all protected state. It exits nonzero and prints
`ROLLED BACK` or `ROLLBACK FAILED`. A refusal before replacement leaves the
installed files intact. For a separate explicit rollback, use the same connection,
standing key and original expected hashes with `--rollback`; `--binary` is then
unnecessary. An explicit successful rollback returns zero. Restarts end existing
relay sessions. Keep both `.prev` files until the upgrade has been accepted.

Issue one pass per machine with `relay/deploy/issue-pass.py issue`; use `revoke`
with the same key and address to revoke that exact single-address record:

```sh
python3 relay/deploy/issue-pass.py issue --dry-run \
  --host relay.example.net --known-hosts /operator/known_hosts \
  --identity /operator/ssh_key --key "$MACHINE_KEY" --address "$MACHINE_IPV4" \
  --expiry-unix "$EXPIRY_UNIX" --standing-key "$STANDING_KEY" \
  --expect-binary-sha256 "$REVIEWED_RELOAD_BINARY_SHA256" \
  --deny-cidr "$EXCLUDED_CIDR"
```

Remove `--expiry-unix` for `revoke`. `--max-hours` defaults to 24 and `--timeout`
to 60 seconds. An issued expiry must exceed the host's current time by 600 seconds
and be no later than current time plus `--max-hours`. Repeat `--deny-cidr` for
additional exclusions. Keys must be valid 64-hex x-only curve points. The address
must be a literal IPv4 for which Python `ipaddress.is_global` is true, outside
`own_public` in the deployed configuration and outside all supplied exclusions.
A live address on another pass, a key on another record, or the standing key is
refused. The configured pass-file path must be the fixed deployed path.

An exact live `(key, address)` returns `ALREADY` without writing or signaling.
For an address recorded on an expired or revoked pass, issuance removes that
entire inactive record and prints a masked tombstone before appending the new
single-address record. The standing record is never changed. The fixed TOML
writer parses its output back to exactly the intended records, preserving even
an omitted standing `revoked` field. A record expiry in the inclusive interval
`[now - 5, now + timeout + 30]` blocks publication, including a record to be removed.
This keeps the expected in-force count stable during confirmation.

The entire remote program runs under one
`sudo -n flock -x /run/lock/tau-relay-passes.lock python3 -` SSH command.
The lock covers preflight, read, planning, staging, cursor capture, atomic rename,
directory fsync, the single reload and the complete confirmation wait. Preflight
requires an active unit, the reviewed running executable hash, the exact
`ExecReload=/bin/kill -HUP $MAINPID` line and both firewall rules. The temporary
pass file retains owner, group and mode, and is fsynced before rename.

Only the first reload outcome after the cursor counts. Success requires an exact
`pass reload applied: N passes, M in force` line for the computed record and
in-force counts, plus an unchanged published file hash, standing digest, running
binary hash and an active unit. `pass reload refused`, timeout or any mismatch
returns nonzero with `NOT CONFIRMED: <reason>`. **Stop on NOT CONFIRMED. Do not
retry by hand.** The file remains published; the script neither restores it nor
sends another reload. Establish the relay's actual state before an operator
chooses a recovery action. Revocation prevents new admissions; existing sessions
continue until they end or the relay is restarted.

Normal output contains status, mode, eight key hex characters, the first two IPv4
octets (`a.b.x.x`), expiry, counts, hashes and masked tombstones. It does not print
complete keys, addresses or file contents. Dry runs execute no remote command
and read no operator binary or trust files. They print the remote program with
sensitive parameter placeholders and the local plan; actual counts, tombstones
and idempotence need the locked remote snapshot. Dry-run previews are deliberately
non-executable. These scripts never read a file with mode 0600.

Offline script tests use a temporary root and fake service, journal, firewall and
running-executable readers; they invoke no real service or network commands:

```sh
python3 -I -m unittest discover -s relay/deploy/tests -v
```
