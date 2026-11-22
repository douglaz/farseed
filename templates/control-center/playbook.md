# Control center playbook

Goal template 1, "Control center". Generated from the control-center sources; edit those, not this file.

The ways in: **T3 Code with T3 Connect** (main), **WireGuard** (second), **Tor** (optional, off unless the user
turns it on). Farseed gives the AI the **Header** and **Facts** with every step, the **Declaration** in the
declaration phase, and then **one step at a time**. Each step is a **Do** block, sometimes a **Wait** block, and a
**Check** whose last line is `CHECKS <part> PASS` or `FAIL`.

---

## Header (send with every step)

You are building the user's control center on this NixOS machine. Follow the step below exactly.

1. Run each block of the step as one command, exactly as written: by name with `run_step_block`, and Farseed then
   fills in the words in CAPITALS itself. Only if `run_step_block` isn't offered, copy the block out and replace
   only the CAPITALS words the step names, with their values.
2. Never print a secret. Don't cat, echo or grep the files in /var/lib/control-center, except files ending in
   `.pub`. Don't print the user's wireguard.conf, login file or Lightning seed file.
3. Never put a secret in /etc/nixos or in any `.nix` file.
4. Make every lasting change through /etc/nixos and `sh /etc/nixos/cc-rebuild.sh`. Never use nix-env,
   nix profile, pip, npm -g or curl|sh, and never edit /etc outside /etc/nixos.
5. Never reboot. Never run `nixos-rebuild` yourself: `cc-rebuild.sh` runs it the right way (switch, the flake
   output `control`, in the background). Never change SSH settings or host keys. (Step 3 adding the user's own
   public key from `USER_SSH_KEY` is not an SSH settings change.)
6. Run every Check block exactly as written and alone: nothing before or after it in the same command, not even
   an echo. Farseed counts a step as passed only when the check's `CHECKS ... PASS` line is the last line of the
   command's output. On FAIL, do what "If it fails" says, at most twice. If it still fails, stop and report the
   FAIL lines and the step number.
7. If Farseed sends you the same step again after that step's own Check printed PASS while it was the step
   Farseed had sent you, run that step's Check block alone, once more, and nothing else. A PASS from before
   Farseed sent the step doesn't count: do the whole step as written. Never explore instead: don't look for
   other steps' text, read package sources, check ports, or build anything a step doesn't ask for. Farseed sends
   the next step itself.
8. Commands already run as root. Keep output short: only the first 8 KiB of output comes back, and the
   scripts print only what matters.
9. Change the `cc-*.nix` files, the two scripts and the user's files (Step 11 writes them) only by running a
   step's Do block. A FAIL line that ends with `(needs the user: ask_operator)` can only be fixed by the user:
   ask with `ask_operator`, wait for the answer, then run that step's Wait and Check again. Don't work around it.
10. When Farseed says every step passed, call `done` with `urls`: `https://app.t3.codes` (label `T3 Code`),
    `http://10.88.0.1:9119/` (label `Hermes dashboard over WireGuard`), and, if Tor is on, the onion address from
    app-url.txt (label `Hermes dashboard over Tor`). If the final check printed `T3 Code: not linked yet`, leave
    `https://app.t3.codes` out of `urls` completely: the machine isn't linked, so that address can't reach it yet.
11. Do only the step Farseed sent you, as its text says. Never start a later step early, and never write your
    own version of a step's block or file (a `cc-*.nix` file, for example): Farseed sends each step's exact blocks
    when that step's turn comes.

## Facts (Farseed fills these in)

- `MACHINE_ADDRESS`: the public IPv4 address or DNS name the user's devices reach this machine at, the same one
  Farseed uses for SSH.
- `AI_BASE_URL`: the AI endpoint URL for the agent, ending in `/v1`.
- `AI_MODEL`: the model name for the agent.
- `TOR`: `yes` if the user turned on Tor, otherwise `no`. Step 10 runs only on `yes`.
- `USER_SSH_KEY`: the user's own SSH public key (one line), or empty. It lets the user log in to the machine
  directly.
- The AI key itself is never a fact: in Step 4 you ask for it with `request_ai_key`, and Farseed saves it in a
  file on this machine whose path the reply gives.

## Declaration

Propose exactly this declaration. It lists every listener and service the finished machine has. With `TOR` =
`no`, leave out the three entries marked Tor.

```json
{
  "version": 2,
  "listeners": {
    "inbound": [
      { "proto": "tcp", "port": 22, "from": "any" },
      { "proto": "udp", "port": 51820, "from": "any" },
      { "proto": "tcp", "port": 9119, "from": "peers" },
      { "proto": "tcp", "port": 9120, "from": "none" },
      { "proto": "tcp", "port": 3773, "from": "none" },
      { "proto": "tcp", "port": 20241, "from": "none" },
      { "proto": "tcp", "port": 53, "from": "none" },
      { "proto": "udp", "port": 53, "from": "none" },
      { "proto": "udp", "port": 68, "from": "any" },
      { "proto": "tcp", "port": 9050, "from": "none" }
    ],
    "outbound": []
  },
  "services": [
    { "name": "sshd", "scope": { "kind": "system" }, "lifecycle": "enabled-survives-reboot" },
    { "name": "systemd-networkd", "scope": { "kind": "system" }, "lifecycle": "enabled-survives-reboot" },
    { "name": "hermes-agent", "scope": { "kind": "system" }, "lifecycle": "enabled-survives-reboot" },
    { "name": "hermes-backend", "scope": { "kind": "system" }, "lifecycle": "enabled-survives-reboot" },
    { "name": "t3code", "scope": { "kind": "system" }, "lifecycle": "enabled-survives-reboot" },
    { "name": "tor", "scope": { "kind": "system" }, "lifecycle": "enabled-survives-reboot" }
  ],
  "key_material": {
    "spendable": true,
    "permitted": [
      { "kind": "private-non-spendable", "where": "/var/lib/control-center/wg-server.key" },
      { "kind": "private-non-spendable", "where": "/var/lib/control-center/wg-user.key" },
      { "kind": "private-non-spendable", "where": "/home/nixos/wireguard.conf" },
      { "kind": "private-non-spendable", "where": "/var/lib/t3code/userdata/secrets" },
      { "kind": "private-non-spendable", "where": "/var/lib/tor/onion/control-center" }
    ]
  },
  "drift_checks": [],
  "required": [],
  "default_credentials": "none"
}
```
What each entry is:
- 22: SSH.
- UDP 51820: WireGuard.
- 9119: the Hermes dashboard. It listens on all addresses, but the firewall opens it on the WireGuard interface
  only.
- 9120: Hermes' internal listener.
- 3773: T3 Code.
- 20241: T3 Connect's tunnel client status port.
- 53: the local DNS stub.
- UDP 68: the network's DHCP client.
- Tor (left out with `TOR` = `no`): 9050, the `tor` service and the onion key.

Every entry with `none` is loopback-only. If the login user isn't `nixos`, change `/home/nixos` to the user's
home.
`spendable: true` covers the Lightning seed file, the wallet password and lnd's wallet; the schema has no
spendable kind, so their paths are not listed.

---

## Step 1: Look at the machine

**Do** (this block is also the check; run it alone, exactly as written)
```sh
sh <<'STEP'
. /etc/os-release
R=$(nixos-version --revision 2>/dev/null)
F=$(df -BG --output=avail / | tail -n 1 | tr -dc 0-9)
echo "OS $ID $VERSION_ID"; echo "NIXPKGS $R"; echo "LOGIN $(getent passwd 1000 | cut -d: -f1,6)"
echo "FREE_GB $F"; free -m | awk 'NR==2{print "RAM_MB", $2}'; echo "CPUS $(nproc)"
ip -4 -o addr show scope global | awk '{print "ADDR", $2, $4}'
if [ "$ID" = nixos ] && echo "$R" | grep -qE '^[0-9a-f]{40}$' && [ "$(id -u)" = 0 ] && [ "${F:-0}" -ge 10 ]; then
  echo "CHECKS machine PASS"; else echo "CHECKS machine FAIL"; fi
STEP
```
Expect `CHECKS machine PASS` on the last line.

**If it fails:** if the OS isn't nixos, or NIXPKGS is empty, stop and report "not a supported NixOS image". If
FREE_GB is below 10, stop and report it. The ADDR may be a private address (10.x, 172.16-31.x, 192.168.x) when the
provider uses NAT. That's fine: later steps use `MACHINE_ADDRESS` from the facts.

---

## Step 2: Put /etc/nixos under git and add the two helper scripts

`cc-rebuild.sh` applies the configuration in the background and logs it. `cc-check.sh` runs every check in this
playbook. Copy both exactly: the check compares their hashes.

**Do**
```sh
sh -eu <<'STEP'
git -C /etc/nixos init -q -b main
mkdir -p /etc/nixos/extra /var/lib/control-center
chmod 700 /var/lib/control-center
getent passwd 1000 | cut -d: -f1 > /var/lib/control-center/login-user
echo "One NixOS module per file. Every *.nix file here is part of the system." > /etc/nixos/extra/README.md
cat > /etc/nixos/cc-rebuild.sh <<'FILE'
#!/bin/sh
# Apply /etc/nixos as its own unit (survives a lost command or SSH). Log: /var/log/cc-rebuild.log
# sh cc-rebuild.sh: start | sh cc-rebuild.sh wait: wait up to 4 min | sh cc-rebuild.sh rollback: previous version
export PATH=/run/current-system/sw/bin:/run/wrappers/bin:$PATH
L=/var/log/cc-rebuild.log
if [ "$1" = wait ]; then
  for i in $(seq 48); do
    case "$(tail -n 1 $L)" in
      "RESULT 0 "*) echo "REBUILD OK $(head -n 1 $L) $(tail -n 1 $L)"; exit 0 ;;
      RESULT*) echo "REBUILD FAILED $(tail -n 1 $L). First error lines:"
        grep -m 8 -iE 'error|failed|assertion' $L | cut -c1-200; exit 1 ;;
    esac
    sleep 5
  done
  echo "STILL RUNNING. Run the same wait command again."; exit 3
fi
systemctl is-active -q cc-rebuild && { echo "BUSY. Run: sh /etc/nixos/cc-rebuild.sh wait"; exit 1; }
if [ "$1" = rollback ]; then
  C='nix-env -p /nix/var/nix/profiles/system --rollback && /nix/var/nix/profiles/system/bin/switch-to-configuration switch'
else
  git -C /etc/nixos add -A; C='nixos-rebuild switch --flake /etc/nixos#control'
fi
echo "QUEUED $(date -u +%T)" > $L
systemd-run -q -u cc-rebuild --collect -E PATH="$PATH" /bin/sh -c "($C) >> $L 2>&1; echo RESULT \$? \$(date -u +%T) >> $L"
echo "STARTED. Now run: sh /etc/nixos/cc-rebuild.sh wait"
FILE
cat > /etc/nixos/cc-check.sh <<'FILE'
#!/bin/sh
# Control center checks, run as root: sh cc-check.sh base|keys|hermes|agent|t3|connect|wireguard|tor|handover|done
# Prints one line per failed check, then "CHECKS <part> PASS|FAIL <passed>/<total>". Never prints a secret.
# Waits share one time budget (90 s for done, 150 s otherwise) and every command has its own timeout, so a run
# ends well within 5 minutes (done: about 4 minutes in the worst case).
export PATH=/run/current-system/sw/bin:/run/wrappers/bin:$PATH
S=/var/lib/control-center; O=/var/lib/tor/onion/control-center/hostname
U=$(cat $S/login-user 2>/dev/null); H=$(getent passwd "$U" | cut -d: -f6); N=0; G=0
T0=$(date +%s); B=150; [ "$1" = done ] && B=90
t() { n=$1; shift; N=$((N+1)); if "$@" >/dev/null 2>&1; then G=$((G+1)); else echo "CHECK $n FAIL"; fi; }
# A check only the user can make pass (an approval in their own account): its FAIL line says so.
tu() { n=$1; shift; N=$((N+1)); if "$@" >/dev/null 2>&1; then G=$((G+1)); else echo "CHECK $n FAIL (needs the user: ask_operator)"; fi; }
w() { e=$(( $(date +%s) + $1 )); [ $e -gt $((T0 + B)) ] && e=$((T0 + B)); shift
  while ! "$@" >/dev/null 2>&1 && [ "$(date +%s)" -lt $e ]; do sleep 2; done; }
m() { [ "$(stat -c '%a %U' "$1" 2>/dev/null)" = "$2" ]; }
k() { test -s "$1" && m "$1" "600 root"; }
up() { systemctl is-active -q "$1" && systemctl show -p WantedBy --value "$1" | grep -qw multi-user.target; }
has() { printf '%s%s\n' "$2" "$(cat "$3")" | grep -qxFf - "$1"; }
lsn() { ss -H -n -l -t | grep -q "$1 "; }
login() { if [ "$1" = right ]; then jq -n --rawfile p $S/dashboard-password '{provider:"basic",username:"owner",password:$p}'
  else echo '{"provider":"basic","username":"owner","password":"x"}'; fi | curl -s -m 10 -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' -d @- http://127.0.0.1:9119/auth/password-login | grep -qx "$2"; }
visit() { case "$1" in *.onion*) x="--socks5-hostname 127.0.0.1:9050" ;; *) x="" ;; esac
  curl -s -m 15 $x -o /dev/null -w '%{http_code} %{redirect_url}\n' "$1" | grep -qE '^(401|403) |^30[1278] .*login'; }
# T3 Connect counts as working when the account link is in place and the tunnel client has a live connection to
# T3's relay. T3's own "reachable" test also resolves the public name, which a stale DNS cache can fail for a
# while, so it is not required here.
linked() { timeout 25 t3c connect status --json 2>/dev/null | jq -e '.authenticated and .linked and (.revoked | not)'; }
tunnel() { curl -sf -m 5 -o /dev/null http://127.0.0.1:20241/ready; }
both() { linked && tunnel; }
# The user may link T3 Code later: Step 8's Later block leaves this marker. While the machine isn't linked, the
# checks then ask for T3 Code running and no sign-in left waiting, instead of the link and the tunnel.
later() { [ -e $S/t3-link-later ] && ! linked >/dev/null 2>&1; }
ready() { jq -e '.status == "ready" and .driver == "acpRegistry"' /var/lib/t3code/caches/hermes.json; }
dash() { curl -sf -m 2 -o /dev/null http://127.0.0.1:9119/api/status; }
tor_on() { systemctl is-enabled -q tor 2>/dev/null; }
base() {
  t os_is_nixos grep -qx ID=nixos /etc/os-release
  t flake_lock_tracked git -C /etc/nixos ls-files --error-unmatch flake.lock
  t running_is_boot_default test "$(readlink -f /run/current-system)" = "$(readlink -f /nix/var/nix/profiles/system)"
  t tools_on_path sh -c 'command -v wg && command -v jq'
  t port_5355_closed sh -c '! ss -H -n -l -t | grep -q ":5355 "'
  t binary_cache_configured sh -c 'nix config show 2>/dev/null | grep -E "^(extra-)?substituters" | grep -q app.poc.asf0.org/images/nix-cache'
  if [ -s /etc/nixos/user-ssh-key.pub ]; then
    t user_ssh_key_authorized grep -qxFf /etc/nixos/user-ssh-key.pub "/etc/ssh/authorized_keys.d/$U"
  fi
}
keys() {
  t secrets_dir_root_700 m $S "700 root"
  for f in wg-server.key wg-user.key dashboard-password dashboard-secret ai-key hermes.env; do t "${f}_root_600" k $S/$f; done
  t hermes_env_names test "$(cut -d= -f1 $S/hermes.env | sort | tr '\n' ' ')" = "CONTROL_CENTER_AI_KEY \
HERMES_DASHBOARD_BASIC_AUTH_PASSWORD HERMES_DASHBOARD_BASIC_AUTH_SECRET HERMES_DASHBOARD_BASIC_AUTH_USERNAME "
}
hermes() {
  t hermes_agent_up up hermes-agent
  t hermes_backend_up up hermes-backend
  w 90 dash
  t signin_gate_on sh -c 'curl -s -m 10 http://127.0.0.1:9119/api/status | jq -e ".auth_required and (.auth_providers | index(\"basic\") != null)"'
  t wrong_password_refused login wrong 401
  t right_password_accepted login right 200
  t hermes_acp_installed test -x /run/current-system/sw/bin/hermes-acp
  w 60 lsn 127.0.0.1:9120
  t gateway_on_loopback_9120 lsn 127.0.0.1:9120
}
agent() {
  # polkit starts on the first request, so the real test is the hermes user starting the apply unit.
  t apply_rule_present sh -c 'grep -qs control-center-apply /etc/polkit-1/rules.d/*'
  t extra_dir_root_hermes_2775 test "$(stat -c '%U:%G %a' /etc/nixos/extra)" = "root:hermes 2775"
  t hermes_starts_apply runuser -u hermes -- systemctl start control-center-apply
  sleep 3
  t apply_rebuild_ok sh /etc/nixos/cc-rebuild.sh wait
  t hermes_refused_other_units sh -c '! runuser -u hermes -- systemctl start sshd'
}
t3() {
  t t3code_up up t3code
  w 60 lsn 127.0.0.1:3773
  t t3_on_loopback_3773_only sh -c 'ss -H -n -l -t | grep ":3773 " | grep -qv "127.0.0.1:3773 " && exit 1; ss -H -n -l -t | grep -q "127.0.0.1:3773 "'
  w 60 ready
  t t3_sees_hermes_ready ready
}
connect() {
  if later; then
    echo "T3 Code: not linked yet (the user chose Later)"
    t t3_link_later_chosen m $S/t3-link-later "600 root"
    t t3_link_later_t3code_up up t3code
    t t3_link_later_no_signin_waiting sh -c '! systemctl is-active -q t3-connect'
    return
  fi
  w 120 both
  tu t3_connect_linked linked
  # Without the link the tunnel can't connect (the user's part); with it, a restart of t3code is the fix.
  if linked >/dev/null 2>&1; then t t3_tunnel_connected tunnel; else tu t3_tunnel_connected tunnel; fi
  tu t3_credential_service_only m /var/lib/t3code/userdata/secrets/cloud-cli-oauth-token.bin "600 hermes"
}
wireguard() {
  t wg0_address sh -c 'ip -4 addr show wg0 | grep -q "inet 10.88.0.1/24"'
  t wg0_port_51820 sh -c 'wg show wg0 listen-port | grep -qx 51820'
  t wg0_peer_is_user_key sh -c "wg show wg0 peers | grep -qxFf $S/wg-user.pub"
  t wg0_server_key_matches test "$(wg show wg0 public-key)" = "$(cat $S/wg-server.pub)"
  t dashboard_on_wg0 curl -sf -m 10 -o /dev/null http://10.88.0.1:9119/api/status
  t fw_udp_51820_open sh -c 'iptables -S nixos-fw | grep -q -- "-p udp -m udp --dport 51820 -j nixos-fw-accept"'
  t fw_9119_on_wg0_only sh -c 'iptables -S nixos-fw | grep -q -- "-i wg0 -p tcp -m tcp --dport 9119" &&
    ! iptables -S nixos-fw | grep -- "--dport 9119" | grep -qv -- "-i wg0"'
  P=$(iptables -S nixos-fw | grep -- '-j nixos-fw-accept' | grep -v -- ' -i ' | grep -oE -- '--dport [0-9:]+' | cut -d' ' -f2 | sort -u | tr '\n' ' ')
  t public_ports_only_22_51820 test "$P" = "22 51820 "
}
tor() {
  t tor_up up tor
  w 60 test -s $O
  t onion_hostname grep -qE '^[a-z2-7]{56}\.onion$' $O
}
handover() {
  t wireguard_conf_600 m "$H/wireguard.conf" "600 $U"
  t login_file_600 m "$H/control-center-login.txt" "600 $U"
  t conf_has_user_key has "$H/wireguard.conf" "PrivateKey = " $S/wg-user.key
  t conf_has_server_key has "$H/wireguard.conf" "PublicKey = " $S/wg-server.pub
  t conf_has_endpoint grep -qE '^Endpoint = .+:51820$' "$H/wireguard.conf"
  t login_has_password has "$H/control-center-login.txt" "password: " $S/dashboard-password
  if later; then t login_says_t3_not_linked_yet grep -qxF 'T3 Code: not linked yet.' "$H/control-center-login.txt"
  else t login_names_t3_app grep -qF 'https://app.t3.codes' "$H/control-center-login.txt"; fi
  t url_wireguard grep -qx 'http://10.88.0.1:9119/' "$H/app-url.txt"
  if tor_on; then t url_onion grep -qxF "http://$(cat $O)/" "$H/app-url.txt"
  else t no_onion_url_without_tor sh -c "! grep -q onion $H/app-url.txt"; fi
}
final() {
  base; keys; hermes; t3; connect; wireguard; handover
  tor_on && tor
  while read -r u; do w 90 visit "$u"; t "visit_unsigned_refused_${u%%.onion*}" visit "$u"; done < "$H/app-url.txt"
  t no_secret_in_config sh -c "! grep -rqF -f $S/wg-server.key -f $S/wg-user.key -f $S/dashboard-password \
    -f $S/dashboard-secret -f $S/ai-key /etc/nixos && ! grep -RqF -f $S/wg-server.key -f $S/wg-user.key \
    -f $S/dashboard-password -f $S/dashboard-secret -f $S/ai-key /etc/static/"
  for u in hermes-agent hermes-backend t3code; do
    t "${u}_unit_from_store" sh -c "readlink -f \"\$(systemctl show -p FragmentPath --value $u)\" | grep -q ^/nix/store/"
  done
  t config_committed test -z "$(git -C /etc/nixos status --porcelain)"
}
case "$1" in
  base|keys|hermes|agent|t3|connect|wireguard|tor|handover) "$1" ;; done) final ;;
  *) echo "usage: sh cc-check.sh base|keys|hermes|agent|t3|connect|wireguard|tor|handover|done"; exit 2 ;;
esac
echo "CHECKS $1 $([ $G = $N ] && echo PASS || echo FAIL) $G/$N"
[ $G = $N ]
FILE
git -C /etc/nixos add -A
echo SCRIPTS_WRITTEN
STEP
```
**Check** (run it alone, exactly as written; the two scripts must match byte for byte):
```sh
printf '%s  /etc/nixos/cc-rebuild.sh\n%s  /etc/nixos/cc-check.sh\n' 369725dca22aba7edd6ad35a83f9ce5fe1b73ac01ed5b4d3d7e2564d2022839f ea4bc57b6bbb983e9ea836542278b0d0ab405d5063ba7da08edb399f9789591e | sha256sum -c && echo "CHECKS scripts PASS" || echo "CHECKS scripts FAIL"
```
Expect `CHECKS scripts PASS`.

**If it fails:** a script that says FAILED doesn't match the playbook's copy. Run the Do block again by name (only
if `run_step_block` isn't offered, copy it exactly, with nothing added, removed or reformatted), then check again.
The final check repeats this hash check, so an edited script fails the whole goal.

---

## Step 3: Make /etc/nixos a flake and apply it

This writes the flake (pinned to the nixpkgs revision the machine already runs, plus Hermes Agent), the base
module (tools, and the user's own SSH key if there is one), the `extra/` loader, and empty modules that later
steps fill in. The first line takes the `USER_SSH_KEY` fact inside its quotes (empty quotes, `KEY=''`, when the
fact is empty); Farseed fills it in when you run the block by name.
The base module also turns off the name-resolution extras (LLMNR on port 5355, mDNS), so port 5355 stops
listening after this step's rebuild; the check confirms it. Nothing else is needed about it.

**Do**
```sh
sh -eu <<'STEP'
KEY='USER_SSH_KEY'
cat > /etc/nixos/flake.nix <<'FILE'
{
  description = "Control center";
  inputs = {
    # The nixpkgs revision this machine already runs (from `nixos-version --revision`).
    nixpkgs.url = "github:NixOS/nixpkgs/@nixpkgs_rev@";
    # Hermes Agent release v0.23.2, pinned by commit. It keeps its own pinned nixpkgs: its
    # packaging does not evaluate against this machine's nixpkgs, so do not add a "follows".
    hermes-agent.url = "github:NousResearch/hermes-agent/ae2a81ccc00e9b7c06301523e5bb09608397149c";
  };
  outputs = { self, nixpkgs, hermes-agent, ... }: {
    nixosConfigurations.control = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        hermes-agent.nixosModules.default
        # The smaller Hermes build: the agent and its web dashboard, without the optional
        # messaging, cloud and voice integrations.
        { services.hermes-agent.package = hermes-agent.packages.x86_64-linux.minimal; }
        ./cc-base.nix
        ./cc-hermes.nix
        ./cc-agent.nix
        ./cc-t3.nix
        ./cc-wireguard.nix
        ./cc-tor.nix
        ./cc-extra.nix
      ];
    };
  };
}
FILE
sed -i "s/@nixpkgs_rev@/$(nixos-version --revision)/" /etc/nixos/flake.nix
cat > /etc/nixos/cc-base.nix <<'FILE'
{ pkgs, lib, ... }:
let
  loginUser = lib.strings.trim (builtins.readFile ./login-user);
  # The user's own SSH public key (the USER_SSH_KEY fact), or an empty file. A public key may be in the store.
  userKey = lib.strings.trim (builtins.readFile ./user-ssh-key.pub);
in
{
  # Tools the control center's steps and checks use.
  environment.systemPackages = with pkgs; [ git curl jq wireguard-tools ];
  # No name-resolution listeners beyond the local DNS stub (127.0.0.53 and 127.0.0.54, port 53).
  services.resolved.settings.Resolve = { LLMNR = false; MulticastDNS = false; };
  # Farseed's binary cache: Hermes Agent and T3 Code prebuilt for these exact pins, signed with this public key.
  # If the cache can't be reached, nix builds from source instead (slower, never a failure).
  nix.settings = {
    extra-substituters = [ "https://app.poc.asf0.org/images/nix-cache" ];
    extra-trusted-public-keys = [ "app.poc.asf0.org-cc-cache-1:S7kgCCntlcwvl0ntC6O4duUCc4uaUn9SERTUqA6+7gM=" ];
    fallback = true;
    connect-timeout = 10;
  };
  # Lets the user log in to the machine directly with their own key, next to the keys already there.
  users.users = lib.mkIf (userKey != "") {
    ${loginUser} = {
      isNormalUser = true;
      openssh.authorizedKeys.keys = [ userKey ];
    };
  };
}
FILE
cat > /etc/nixos/cc-extra.nix <<'FILE'
{ lib, ... }:
let
  # Every *.nix file in /etc/nixos/extra is part of the system. To install something more,
  # add one file there and rebuild; to remove it, delete the file and rebuild.
  dir = ./extra;
  files = lib.filterAttrs (name: type: type == "regular" && lib.hasSuffix ".nix" name) (builtins.readDir dir);
in
{
  imports = map (name: dir + "/${name}") (builtins.attrNames files);
}
FILE
for f in cc-hermes cc-agent cc-t3 cc-wireguard cc-tor; do echo '{ ... }: { }' > /etc/nixos/$f.nix; done
cp /var/lib/control-center/login-user /etc/nixos/login-user
case "$KEY" in
  ssh-*|ecdsa-*|sk-*) printf '%s\n' "$KEY" > /etc/nixos/user-ssh-key.pub; echo USER_KEY_SET ;;
  *) : > /etc/nixos/user-ssh-key.pub; echo NO_USER_KEY ;;
esac
git -C /etc/nixos add -A
nix flake lock /etc/nixos 2>&1 | grep -E "^error" || true
git -C /etc/nixos add -A
grep -c narHash /etc/nixos/flake.lock
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait** (repeat until it no longer says STILL RUNNING; about 1 minute):
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh base
```
Expect `CHECKS base PASS`.

**If it fails:** if the lock printed an `error` line about fetching, the machine can't reach github.com: wait one
minute and run the Do block again. On `REBUILD FAILED`, see **Recovery R1**.

---

## Step 4: Create the keys and the secrets file

First call `request_ai_key` with application `Hermes Agent` and purpose `The control center's own AI agent`.
The user approves it on a card. The reply gives the path of the key file on this machine. The Do block's first
line takes that path in place of `AI_KEY_PATH`; Farseed fills it in when you run the block by name. All values go
only into files, and nothing here prints them.

**Do**
```sh
sh -eu <<'STEP'
KEY_FILE='AI_KEY_PATH'
cd /var/lib/control-center
umask 077
install -m 600 -o root -g root "$KEY_FILE" ai-key
[ -s wg-server.key ] || wg genkey > wg-server.key
[ -s wg-user.key ] || wg genkey > wg-user.key
wg pubkey < wg-server.key > wg-server.pub
wg pubkey < wg-user.key > wg-user.pub
[ -s dashboard-password ] || tr -dc A-Za-z0-9 < /dev/urandom | head -c 24 > dashboard-password
[ -s dashboard-secret ] || od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > dashboard-secret
{
  echo "CONTROL_CENTER_AI_KEY=$(tr -d '\r\n' < ai-key)"
  echo "HERMES_DASHBOARD_BASIC_AUTH_USERNAME=owner"
  echo "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=$(cat dashboard-password)"
  echo "HERMES_DASHBOARD_BASIC_AUTH_SECRET=$(cat dashboard-secret)"
} > hermes.env
echo KEYS_WRITTEN
STEP
```
**Check** (run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh keys
```
Expect `CHECKS keys PASS`.

**If it fails:** `install: cannot stat` means no key file is at that path. Run the Do block again by name, so
Farseed fills in the path from the `request_ai_key` reply; if it fails the same way, call `request_ai_key` again,
then run the Do block again. The block never overwrites a WireGuard key or password that already exists, so
running it again is safe.

---

## Step 5: Hermes Agent with its web dashboard

The first two lines take the `AI_BASE_URL` and `AI_MODEL` facts inside their quotes; Farseed fills them in when
you run the block by name. The first Hermes build downloads and builds a lot: **expect 5 minutes, and up to 40
on a slow network.** Keep running the Wait block until it says REBUILD OK or REBUILD FAILED. Do nothing else
meanwhile.

**Do**
```sh
sh -eu <<'STEP'
URL='AI_BASE_URL'
MODEL='AI_MODEL'
cat > /etc/nixos/cc-hermes.nix <<'FILE'
{ ... }:
{
  services.hermes-agent = {
    enable = true;
    addToSystemPackages = true;
    # ACP: the protocol T3 Code uses to drive Hermes (adds `hermes-acp`).
    extraDependencyGroups = [ "acp" ];
    # Secrets (AI key, dashboard sign-in) live in this root-only file, never in /etc/nixos.
    environmentFiles = [ "/var/lib/control-center/hermes.env" ];
    settings.model = {
      provider = "custom:farseed-credit";
      base_url = "@ai_base_url@";
      default = "@ai_model@";
      key_env = "CONTROL_CENTER_AI_KEY";
    };
    settings.custom_providers = [ {
      name = "farseed-credit";
      base_url = "@ai_base_url@";
      key_env = "CONTROL_CENTER_AI_KEY";
      discover_models = false;
      models = [
        "@ai_model@"
        "anthropic/claude-opus-5.5"
        "anthropic/claude-sonnet-5.5"
      ];
      extra_body = { provider = { zdr = true; }; };
    } ];
    # Hermes' internal listener gets a fixed loopback port (otherwise a random one at every start).
    settings.webapp = { enabled = true; host = "127.0.0.1"; port = 9120; };
    # The web dashboard. A non-loopback bind turns on its sign-in gate; the firewall keeps the port
    # off the public interface (see cc-wireguard.nix).
    backend = {
      mode = "dashboard";
      host = "0.0.0.0";
      port = 9119;
    };
  };
}
FILE
sed -i -e "s|@ai_base_url@|$URL|" -e "s|@ai_model@|$MODEL|" /etc/nixos/cc-hermes.nix
grep -E 'base_url|default =' /etc/nixos/cc-hermes.nix
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait** (repeat; each call waits up to 4 minutes):
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh hermes
```
Expect `CHECKS hermes PASS`. The check itself waits up to 90 seconds for the dashboard to start answering.

**If it fails:** on `REBUILD FAILED`, see **Recovery R1**. If `hermes_backend_up` fails, look at
`journalctl -u hermes-backend -n 20 --no-pager | cut -c1-200` and report those lines. If the only FAIL line is
`gateway_on_loopback_9120`, Hermes is still starting (on a busy machine this can take about 2 minutes): wait 1
minute (`sleep 60`) and run the Check again, once.

---

## Step 6: Let the agent install more

After this step, Hermes can add a module to /etc/nixos/extra and apply it. Every command it flags as risky waits
for the user's approval in the chat. The step also puts the recipes Hermes follows for a Bitcoin node,
Tailscale, a wallet balance and Lightning in /etc/nixos/recipes (public text: no secret is in them).

Run **Recipes** first with `run_step_block` (step 6, block `Recipes`), then **Do** with
`run_step_block` (step 6, block `Do`), then Wait and Check by name.

**Recipes**
```sh
sh -eu <<'STEP'
install -d -m 0755 /etc/nixos/recipes
cat > /etc/nixos/recipes/bitcoin-node.md <<'RECIPE'
# Recipe: a pruned Bitcoin node, with Tailscale

Use it when the user asks for a Bitcoin node (this disk only fits a pruned one) or for Tailscale.

1. One rebuild for both. Copy the two module templates unchanged with the shell (don't write your own: tailscaled
   has no --operator flag; tailscale.nix sets the operator with services.tailscale.extraSetFlags), and apply:
   `cp /etc/nixos/recipes/bitcoin-node.nix /etc/nixos/recipes/tailscale.nix /etc/nixos/extra/ && systemctl start control-center-apply`
   - bitcoin-node.nix: Bitcoin Core, pruned, as services.bitcoind.main (data in /var/lib/bitcoind-main). Before its
     first start, a one-shot service streams the published pruned copy into a staging folder, checks its sha256
     (both read from https://lnvps.poc.asf0.org/snapshots/latest.json; about 12.5 GB, 5-15 minutes), and only then
     puts it in place.
   - tailscale.nix: Tailscale, with you (hermes) as its operator.
2. The Tailscale sign-in link comes first. Don't wait for the rebuild: every 15 seconds, for up to 3 minutes, run
   `timeout 20 tailscale up --operator=hermes` (keep the flag: a bare `tailscale up` drops you as operator). As
   soon as it prints a https://login.tailscale.com/... link, your next message, before any other command, must
   contain the full link alone in a code block: do
   not save it for your final reply, and do not send it through a message tool, which hides it in a collapsed
   card. Then carry on in the same turn. Don't wait for them to sign in; `tailscale status` shows the link again.
3. Wait for the rebuild: `tail -n 5 /var/log/cc-rebuild.log` about once a minute, until it ends with RESULT. If it
   failed, read `journalctl -u bitcoind-main-snapshot -n 20 --no-pager`.
4. Use the node from your own shell: `bitcoin-cli -datadir=/var/lib/bitcoind-main getblockchaininfo`. The module
   already lets you read its cookie: add no groups or ACLs yourself, and no systemd-run or second rebuild. It catches
   up from the copy in a few minutes. Check about once a minute until blocks equals headers, then tell the user the
   latest block (height and time) and that the node is pruned and synced.
RECIPE
cat > /etc/nixos/recipes/bitcoin-wallet.md <<'RECIPE'
# Recipe: the balance of a watch-only wallet

Use it when the user gives an xpub (or output descriptors) and asks for its balance. It needs the Bitcoin node
recipe done and caught up (blocks equals headers). Only public keys: never ask for a seed or an xprv.

- One command: no wallet, no rescan, no keys. It reads Core's set of unspent outputs, takes about 1-3 minutes, and
  only one scan can run at a time:
  `bitcoin-cli -datadir=/var/lib/bitcoind-main scantxoutset start '[{"desc":"wpkh(<xpub>/0/*)","range":[0,1999]},{"desc":"wpkh(<xpub>/1/*)","range":[0,1999]}]'`
  Put the user's xpub in place of `<xpub>`. Report total_amount in sats (BTC x 100,000,000) as the balance of the
  wallet's first 2,000 receive and 2,000 change addresses, with the number of unspent outputs and their block
  heights.
- Phone wallets mostly use native segwit (wpkh). If the total is 0 but the user expects funds, try the same with
  sh(wpkh(...)) and with pkh(...), or the descriptors the user gives. Core reads xpub keys only: for a zpub or a
  ypub, ask the user for the wallet's xpub or its descriptors.
RECIPE
cat > /etc/nixos/recipes/lightning-node.md <<'RECIPE'
# Recipe: a Lightning node (lnd), with a read-only Zeus link over Tailscale

Use it when the user asks for a Lightning node, lnd or a Zeus connection. It needs the Bitcoin node recipe done and
Tailscale signed in: if `tailscale ip -4` prints no 100.x address, show the user the link from `tailscale status`
and wait for them to sign in.

The node's wallet was made at set-up from a seed that the page handed to the user as a file (lnd-seed-....txt).
Never open, print, copy or look for that file. Before anyone puts money on the node, ask the
user whether they saved that file in their password manager. When they answer "saved", delete the machine's copy:
`systemctl start lnd-seed-delete`, and tell them it is gone. Until then, tell them plainly not to fund the node.
You only get its read-only macaroon, so you can't make an address, an invoice or a channel, and you must not try,
unless the user asks for payment access ("Payment access" below).

Install nothing else: no QR tools or other extras. The plain-text link is the result.

1. One rebuild. Copy the module template unchanged with the shell and apply:
   `cp /etc/nixos/recipes/lightning-node.nix /etc/nixos/extra/ && systemctl start control-center-apply`
   The module runs lnd as its own user (lnd) on the set-up's wallet (it unlocks itself), with no peers or
   channels, starts it once Core's RPC answers, and opens lnd's REST port 8080 only on tailscale0. Do not change
   Bitcoin Core's configuration; ZMQ is already on. Then `tail -n 5 /var/log/cc-rebuild.log` about once a minute,
   until it ends with RESULT. If lnd does not start because the wallet is missing (a machine set up before
   wallets were made at set-up), stop and tell the user: don't create a wallet yourself. If you ever need to
   restart lnd, ask the user and wait first, then run `systemctl restart lnd` (no rebuild needed).
2. lnd's state, read-only:
   `lncli --tlscertpath=/var/lib/lnd/tls.cert --macaroonpath=/var/lib/lnd-pub/readonly.macaroon getinfo`
   Repeat until synced_to_chain is true (usually under a minute once Core is at the tip). Tell the user the
   version, the block height and synced_to_chain. synced_to_graph stays false, because the node has no peers.
3. The Zeus link, with the read-only macaroon (it can show the node but never spend or receive):
   `lndconnect --lnddir=/var/lib/lnd --configfile=/etc/lnd/lnd.conf --tlscertpath=/var/lib/lnd/tls.cert --readonlymacaroonpath=/var/lib/lnd-pub/readonly.macaroon --readonly --host=$(tailscale ip -4) --port=8080 -j`
   Your next message, before any other command, must contain the full link as plain text in a code block: do not
   save it for a later reply, and do not send it through a message tool, which hides it in a collapsed card. In
   Zeus, the user copies it, accepts IMPORT, then SAVE; certificate verification is off
   by default. The phone needs the Tailscale app on, in the same tailnet.

**Payment access** (only when the user asks the node to pay or be paid)
Only after the seed file is deleted (the user said "saved"); the module refuses before that.
1. One rebuild. Copy the module template unchanged and apply:
   `cp /etc/nixos/recipes/lightning-pay.nix /etc/nixos/extra/ && systemctl start control-center-apply`
   As root it bakes /var/lib/lnd-pub/pay.macaroon, valid 2 days and allowed only the lnd calls that step 2's
   commands make. It works on this machine and through lnd's REST port from any device on the user's tailnet:
   anyone there who holds a copy can spend with it. Never print, copy or send it, and never read admin.macaroon.
   Renew it with `systemctl restart lnd-pay-macaroon`, which also revokes the old one. Keep nolisten, open no port, and change no
   other module.
2. Use it only as
   `lncli --tlscertpath=/var/lib/lnd/tls.cert --macaroonpath=/var/lib/lnd-pub/pay.macaroon <command>`, with these
   commands: getinfo, newaddress, connect, listpeers, openchannel, closechannel, pendingchannels, listchannels,
   decodepayreq, payinvoice, trackpayment, addinvoice, lookupinvoice, listpayments, listinvoices, walletbalance,
   listchaintxns, sendcoins and estimatefee. Use no other command except the read-only lookup below.
   lnd checks calls, not commands: it refuses calls outside that set, but another command made of the same calls
   still works. Never use closeallchannels,
   which closes every channel at once.
   To receive, always use `lncli ... addinvoice --private`, even for "give me an invoice": private channels need
   route hints. Put the invoice alone in a code block.
   To reach a peer: `lncli ... connect <pubkey>@<host>:<port>` (outbound only).
   After connect, look up its alias with the read-only key:
   `lncli --tlscertpath=/var/lib/lnd/tls.cert --macaroonpath=/var/lib/lnd-pub/readonly.macaroon getnodeinfo <pubkey>`.
   A node with no peers has no network map yet. If the lookup gives no alias, say so and ask the user.
   Before proposing a channel, show the peer's alias and public key. It must be able to route to the user's phone
   wallet. Say why in one sentence, including what you checked and what you couldn't check. If you can't establish
   that it can route there, pause and ask the user. For a user-supplied peer, show its alias and ask for confirmation.
3. Before every spend (opening or closing a channel, paying an invoice, sending on-chain), tell the user the exact
   command, the amount in sat and the fee (rate or limit), and wait for their yes. One yes is for one command.
   Channels are private (`--private`). If an open is refused, tell the user why and wait.
   Default payment fee limit: 1% of the amount, rounded up to whole sat, at least 10 sat and at most 50 sat.
   For a channel open, use the node's fee estimate, never above 10 sat/vB or 2,000 sat total fee. If the total
   fee can't be bounded, stop and ask. Anything outside these defaults needs the user to state the number;
   a general yes isn't enough. Still ask before every spend, showing the exact amount and fee rate or limit.
4. If a payment's result is unclear, never pay again: check it with
   `lncli ... listpayments --include_incomplete` and tell the user. After an unclear sendcoins, openchannel or
   closechannel, first check `lncli ... listchaintxns` and `lncli ... pendingchannels`, and never send again until
   that result is known.
5. After a channel opens or closes, record `date -Ins`, then copy the channel backup for the user:
   `systemctl start lnd-backup-copy`. Check `stat -c %y /var/lib/farseed-files-receipt/latest`, then read
   `cat /var/lib/farseed-files-receipt/latest`: the real name, then the size in bytes. If the receipt is missing
   or older than the copy you just started, say so and stop. Never compose a name. Tell the user, without waiting
   to be asked, that the backup is ready under "Get a file from this machine". Give its real name alone in a code
   block and its size, never its contents.
6. To end payment access: delete /etc/nixos/extra/lightning-pay.nix and apply. That removes the macaroon and, while
   lnd answers, revokes every copy of it. If lnd isn't answering at that moment, copies stay valid until they
   expire (at most 2 days), unless payment access is turned on again, which revokes them first.
RECIPE
cat > /etc/nixos/recipes/bitcoin-node.nix <<'RECIPE'
{ pkgs, ... }:
{
  # Bitcoin Core 32.1, pruned. It runs as bitcoind-main in its own group, never the hermes group: Hermes refuses
  # every new chat when another account shares its group. The agent (hermes) reads the RPC cookie through an ACL
  # (below), so its running shell can use bitcoin-cli at once, with no new group and no restart.
  services.bitcoind.main = {
    enable = true;
    # The Core version: this system's nixpkgs (32.1, the latest release on 2026-11-20). To bump, point this one line
    # at a newer pinned nixpkgs: (builtins.getFlake "github:NixOS/nixpkgs/<rev>?narHash=<hash>").legacyPackages.x86_64-linux.bitcoind
    package = pkgs.bitcoind;
    # Keep about a week of blocks (2000 MiB): lnd's new wallet rescans from 48 hours before its creation, and a
    # 550 MiB window (about 295 blocks) is just short of that, so lnd would need blocks Core has already pruned.
    prune = 2000;
    # Small machines (4 GiB): a smaller UTXO cache and mempool leave memory for the page cache, the agent and T3.
    dbCache = 300;
    # ZMQ is on from the start, so adding Lightning later never changes Core's config (no restart, no re-check).
    # checklevel=1: the startup check still reads the last 6 blocks and checks their validity, but skips the undo
    # and chainstate-disconnect levels, which on a small machine's disk take many minutes.
    # addnode: one reliable peer that serves blocks at once (Farseed's own node), so a silent peer can't hold the next
    # block while the node catches up after the copy.
    extraConfig = ''
      rpccookieperms=group
      listenonion=0
      maxmempool=50
      checklevel=1
      zmqpubrawblock=tcp://127.0.0.1:28332
      zmqpubrawtx=tcp://127.0.0.1:28333
      addnode=65.109.125.160:8333
    '';
  };

  # Core gives way on the disk to sshd, the agent and T3 when they need it, and its memory (page cache included) stays
  # at 60% of the machine's RAM, so its chainstate cache can grow without pushing the agent and T3 out of memory.
  # A fixed cap starves Core's cache on big machines; no cap starves everything else on small ones.
  systemd.services.bitcoind-main.serviceConfig = {
    MemoryHigh = "60%";
    IOWeight = 50;
    # Before every start, as root ("+"): hermes may enter the data directory, and what Core creates there from now
    # on, the RPC cookie included, is readable (never writable) by hermes and by Core's group (lnd). The cookie
    # stays 0640 (rpccookieperms=group), so no other user can read it.
    ExecStartPre = [
      "+${pkgs.coreutils}/bin/chown bitcoind-main:bitcoind-main /var/lib/bitcoind-main"
      "+${pkgs.acl}/bin/setfacl -m u:hermes:r-x,d:u:hermes:r-x,d:m::r-x /var/lib/bitcoind-main"
    ];
  };

  # Compressed swap in RAM: idle memory can move there, so the kernel stops evicting program code and file pages.
  zramSwap.enable = true;

  # Before Core's first start: stream the published pruned copy into a staging folder, check its sha256, and only
  # then move blocks/ and chainstate/ into place and write the completion marker (last). The address and the sha256
  # come from the manifest at run time. Core requires this unit, so it never starts on an unfinished import; an
  # unfinished one (no marker) is removed and redone on the next start.
  systemd.services.bitcoind-main-snapshot = {
    description = "Seed Bitcoin Core from the published pruned copy";
    requiredBy = [ "bitcoind-main.service" ];
    before = [ "bitcoind-main.service" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/bitcoind-main/.snapshot-complete";
    path = with pkgs; [ curl jq zstd gnutar coreutils ];
    environment.MANIFEST_URL = "https://lnvps.poc.asf0.org/snapshots/latest.json";
    serviceConfig = {
      Type = "oneshot";
      User = "bitcoind-main";
      StateDirectory = "bitcoind-main";
      StateDirectoryMode = "0770";
      PrivateTmp = true;
      TimeoutStartSec = "infinity";
      # The 12.5 GB stream must not fill memory with dirty pages or take the whole disk.
      MemoryHigh = "1G";
      IOWeight = 50;
    };
    script = ''
      set -euo pipefail
      cd /var/lib/bitcoind-main
      # No marker: anything here is an unfinished import. Start clean.
      rm -rf .snapshot-staging blocks chainstate
      mkdir .snapshot-staging
      m=$(curl -fsS --retry 5 --retry-delay 5 --retry-connrefused "$MANIFEST_URL")
      url=$(printf '%s' "$m" | jq -er .url)
      want=$(printf '%s' "$m" | jq -er .sha256)
      echo "snapshot: $url"
      fifo=$(mktemp -u)
      mkfifo "$fifo"
      ( set -o pipefail; zstd -dc < "$fifo" | tar -x -C .snapshot-staging -f - ) &
      unpack=$!
      got=$(curl -fsSL "$url" | tee "$fifo" | sha256sum | cut -d' ' -f1)
      wait "$unpack"
      if [ "$got" != "$want" ]; then
        echo "sha256 mismatch: got $got, want $want"
        rm -rf .snapshot-staging
        exit 1
      fi
      mv .snapshot-staging/blocks .snapshot-staging/chainstate .
      rm -rf .snapshot-staging
      sync -f .
      touch .snapshot-complete
      sync -f .
      echo "snapshot ok: sha256 $got"
    '';
  };
}
RECIPE
cat > /etc/nixos/recipes/tailscale.nix <<'RECIPE'
{ ... }:
{
  # Tailscale, with the agent's user as operator, so it can run `tailscale up` itself and show the sign-in link.
  services.tailscale = {
    enable = true;
    extraSetFlags = [ "--operator=hermes" ];
  };
}
RECIPE
STEP
```
**Do**
```sh
sh -eu <<'STEP'
cat > /etc/nixos/recipes/lightning-node.nix <<'RECIPE'
{ pkgs, config, ... }:
let
  # The lnd version: lnd's own static release binary (0.21.8-beta, the latest release on 2026-11-20), pinned by the
  # sha256 in its signed release manifest. One small download, no second nixpkgs to fetch or evaluate. This
  # system's nixpkgs has lnd 0.20.8, which refuses Bitcoin Core 32 ("node backend does not support taproot").
  # To bump: change the version and the sha256 (from manifest-v<version>.txt) together.
  lndVersion = "0.21.8-beta";
  lndSha256 = "4910a14801e10164ca2ea67f5935e2486874331d56bbd0638a68c6158a8e82c9";
  lnd = pkgs.runCommandLocal "lnd-${lndVersion}" {
    src = pkgs.fetchurl {
      url = "https://github.com/lightningnetwork/lnd/releases/download/v${lndVersion}/lnd-linux-amd64-v${lndVersion}.tar.gz";
      sha256 = lndSha256;
    };
  } ''
    mkdir -p $out/bin
    tar -xzf $src --strip-components=1 -C $out/bin
  '';
in
{
  # Core already publishes ZMQ (the Bitcoin node module), so this module never restarts Core.

  # lnd with the wallet made at set-up (Step 11) from the seed the user got through the page; lnd unlocks it itself
  # with the set-up's password file, also after a reboot. No peers, no channels. It runs as its own user, lnd. The
  # agent (hermes) gets only the read-only macaroon (in /var/lib/lnd-pub) and the TLS certificate
  # (/var/lib/lnd/tls.cert, public), so neither the agent nor Zeus can make an address or an invoice, or open a channel.
  # REST on 8080, reachable only over Tailscale. lnd puts every interface address it sees at its first start into
  # its TLS certificate, Tailscale's 100.x included (Tailscale is up before this module), and Zeus uses the
  # certificate carried in the link, so nothing machine-specific is written here.
  environment.etc."lnd/lnd.conf".text = ''
    [Application Options]
    wallet-unlock-password-file=/var/lib/lnd/wallet-password
    nolisten=true
    nobootstrap=true
    rpclisten=127.0.0.1:10009
    restlisten=0.0.0.0:8080
    readonlymacaroonpath=/var/lib/lnd-pub/readonly.macaroon

    [Bitcoin]
    bitcoin.mainnet=true
    bitcoin.node=bitcoind

    [Bitcoind]
    bitcoind.rpchost=127.0.0.1:8332
    bitcoind.rpccookie=/var/lib/bitcoind-main/.cookie
    bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332
    bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333
  '';

  environment.systemPackages = [ lnd pkgs.lndconnect ];

  users.users.lnd = { isSystemUser = true; group = "lnd"; };
  users.groups.lnd = { };
  # lnd's own data (admin macaroon, wallet, TLS key) stays private to lnd: /var/lib/lnd is 0711 (enter only, no
  # listing) and its data/, logs/ and tls.key are lnd-only. The read-only macaroon goes to lnd-pub, which hermes
  # can read.
  systemd.tmpfiles.rules = [ "d /var/lib/lnd-pub 0750 lnd hermes - -" ];

  systemd.services.lnd = {
    description = "Lightning Network Daemon";
    wantedBy = [ "multi-user.target" ];
    wants = [ "bitcoind-main.service" ];
    after = [ "bitcoind-main.service" ];
    # lnd stops and restarts with Core.
    partOf = [ "bitcoind-main.service" ];
    restartTriggers = [ config.environment.etc."lnd/lnd.conf".source ];
    serviceConfig = {
      User = "lnd";
      Group = "lnd";
      # Core's RPC cookie is readable by Core's own group. Never the hermes group: it would let lnd write into the
      # agent's home.
      SupplementaryGroups = [ "bitcoind-main" ];
      StateDirectory = "lnd";
      StateDirectoryMode = "0711";
      ExecStartPre = [
        # Make lnd-pub before every start (as root, "+"): on a live apply, tmpfiles and lnd start unordered.
        "+${pkgs.coreutils}/bin/install -d -m 0750 -o lnd -g hermes /var/lib/lnd-pub"
        # Only the wallet made at set-up (from the seed the user has): with none, lnd does not start at all.
        "+${pkgs.coreutils}/bin/test -s /var/lib/lnd/data/chain/bitcoin/mainnet/wallet.db"
        # Set-up made the wallet as root; lnd owns its data whatever order things ran in.
        "+${pkgs.coreutils}/bin/chown -R lnd:lnd /var/lib/lnd/data"
        # lnd's own copy of the wallet password (root-only original from set-up), so it unlocks without anyone.
        "+${pkgs.coreutils}/bin/install -m 0400 -o lnd -g lnd /var/lib/control-center/lnd-wallet-password /var/lib/lnd/wallet-password"
        # Start lnd only once Core's RPC answers (Core's startup check can take minutes), not in a retry loop.
        "${config.services.bitcoind.main.package}/bin/bitcoin-cli -datadir=/var/lib/bitcoind-main -rpcwait -rpcwaittimeout=3600 getblockcount"
      ];
      ExecStart = "${lnd}/bin/lnd --lnddir=/var/lib/lnd --configfile=/etc/lnd/lnd.conf";
      TimeoutStartSec = "infinity";
      Restart = "on-failure";
      RestartSec = 30;
    };
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ 8080 ];

  # Once the user says they saved the seed file (handed over at set-up, root-only in /var/lib/control-center), the
  # agent deletes the machine's copy. It must find exactly one file; the agent never opens it.
  systemd.services.lnd-seed-delete = {
    description = "Delete the Lightning seed file the page handed to the user";
    path = [ pkgs.coreutils pkgs.findutils ];
    serviceConfig.Type = "oneshot";
    script = ''
      set -eu
      n=$(find /var/lib/control-center -maxdepth 1 -name 'lnd-seed-*.txt' -type f | wc -l)
      [ "$n" -eq 1 ] || { echo "expected exactly one seed file, found $n"; exit 1; }
      find /var/lib/control-center -maxdepth 1 -name 'lnd-seed-*.txt' -type f -exec shred -u {} +
      [ "$(find /var/lib/control-center -maxdepth 1 -name 'lnd-seed-*.txt' | wc -l)" -eq 0 ]
      echo "seed file deleted"
    '';
  };

  # The agent may start, stop and restart lnd, and start the seed deletion (nothing else through this rule).
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" &&
          ((action.lookup("unit") == "lnd.service" &&
            ["start", "stop", "restart"].indexOf(action.lookup("verb")) >= 0) ||
           (action.lookup("unit") == "lnd-seed-delete.service" && action.lookup("verb") == "start")) &&
          subject.user == "hermes") {
        return polkit.Result.YES;
      }
    });
  '';
}
RECIPE
cat > /etc/nixos/recipes/lightning-pay.nix <<'RECIPE'
{ pkgs, lib, ... }:
# Payment access for the agent (only when the user asks the node to pay and be paid). Copy unchanged.
# - A root one-shot bakes /var/lib/lnd-pub/pay.macaroon (root:hermes 0440), valid 2 days and allowed exactly the lnd
#   calls the recipe uses (the list below): no macaroon, signing, backup, abandon or delete rights.
#   It works on this machine and through lnd's REST port 8080 from any device on the user's tailnet: anyone there who
#   holds a copy of the file can spend with it.
#   lnd enforces that list of calls, not lncli commands: an lncli command made only of those calls works too (for
#   example closeallchannels), so the recipe tells the agent which commands to use.
# - It is baked under its own root key. Every bake first deletes that key. Whenever the unit stops (removing this
#   module, a restart, or a start that failed or was killed after the file was written), ExecStopPost removes the
#   file and deletes the key: that revokes every copy, wherever it is. That deletion needs lnd to answer; if it
#   doesn't, copies stay valid until they expire (at most 2 days), unless a new bake revokes them first.
# - It refuses while the set-up seed file is still on the machine (the user hasn't said "saved").
# - lnd-backup-copy.service copies lnd's channel backup into /var/lib/farseed-files for the user (root-only there).
# - The agent may start (or restart, to renew) the bake and start the copy; nothing else through this rule.
# The agent never reads admin.macaroon. nolisten stays; no port is opened.
let
  lncli = "/run/current-system/sw/bin/lncli --rpcserver=127.0.0.1:10009 --tlscertpath=/var/lib/lnd/tls.cert";
  admin = "/var/lib/lnd/data/chain/bitcoin/mainnet/admin.macaroon";
  out = "/var/lib/lnd-pub/pay.macaroon";
  # This macaroon's own root key (0 is lnd's default key, which the other macaroons use): deleting it revokes this
  # macaroon and nothing else.
  keyId = "7301";
  # Exactly the calls the recipe uses.
  calls = [
    "/lnrpc.Lightning/GetInfo"
    "/lnrpc.Lightning/NewAddress"
    "/lnrpc.Lightning/ConnectPeer"
    "/lnrpc.Lightning/ListPeers"
    "/lnrpc.Lightning/OpenChannel"
    "/lnrpc.Lightning/CloseChannel"
    "/lnrpc.Lightning/PendingChannels"
    "/lnrpc.Lightning/ListChannels"
    "/lnrpc.Lightning/DecodePayReq"
    "/routerrpc.Router/SendPaymentV2"
    "/routerrpc.Router/TrackPaymentV2"
    "/lnrpc.Lightning/AddInvoice"
    "/lnrpc.Lightning/LookupInvoice"
    "/lnrpc.Lightning/ListPayments"
    "/lnrpc.Lightning/ListInvoices"
    "/lnrpc.Lightning/WalletBalance"
    "/lnrpc.Lightning/GetTransactions"
    "/lnrpc.Lightning/SendCoins"
    "/lnrpc.Lightning/EstimateFee"
  ];
  revoke = "${lncli} --macaroonpath=${admin} deletemacaroonid ${keyId}";
  stop = pkgs.writeShellScript "lnd-pay-macaroon-stop" ''
    ${pkgs.coreutils}/bin/rm -f ${out} ${out}.tmp
    if ${revoke} > /dev/null; then
      echo "payment macaroon revoked (root key ${keyId} deleted)"
    else
      echo "could not revoke now (is lnd running?): copies stay valid until they expire (at most 2 days), unless a new bake revokes them first"
    fi
  '';
in
{
  systemd.services.lnd-pay-macaroon = {
    description = "Bake the agent's limited lnd payment macaroon";
    wantedBy = [ "multi-user.target" ];
    after = [ "lnd.service" ];
    wants = [ "lnd.service" ];
    path = [ pkgs.coreutils pkgs.findutils ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
      TimeoutStartSec = "infinity";
      # ExecStopPost, not ExecStop: it also runs after a failed or killed start.
      ExecStopPost = "${stop}";
    };
    script = ''
      set -eu
      n=$(find /var/lib/control-center -maxdepth 1 -name 'lnd-seed-*.txt' -type f | wc -l)
      [ "$n" -eq 0 ] || { echo "the seed file is still on the machine: the user must save it first"; exit 1; }
      until ${lncli} --macaroonpath=${admin} getinfo > /dev/null 2>&1; do sleep 10; done
      rm -f ${out}.tmp
      # Revoke every earlier copy before making a new one.
      ${revoke} > /dev/null
      ${lncli} --macaroonpath=${admin} bakemacaroon --root_key_id ${keyId} --timeout 172800 --save_to ${out}.tmp \
        ${lib.concatMapStringsSep " " (c: "uri:${c}") calls} > /dev/null
      chown root:hermes ${out}.tmp
      chmod 0440 ${out}.tmp
      mv ${out}.tmp ${out}
      echo "payment macaroon baked: ${out} (own root key ${keyId}, 2 days)"
    '';
  };

  systemd.services.lnd-backup-copy = {
    description = "Copy lnd's channel backup into /var/lib/farseed-files";
    path = [ pkgs.coreutils ];
    serviceConfig = { Type = "oneshot"; UMask = "0077"; };
    script = ''
      set -eu
      install -d -m 0700 /var/lib/farseed-files
      name="channel-backup-$(date -u +%Y%m%dT%H%M%SZ).backup"
      install -m 0600 /var/lib/lnd/data/chain/bitcoin/mainnet/channel.backup "/var/lib/farseed-files/$name"
      echo "copied: /var/lib/farseed-files/$name ($(stat -c %s "/var/lib/farseed-files/$name") bytes)"
      (
        receipt=/var/lib/farseed-files-receipt
        install -d -o root -g hermes -m 0750 "$receipt" &&
          size=$(stat -c %s "/var/lib/farseed-files/$name") &&
          printf '%s\n%s\n' "$name" "$size" > "$receipt/latest.tmp" &&
          chown root:hermes "$receipt/latest.tmp" &&
          chmod 0440 "$receipt/latest.tmp" &&
          mv -f "$receipt/latest.tmp" "$receipt/latest"
      ) || echo "backup copied; receipt not updated"
    '';
  };

  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "hermes" &&
          ((action.lookup("unit") == "lnd-pay-macaroon.service" &&
            ["start", "restart"].indexOf(action.lookup("verb")) >= 0) ||
           (action.lookup("unit") == "lnd-backup-copy.service" && action.lookup("verb") == "start"))) {
        return polkit.Result.YES;
      }
    });
  '';
}
RECIPE
cat > /etc/nixos/recipes/stronger-agent-model.md <<'RECIPE'
# Recipe: a stronger model for this agent

To use a stronger model for this agent, follow these steps only when the user asks.

1. Before applying, tell the user plainly:
   - The agent's AI key has a 5 USD cap, roughly a dozen turns of the stronger model. When it runs out, the
     agent stops answering until the key is renewed from the page.
   - The credit service lists this model on its weaker 'anon' tier. This agent still asks for zero retention on
     every request, and the service accepted that for this model in a test on 2026-11-22. Whether the upstream
     provider keeps nothing is the service's promise; Farseed can't check it.
   Ask the user whether to apply this change, including undo if the read-back fails, and wait for their approval.
2. Write /etc/nixos/extra/agent-model.nix with the shell (`cat >`), using this module. The model id is on its
   own line so it is easy to change:

       { lib, ... }:
       {
         services.hermes-agent.settings = lib.mkAfter { model.default =
           "anthropic/claude-sonnet-5.5";
         };
       }

   Change only the model default. Leave the connection settings and AI key alone; keep zero retention on every
   request.
3. Run `systemctl start control-center-apply`. Read `tail -n 5 /var/log/cc-rebuild.log` about once a minute until
   it ends with RESULT. Continue only on `RESULT 0`. If it fails or the result is unclear, stop and tell the user.
4. Run the read-only command `HERMES_HOME=/var/lib/hermes/.hermes hermes config get model.default`. It
   reads `model.default` from /var/lib/hermes/.hermes/config.yaml. Confirm the printed value equals the model id in step 2.
   If the command fails or the value differs, tell the user and undo the change they approved:
   delete /etc/nixos/extra/agent-model.nix, then apply again and wait for `RESULT 0` as in step 3. Do not report success.
5. The new model applies to conversations started after the change: start a new T3 thread.

To undo: ask the user and wait before applying, delete /etc/nixos/extra/agent-model.nix, then apply and wait for
`RESULT 0` as in step 3. In a new T3 thread, the agent returns to the set-up model.
RECIPE
chmod 0644 /etc/nixos/recipes/bitcoin-node.md /etc/nixos/recipes/bitcoin-wallet.md /etc/nixos/recipes/lightning-node.md /etc/nixos/recipes/bitcoin-node.nix /etc/nixos/recipes/tailscale.nix /etc/nixos/recipes/lightning-node.nix /etc/nixos/recipes/lightning-pay.nix
chmod 0644 /etc/nixos/recipes/stronger-agent-model.md
cat > /etc/nixos/cc-agent.nix <<'FILE'
{ config, lib, ... }:
{
  # Lets the machine's own agent install more, the same declarative way: it writes one module
  # into /etc/nixos/extra and starts control-center-apply.service, which runs the rebuild as root.
  # Every terminal command the agent flags as risky waits for the user's approval in the chat.
  services.hermes-agent.settings.approvals.mode = "manual";

  services.hermes-agent.workingDirectory = "/var/lib/hermes/workspace";
  services.hermes-agent.documents."AGENTS.md" = ''
    This machine runs NixOS and is configured only through /etc/nixos (a flake, output "control").
    To install or change something: write ONE file /etc/nixos/extra/<name>.nix (a NixOS module),
    then run: systemctl start control-center-apply
    then read the result: tail -n 5 /var/log/cc-rebuild.log  (it ends with "RESULT 0" on success).
    Never put a password, key or token in a .nix file: the Nix store is readable by everyone.
    To undo: delete your file and start control-center-apply again.
    Write files under /etc/nixos with the shell (cp, cat >): the file tool refuses paths under /etc.
    Give the user links and results as plain text in your reply, not through a message tool.
    Put anything the user must copy (an address, an invoice, a file name, a link) alone in a code block.
    Before stopping or restarting a service, applying a rebuild, a large download, a new recurring automation or
    any spend, ask the user and wait, in every access mode.
    Recipes for common requests are in recipes/ next to this file: bitcoin-node.md (a pruned Bitcoin node and
    Tailscale), bitcoin-wallet.md (a watch-only wallet's balance), lightning-node.md (lnd, a read-only
    Zeus link, and payment access when the user wants the node to pay or be paid), and stronger-agent-model.md
    (a stronger model for this agent, only when asked). Read the matching recipe
    first and follow it. The Lightning node's seed was handed to the user
    at set-up: before anyone funds the node, make sure they saved it (lightning-node.md).
  '';
  # The recipes the lines above point to. The module files they copy are in /etc/nixos/recipes.
  services.hermes-agent.documents."recipes/bitcoin-node.md" = ./recipes/bitcoin-node.md;
  services.hermes-agent.documents."recipes/bitcoin-wallet.md" = ./recipes/bitcoin-wallet.md;
  services.hermes-agent.documents."recipes/lightning-node.md" = ./recipes/lightning-node.md;
  services.hermes-agent.documents."recipes/stronger-agent-model.md" = ./recipes/stronger-agent-model.md;
  # Read in every session, whatever folder T3 starts it in (a "No project" thread starts outside the workspace).
  services.hermes-agent.hermesHomeFiles."SOUL.md" = ''
    Before stopping or restarting a service, applying a rebuild, a large download, a new recurring automation or
    any spend, ask the user and wait, in every access mode.

    You are Hermes Agent, built by Nous Research. Be direct: match the length of your reply to the weight of the ask — a one-line question gets a one-line answer, and finished work gets a short report of what changed, what's verified, and what's left, never a replay of the process. No filler ("Great question," "I'd be happy to"), no restating the request back, no re-summarizing what you already said, no narrating tool calls the user can see. Plain claims over adjectives; when unsure, say so plainly. Agree because it's right, not because the user said it. Depth is earned — give it when the user asks for detail, teaches, or the stakes demand it, not by default.

    You are the agent of this NixOS machine. Your instructions for it are in /var/lib/hermes/workspace/AGENTS.md, and
    the recipes it names are in /var/lib/hermes/workspace/recipes/. Read AGENTS.md before you act in every
    conversation, whatever folder the conversation starts in, and follow it. You have no sudo: change this machine only
    the way AGENTS.md says.
  '';

  systemd.tmpfiles.rules = [ "d /etc/nixos/extra 2775 root hermes - -" ];
  systemd.services.hermes-agent.serviceConfig.ReadWritePaths = [ "/etc/nixos/extra" ];
  systemd.services.hermes-backend.serviceConfig.ReadWritePaths = [ "/etc/nixos/extra" ];

  # Hermes refuses every new chat when another account shares its group (its home is group-writable). So no other
  # account may have the hermes group, as its own group or as a member, and no service running as another user may
  # get it (Group= or SupplementaryGroups=). A module that breaks this fails the rebuild before anything changes.
  assertions =
    let
      h = config.services.hermes-agent.group;
      me = config.services.hermes-agent.user;
      extra = c: lib.concatMap (g: lib.splitString " " (toString g)) (lib.toList (c.SupplementaryGroups or [ ]));
      accounts = lib.unique (lib.remove me config.users.groups.${h}.members ++ lib.attrNames
        (lib.filterAttrs (_: u: u.name != me && (u.group == h || lib.elem h u.extraGroups)) config.users.users));
      services = lib.attrNames (lib.filterAttrs (_: s: toString (s.serviceConfig.User or me) != me
        && (toString (s.serviceConfig.Group or "") == h || lib.elem h (extra s.serviceConfig))) config.systemd.services);
    in
    [ {
      assertion = accounts == [ ] && services == [ ];
      message = "The ${h} group must stay the agent's own (Hermes refuses new chats otherwise). Shared by accounts: ${toString accounts}; services: ${toString services}.";
    } ];

  systemd.services.control-center-apply = {
    description = "Apply /etc/nixos for the agent";
    serviceConfig.Type = "oneshot";
    serviceConfig.ExecStart = "/run/current-system/sw/bin/sh /etc/nixos/cc-rebuild.sh";
  };

  # The agent's user may start that one unit, nothing else. (The image has polkit off.)
  security.polkit.enable = true;
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" &&
          action.lookup("unit") == "control-center-apply.service" &&
          action.lookup("verb") == "start" &&
          subject.user == "hermes") {
        return polkit.Result.YES;
      }
    });
  '';
}
FILE
touch /var/log/cc-rebuild.log && chown root:hermes /var/log/cc-rebuild.log && chmod 0640 /var/log/cc-rebuild.log
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait**
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (run it alone, exactly as written; it asks for one rebuild as the hermes user, the way the agent will, and takes up to a minute):
```sh
sh /etc/nixos/cc-check.sh agent
```
Expect `CHECKS agent PASS`.

**If it fails:** if `apply_rule_present` fails, the new module wasn't applied. Run the Do block
again exactly, then the Wait, then the Check.

---

## Step 7: T3 Code, driving Hermes

T3 Code is the user's main way in. It runs as a service, and it drives Hermes over ACP (Hermes' `hermes-acp`
command). Its Check, run after the Do and the Wait as always, also adds this machine's workspace as a T3
project.

**Do**
```sh
sh -eu <<'STEP'
cat > /etc/nixos/cc-t3.nix <<'FILE'
{ pkgs, config, ... }:
let
  # T3 Code's headless server for Linux (no Electron): one Node single-executable plus its web client.
  # Pinned release v0.1.10; the hash is the one in the release's SHA256SUMS.
  t3 = pkgs.stdenvNoCC.mkDerivation {
    pname = "t3code-server";
    version = "0.1.10";
    src = pkgs.fetchurl {
      url = "https://github.com/pingdotgg/t3code/releases/download/v0.1.10/t3-0.1.10-linux-x64.tar.gz";
      sha256 = "9bea9d36a217299a0af880e8c347b536ed6a9a2f5bf328a695d174d63628c5e8";
    };
    # The executable carries its program inside; it runs unpatched through nix-ld.
    dontConfigure = true;
    dontBuild = true;
    dontFixup = true;
    installPhase = ''
      mkdir -p $out/libexec $out/bin
      cp -r . $out/libexec/t3
      ln -s $out/libexec/t3/t3 $out/bin/t3
    '';
  };
  # T3 Connect's tunnel client, from nixpkgs. T3 asks it for a metrics port of 0 (a random one); this wrapper
  # pins that loopback port to 20241, so every listener on the machine has a fixed, declared port.
  cloudflared = pkgs.writeShellScript "cloudflared" ''
    args=()
    for a in "$@"; do [ "$a" = "127.0.0.1:0" ] && a="127.0.0.1:20241"; args+=("$a"); done
    exec ${pkgs.cloudflared}/bin/cloudflared "''${args[@]}"
  '';
  # T3 drives Hermes over ACP as a local command. Merged into T3's settings at each start; other settings stay.
  provider = pkgs.writeText "t3-hermes-provider.json" (builtins.toJSON {
    providerInstances.hermes = {
      driver = "acpRegistry";
      displayName = "Hermes Agent";
      config = { source = "local"; commandPath = "/run/current-system/sw/bin/hermes-acp"; commandArgs = [ ]; };
    };
  });
  env = "HOME=/var/lib/t3code T3CODE_HOME=/var/lib/t3code T3CODE_CLOUDFLARED_PATH=${cloudflared} "
    + "NIX_LD=/run/current-system/sw/share/nix-ld/lib/ld.so NIX_LD_LIBRARY_PATH=/run/current-system/sw/share/nix-ld/lib";
  # `t3c <args>`: the T3 CLI as the T3 service's user, with its home (for sign-in and status checks).
  t3c = pkgs.writeShellScriptBin "t3c" ''
    exec /run/wrappers/bin/sudo -u ${config.services.hermes-agent.user} ${pkgs.coreutils}/bin/env ${env} ${t3}/bin/t3 "$@"
  '';
in
{
  programs.nix-ld.enable = true;
  environment.systemPackages = [ t3 t3c ];

  # T3 Code runs as the hermes user, so the Hermes it starts shares the dashboard's memory, settings and key.
  systemd.services.t3code = {
    description = "T3 Code server";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "hermes-agent.service" ];
    wants = [ "network-online.target" ];
    path = [ pkgs.git pkgs.coreutils pkgs.bash "/run/current-system/sw" ];
    environment = {
      HOME = "/var/lib/t3code";
      T3CODE_HOME = "/var/lib/t3code";
      T3CODE_CLOUDFLARED_PATH = "${cloudflared}";
      HERMES_HOME = "/var/lib/hermes/.hermes";
      NIX_LD = "/run/current-system/sw/share/nix-ld/lib/ld.so";
      NIX_LD_LIBRARY_PATH = "/run/current-system/sw/share/nix-ld/lib";
    };
    preStart = ''
      mkdir -p /var/lib/t3code/userdata
      s=/var/lib/t3code/userdata/settings.json
      [ -s $s ] || echo '{}' > $s
      ${pkgs.jq}/bin/jq -s '.[0] * .[1]' $s ${provider} > $s.new && mv $s.new $s && chmod 600 $s
    '';
    serviceConfig = {
      User = config.services.hermes-agent.user;
      Group = config.services.hermes-agent.group;
      StateDirectory = "t3code";
      StateDirectoryMode = "0700";
      WorkingDirectory = "/var/lib/hermes/workspace";
      ExecStart = "${t3}/bin/t3 serve";
      Restart = "always";
      RestartSec = 5;
    };
  };
}
FILE
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait**
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (run it alone, exactly as written)
```sh
sh -c 't3c project add /var/lib/hermes/workspace --title control-center >/dev/null 2>&1; sh /etc/nixos/cc-check.sh t3'
```
Expect `CHECKS t3 PASS`. The check waits up to a minute for T3 to start and to report Hermes as ready.

**If it fails:** on `REBUILD FAILED`, see **Recovery R1**. If `t3_sees_hermes_ready` fails, run
`systemctl restart t3code`, wait 30 seconds, and check again.

---

## Step 8: T3 Connect (the user approves this machine)

Do this step now: run its Do block first, unless you already have. WireGuard is Step 9: it comes only after
this step's `CHECKS connect PASS`.

This links the machine to the user's T3 account, so the user reaches T3 Code from app.t3.codes or the T3 apps,
with no open port. Nothing is typed back on this machine: it notices the user's approval by itself. The user may
also choose `Later`: T3 Code still runs here, not linked yet, and the user's files say how to link it.

1. Run the Do block. It prints a sign-in link (`https://accounts.t3.codes/device?user_code=...`) and its code. The
   link expires after 10 minutes.
2. Then call `ask_operator` with:
   - `purpose`: `Approve this machine in your T3 account: open the link, check the code, approve. Or choose Later to link it afterwards`;
   - `link`: the printed `https://accounts.t3.codes/device?user_code=...` address, copied exactly;
   - `choices`: `["Approved", "Later"]`.

   The user opens the link in a browser signed in to their T3 account (or creates the account there: email and
   password, or Google, GitHub, Apple or Microsoft), checks the code and approves.
3. If the answer is `Approved`, run the Wait block, then the Check. If the answer is `Later`, run the Later block
   (not the Wait block). It ends by running the Check itself: the step is done only when its output's last line
   is `CHECKS connect PASS`.

**Do**
```sh
sh -eu <<'STEP'
rm -f /var/lib/control-center/t3-link-later
L=/var/lib/t3code/connect.log
if ! systemctl is-active -q t3-connect; then
  install -m 600 -o hermes -g hermes /dev/null $L
  systemd-run -q -u t3-connect --collect -p StandardOutput=append:$L -p StandardError=append:$L \
    /run/current-system/sw/bin/t3c connect link --headless
fi
for i in $(seq 30); do grep -q 'user_code=' $L && break; sleep 1; done
grep -E 'user_code=|^Code:' $L | tail -n 2
if grep -q 'user_code=' $L; then echo "LINK READY: the sign-in waits in the background for 10 minutes. Next: call ask_operator with this link."
else echo "NO LINK YET: run this block again."; fi
STEP
```
**Wait** (each call waits up to 4 minutes; repeat while it says STILL WAITING):
```sh
sh <<'STEP'
ok() { grep -q 'to make this machine reachable' /var/lib/t3code/connect.log; }
for i in $(seq 40); do ok && break; systemctl is-active -q t3-connect || break; sleep 5; done
if ok; then
  for i in $(seq 6); do systemctl is-active -q t3-connect || break; sleep 5; done
  systemctl restart t3code; echo "APPROVED: T3 Code restarted to apply the link and open the tunnel"
elif systemctl is-active -q t3-connect; then echo "STILL WAITING for the user's approval. Run the same Wait block again."
else echo "SIGN-IN ENDED without approval (expired or cancelled): run the Do block again and ask the user again."; fi
STEP
```
**Later** (when the answer is `Later`; it ends the waiting sign-in, records the choice and runs the Check):
```sh
sh <<'STEP'
systemctl stop t3-connect 2>/dev/null || true
install -m 600 -o root -g root /dev/null /var/lib/control-center/t3-link-later
echo "LATER: T3 Code: not linked yet."
sh /etc/nixos/cc-check.sh connect
STEP
```
**Check** (the Later block already ends with it; after the Wait block, or to check again, run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh connect
```
Expect `CHECKS connect PASS`. After `Approved`, the check waits up to 2 minutes for the tunnel to connect. After
`Later`, it prints `T3 Code: not linked yet` and checks that T3 Code runs and no sign-in is left waiting.

**If it fails:** if the Wait said SIGN-IN ENDED, or a FAIL line says `(needs the user: ask_operator)`, run the Do
block again (a new link) and call `ask_operator` again. If only `t3_tunnel_connected` fails, without that note,
run `systemctl restart t3code`, wait one minute, and check again. If `t3_link_later_no_signin_waiting` fails, run
the Later block again; if `t3_link_later_t3code_up` fails, run `systemctl restart t3code`, wait one minute, and
check again.

---

## Step 9: WireGuard (the second way in)

**Do**
```sh
sh -eu <<'STEP'
cat > /etc/nixos/cc-wireguard.nix <<'FILE'
{ ... }:
{
  # The second way in: a WireGuard VPN. UDP 51820 is its one public port; the dashboard port 9119 is open on the
  # WireGuard interface only, never on the public one.
  networking.firewall.enable = true;
  networking.firewall.allowedUDPPorts = [ 51820 ];
  networking.firewall.interfaces.wg0.allowedTCPPorts = [ 9119 ];

  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.88.0.1/24" ];
    listenPort = 51820;
    # Generated in the keys step; root-only file outside the Nix store.
    privateKeyFile = "/var/lib/control-center/wg-server.key";
    peers = [
      { publicKey = "@wg_user_public_key@"; allowedIPs = [ "10.88.0.2/32" ]; }
    ];
  };
}
FILE
sed -i "s|@wg_user_public_key@|$(cat /var/lib/control-center/wg-user.pub)|" /etc/nixos/cc-wireguard.nix
grep -c 'publicKey = "' /etc/nixos/cc-wireguard.nix
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait** (about 1 minute):
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh wireguard
```
Expect `CHECKS wireguard PASS`.

**If it fails:** on `REBUILD FAILED`, see **Recovery R1**. If `wg0_peer_is_user_key` fails, run the Do block
again (it rewrites the file).

---

## Step 10 (only if `TOR` is `yes`; otherwise skip to Step 11): Tor

**Do**
```sh
sh -eu <<'STEP'
cat > /etc/nixos/cc-tor.nix <<'FILE'
{ ... }:
{
  # Optional way in: a Tor onion service whose port 80 leads to the dashboard on loopback.
  services.tor = {
    enable = true;
    # Local SOCKS port 127.0.0.1:9050, used to check the onion address from the machine itself.
    client.enable = true;
    relay.onionServices.control-center.map = [
      { port = 80; target = { addr = "127.0.0.1"; port = 9119; }; }
    ];
  };
}
FILE
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait** (about 1 minute):
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh tor
```
Expect `CHECKS tor PASS`. The check waits up to a minute for Tor to make the onion address.

**If it fails:** on `REBUILD FAILED`, see **Recovery R1**.

---

## Step 11: The user's files

The Do block takes the `MACHINE_ADDRESS` fact (an IP address or a name, without a port); Farseed fills it in
when you run the block by name.

**Do**
```sh
sh -eu <<'STEP'
S=/var/lib/control-center
U=$(cat $S/login-user); H=$(getent passwd "$U" | cut -d: -f6)
ONION=$(cat /var/lib/tor/onion/control-center/hostname 2>/dev/null || true)
umask 077
{
  echo "[Interface]"
  echo "PrivateKey = $(cat $S/wg-user.key)"
  echo "Address = 10.88.0.2/32"
  echo ""
  echo "[Peer]"
  echo "PublicKey = $(cat $S/wg-server.pub)"
  echo "Endpoint = MACHINE_ADDRESS:51820"
  echo "AllowedIPs = 10.88.0.1/32"
  echo "PersistentKeepalive = 25"
} > "$H/wireguard.conf"
{
  echo "Your control center"
  echo ""
  if [ -e $S/t3-link-later ]; then
    echo "T3 Code: not linked yet."
    echo "T3 Code runs on this machine, but the machine isn't linked to a T3 account yet, so app.t3.codes and the"
    echo "T3 apps can't reach it. To link it, run as root on this machine:"
    echo "  t3c connect link --headless"
    echo "open the link it prints, check the code and approve, then run: systemctl restart t3code"
    echo "After that, open https://app.t3.codes, choose this machine, and start a thread with Hermes Agent."
  else
    echo "T3 Code (main way in): open https://app.t3.codes (or the T3 desktop or phone app), sign in to the T3"
    echo "account you approved this machine with, choose this machine, and start a thread with Hermes Agent."
  fi
  echo ""
  echo "Hermes dashboard over WireGuard: import wireguard.conf from this folder, then open http://10.88.0.1:9119/"
  echo "user: owner"
  echo "password: $(cat $S/dashboard-password)"
  [ -n "$ONION" ] && echo "Over Tor (Tor Browser): http://$ONION/ with the same user and password"
} > "$H/control-center-login.txt"
{ echo "http://10.88.0.1:9119/"; [ -n "$ONION" ] && echo "http://$ONION/"; } > "$H/app-url.txt"
chmod 600 "$H/wireguard.conf" "$H/control-center-login.txt"; chmod 644 "$H/app-url.txt"
chown "$U": "$H/wireguard.conf" "$H/control-center-login.txt" "$H/app-url.txt"
# The Lightning wallet (used only if the user later asks for a Lightning node). Its seed goes to the user now,
# through the page like the files above, as a root-only file; never printed. A rerun never makes a second seed: with
# a complete wallet it offers the one seed file again (until the user has it deleted); anything half made stops here.
W=/var/lib/lnd/data/chain/bitcoin/mainnet
SEEDS=$(find $S -maxdepth 1 -name 'lnd-seed-*.txt' -type f | wc -l)
if [ -e $W/wallet.db ] || [ -e $S/lnd-wallet-password ] || [ -e $S/lnd-new ] || [ "$SEEDS" -gt 0 ]; then
  if [ ! -e $W/wallet.db ] || [ ! -e $S/lnd-wallet-password ] || [ -e $S/lnd-new ] || [ "$SEEDS" -gt 1 ]; then
    echo "STOP: a half-made Lightning wallet is on this machine; don't make another seed. Report this."; exit 1
  fi
else
  L=$(nix build --no-link --print-out-paths --inputs-from /etc/nixos nixpkgs#lndinit)/bin/lndinit
  install -d -m 0700 $S/lnd-new
  $L gen-seed > $S/lnd-new/seed
  $L gen-password > $S/lnd-new/password
  install -d -m 0700 $W
  $L init-wallet --network=mainnet --secret-source=file --file.seed=$S/lnd-new/seed \
    --file.wallet-password=$S/lnd-new/password --init-type=file --init-file.output-wallet-dir=$W > /dev/null 2>&1
  test -s $W/wallet.db
  install -m 0600 $S/lnd-new/seed "$S/lnd-seed-$(date -u +%Y%m%dT%H%MZ)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n').txt"
  mv $S/lnd-new/password $S/lnd-wallet-password
  shred -u $S/lnd-new/seed
  rmdir $S/lnd-new
fi
SEED=$(find $S -maxdepth 1 -name 'lnd-seed-*.txt' -type f)
echo FILES_WRITTEN; echo "OFFER $H/wireguard.conf"; echo "OFFER $H/control-center-login.txt"
if [ -n "$SEED" ]; then echo "OFFER $SEED"; fi
STEP
```
Then call `offer_file` for each `OFFER` path the block printed, so the user can download them from the page:
- the `wireguard.conf` path: label `WireGuard connection file`, why `Import it in your WireGuard app to reach
  the dashboard privately`;
- the `control-center-login.txt` path: label `Control center sign-in`, why `Your dashboard password and how to
  open T3 Code`;
- the `lnd-seed-....txt` path: label `Lightning wallet seed`, why `Controls your node's money: anyone with this
  file can take it. Save it in your password manager, then delete it from Downloads.`

Never print these files: their contents only reach the user through `offer_file`.

After the `offer_file` calls, run the Check below. This step isn't done until it prints
`CHECKS handover PASS`; don't go on to the final check or commit before that.

**Check** (run it alone, exactly as written)
```sh
sh /etc/nixos/cc-check.sh handover
```
Expect `CHECKS handover PASS`.

**If it fails:** if `conf_has_endpoint` fails, `MACHINE_ADDRESS` wasn't filled in. Run the Do block again, by
name or with the fact in its place.

---

## Step 12: Commit, final check, report

If you didn't call `offer_file` for `wireguard.conf` and `control-center-login.txt` in Step 11, do it first (the
paths are in the user's home folder, which Step 1 printed). If you didn't offer the Lightning seed file either,
offer it right after this step's Do block: its path is the `OFFER` line that block prints. If it prints a `STOP`
line instead, offer no seed file and report that line.

**Do**
```sh
sh -eu <<'STEP'
git -C /etc/nixos add -A
git -C /etc/nixos -c user.name=control-center -c user.email=root@localhost commit -q -m "Control center" || true
git -C /etc/nixos log --oneline | head -n 3
n=$(find /var/lib/control-center -maxdepth 1 -name 'lnd-seed-*.txt' -type f | wc -l)
if [ "$n" -eq 1 ]; then echo "OFFER $(find /var/lib/control-center -maxdepth 1 -name 'lnd-seed-*.txt' -type f)"
elif [ "$n" -eq 0 ]; then echo "No Lightning seed file to offer (deleted after the user saved it, or none made)."
else echo "STOP: $n Lightning seed files; offer none and report this."; fi
STEP
```
**Check** (run it alone, exactly as written; it takes up to 5 minutes: it also checks T3 Connect and visits every address in app-url.txt):
```sh
printf '%s  /etc/nixos/cc-rebuild.sh\n%s  /etc/nixos/cc-check.sh\n' 369725dca22aba7edd6ad35a83f9ce5fe1b73ac01ed5b4d3d7e2564d2022839f ea4bc57b6bbb983e9ea836542278b0d0ab405d5063ba7da08edb399f9789591e | sha256sum -c --quiet && sh /etc/nixos/cc-check.sh done
```
Expect `CHECKS done PASS`. If only a `visit_` check fails for an onion address, wait 2 minutes and run it again: a
new onion service can take a few minutes to become reachable.
If the only FAIL line is `t3_sees_hermes_ready`: T3 Code checks Hermes only when it starts, so waiting doesn't
help. Run `systemctl restart t3code`, wait 1 minute (`sleep 60`) and run the Check again, once. If it still fails,
stop and report the FAIL lines; don't investigate further.

**Then report to the user:** "Your control center is ready. Open https://app.t3.codes, sign in to your T3
account, choose this machine and talk to Hermes Agent. You can also reach Hermes' own dashboard over WireGuard:
import `wireguard.conf` from your home folder and open http://10.88.0.1:9119/. Your sign-in details are in
`control-center-login.txt` in your home folder, readable only by you. Everything is declared in /etc/nixos and
comes back after a reboot. To add software later, ask me, or ask Hermes."

If the check printed `T3 Code: not linked yet`, report this instead: "Your control center is ready. T3 Code: not
linked yet. T3 Code runs on the machine, and `control-center-login.txt` in your home folder says how to link it
to your T3 account; until then, reach Hermes' own dashboard over WireGuard: import `wireguard.conf` from your
home folder and open http://10.88.0.1:9119/. Your sign-in details are in `control-center-login.txt`, readable only
by you. Everything is declared in /etc/nixos and comes back after a reboot. To add software later, ask me, or ask
Hermes."

Then call `done` with the `urls` that Header rule 10 lists. If the check printed `T3 Code: not linked yet`, leave
`https://app.t3.codes` out of `urls` completely.

---

## Recovery

**R0: what not to do.** Never edit `cc-*.nix`, `cc-rebuild.sh` or `cc-check.sh` except by running a step's Do
block. Never rewrite the user's files except by running Step 11's Do block. A FAIL line that ends with
`(needs the user: ask_operator)` waits on the user: ask with `ask_operator`, wait for the answer, then run that
step's Wait and Check again.

**R1: the rebuild failed (`REBUILD FAILED`).** Nothing changed: the old system is still running. Read the error
lines that the wait command printed.
- `error: path '/nix/store/...' does not exist` or `file '...' not found`: a file wasn't added to git. Run
  `git -C /etc/nixos add -A`, then start the rebuild again.
- `syntax error` or `undefined variable` in `cc-*.nix`: the file was mistyped. Run that step's Do block again
  exactly.
- `assertion ... failed` or `The option ... does not exist`: report the line to Farseed and stop. Don't invent
  options.
- `No space left on device`: run `nix-collect-garbage --delete-older-than 7d`, then start the rebuild again.
- Anything else: run the step's Do block once more. If it fails again, undo that step's file with
  `git -C /etc/nixos checkout -- <file>` (for example `cc-hermes.nix`), start the rebuild so the machine
  matches the files again, and report.

**R2: the rebuild succeeded but something broke** (a service down, or the dashboard gone):
```sh
sh /etc/nixos/cc-rebuild.sh rollback
```
then `sh /etc/nixos/cc-rebuild.sh wait`. This switches back to the previous system version without reading
/etc/nixos. (Plain `nixos-rebuild --rollback` doesn't work here: it looks for a flake output named after the
hostname.) Then undo the source too, or the next rebuild brings the problem back:
`git -C /etc/nixos checkout -- <file>`, or delete a new file in `extra/` (or `git revert` if it was
committed). Report.

**R3: SSH stopped answering during a rebuild.** Wait 3 minutes and try again. The rebuild runs as its own unit,
so it finishes anyway. If the machine is still unreachable, tell the user. The previous system version can be
chosen in the boot menu from the provider's console.

---

## Change recipe: installing more later

When the user asks for more software or a service:
1. Write one file, `/etc/nixos/extra/<short-name>.nix`. It's a NixOS module, for example
   `{ pkgs, ... }: { environment.systemPackages = [ pkgs.htop ]; }`. Check the package or option name first with
   `nix search nixpkgs#<name> 2>/dev/null | head` or
   `nix eval --raw nixpkgs#<name>.meta.description`.
2. Secrets go into a file under `/var/lib/control-center/` (mode 600, made with `umask 077`). The module refers to
   the file's path, never to the value.
3. A service the user should reach listens on 127.0.0.1 or 10.88.0.1 only. Open its port on `wg0` only, with
   `networking.firewall.interfaces.wg0.allowedTCPPorts`.
4. Run `sh /etc/nixos/cc-rebuild.sh`, then the wait command. Check the result, and commit as in Step 12.
5. To remove something: delete the file, rebuild, commit.

## New AI key (the key card was renewed)

1. Call `request_ai_key` again. The reply gives the new key file's path.
2. Run Step 4's Do block with the new path. It replaces the key, keeps the other keys and rewrites
   `hermes.env`.
3. Run `sh /etc/nixos/cc-rebuild.sh`, then the wait command. Activation copies `hermes.env` into Hermes'
   own settings.
4. Run `systemctl restart hermes-agent hermes-backend t3code`, then `sh /etc/nixos/cc-check.sh hermes`.

## Launching further machines

Not in this version. The decided shape: the agent prepares an order, and the user approves and pays it in Farseed.
