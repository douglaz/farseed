# Control center playbook

Goal template 1, "Control center". Generated from the control-center sources; edit those, not this file.

tau-web gives the AI the **Header** and **Facts** with every step, plus **one step at a time**. Each step is a
**Do** block, sometimes a **Wait** command, and a **Check** command. The check's last line says PASS or FAIL.

---

## Header (send with every step)

You are building the user's control center on this NixOS machine. Follow the step below exactly.

1. Run the step's commands exactly as written. Change only the words in CAPITALS that the step tells you to
   replace with a fact. Send each block as one command.
2. Never print a secret. Don't cat, echo or grep the files in /var/lib/control-center, except files ending in
   `.pub`. Don't print the user's wireguard.conf or login file.
3. Never put a secret in /etc/nixos or in any `.nix` file.
4. Make every lasting change through /etc/nixos and `sh /etc/nixos/cc-rebuild.sh`. Never use nix-env,
   nix profile, pip, npm -g or curl|sh, and never edit /etc outside /etc/nixos.
5. Never reboot. Never run `nixos-rebuild` yourself: `cc-rebuild.sh` runs it the right way (switch, the flake
   output `control`, in the background). Never change SSH settings or host keys.
6. Go to the next step only when the check's last line says PASS. On FAIL, do what "If it fails" says, at most
   twice. If it still fails, stop and report the FAIL lines and the step number.
7. Commands already run as root. Keep output short: only the first 8 KiB of output comes back, and the
   scripts print only what matters.

## Facts (tau-web fills these in)

- `MACHINE_ADDRESS`: the public IPv4 address or DNS name the user's devices reach this machine at, the same one
  tau-web uses for SSH.
- `AI_BASE_URL`: the AI endpoint URL for the agent, ending in `/v1`.
- `AI_MODEL`: the model name for the agent.
- The AI key itself is never a fact: in Step 4 you ask for it with `request_ai_key`, and tau-web saves it in a
  file on this machine whose path the reply gives.
- `AGENT_MAY_CHANGE_MACHINE`: `yes` or `no`. Step 8 runs only on `yes`.

---

## Step 1: Look at the machine

**Do** (this block is also the check)
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
# Control center checks, run as root: sh cc-check.sh base|keys|access|hermes|handover|agent|done
# Prints one line per failed check, then "CHECKS <part> PASS|FAIL <passed>/<total>". Never prints a secret.
export PATH=/run/current-system/sw/bin:/run/wrappers/bin:$PATH
S=/var/lib/control-center; O=/var/lib/tor/onion/control-center/hostname
U=$(cat $S/login-user 2>/dev/null); H=$(getent passwd "$U" | cut -d: -f6); N=0; G=0
t() { n=$1; shift; N=$((N+1)); if "$@" >/dev/null 2>&1; then G=$((G+1)); else echo "CHECK $n FAIL"; fi; }
m() { [ "$(stat -c '%a %U' "$1" 2>/dev/null)" = "$2" ]; }
k() { test -s "$1" && m "$1" "600 root"; }
w() { s=$1; shift; i=0; while [ $i -lt "$s" ] && ! "$@" >/dev/null 2>&1; do sleep 2; i=$((i+2)); done; }
fw() { iptables -S nixos-fw; }
has() { printf '%s%s\n' "$2" "$(cat "$3")" | grep -qxFf - "$1"; }
login() { if [ "$1" = right ]; then jq -n --rawfile p $S/dashboard-password '{provider:"basic",username:"owner",password:$p}'
  else echo '{"provider":"basic","username":"owner","password":"x"}'; fi | curl -s -m 10 -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' -d @- http://127.0.0.1:9119/auth/password-login | grep -qx "$2"; }
visit() { case "$1" in *.onion*) x="--socks5-hostname 127.0.0.1:9050" ;; *) x="" ;; esac
  curl -s -m 30 $x -o /dev/null -w '%{http_code} %{redirect_url}\n' "$1" | grep -qE '^(401|403) |^30[1278] .*login'; }
base() {
  t os_is_nixos grep -qx ID=nixos /etc/os-release
  t flake_lock_tracked git -C /etc/nixos ls-files --error-unmatch flake.lock
  t running_is_boot_default test "$(readlink -f /run/current-system)" = "$(readlink -f /nix/var/nix/profiles/system)"
  t tools_on_path sh -c 'command -v wg && command -v jq'
}
keys() {
  t secrets_dir_root_700 m $S "700 root"
  for f in wg-server.key wg-user.key dashboard-password dashboard-secret ai-key hermes.env; do t "${f}_root_600" k $S/$f; done
  t hermes_env_names test "$(cut -d= -f1 $S/hermes.env | sort | tr '\n' ' ')" = "CONTROL_CENTER_AI_KEY \
HERMES_DASHBOARD_BASIC_AUTH_PASSWORD HERMES_DASHBOARD_BASIC_AUTH_SECRET HERMES_DASHBOARD_BASIC_AUTH_USERNAME "
}
access() {
  t wg0_address sh -c 'ip -4 addr show wg0 | grep -q "inet 10.88.0.1/24"'
  t wg0_port_51820 sh -c 'wg show wg0 listen-port | grep -qx 51820'
  t wg0_peer_is_user_key sh -c "wg show wg0 peers | grep -qxFf $S/wg-user.pub"
  t wg0_server_key_matches test "$(wg show wg0 public-key)" = "$(cat $S/wg-server.pub)"
  t tor_active systemctl is-active -q tor
  w 60 test -s $O
  t onion_hostname grep -qE '^[a-z2-7]{56}\.onion$' $O
  t fw_udp_51820_open sh -c 'iptables -S nixos-fw | grep -q -- "-p udp -m udp --dport 51820 -j nixos-fw-accept"'
  t fw_9119_on_wg0_only sh -c 'iptables -S nixos-fw | grep -q -- "-i wg0 -p tcp -m tcp --dport 9119" &&
    ! iptables -S nixos-fw | grep -- "--dport 9119" | grep -qv -- "-i wg0"'
  P=$(fw | grep -- '-j nixos-fw-accept' | grep -v -- ' -i ' | grep -oE -- '--dport [0-9:]+' | cut -d' ' -f2 | sort -u | tr '\n' ' ')
  t public_ports_only_22_51820 test "$P" = "22 51820 "
}
hermes() {
  t hermes_agent_active systemctl is-active -q hermes-agent
  t hermes_backend_active systemctl is-active -q hermes-backend
  w 90 curl -sf -m 2 -o /dev/null http://127.0.0.1:9119/api/status
  t signin_gate_on sh -c 'curl -s -m 10 http://127.0.0.1:9119/api/status | jq -e ".auth_required and (.auth_providers | index(\"basic\") != null)"'
  t answers_on_wg0 curl -sf -m 10 -o /dev/null http://10.88.0.1:9119/api/status
  t wrong_password_refused login wrong 401
  t right_password_accepted login right 200
}
handover() {
  t wireguard_conf_600 m "$H/wireguard.conf" "600 $U"
  t login_file_600 m "$H/control-center-login.txt" "600 $U"
  t conf_has_user_key has "$H/wireguard.conf" "PrivateKey = " $S/wg-user.key
  t conf_has_server_key has "$H/wireguard.conf" "PublicKey = " $S/wg-server.pub
  t conf_has_endpoint grep -qE '^Endpoint = .+:51820$' "$H/wireguard.conf"
  t login_has_password has "$H/control-center-login.txt" "password: " $S/dashboard-password
  t url_wireguard grep -qx 'http://10.88.0.1:9119/' "$H/app-url.txt"
  t url_onion grep -qxF "http://$(cat $O)/" "$H/app-url.txt"
}
agent() {
  t polkit_active systemctl is-active -q polkit
  t apply_rule_present sh -c 'grep -qs control-center-apply /etc/polkit-1/rules.d/*'
  t extra_dir_root_hermes_2775 test "$(stat -c '%U:%G %a' /etc/nixos/extra)" = "root:hermes 2775"
  t hermes_starts_apply runuser -u hermes -- systemctl start control-center-apply
  sleep 3
  t apply_rebuild_ok sh /etc/nixos/cc-rebuild.sh wait
  t hermes_refused_other_units sh -c '! runuser -u hermes -- systemctl start sshd'
}
final() {
  base; keys; access; hermes; handover
  while read -r u; do w 270 visit "$u"; t "visit_unsigned_refused_${u%%.onion*}" visit "$u"; done < "$H/app-url.txt"
  t no_secret_in_config sh -c "! grep -rqF -f $S/wg-server.key -f $S/wg-user.key -f $S/dashboard-password \
    -f $S/dashboard-secret -f $S/ai-key /etc/nixos && ! grep -RqF -f $S/wg-server.key -f $S/wg-user.key \
    -f $S/dashboard-password -f $S/dashboard-secret -f $S/ai-key /etc/static/"
  for u in hermes-agent hermes-backend tor; do
    t "${u}_unit_from_store" sh -c "readlink -f \"\$(systemctl show -p FragmentPath --value $u)\" | grep -q ^/nix/store/"
    t "${u}_enabled_at_boot" sh -c "systemctl show -p WantedBy --value $u | grep -qw multi-user.target"
  done
  t config_committed test -z "$(git -C /etc/nixos status --porcelain)"
}
case "$1" in
  base|keys|access|hermes|handover|agent) "$1" ;; done) final ;;
  *) echo "usage: sh cc-check.sh base|keys|access|hermes|handover|agent|done"; exit 2 ;;
esac
echo "CHECKS $1 $([ $G = $N ] && echo PASS || echo FAIL) $G/$N"
[ $G = $N ]
FILE
git -C /etc/nixos add -A
echo SCRIPTS_WRITTEN
STEP
```
**Check** (the two scripts must match byte for byte):
```sh
printf '%s  /etc/nixos/cc-rebuild.sh\n%s  /etc/nixos/cc-check.sh\n' 369725dca22aba7edd6ad35a83f9ce5fe1b73ac01ed5b4d3d7e2564d2022839f 48a97e9977db19336abf9bd07fc003b0a32753309e591803ec31d28bab07acab | sha256sum -c && echo "CHECKS scripts PASS" || echo "CHECKS scripts FAIL"
```
Expect `CHECKS scripts PASS`.

**If it fails:** a script that says FAILED was copied wrongly. Run the Do block again, copying it exactly with
nothing added, removed or reformatted, then check again. The final check repeats this hash check, so an edited
script fails the whole goal.

---

## Step 3: Make /etc/nixos a flake and apply it

This writes the flake (pinned to the nixpkgs revision the machine already runs, plus Hermes Agent), the tools
module, the `extra/` loader, and three empty modules that later steps fill in.

**Do**
```sh
sh -eu <<'STEP'
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
        ./cc-access.nix
        ./cc-hermes.nix
        ./cc-agent.nix
        ./cc-extra.nix
      ];
    };
  };
}
FILE
sed -i "s/@nixpkgs_rev@/$(nixos-version --revision)/" /etc/nixos/flake.nix
cat > /etc/nixos/cc-base.nix <<'FILE'
{ pkgs, ... }:
{
  # Tools the control center's steps and checks use.
  environment.systemPackages = with pkgs; [ git curl jq wireguard-tools ];
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
for f in cc-access cc-hermes cc-agent; do echo '{ ... }: { }' > /etc/nixos/$f.nix; done
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
**Check**
```sh
sh /etc/nixos/cc-check.sh base
```
Expect `CHECKS base PASS`.

**If it fails:** if the lock printed an `error` line about fetching, the machine can't reach github.com: wait one
minute and run the Do block again. On `REBUILD FAILED`, see **Recovery R1**.

---

## Step 4: Create the keys and the secrets file

First call `request_ai_key` with application `Hermes Agent` and purpose `The control center's own AI agent`.
The user approves it on a card. The reply gives the path of the key file on this machine: put that path in the
first line of the Do block instead of `AI_KEY_PATH`. All values go only into files, and nothing here prints them.

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
**Check**
```sh
sh /etc/nixos/cc-check.sh keys
```
Expect `CHECKS keys PASS`.

**If it fails:** `install: cannot stat` means the key path is wrong: use the path from the `request_ai_key`
reply exactly. The block never overwrites a key that already exists, so running it again is safe.

---

## Step 5: Private access (WireGuard, Tor, firewall)

**Do**
```sh
sh -eu <<'STEP'
cat > /etc/nixos/cc-access.nix <<'FILE'
{ ... }:
{
  # Private access only: WireGuard (UDP 51820 is the one new public port) and a Tor onion service.
  # The dashboard port 9119 is open on the WireGuard interface only, never on the public one.
  networking.firewall.enable = true;
  networking.firewall.allowedUDPPorts = [ 51820 ];
  networking.firewall.interfaces.wg0.allowedTCPPorts = [ 9119 ];

  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.88.0.1/24" ];
    listenPort = 51820;
    # Generated in step 4; root-only file outside the Nix store.
    privateKeyFile = "/var/lib/control-center/wg-server.key";
    peers = [
      { publicKey = "@wg_user_public_key@"; allowedIPs = [ "10.88.0.2/32" ]; }
    ];
  };

  services.tor = {
    enable = true;
    # Local SOCKS port 127.0.0.1:9050, used by the self-check through Tor.
    client.enable = true;
    relay.onionServices.control-center.map = [
      { port = 80; target = { addr = "127.0.0.1"; port = 9119; }; }
    ];
  };
}
FILE
sed -i "s|@wg_user_public_key@|$(cat /var/lib/control-center/wg-user.pub)|" /etc/nixos/cc-access.nix
grep -c 'publicKey = "' /etc/nixos/cc-access.nix
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait** (about 1 minute):
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check**
```sh
sh /etc/nixos/cc-check.sh access
```
Expect `CHECKS access PASS`. The check itself waits up to a minute for Tor.

**If it fails:** on `REBUILD FAILED`, see **Recovery R1**. If `wg0_peer_is_user_key` fails, run the Do block
again (it rewrites the file).

---

## Step 6: Hermes Agent with its web dashboard

Replace `AI_BASE_URL` and `AI_MODEL` in the first two lines with the facts, keeping the quotes. The first Hermes
build downloads and builds a lot: **expect 5 minutes, and up to 40 on a slow network.** Keep running the Wait
command until it says REBUILD OK or REBUILD FAILED. Do nothing else meanwhile.

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
    # Secrets (AI key, dashboard sign-in) live in this root-only file, never in /etc/nixos.
    environmentFiles = [ "/var/lib/control-center/hermes.env" ];
    settings.model = {
      provider = "custom";
      base_url = "@ai_base_url@";
      default = "@ai_model@";
      key_env = "CONTROL_CENTER_AI_KEY";
    };
    # The web dashboard. A non-loopback bind turns on its sign-in gate; the firewall keeps
    # the port off the public interface (see cc-access.nix).
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
**Check**
```sh
sh /etc/nixos/cc-check.sh hermes
```
Expect `CHECKS hermes PASS`. The check itself waits up to 90 seconds for the dashboard to start answering.

**If it fails:** on `REBUILD FAILED`, see **Recovery R1**. If `hermes_backend_active` fails, look at
`journalctl -u hermes-backend -n 20 --no-pager | cut -c1-200` and report those lines.

---

## Step 7: The user's files

Replace `MACHINE_ADDRESS` with the fact (an IP address or a name, without a port).

**Do**
```sh
sh -eu <<'STEP'
S=/var/lib/control-center
U=$(cat $S/login-user); H=$(getent passwd "$U" | cut -d: -f6)
ONION=$(cat /var/lib/tor/onion/control-center/hostname)
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
  echo "Control center dashboard sign-in"
  echo "user: owner"
  echo "password: $(cat $S/dashboard-password)"
  echo "Over WireGuard (import wireguard.conf first): http://10.88.0.1:9119/"
  echo "Over Tor (Tor Browser): http://$ONION/"
} > "$H/control-center-login.txt"
printf 'http://10.88.0.1:9119/\nhttp://%s/\n' "$ONION" > "$H/app-url.txt"
chmod 600 "$H/wireguard.conf" "$H/control-center-login.txt"; chmod 644 "$H/app-url.txt"
chown "$U": "$H/wireguard.conf" "$H/control-center-login.txt" "$H/app-url.txt"
echo FILES_WRITTEN
STEP
```
**Check**
```sh
sh /etc/nixos/cc-check.sh handover
```
Expect `CHECKS handover PASS`.

**If it fails:** if `wireguard_conf_has_endpoint` fails, `MACHINE_ADDRESS` wasn't replaced. Run the Do block
again with the fact filled in.

---

## Step 8 (only if `AGENT_MAY_CHANGE_MACHINE` is `yes`; otherwise skip to Step 9): let the agent install more

After this step, Hermes can add a module to /etc/nixos/extra and apply it. Every command it flags as risky waits
for the user's approval in the chat.

**Do**
```sh
sh -eu <<'STEP'
cat > /etc/nixos/cc-agent.nix <<'FILE'
{ ... }:
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
  '';

  systemd.tmpfiles.rules = [ "d /etc/nixos/extra 2775 root hermes - -" ];
  systemd.services.hermes-agent.serviceConfig.ReadWritePaths = [ "/etc/nixos/extra" ];
  systemd.services.hermes-backend.serviceConfig.ReadWritePaths = [ "/etc/nixos/extra" ];

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
sh /etc/nixos/cc-rebuild.sh
STEP
```
**Wait**
```sh
sh /etc/nixos/cc-rebuild.sh wait
```
**Check** (asks for one rebuild as the hermes user, the way the agent will; takes up to a minute):
```sh
sh /etc/nixos/cc-check.sh agent
```
Expect `CHECKS agent PASS`.

**If it fails:** if `polkit_active` or `apply_rule_present` fails, the new module wasn't applied. Run the Do block
again exactly, then the Wait, then the Check.

---

## Step 9: Commit, final check, report

**Do**
```sh
sh -eu <<'STEP'
git -C /etc/nixos add -A
git -C /etc/nixos -c user.name=control-center -c user.email=root@localhost commit -q -m "Control center" || true
git -C /etc/nixos log --oneline | head -n 3
STEP
```
**Check** (takes up to 5 minutes: it also visits both addresses, the onion one through Tor):
```sh
printf '%s  /etc/nixos/cc-rebuild.sh\n%s  /etc/nixos/cc-check.sh\n' 369725dca22aba7edd6ad35a83f9ce5fe1b73ac01ed5b4d3d7e2564d2022839f 48a97e9977db19336abf9bd07fc003b0a32753309e591803ec31d28bab07acab | sha256sum -c --quiet && sh /etc/nixos/cc-check.sh done
```
Expect `CHECKS done PASS`. If only a `visit_` check fails for the onion address, wait 2 minutes and run it
again: a new onion service can take a few minutes to become reachable.

**Then report to the user** (fill in the onion address from `/home/<user>/app-url.txt`, which is safe to print):
"Your control center is ready. Open it privately over WireGuard (import `wireguard.conf` from your home folder,
then open http://10.88.0.1:9119/) or over Tor (http://….onion/ in Tor Browser). Your sign-in is in
`control-center-login.txt` in your home folder, readable only by you. Everything is declared in /etc/nixos and
comes back after a reboot. To add software later, ask me."

---

## Recovery

**R1: the rebuild failed (`REBUILD FAILED`).** Nothing changed: the old system is still running. Read the error
lines that the wait command printed.
- `error: path '/nix/store/...' does not exist` or `file '...' not found`: a file wasn't added to git. Run
  `git -C /etc/nixos add -A`, then start the rebuild again.
- `syntax error` or `undefined variable` in `cc-*.nix`: the file was mistyped. Run that step's Do block again
  exactly.
- `assertion ... failed` or `The option ... does not exist`: report the line to tau-web and stop. Don't invent
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
4. Run `sh /etc/nixos/cc-rebuild.sh`, then the wait command. Check the result, and commit as in Step 9.
5. To remove something: delete the file, rebuild, commit.

## New AI key (the key card was renewed)

1. Call `request_ai_key` again. The reply gives the new key file's path.
2. Run `rm /var/lib/control-center/ai-key`, then Step 4's Do block with the new path. It keeps the other keys
   and rewrites `hermes.env`.
3. Run `sh /etc/nixos/cc-rebuild.sh`, then the wait command. Activation copies `hermes.env` into Hermes'
   own settings.
4. Run `systemctl restart hermes-agent hermes-backend`, then `sh /etc/nixos/cc-check.sh hermes`.

## Launching further machines

Not in this version. The decided shape: the agent prepares an order, and the user approves and pays it in tau-web.
