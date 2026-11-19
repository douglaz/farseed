# ---- fixed body of tau-web's CHN-R5a first-boot hook (the page puts the values above it) ----
# Runs once per instance as root (cloud-init's user script, scripts-user in cloud-final), after cloud-init's ssh module
# has made this machine's own host keys. It certifies the Ed25519 host key with the one-time authority above, for
# exactly the principal and until the deadline, makes sshd offer the certificate and checks that it does. On any
# failure the machine ends with NO certificate (never a weaker one): the page then refuses every presentation until
# its deadline passes. The whole body is one function, read before it runs: the scrub empties cloud-init's copy of
# this very script, and a shell still reading it line by line would stop there. The result line (no secret) is also
# kept in /var/log/tau-attest.log, root-only, because cloud-init on this image keeps no output log.
set -u
PATH=/run/current-system/sw/bin:/run/wrappers/bin:/usr/bin:/bin:$PATH
SYSTEMCTL=${SYSTEMCTL:-systemctl}
KEY=/etc/ssh/ssh_host_ed25519_key
CERT=/etc/ssh/ssh_host_ed25519_key-cert.pub
log() {
  echo "tau-attest: $*"
  logger -t tau-attest "$*" 2>/dev/null || true
  printf '%s tau-attest: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> /var/log/tau-attest.log 2>/dev/null || true
}
scrub() {
  rm -f /run/tau-attest/ca
  # Defence in depth only (the bound is the page's deadline and single use): empty cloud-init's own copies of this
  # script and of the user-data it came in.
  for f in $(grep -rlF 'tau-web CHN-R5a first-boot hook' /var/lib/cloud /run/cloud-init 2>/dev/null); do : > "$f"; done
}
fail() {
  rm -f "$CERT"
  $SYSTEMCTL reload sshd.service >/dev/null 2>&1 || true
  scrub
  log "FAILED: $1 (no certificate)"
  exit 1
}
tau_attest() {
  [ "$(date -u +%s)" -lt "$DEADLINE_EPOCH" ] || fail "deadline passed"
  # The login user and the page's key (the vendor's own key handling isn't relied on).
  if ! id nixos >/dev/null 2>&1; then
    useradd -m -G wheel -s /run/current-system/sw/bin/bash nixos || fail "no login user"
    printf 'nixos ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/90-tau-nixos
  fi
  HOME_DIR=$(getent passwd nixos | cut -d: -f6)
  install -d -m 700 -o nixos -g "$(id -gn nixos)" "$HOME_DIR/.ssh" || fail "no .ssh folder"
  printf '%s\n' "$CLIENT" >> "$HOME_DIR/.ssh/authorized_keys" || fail "client key not written"
  chown nixos: "$HOME_DIR/.ssh/authorized_keys"; chmod 600 "$HOME_DIR/.ssh/authorized_keys"
  # This machine's own Ed25519 host key, made at first boot.
  i=0
  while { [ ! -s "$KEY" ] || [ ! -s "$KEY.pub" ]; } && [ "$i" -lt "${KEY_WAIT:-60}" ]; do sleep 2; i=$((i + 2)); done
  [ -s "$KEY" ] && [ -s "$KEY.pub" ] || fail "no host key"
  [ "$(cut -d' ' -f1 "$KEY.pub")" = ssh-ed25519 ] || fail "host key is not ssh-ed25519"
  rm -f "$CERT"
  ssh-keygen -q -s /run/tau-attest/ca -h -I "$P" -n "$P" -V "-5m:${DEADLINE}Z" "$KEY.pub" || fail "signing failed"
  [ -s "$CERT" ] || fail "no certificate written"
  [ "$(date -u +%s)" -lt "$DEADLINE_EPOCH" ] || fail "deadline passed"
  chmod 644 "$CERT"
  $SYSTEMCTL reload sshd.service || fail "sshd reload failed"
  n=0; offered=no
  while [ "$n" -lt 15 ]; do
    # ssh-keyscan -c prints a certificate as "<type> <base64>", with no host field in front.
    if ssh-keyscan -c -t ed25519 -p 22 127.0.0.1 2>/dev/null | grep -q '^ssh-ed25519-cert-v01@openssh.com '; then offered=yes; break; fi
    sleep 1; n=$((n + 1))
  done
  [ "$offered" = yes ] || fail "sshd does not offer the certificate"
  scrub
  log "CERTIFIED principal $P until ${DEADLINE}Z"
}
tau_attest; exit $?
