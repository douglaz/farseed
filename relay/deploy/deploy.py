#!/usr/bin/env python3
"""Install a relay on a dedicated Arch host through one strictly pinned SSH hop."""
import argparse
import base64
import ipaddress
from pathlib import Path
import re
import shlex
import subprocess


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "domain", "known-hosts", "identity", "binary", "passes", "dns-server"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--own-address", action="append", required=True)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    for label in (a.host, a.domain):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", label):
            p.error("host and domain must be lowercase DNS names or IPv4")
        if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in label.split(".")):
            p.error("invalid host or domain")
    try:
        a.dns_server = str(ipaddress.IPv4Address(a.dns_server))
        a.own_address = [str(ipaddress.ip_address(s)) for s in a.own_address]
    except ValueError:
        p.error("DNS must be numeric IPv4 and own addresses numeric IP addresses")
    for value in (a.known_hosts, a.identity, a.binary, a.passes):
        if "\n" in value or "\r" in value or "\0" in value:
            p.error("invalid file path")
    # OpenSSH parses this option again, including quotes, lists and expansions.
    # Restrict it to one absolute literal path rather than adding a trust source.
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", a.known_hosts):
        p.error("known-hosts must be an absolute literal path using letters, digits, /, _, ., -")
    return a


def main():
    a = arguments()
    root = Path(__file__).resolve().parent
    config = ('listen = "127.0.0.1:9000"\n'
              f'public_url = "wss://{a.domain}/"\n'
              'pass_file = "/etc/tau-relay/passes.toml"\n'
              f'dns_server = "{a.dns_server}:53"\n'
              'own_public = [' + ', '.join(f'"{ip}"' for ip in a.own_address) + ']\n')
    files = [
        ("/usr/local/bin/tau-relay", "0755", None, a.binary),
        ("/etc/tau-relay/passes.toml", "0640", None, a.passes),
        ("/etc/tau-relay/config.toml", "0640", config.encode(), None),
        ("/etc/systemd/system/tau-relay.service", "0644", (root / "tau-relay.service").read_bytes(), None),
        ("/etc/systemd/system/tau-relay-firewall.service", "0644", (root / "tau-relay-firewall.service").read_bytes(), None),
        ("/etc/caddy/Caddyfile", "0644", (root / "Caddyfile").read_text().replace("relay.example.net", a.domain).encode(), None),
        ("/etc/tau-relay/relay.nft", "0644", (root / "relay.nft").read_text().replace("192.0.2.53", a.dns_server).encode(), None),
    ]
    ssh = ["ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=" + a.known_hosts,
           "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
           "-o", "IdentitiesOnly=yes", "-i", a.identity,
           "arch@" + a.host, "sudo -n /bin/bash -s"]
    script = ["set -euo pipefail", "umask 077",
              "# Full upgrade and installation in a single transaction: no partial upgrade.",
              "pacman -Syu --noconfirm --needed caddy nftables",
              "getent passwd tau-relay >/dev/null || useradd --system --user-group --no-create-home --shell /usr/bin/nologin tau-relay",
              "install -d -o root -g tau-relay -m 0750 /etc/tau-relay"]
    for destination, mode, data, source in files:
        if source:
            data = f"contents of {source}".encode() if a.dry_run else Path(source).read_bytes()
        encoded = base64.b64encode(data).decode()
        stage = destination + ".new"
        script += [f"base64 -d > {shlex.quote(stage)} <<'RELAY_PAYLOAD'", encoded, "RELAY_PAYLOAD",
                   f"chmod {mode} {shlex.quote(stage)}",
                   f"mv -f {shlex.quote(stage)} {shlex.quote(destination)}"]
    script += ["chown root:tau-relay /etc/tau-relay/config.toml /etc/tau-relay/passes.toml",
               "relay_uid=$(id -u tau-relay)",
               "sed -i \"s/define relay_uid = 999/define relay_uid = ${relay_uid}/\" /etc/tau-relay/relay.nft",
               "nft -c -f /etc/tau-relay/relay.nft",
               "caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null",
               "systemd-analyze verify /etc/systemd/system/tau-relay.service",
               "nft -f /etc/tau-relay/relay.nft",
               "# Boot persistence owns only this table, never the system-wide ruleset.",
               "systemctl daemon-reload",
               "systemctl enable tau-relay-firewall.service tau-relay.service caddy.service",
               "systemctl restart tau-relay-firewall.service tau-relay.service caddy.service"]
    payload = "\n".join(script) + "\n"
    if a.dry_run:
        print(shlex.join(ssh))
        print("# stdin follows; binary/pass payloads use named placeholders")
        print(payload, end="")
    else:
        subprocess.run(ssh, input=payload.encode(), check=True)


if __name__ == "__main__":
    main()
