"""Shared local transport and remote operating-system boundary."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

BINARY = '/usr/local/bin/tau-relay'
UNIT = '/etc/systemd/system/tau-relay.service'
CONFIG = '/etc/tau-relay/config.toml'
PASSES = '/etc/tau-relay/passes.toml'
NFT = '/etc/tau-relay/relay.nft'
CADDY = '/etc/caddy/Caddyfile'
SERVICE = 'tau-relay.service'


class Refused(Exception):
    """A safe, value-free operational refusal."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def valid_key(key):
    if not isinstance(key, str) or not re.fullmatch('[0-9a-f]{64}', key):
        return False
    x = int(key, 16)
    prime = 2**256 - 2**32 - 977
    y2 = (x**3 + 7) % prime
    return x < prime and pow(pow(y2, (prime + 1) // 4, prime), 2, prime) == y2


def mask(address):
    return '.'.join(address.split('.')[:2]) + '.x.x'


class System:
    def __init__(self, root='/'):
        self.root = Path(root)

    def path(self, name):
        return self.root / name.lstrip('/')

    def read(self, name):
        path = self.path(name)
        require(stat.S_IMODE(path.stat().st_mode) != 0o600, 'file mode 0600 refused')
        return path.read_bytes()

    def digest(self, name):
        return sha(self.read(name))

    def run(self, *args):
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=10, check=False)
        require(result.returncode == 0, 'command failed: ' + args[0])
        return result.stdout

    def active(self):
        try:
            return self.run('systemctl', 'is-active', SERVICE).strip() == 'active'
        except Refused:
            return False

    def running_sha(self):
        pid = self.run('systemctl', 'show', SERVICE, '--property=MainPID', '--value').strip()
        require(pid.isdecimal() and int(pid) > 0, 'invalid MainPID')
        return self.digest('/proc/' + pid + '/exe')

    def cursor(self):
        output = self.run('journalctl', '-u', 'tau-relay', '--show-cursor', '-n', '0')
        cursors = re.findall(r'^-- cursor: (\S+)$', output, re.M)
        require(len(cursors) == 1, 'journal cursor missing')
        return cursors[0]

    def journal(self, cursor):
        return self.run('journalctl', '-u', 'tau-relay', '--after-cursor', cursor,
                        '-o', 'cat', '--no-pager').splitlines()

    def now(self):
        return int(time.time())

    def monotonic(self):
        return time.monotonic()

    def sleep(self):
        time.sleep(0.2)

    def stage(self, name, data, mode, owner=None):
        path = self.path(name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.fchmod(fd, mode)
            if owner is not None:
                os.fchown(fd, *owner)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)

    def sync_dir(self, name):
        fd = os.open(self.path(name), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def atomic_pass(self, data, before_replace):
        metadata = self.path(PASSES).stat()
        temp = PASSES + '.' + uuid.uuid4().hex + '.new'
        try:
            self.stage(temp, data, stat.S_IMODE(metadata.st_mode),
                       (metadata.st_uid, metadata.st_gid))
            cursor = before_replace()
            os.replace(self.path(temp), self.path(PASSES))
            self.sync_dir('/etc/tau-relay')
            return cursor
        finally:
            self.path(temp).unlink(missing_ok=True)


def check_rule(system):
    uid = system.run('id', '-u', 'tau-relay').strip()
    require(uid.isdecimal(), 'invalid relay uid')
    live = system.run('nft', '-n', 'list', 'chain', 'inet', 'tau_relay', 'output')
    rule = r'^\s*meta skuid ' + re.escape(uid) + r' tcp dport != 22 reject(?:\s+# handle \d+)?\s*$'
    require(re.search(rule, live, re.M), 'port-22 rule missing live')
    stored = system.read(NFT).decode()
    # Only an uncommented rule inside the output chain counts.
    stored = re.sub(r'#.*', '', stored)
    stored = re.sub(r'\$relay_uid\b', uid, stored)
    require(re.search(r'^\s*define relay_uid = ' + re.escape(uid) + r'\s*$', stored, re.M),
            'firewall uid mismatch')
    chain = re.search(r'\bchain output\s*\{([^{}]*)\}', stored, re.S)
    require(chain and re.search(rule, chain[1], re.M), 'port-22 rule missing file')


def connection_arguments(parser):
    for name in ('host', 'known-hosts', 'identity'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--dry-run', action='store_true')


def validate_connection(parser, args):
    require(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', args.host)
            and all(part and len(part) <= 63 and not part.startswith('-')
                    and not part.endswith('-') for part in args.host.split('.')),
            'invalid host')
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', args.known_hosts),
            'known-hosts must be an absolute literal path using letters, digits, /, _, ., -')
    require(not any(c in args.identity for c in '\n\r\0'), 'invalid identity path')


def ssh(args, command):
    return ['ssh', '-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + args.known_hosts,
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no',
            '-o', 'IdentitiesOnly=yes', '-i', args.identity,
            'arch@' + args.host, command]


def run_remote(args, command, program, failure_prefix):
    result = subprocess.run(ssh(args, command), input=program.encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    # Remote programs emit only their controlled audit output; transport diagnostics
    # can contain complete host addresses, so do not forward stderr.
    print(result.stdout.decode(errors='replace'), end='')
    if result.returncode:
        print(failure_prefix + ': remote session failed; stop and establish the outcome')
    return result.returncode


def remote_program(module, params):
    root = Path(__file__).resolve().parent
    parts = ['import json, sys, types']
    modules = ('relay_ops', 'pass_ops', module) if module == 'upgrade_ops' else ('relay_ops', module)
    for name in modules:
        path = root / (name + '.py')
        require(stat.S_IMODE(path.stat().st_mode) != 0o600, 'file mode 0600 refused')
        source = path.read_text()
        parts += [f'm = types.ModuleType({name!r})', f'sys.modules[{name!r}] = m',
                  f'exec(compile({source!r}, {name!r}, "exec"), m.__dict__)']
    parts.append('sys.exit(m.remote_main(json.loads(' + repr(json.dumps(params)) + ')))')
    return '\n'.join(parts) + '\n'


def hash_argument(value):
    require(re.fullmatch('[0-9a-f]{64}', value), 'invalid sha256')
    return value


def cli_error(action, prefix='FAIL'):
    try:
        return action()
    except Refused as error:
        print(prefix + ': ' + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print(prefix + ': local validation or transport failed', file=sys.stderr)
        return 1
